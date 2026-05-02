// Package csharp is the SentinelCore SAST engine's C# source frontend.
//
// This package ships a pure-Go hand-rolled tokenizer and structural parser
// targeting the C# subset the MVP rule set needs:
//
//   - using directives (including `using static`)
//   - block-scoped and file-scoped namespaces
//   - top-level and nested classes, interfaces, structs, enums
//   - method declarations with parameter type tracking
//   - method invocations (instance + static + constructor)
//   - string literals, verbatim strings, and interpolated strings
//   - field initializers with string-literal values (secret detection)
//
// This is deliberately NOT a complete C# parser. It models only enough
// of the language to detect the 6 MVP vulnerability classes
// (command injection, path traversal, SQL injection, unsafe deserialization,
// SSRF, hardcoded secrets) with high confidence and zero false positives on
// safe cases.
package csharp

// TokenKind is the coarse category of a C# lexical token. Keywords are NOT
// distinguished from identifiers at the lexer level — the parser decides
// what's a keyword contextually.
type TokenKind int

const (
	// TokEOF terminates every token stream.
	TokEOF TokenKind = iota
	// TokIdent is any C# identifier, including keywords. Val holds the raw
	// source text (with any leading '@' stripped).
	TokIdent
	// TokString is a string literal ("…", @"…", $"…", $@"…"). Val holds the
	// decoded contents. Interpolated strings preserve their `{expr}` segments
	// as literal text inside Val; the parser scans Val for `{localName}` to
	// propagate taint.
	TokString
	// TokNumber is any numeric literal.
	TokNumber
	// TokChar is a single character literal 'x'.
	TokChar
	// TokPunct is any operator or separator.
	TokPunct
)

// Token is one lexical unit. Line and Col are 1-indexed so they round-trip
// to the existing ir.Location used by the rule engine.
type Token struct {
	Kind TokenKind
	Val  string
	Line int
	Col  int
}

// Tokenize returns a flat slice of tokens terminated with a single TokEOF.
// Line, block, and XML-doc comments are skipped. The lexer is resilient to
// malformed input — it never returns an error.
func Tokenize(src []byte) []Token {
	l := &lexer{src: src, line: 1, col: 1}
	for l.pos < len(l.src) {
		l.skipWhitespaceAndComments()
		if l.pos >= len(l.src) {
			break
		}
		l.readToken()
	}
	l.toks = append(l.toks, Token{Kind: TokEOF, Line: l.line, Col: l.col})
	return l.toks
}

type lexer struct {
	src  []byte
	pos  int
	line int
	col  int
	toks []Token
}

func (l *lexer) advance() {
	if l.pos < len(l.src) {
		l.pos++
		l.col++
	}
}

// skipWhitespaceAndComments consumes runs of ASCII whitespace, line comments
// (// to end of line, also /// XML docs), and block comments (/* … */).
func (l *lexer) skipWhitespaceAndComments() {
	for l.pos < len(l.src) {
		b := l.src[l.pos]
		switch {
		case b == ' ' || b == '\t' || b == '\r':
			l.advance()
		case b == '\n':
			l.pos++
			l.line++
			l.col = 1
		case b == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			// Line comment (also handles /// XML doc comments).
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case b == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			l.pos += 2
			l.col += 2
			for l.pos+1 < len(l.src) && !(l.src[l.pos] == '*' && l.src[l.pos+1] == '/') {
				if l.src[l.pos] == '\n' {
					l.line++
					l.col = 1
					l.pos++
				} else {
					l.advance()
				}
			}
			if l.pos+1 < len(l.src) {
				l.pos += 2
				l.col += 2
			}
		default:
			return
		}
	}
}

// readToken dispatches on the current byte to one of the specialized readers.
func (l *lexer) readToken() {
	startLine, startCol := l.line, l.col
	b := l.src[l.pos]

	// `@"..."` verbatim string or `@identifier` (reserved-word-as-identifier).
	if b == '@' && l.pos+1 < len(l.src) {
		next := l.src[l.pos+1]
		if next == '"' {
			l.pos++ // skip '@'
			l.col++
			l.readVerbatimString(startLine, startCol, false)
			return
		}
		if isIdentStart(next) {
			// Skip the '@' and read identifier.
			l.advance()
			l.readIdent(startLine, startCol)
			return
		}
	}

	// `$"..."` interpolated string or `$@"..."` verbatim interpolated.
	if b == '$' && l.pos+1 < len(l.src) {
		next := l.src[l.pos+1]
		if next == '"' {
			l.pos++ // skip '$'
			l.col++
			l.readString(startLine, startCol)
			return
		}
		if next == '@' && l.pos+2 < len(l.src) && l.src[l.pos+2] == '"' {
			l.pos += 2 // skip '$@'
			l.col += 2
			l.readVerbatimString(startLine, startCol, true)
			return
		}
	}

	if isIdentStart(b) {
		l.readIdent(startLine, startCol)
		return
	}
	if isDigit(b) {
		l.readNumber(startLine, startCol)
		return
	}
	if b == '"' {
		l.readString(startLine, startCol)
		return
	}
	if b == '\'' {
		l.readChar(startLine, startCol)
		return
	}
	l.readPunct(startLine, startCol)
}

func (l *lexer) readIdent(startLine, startCol int) {
	start := l.pos
	for l.pos < len(l.src) && isIdentCont(l.src[l.pos]) {
		l.advance()
	}
	l.toks = append(l.toks, Token{
		Kind: TokIdent,
		Val:  string(l.src[start:l.pos]),
		Line: startLine,
		Col:  startCol,
	})
}

func (l *lexer) readNumber(startLine, startCol int) {
	start := l.pos
	for l.pos < len(l.src) {
		b := l.src[l.pos]
		if isDigit(b) ||
			b == '.' ||
			b == '_' ||
			b == 'x' || b == 'X' ||
			b == 'b' || b == 'B' ||
			(b >= 'a' && b <= 'f') ||
			(b >= 'A' && b <= 'F') ||
			b == 'L' || b == 'l' ||
			b == 'F' || b == 'f' ||
			b == 'D' || b == 'd' ||
			b == 'M' || b == 'm' ||
			b == 'U' || b == 'u' {
			l.advance()
			continue
		}
		break
	}
	l.toks = append(l.toks, Token{
		Kind: TokNumber,
		Val:  string(l.src[start:l.pos]),
		Line: startLine,
		Col:  startCol,
	})
}

// readString consumes a single-line string literal with backslash escapes.
// Handles both regular "..." and interpolated $"..." strings — for
// interpolated strings the `{...}` segments are preserved verbatim in the
// token value so the parser can scan them for local variable references.
func (l *lexer) readString(startLine, startCol int) {
	l.advance() // opening "
	var sb []byte
	for l.pos < len(l.src) {
		b := l.src[l.pos]
		if b == '"' {
			l.advance()
			break
		}
		if b == '\n' {
			break
		}
		if b == '\\' && l.pos+1 < len(l.src) {
			l.pos++
			l.col++
			next := l.src[l.pos]
			switch next {
			case 'n':
				sb = append(sb, '\n')
			case 't':
				sb = append(sb, '\t')
			case 'r':
				sb = append(sb, '\r')
			case '\\':
				sb = append(sb, '\\')
			case '"':
				sb = append(sb, '"')
			case '\'':
				sb = append(sb, '\'')
			case '0':
				sb = append(sb, 0)
			default:
				sb = append(sb, next)
			}
			l.pos++
			l.col++
			continue
		}
		sb = append(sb, b)
		l.advance()
	}
	l.toks = append(l.toks, Token{
		Kind: TokString,
		Val:  string(sb),
		Line: startLine,
		Col:  startCol,
	})
}

// readVerbatimString consumes a `@"..."` or `$@"..."` verbatim string. The
// caller must have already consumed the `@` or `$@` prefix — this function
// is positioned at the opening `"`. Inside a verbatim string, backslashes
// are literal and `""` is an escape for a single `"`. Newlines are allowed
// and preserved.
func (l *lexer) readVerbatimString(startLine, startCol int, isInterpolated bool) {
	_ = isInterpolated
	l.advance() // skip opening "
	var sb []byte
	for l.pos < len(l.src) {
		b := l.src[l.pos]
		if b == '"' {
			// Check for `""` escape.
			if l.pos+1 < len(l.src) && l.src[l.pos+1] == '"' {
				sb = append(sb, '"')
				l.pos += 2
				l.col += 2
				continue
			}
			l.advance() // closing "
			break
		}
		if b == '\n' {
			sb = append(sb, '\n')
			l.pos++
			l.line++
			l.col = 1
			continue
		}
		sb = append(sb, b)
		l.advance()
	}
	l.toks = append(l.toks, Token{
		Kind: TokString,
		Val:  string(sb),
		Line: startLine,
		Col:  startCol,
	})
}

// readChar consumes a char literal. We don't care about the decoded value.
func (l *lexer) readChar(startLine, startCol int) {
	start := l.pos
	l.advance() // opening '
	for l.pos < len(l.src) && l.src[l.pos] != '\'' {
		if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
			l.advance()
		}
		if l.pos < len(l.src) {
			l.advance()
		}
	}
	if l.pos < len(l.src) {
		l.advance() // closing '
	}
	l.toks = append(l.toks, Token{
		Kind: TokChar,
		Val:  string(l.src[start:l.pos]),
		Line: startLine,
		Col:  startCol,
	})
}

// readPunct handles single and multi-character operators. C# adds several
// operators not in Java: `??`, `?.`, `=>`, `??=`.
func (l *lexer) readPunct(startLine, startCol int) {
	if l.pos+2 < len(l.src) {
		three := string(l.src[l.pos : l.pos+3])
		if three == "<<=" || three == ">>=" || three == "??=" || three == "..." {
			l.toks = append(l.toks, Token{Kind: TokPunct, Val: three, Line: startLine, Col: startCol})
			l.pos += 3
			l.col += 3
			return
		}
	}
	if l.pos+1 < len(l.src) {
		two := string(l.src[l.pos : l.pos+2])
		switch two {
		case "==", "!=", "<=", ">=", "&&", "||", "++", "--",
			"<<", ">>", "+=", "-=", "*=", "/=", "%=",
			"&=", "|=", "^=", "->", "::",
			"??", "?.", "=>":
			l.toks = append(l.toks, Token{Kind: TokPunct, Val: two, Line: startLine, Col: startCol})
			l.pos += 2
			l.col += 2
			return
		}
	}
	l.toks = append(l.toks, Token{Kind: TokPunct, Val: string(l.src[l.pos]), Line: startLine, Col: startCol})
	l.advance()
}

// isIdentStart: C# identifiers begin with a letter or underscore. Dollar is
// not a valid identifier start in C# (unlike Java).
func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || isDigit(b)
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
