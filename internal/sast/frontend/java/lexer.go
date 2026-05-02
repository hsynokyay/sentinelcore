// Package java is the SentinelCore SAST engine's Java source frontend.
//
// Chunk SAST-2 ships this as a pure-Go, hand-rolled tokenizer and structural
// parser targeting the exact Java subset the MVP slice needs:
//
//   - package declarations
//   - import declarations (including static + wildcard)
//   - top-level and nested classes, interfaces, enums
//   - method declarations (bodies only — we don't model parameters yet)
//   - method invocations with receiver chains
//   - string literal arguments
//
// This is deliberately NOT a complete Java parser. It is the smallest
// pragmatic stand-in for a JVM-based JavaParser sidecar, sized for the
// current rule set (weak crypto, hardcoded secrets) and for the upcoming
// taint engine's "find the getInstance-shaped calls" needs.
//
// When the MVP slice needs richer Java semantics (generics, overload
// resolution, field-type tracking for local variables) the right move is to
// replace this file with a JVM sidecar that emits the same SentinelIR over
// a stable protobuf protocol. The IR boundary insulates every other
// package from that change. Until then, hand-rolled keeps the engine
// dependency-free, CGO-free, and easy to reason about.
package java

// TokenKind is the coarse category of a Java lexical token. We deliberately
// do NOT distinguish keywords from identifiers at the lexer level — the
// parser decides what's a keyword contextually. This keeps the lexer small
// and lets us recognize unfamiliar identifiers (framework-defined annotation
// types, user-defined classes) without a keyword table.
type TokenKind int

const (
	// TokEOF terminates every token stream.
	TokEOF TokenKind = iota
	// TokIdent is any Java identifier, including keywords. Val holds the
	// raw source text.
	TokIdent
	// TokString is a string literal (single-line "…" or multi-line text
	// block """…"""). Val holds the decoded, unescaped contents — NOT the
	// quotes.
	TokString
	// TokNumber is any numeric literal (integer, float, hex, binary). Val
	// holds the raw source text; we don't parse the numeric value because
	// no Chunk SAST-2 rule matches on numeric constants yet.
	TokNumber
	// TokChar is a single character literal 'x'. Skipped semantically for
	// the same reason as numbers.
	TokChar
	// TokPunct is any operator or separator character or multi-character
	// operator: . , ; : ( ) [ ] { } < > == != <= >= && || ++ -- etc. Val
	// holds the exact operator text.
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
// Line and block comments are skipped (including Javadoc). The lexer is
// resilient to malformed input — it never returns an error. Pathological
// inputs (unterminated strings, unterminated block comments) produce a
// partial token stream that the parser can still walk, which means a
// single malformed file cannot crash the SAST worker.
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

// advance moves one byte forward, updating the column counter. Callers are
// responsible for updating line+col themselves when they consume a newline.
func (l *lexer) advance() {
	if l.pos < len(l.src) {
		l.pos++
		l.col++
	}
}

// skipWhitespaceAndComments consumes runs of ASCII whitespace, line comments
// (// to end of line), and block comments (/* … */). Block comments can
// contain newlines — we track them so subsequent token positions are
// correct.
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

// readToken dispatches on the current byte to one of the specialized
// readers. Called after skipWhitespaceAndComments.
func (l *lexer) readToken() {
	startLine, startCol := l.line, l.col
	b := l.src[l.pos]

	if isIdentStart(b) {
		l.readIdent(startLine, startCol)
		return
	}
	if isDigit(b) {
		l.readNumber(startLine, startCol)
		return
	}
	if b == '"' {
		// Text block """…""" or regular string "…".
		if l.pos+2 < len(l.src) && l.src[l.pos+1] == '"' && l.src[l.pos+2] == '"' {
			l.readTextBlock(startLine, startCol)
		} else {
			l.readString(startLine, startCol)
		}
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
	// Accept digits, dots, hex prefix 0x/0X, hex digits, exponent e/E,
	// underscore separators, and type suffixes L/l/F/f/D/d. We don't parse
	// the value — Chunk SAST-2 doesn't use numeric constants — we just
	// consume the extent so the next token starts at the right place.
	for l.pos < len(l.src) {
		b := l.src[l.pos]
		if isDigit(b) ||
			b == '.' ||
			b == '_' ||
			b == 'x' || b == 'X' ||
			b == 'b' || b == 'B' || // binary literal prefix
			(b >= 'a' && b <= 'f') ||
			(b >= 'A' && b <= 'F') ||
			b == 'L' || b == 'l' ||
			b == 'F' || b == 'f' ||
			b == 'D' || b == 'd' {
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
// We decode the standard escapes (\n, \t, \r, \", \\, \') so the parser sees
// the logical string the source expresses. Unterminated strings stop at the
// next newline — the parser treats the partial token as a best-effort
// decode rather than crashing.
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
			// Unterminated — leave the newline alone, the whitespace skipper
			// will handle it on the next iteration.
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
				// Unknown escape: preserve the literal char.
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

// readTextBlock consumes a Java 15+ text block """…""". We preserve internal
// newlines and do NOT do Java's indentation-stripping (Spec §3.10.6) because
// no current rule matches on multi-line literals.
func (l *lexer) readTextBlock(startLine, startCol int) {
	l.pos += 3
	l.col += 3
	var sb []byte
	for l.pos+2 < len(l.src) && !(l.src[l.pos] == '"' && l.src[l.pos+1] == '"' && l.src[l.pos+2] == '"') {
		if l.src[l.pos] == '\n' {
			l.line++
			l.col = 1
			sb = append(sb, '\n')
			l.pos++
			continue
		}
		sb = append(sb, l.src[l.pos])
		l.advance()
	}
	if l.pos+2 < len(l.src) {
		l.pos += 3
		l.col += 3
	}
	l.toks = append(l.toks, Token{
		Kind: TokString,
		Val:  string(sb),
		Line: startLine,
		Col:  startCol,
	})
}

// readChar consumes a char literal. We don't care about the decoded value;
// we just record the raw bytes for debugging and advance past it.
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

// readPunct handles single and multi-character operators. We try three-char
// operators first (>>>, <<=, >>=), then two-char (==, !=, <=, >=, &&, ||,
// ++, --, <<, >>, +=, -=, *=, /=, %=, &=, |=, ^=, ->, ::), then fall back
// to a single character.
func (l *lexer) readPunct(startLine, startCol int) {
	if l.pos+2 < len(l.src) {
		three := string(l.src[l.pos : l.pos+3])
		if three == ">>>" || three == "<<=" || three == ">>=" {
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
			"&=", "|=", "^=", "->", "::":
			l.toks = append(l.toks, Token{Kind: TokPunct, Val: two, Line: startLine, Col: startCol})
			l.pos += 2
			l.col += 2
			return
		}
	}
	l.toks = append(l.toks, Token{Kind: TokPunct, Val: string(l.src[l.pos]), Line: startLine, Col: startCol})
	l.advance()
}

// isIdentStart: Java identifiers begin with a letter, underscore, or dollar.
// The full Java spec allows any Unicode letter; we restrict to ASCII for
// the MVP, which covers essentially all real-world framework code. Non-ASCII
// identifiers in user code still parse (bytes beyond 0x7F fall through to
// punct and are harmless for the structural parser).
func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || b == '$'
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || isDigit(b)
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
