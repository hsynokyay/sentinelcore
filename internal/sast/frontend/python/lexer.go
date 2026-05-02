// Package python is the SentinelCore SAST engine's Python source frontend.
// Pure-Go tokenizer + structural parser for the Python subset the MVP rules
// need: function defs, imports, assignments, method calls, string literals.
package python

// TokenKind classifies Python tokens.
type TokenKind int

const (
	TokEOF    TokenKind = iota
	TokIdent
	TokString
	TokNumber
	TokPunct
	TokNewline // significant in Python for statement boundaries
	TokIndent  // indentation increase
	TokDedent  // indentation decrease
)

// Token is one lexical unit.
type Token struct {
	Kind TokenKind
	Val  string
	Line int
	Col  int
}

// Tokenize returns a flat token slice. Python's indentation-based blocks are
// simplified: we track indent depth but emit TokNewline for statement
// boundaries rather than full INDENT/DEDENT tokens. This is sufficient for
// the structural parser which uses ':' + indentation heuristics.
func Tokenize(src []byte) []Token {
	l := &lexer{src: src, line: 1, col: 1}
	for l.pos < len(l.src) {
		l.readLine()
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

func (l *lexer) readLine() {
	// Skip blank lines and comments.
	for l.pos < len(l.src) {
		if l.src[l.pos] == '\n' {
			l.pos++
			l.line++
			l.col = 1
			continue
		}
		if l.src[l.pos] == '\r' {
			l.advance()
			continue
		}
		if l.src[l.pos] == '#' {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		break
	}
	if l.pos >= len(l.src) {
		return
	}

	// Read tokens until newline.
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		l.skipSpaces()
		if l.pos >= len(l.src) || l.src[l.pos] == '\n' {
			break
		}
		if l.src[l.pos] == '#' {
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
			break
		}
		if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n' {
			l.pos += 2
			l.line++
			l.col = 1
			continue
		}
		l.readToken()
	}
	if l.pos < len(l.src) && l.src[l.pos] == '\n' {
		l.toks = append(l.toks, Token{Kind: TokNewline, Line: l.line, Col: l.col})
		l.pos++
		l.line++
		l.col = 1
	}
}

func (l *lexer) skipSpaces() {
	for l.pos < len(l.src) && (l.src[l.pos] == ' ' || l.src[l.pos] == '\t') {
		l.advance()
	}
}

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
	if b == '"' || b == '\'' {
		l.readString(startLine, startCol)
		return
	}
	l.readPunct(startLine, startCol)
}

func (l *lexer) readIdent(startLine, startCol int) {
	start := l.pos
	for l.pos < len(l.src) && isIdentCont(l.src[l.pos]) {
		l.advance()
	}
	l.toks = append(l.toks, Token{Kind: TokIdent, Val: string(l.src[start:l.pos]), Line: startLine, Col: startCol})
}

func (l *lexer) readNumber(startLine, startCol int) {
	start := l.pos
	for l.pos < len(l.src) && (isDigit(l.src[l.pos]) || l.src[l.pos] == '.' || l.src[l.pos] == 'x' || l.src[l.pos] == '_' ||
		(l.src[l.pos] >= 'a' && l.src[l.pos] <= 'f') || (l.src[l.pos] >= 'A' && l.src[l.pos] <= 'F')) {
		l.advance()
	}
	l.toks = append(l.toks, Token{Kind: TokNumber, Val: string(l.src[start:l.pos]), Line: startLine, Col: startCol})
}

func (l *lexer) readString(startLine, startCol int) {
	quote := l.src[l.pos]
	// Check for triple-quote.
	if l.pos+2 < len(l.src) && l.src[l.pos+1] == quote && l.src[l.pos+2] == quote {
		l.readTripleString(startLine, startCol, quote)
		return
	}
	l.advance() // opening quote
	var sb []byte
	for l.pos < len(l.src) {
		b := l.src[l.pos]
		if b == quote {
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
			case '\\':
				sb = append(sb, '\\')
			case '\'':
				sb = append(sb, '\'')
			case '"':
				sb = append(sb, '"')
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
	l.toks = append(l.toks, Token{Kind: TokString, Val: string(sb), Line: startLine, Col: startCol})
}

func (l *lexer) readTripleString(startLine, startCol int, quote byte) {
	l.pos += 3
	l.col += 3
	var sb []byte
	for l.pos+2 < len(l.src) && !(l.src[l.pos] == quote && l.src[l.pos+1] == quote && l.src[l.pos+2] == quote) {
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
	l.toks = append(l.toks, Token{Kind: TokString, Val: string(sb), Line: startLine, Col: startCol})
}

func (l *lexer) readPunct(startLine, startCol int) {
	if l.pos+1 < len(l.src) {
		two := string(l.src[l.pos : l.pos+2])
		switch two {
		case "==", "!=", "<=", ">=", "+=", "-=", "*=", "/=", "//", "**", "->", ":=":
			l.toks = append(l.toks, Token{Kind: TokPunct, Val: two, Line: startLine, Col: startCol})
			l.pos += 2
			l.col += 2
			return
		}
	}
	l.toks = append(l.toks, Token{Kind: TokPunct, Val: string(l.src[l.pos]), Line: startLine, Col: startCol})
	l.advance()
}

func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}
func isIdentCont(b byte) bool { return isIdentStart(b) || isDigit(b) }
func isDigit(b byte) bool     { return b >= '0' && b <= '9' }
