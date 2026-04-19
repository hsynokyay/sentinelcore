// Package js is the SentinelCore SAST engine's JavaScript/TypeScript frontend.
// Pure-Go tokenizer + structural parser targeting the JS/TS subset needed for
// the MVP rules: XSS, command injection, path traversal, eval, and secrets.
package js

// TokenKind classifies JS/TS tokens.
type TokenKind int

const (
	TokEOF    TokenKind = iota
	TokIdent            // identifiers and keywords
	TokString           // "...", '...', `...` (template literals simplified)
	TokNumber
	TokRegex            // /pattern/flags
	TokPunct            // operators and separators
)

// Token is one lexical unit.
type Token struct {
	Kind TokenKind
	Val  string
	Line int
	Col  int
}

// Tokenize returns a flat token slice terminated with TokEOF.
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
		l.readString(startLine, startCol, b)
		return
	}
	if b == '`' {
		l.readTemplateLiteral(startLine, startCol)
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
	for l.pos < len(l.src) && (isDigit(l.src[l.pos]) || l.src[l.pos] == '.' || l.src[l.pos] == 'x' || l.src[l.pos] == 'X' ||
		(l.src[l.pos] >= 'a' && l.src[l.pos] <= 'f') || (l.src[l.pos] >= 'A' && l.src[l.pos] <= 'F') ||
		l.src[l.pos] == '_' || l.src[l.pos] == 'n') {
		l.advance()
	}
	l.toks = append(l.toks, Token{Kind: TokNumber, Val: string(l.src[start:l.pos]), Line: startLine, Col: startCol})
}

func (l *lexer) readString(startLine, startCol int, quote byte) {
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
			case 'r':
				sb = append(sb, '\r')
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

func (l *lexer) readTemplateLiteral(startLine, startCol int) {
	l.advance() // opening `
	var sb []byte
	for l.pos < len(l.src) && l.src[l.pos] != '`' {
		if l.src[l.pos] == '\n' {
			l.line++
			l.col = 1
			sb = append(sb, '\n')
			l.pos++
			continue
		}
		// Skip ${...} interpolations — just consume as literal text for MVP.
		if l.src[l.pos] == '$' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '{' {
			sb = append(sb, '$', '{')
			l.pos += 2
			l.col += 2
			depth := 1
			for l.pos < len(l.src) && depth > 0 {
				if l.src[l.pos] == '{' {
					depth++
				} else if l.src[l.pos] == '}' {
					depth--
				}
				if l.src[l.pos] == '\n' {
					l.line++
					l.col = 1
				}
				sb = append(sb, l.src[l.pos])
				l.pos++
				l.col++
			}
			continue
		}
		sb = append(sb, l.src[l.pos])
		l.advance()
	}
	if l.pos < len(l.src) {
		l.advance() // closing `
	}
	l.toks = append(l.toks, Token{Kind: TokString, Val: string(sb), Line: startLine, Col: startCol})
}

func (l *lexer) readPunct(startLine, startCol int) {
	if l.pos+2 < len(l.src) {
		three := string(l.src[l.pos : l.pos+3])
		if three == "===" || three == "!==" || three == ">>>" || three == "..." {
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
			"+=", "-=", "*=", "/=", "%=", "=>", "**", "??",
			"?.":
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
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || b == '$'
}
func isIdentCont(b byte) bool { return isIdentStart(b) || isDigit(b) }
func isDigit(b byte) bool     { return b >= '0' && b <= '9' }
