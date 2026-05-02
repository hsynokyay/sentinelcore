package java

import "testing"

// TestTokenizeBasicShape exercises identifiers, keywords (as idents),
// string literals, punctuation, line/column tracking, and comment
// skipping on a small but realistic Java snippet.
func TestTokenizeBasicShape(t *testing.T) {
	src := []byte(`
package com.example;

// line comment
import javax.crypto.Cipher;

public class Foo {
    /* block
       comment */
    void bad() {
        Cipher c = Cipher.getInstance("DES");
    }
}
`)
	toks := Tokenize(src)
	if len(toks) == 0 {
		t.Fatal("no tokens")
	}
	if toks[len(toks)-1].Kind != TokEOF {
		t.Fatalf("last token not EOF: %+v", toks[len(toks)-1])
	}

	// Find the first string literal and verify its decoded value.
	var strTok *Token
	for i := range toks {
		if toks[i].Kind == TokString {
			strTok = &toks[i]
			break
		}
	}
	if strTok == nil {
		t.Fatal("no string literal tokenized")
	}
	if strTok.Val != "DES" {
		t.Errorf("string literal decoded value: got %q, want %q", strTok.Val, "DES")
	}

	// Verify "Cipher.getInstance" appears as IDENT '.' IDENT sequence and
	// the line number matches the source.
	for i := 0; i < len(toks)-2; i++ {
		if toks[i].Kind == TokIdent && toks[i].Val == "Cipher" &&
			toks[i+1].Kind == TokPunct && toks[i+1].Val == "." &&
			toks[i+2].Kind == TokIdent && toks[i+2].Val == "getInstance" {
			if toks[i].Line != 11 {
				t.Errorf("Cipher.getInstance line: got %d, want 11", toks[i].Line)
			}
			return
		}
	}
	t.Fatal("did not find Cipher.getInstance sequence")
}

// TestStringEscapes verifies that common backslash escapes are decoded
// correctly. Important because rule patterns match on the decoded value.
func TestStringEscapes(t *testing.T) {
	src := []byte(`"hello\nworld\t\"quoted\\"`)
	toks := Tokenize(src)
	if len(toks) < 1 || toks[0].Kind != TokString {
		t.Fatalf("expected string, got %+v", toks)
	}
	want := "hello\nworld\t\"quoted\\"
	if toks[0].Val != want {
		t.Errorf("decoded string: got %q, want %q", toks[0].Val, want)
	}
}

// TestTextBlock verifies Java 15+ text block tokenization.
func TestTextBlock(t *testing.T) {
	src := []byte("\"\"\"\nhello\nworld\n\"\"\"")
	toks := Tokenize(src)
	if len(toks) < 1 || toks[0].Kind != TokString {
		t.Fatalf("expected text block as string, got %+v", toks)
	}
	if toks[0].Val != "\nhello\nworld\n" {
		t.Errorf("text block content: %q", toks[0].Val)
	}
}

// TestMultiCharPunct covers every multi-character operator we explicitly
// lex so future refactors catch accidental regressions.
func TestMultiCharPunct(t *testing.T) {
	cases := map[string]string{
		"==":  "==",
		"!=":  "!=",
		"&&":  "&&",
		"||":  "||",
		"++":  "++",
		"--":  "--",
		"<=":  "<=",
		">=":  ">=",
		"->":  "->",
		"::":  "::",
		">>>": ">>>",
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			toks := Tokenize([]byte(input))
			if len(toks) < 2 || toks[0].Kind != TokPunct || toks[0].Val != want {
				t.Errorf("got %+v, want first token %q", toks, want)
			}
		})
	}
}

// TestLineTracking verifies the lexer assigns correct line numbers across
// multi-line comments and strings.
func TestLineTracking(t *testing.T) {
	src := []byte("a\n/* block\n   comment */\nb\n")
	toks := Tokenize(src)
	var a, b *Token
	for i := range toks {
		if toks[i].Kind == TokIdent && toks[i].Val == "a" {
			a = &toks[i]
		}
		if toks[i].Kind == TokIdent && toks[i].Val == "b" {
			b = &toks[i]
		}
	}
	if a == nil || a.Line != 1 {
		t.Errorf("a on wrong line: %+v", a)
	}
	if b == nil || b.Line != 4 {
		t.Errorf("b on wrong line: %+v", b)
	}
}

// TestResilientToUnterminatedString verifies the lexer does not crash or
// loop forever when the source has an unterminated string.
func TestResilientToUnterminatedString(t *testing.T) {
	src := []byte(`"oops`)
	toks := Tokenize(src)
	if len(toks) == 0 {
		t.Fatal("no tokens")
	}
	if toks[len(toks)-1].Kind != TokEOF {
		t.Fatalf("last token not EOF: %+v", toks[len(toks)-1])
	}
}
