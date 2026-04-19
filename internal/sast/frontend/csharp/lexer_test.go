package csharp

import "testing"

// TestTokenizeBasicShape exercises identifiers, keywords, string literals,
// punctuation, line/column tracking, and comment skipping.
func TestTokenizeBasicShape(t *testing.T) {
	src := []byte(`
using System;
using System.Diagnostics;

// line comment
namespace Foo.Bar {
    /* block
       comment */
    public class Baz {
        public void Bad() {
            Process.Start("notepad.exe");
        }
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
	if strTok.Val != "notepad.exe" {
		t.Errorf("string literal decoded value: got %q, want %q", strTok.Val, "notepad.exe")
	}

	// Verify "Process.Start" appears as IDENT '.' IDENT.
	for i := 0; i < len(toks)-2; i++ {
		if toks[i].Kind == TokIdent && toks[i].Val == "Process" &&
			toks[i+1].Kind == TokPunct && toks[i+1].Val == "." &&
			toks[i+2].Kind == TokIdent && toks[i+2].Val == "Start" {
			return
		}
	}
	t.Fatal("did not find Process.Start sequence")
}

// TestStringEscapes verifies that common backslash escapes are decoded
// correctly in regular strings.
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

// TestVerbatimString verifies @"..." verbatim string tokenization,
// including doubled-quote escape.
func TestVerbatimString(t *testing.T) {
	src := []byte(`@"C:\path\to\file and ""quoted"" text"`)
	toks := Tokenize(src)
	if len(toks) < 1 || toks[0].Kind != TokString {
		t.Fatalf("expected verbatim string, got %+v", toks)
	}
	want := `C:\path\to\file and "quoted" text`
	if toks[0].Val != want {
		t.Errorf("verbatim string: got %q, want %q", toks[0].Val, want)
	}
}

// TestVerbatimMultilineString verifies a verbatim string with embedded
// newlines is captured intact.
func TestVerbatimMultilineString(t *testing.T) {
	src := []byte("@\"line1\nline2\nline3\"")
	toks := Tokenize(src)
	if len(toks) < 1 || toks[0].Kind != TokString {
		t.Fatalf("expected verbatim string, got %+v", toks)
	}
	want := "line1\nline2\nline3"
	if toks[0].Val != want {
		t.Errorf("verbatim multiline: got %q, want %q", toks[0].Val, want)
	}
}

// TestInterpolatedString verifies $"..." preserves {expr} literally in the
// token value (so the parser can scan for local var refs).
func TestInterpolatedString(t *testing.T) {
	src := []byte(`$"SELECT * FROM users WHERE id = {id}"`)
	toks := Tokenize(src)
	if len(toks) < 1 || toks[0].Kind != TokString {
		t.Fatalf("expected interpolated string, got %+v", toks)
	}
	want := "SELECT * FROM users WHERE id = {id}"
	if toks[0].Val != want {
		t.Errorf("interpolated string: got %q, want %q", toks[0].Val, want)
	}
}

// TestVerbatimInterpolatedString verifies $@"..." is tokenized as a single
// string token with embedded newlines and {expr} preserved.
func TestVerbatimInterpolatedString(t *testing.T) {
	src := []byte("$@\"SELECT * FROM t\nWHERE id = {id}\"")
	toks := Tokenize(src)
	if len(toks) < 1 || toks[0].Kind != TokString {
		t.Fatalf("expected verbatim interpolated string, got %+v", toks)
	}
	want := "SELECT * FROM t\nWHERE id = {id}"
	if toks[0].Val != want {
		t.Errorf("verbatim interpolated: got %q, want %q", toks[0].Val, want)
	}
}

// TestAtIdentifierPrefix verifies the lexer strips a leading @ from an
// identifier (C# allows @class, @return, etc. to use reserved words).
func TestAtIdentifierPrefix(t *testing.T) {
	src := []byte("@class")
	toks := Tokenize(src)
	if len(toks) < 1 || toks[0].Kind != TokIdent || toks[0].Val != "class" {
		t.Errorf("@class: got %+v, want TokIdent 'class'", toks[0])
	}
}

// TestXmlDocComment verifies /// XML doc comments are skipped.
func TestXmlDocComment(t *testing.T) {
	src := []byte("/// <summary>Doc</summary>\nint x = 1;")
	toks := Tokenize(src)
	// First token should be 'int', not doc comment content.
	if len(toks) < 1 || toks[0].Kind != TokIdent || toks[0].Val != "int" {
		t.Errorf("xml doc not skipped: first token %+v", toks[0])
	}
}

// TestMultiCharPunct covers every multi-character operator we explicitly lex.
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
		"=>":  "=>",
		"??":  "??",
		"?.":  "?.",
		"??=": "??=",
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
// multi-line comments.
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

// TestResilientToUnterminatedBlockComment verifies unterminated /* ... */
// doesn't loop forever.
func TestResilientToUnterminatedBlockComment(t *testing.T) {
	src := []byte(`/* never ends`)
	toks := Tokenize(src)
	if len(toks) == 0 {
		t.Fatal("no tokens")
	}
	if toks[len(toks)-1].Kind != TokEOF {
		t.Fatalf("last token not EOF: %+v", toks[len(toks)-1])
	}
}
