package replay

import (
	"net/http"
	"testing"
)

func TestExtractPrincipal_FromJWT(t *testing.T) {
	// payload: {"sub":"alice"} → eyJzdWIiOiJhbGljZSJ9
	jwt := "x.eyJzdWIiOiJhbGljZSJ9.y"
	cookies := []*http.Cookie{{Name: "sess", Value: jwt}}
	got, ok := ExtractPrincipal(cookies, "sub")
	if !ok || got != "alice" {
		t.Fatalf("got=%q ok=%v", got, ok)
	}
}

func TestExtractPrincipal_DefaultClaim(t *testing.T) {
	jwt := "x.eyJzdWIiOiJjYXJvbCJ9.y"
	cookies := []*http.Cookie{{Name: "sess", Value: jwt}}
	got, ok := ExtractPrincipal(cookies, "")
	if !ok || got != "carol" {
		t.Fatalf("default claim should be sub: got=%q ok=%v", got, ok)
	}
}

func TestExtractPrincipal_CustomClaim(t *testing.T) {
	// payload: {"email":"x@y.tld"} → eyJlbWFpbCI6InhAeS50bGQifQ
	jwt := "x.eyJlbWFpbCI6InhAeS50bGQifQ.y"
	cookies := []*http.Cookie{{Name: "sess", Value: jwt}}
	got, ok := ExtractPrincipal(cookies, "email")
	if !ok || got != "x@y.tld" {
		t.Fatalf("got=%q ok=%v", got, ok)
	}
}

func TestExtractPrincipal_NoJWT(t *testing.T) {
	if _, ok := ExtractPrincipal([]*http.Cookie{{Name: "x", Value: "plain"}}, "sub"); ok {
		t.Fatal("plain cookie must not match")
	}
}

func TestExtractPrincipal_MalformedSegmentSkipped(t *testing.T) {
	// Three segments but middle is not valid base64.
	jwt := "x.!!!notbase64!!!.y"
	if _, ok := ExtractPrincipal([]*http.Cookie{{Name: "s", Value: jwt}}, "sub"); ok {
		t.Fatal("malformed payload must not match")
	}
}

func TestExtractPrincipal_ClaimMissing(t *testing.T) {
	jwt := "x.eyJzdWIiOiJhbGljZSJ9.y"
	if _, ok := ExtractPrincipal([]*http.Cookie{{Name: "s", Value: jwt}}, "iss"); ok {
		t.Fatal("missing claim must not match")
	}
}

func TestVerifyPrincipal_Match(t *testing.T) {
	if err := VerifyPrincipal("alice", "alice"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPrincipal_Mismatch(t *testing.T) {
	if err := VerifyPrincipal("alice", "bob"); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestVerifyPrincipal_EitherEmpty(t *testing.T) {
	if err := VerifyPrincipal("", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrincipal("alice", ""); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPrincipal("", ""); err != nil {
		t.Fatal(err)
	}
}
