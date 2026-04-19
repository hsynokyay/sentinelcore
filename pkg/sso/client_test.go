package sso

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestClient(t *testing.T, idp *fakeIdP) *Client {
	t.Helper()
	c, err := New(context.Background(), Config{
		IssuerURL:    idp.issuer(),
		ClientID:     "client-abc",
		ClientSecret: "s",
		RedirectURL:  "https://sc.example.com/cb",
		Scopes:       []string{"openid", "email", "groups"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestClient_VerifyIDToken_HappyPath(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	tok := idp.signToken(t, jwt.MapClaims{
		"sub":    "user-123",
		"email":  "alice@example.com",
		"aud":    "client-abc",
		"nonce":  "n-original",
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
		"groups": []string{"admins"},
	})
	claims, err := client.VerifyIDToken(context.Background(), tok, "n-original")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Sub != "user-123" {
		t.Errorf("sub mismatch: %s", claims.Sub)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email mismatch: %s", claims.Email)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "admins" {
		t.Errorf("groups mismatch: %v", claims.Groups)
	}
}

func TestClient_VerifyIDToken_NonceMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	tok := idp.signToken(t, jwt.MapClaims{
		"sub":   "u",
		"email": "e@x",
		"aud":   "client-abc",
		"nonce": "n-actual",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
	_, err := client.VerifyIDToken(context.Background(), tok, "n-expected")
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch, got %v", err)
	}
}

func TestClient_VerifyIDToken_AudMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	tok := idp.signToken(t, jwt.MapClaims{
		"sub":   "u",
		"email": "e@x",
		"aud":   "other-client",
		"nonce": "n",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
	_, err := client.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, ErrAudMismatch) {
		t.Fatalf("expected ErrAudMismatch, got %v", err)
	}
}

func TestClient_VerifyIDToken_IssuerMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	tok := idp.signToken(t, jwt.MapClaims{
		"iss":   "https://other-issuer.example.com",
		"sub":   "u",
		"email": "e@x",
		"aud":   "client-abc",
		"nonce": "n",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
	_, err := client.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestClient_VerifyIDToken_Expired(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	tok := idp.signToken(t, jwt.MapClaims{
		"sub":   "u",
		"email": "e@x",
		"aud":   "client-abc",
		"nonce": "n",
		"exp":   time.Now().Add(-1 * time.Minute).Unix(),
	})
	_, err := client.VerifyIDToken(context.Background(), tok, "n")
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestClient_VerifyIDToken_TamperedSignature(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	tok := idp.signToken(t, jwt.MapClaims{
		"sub":   "u",
		"email": "e@x",
		"aud":   "client-abc",
		"nonce": "n",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
	bad := tamperSignature(tok)
	_, err := client.VerifyIDToken(context.Background(), bad, "n")
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
	// go-oidc reports signature errors as opaque strings — just ensure it
	// did NOT pass. We don't classify with a sentinel here.
}

func TestClient_VerifyIDToken_MalformedJWT(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	_, err := client.VerifyIDToken(context.Background(), "not.a.valid.jwt.at.all", "n")
	if !errors.Is(err, ErrClaimsMalformed) {
		t.Fatalf("expected ErrClaimsMalformed, got %v", err)
	}
}

func TestClient_EndSessionURL(t *testing.T) {
	idp := newFakeIdP(t)
	client := newTestClient(t, idp)
	got := client.EndSessionURL()
	want := idp.issuer() + "/logout"
	if got != want {
		t.Errorf("end_session url: got %q want %q", got, want)
	}
}
