package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestKeys(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return privPEM, pubPEM
}

func TestJWT_IssueAndValidate(t *testing.T) {
	privPEM, pubPEM := generateTestKeys(t)
	mgr, err := NewJWTManager(privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	token, jti, err := mgr.IssueAccessToken("user-1", "org-1", "admin")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if token == "" || jti == "" {
		t.Fatal("token and jti should not be empty")
	}

	claims, err := mgr.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", claims.Subject)
	}
	if claims.OrgID != "org-1" {
		t.Errorf("org_id = %q, want org-1", claims.OrgID)
	}
	if claims.Role != "admin" {
		t.Errorf("role = %q, want admin", claims.Role)
	}
	if claims.ID != jti {
		t.Errorf("jti = %q, want %q", claims.ID, jti)
	}
}

func TestJWT_RefreshToken(t *testing.T) {
	privPEM, pubPEM := generateTestKeys(t)
	mgr, err := NewJWTManager(privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	token, _, err := mgr.IssueRefreshToken("user-2", "org-2", "viewer")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}

	claims, err := mgr.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject != "user-2" {
		t.Errorf("subject = %q, want user-2", claims.Subject)
	}
}

func TestJWT_ExpiredToken(t *testing.T) {
	privPEM, pubPEM := generateTestKeys(t)
	mgr, err := NewJWTManager(privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	// Manually create an expired token
	mgr.accessTTL = -1 * time.Hour
	token, _, err := mgr.IssueAccessToken("user-3", "org-3", "admin")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	_, err = mgr.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestJWT_InvalidToken(t *testing.T) {
	privPEM, pubPEM := generateTestKeys(t)
	mgr, err := NewJWTManager(privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	_, err = mgr.ValidateToken("not-a-valid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestJWT_WrongKey(t *testing.T) {
	privPEM1, _ := generateTestKeys(t)
	_, pubPEM2 := generateTestKeys(t)

	mgr1, err := NewJWTManager(privPEM1, pubPEM2) // mismatched keys intentionally
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	// Sign with key1's private key
	jti := "test-jti"
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-4",
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "sentinelcore",
		},
		OrgID: "org-4",
		Role:  "admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(mgr1.privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Validate with key2's public key (should fail)
	_, err = mgr1.ValidateToken(signed)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}
