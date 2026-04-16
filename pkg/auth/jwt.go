package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TODO(iac-phase1-cleanup): remove this map + translateLegacyRole call
// +14 days after Phase 1 production deploy. Tracked by the author;
// see docs/superpowers/plans/2026-04-13-iac-phase1-rbac-refactor.md
// Task 10.3.

// compatRoleMap translates pre-migration role strings to the new vocabulary.
// This is the SINGLE chokepoint for legacy role handling — no other code
// in the codebase should see or handle old role names. Remove this map
// and the translateLegacyRole call 14 days after the role-rename migration ships.
var compatRoleMap = map[string]string{
	"platform_admin": "owner",
	"security_admin": "admin",
	"appsec_analyst": "security_engineer",
	// auditor is unchanged — no entry needed (identity translation).
}

// translateLegacyRole maps an old role string to the new vocabulary.
// Returns the input unchanged if no mapping exists (new roles, auditor).
func translateLegacyRole(role string) string {
	if mapped, ok := compatRoleMap[role]; ok {
		return mapped
	}
	return role
}

// Claims represents the JWT claims used by SentinelCore.
type Claims struct {
	jwt.RegisteredClaims
	OrgID string `json:"org_id"`
	Role  string `json:"role"`
}

// JWTManager handles JWT token issuance and validation.
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewJWTManager creates a JWTManager from PEM-encoded RSA keys.
func NewJWTManager(privateKeyPEM, publicKeyPEM []byte) (*JWTManager, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("auth: failed to decode private key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse private key: %w", err)
	}

	block, _ = pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("auth: failed to decode public key PEM")
	}
	pubKeyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse public key: %w", err)
	}
	pubKey, ok := pubKeyIface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("auth: public key is not RSA")
	}

	return &JWTManager{
		privateKey: privKey,
		publicKey:  pubKey,
		accessTTL:  15 * time.Minute,
		refreshTTL: 7 * 24 * time.Hour,
	}, nil
}

// IssueAccessToken creates a short-lived access token.
// Returns (token, jti, error).
func (m *JWTManager) IssueAccessToken(userID, orgID, role string) (string, string, error) {
	return m.issueToken(userID, orgID, role, m.accessTTL)
}

// IssueRefreshToken creates a long-lived refresh token.
// Returns (token, jti, error).
func (m *JWTManager) IssueRefreshToken(userID, orgID, role string) (string, string, error) {
	return m.issueToken(userID, orgID, role, m.refreshTTL)
}

func (m *JWTManager) issueToken(userID, orgID, role string, ttl time.Duration) (string, string, error) {
	jti := uuid.New().String()
	now := time.Now().UTC()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Issuer:    "sentinelcore",
		},
		OrgID: orgID,
		Role:  role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("auth: sign token: %w", err)
	}

	return signed, jti, nil
}

// ValidateToken parses and validates a JWT token string, returning its claims.
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("auth: validate token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("auth: invalid token claims")
	}

	claims.Role = translateLegacyRole(claims.Role)

	return claims, nil
}
