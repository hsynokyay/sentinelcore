// gen-test-keys generates a test trust chain for SentinelCore update verification.
//
// Usage: go run scripts/gen-test-keys.go [output-dir]
//
// It creates:
//   - root_privkey.pem          — Ed25519 root private key (KEEP SECRET)
//   - root_pubkey.json          — Pinned root public key
//   - signing_privkey.pem       — Ed25519 signing private key
//   - signing_key_cert.json     — Signing key certificate (signed by root)
//   - signing_key_cert.json.sig — Detached signature
//   - revocations.json          — Empty revocation list (signed by root)
//   - revocations.json.sig      — Detached signature

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sentinelcore/sentinelcore/pkg/crypto"
)

func main() {
	outDir := "testdata/trust"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fatal("mkdir: %v", err)
	}

	// 1. Generate root keypair
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fatal("generate root key: %v", err)
	}

	// Write root private key as PEM
	rootPrivPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: rootPriv.Seed(),
	})
	writeFile(outDir, "root_privkey.pem", rootPrivPEM)

	// Write root public key as JSON
	rootKeyJSON := map[string]any{
		"format":         "sentinelcore-root-key",
		"format_version": 1,
		"key_id":         "root-test-001",
		"public_key":     base64.StdEncoding.EncodeToString(rootPub),
		"fingerprint":    "sha256:" + crypto.HashBytes(rootPub),
		"created_at":     time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(outDir, "root_pubkey.json", rootKeyJSON)

	// 2. Generate signing keypair
	signingPub, signingPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fatal("generate signing key: %v", err)
	}

	signingPrivPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: signingPriv.Seed(),
	})
	writeFile(outDir, "signing_privkey.pem", signingPrivPEM)

	// 3. Create and sign signing key certificate
	cert := map[string]any{
		"format":                     "sentinelcore-signing-cert",
		"format_version":             1,
		"serial":                     "test-cert-001",
		"purpose":                    "platform_signing",
		"public_key":                 base64.StdEncoding.EncodeToString(signingPub),
		"valid_from":                 time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
		"valid_until":                time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"issued_at":                  time.Now().UTC().Format(time.RFC3339),
		"issued_by_root_fingerprint": "sha256:" + crypto.HashBytes(rootPub),
	}
	certJSON := writeJSON(outDir, "signing_key_cert.json", cert)

	canonical, err := crypto.Canonicalize(json.RawMessage(certJSON))
	if err != nil {
		fatal("canonicalize cert: %v", err)
	}
	certSig := crypto.Ed25519Sign(rootPriv, canonical)
	writeFile(outDir, "signing_key_cert.json.sig",
		[]byte(base64.StdEncoding.EncodeToString(certSig)))

	// 4. Create and sign empty revocation list
	revList := map[string]any{
		"format":               "sentinelcore-revocation-list",
		"format_version":       1,
		"issued_at":            time.Now().UTC().Format(time.RFC3339),
		"sequence":             1,
		"revoked_certificates": []any{},
		"revoked_root_keys":    []any{},
	}
	revJSON := writeJSON(outDir, "revocations.json", revList)

	revCanonical, err := crypto.Canonicalize(json.RawMessage(revJSON))
	if err != nil {
		fatal("canonicalize revocations: %v", err)
	}
	revSig := crypto.Ed25519Sign(rootPriv, revCanonical)
	writeFile(outDir, "revocations.json.sig",
		[]byte(base64.StdEncoding.EncodeToString(revSig)))

	fmt.Printf("Test trust chain written to %s/\n", outDir)
	fmt.Printf("  Root key fingerprint: sha256:%s\n", crypto.HashBytes(rootPub))
	fmt.Printf("  Signing cert serial:  test-cert-001\n")
}

func writeFile(dir, name string, data []byte) {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		fatal("write %s: %v", path, err)
	}
	fmt.Printf("  wrote %s (%d bytes)\n", path, len(data))
}

func writeJSON(dir, name string, v any) []byte {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal("marshal %s: %v", name, err)
	}
	writeFile(dir, name, data)
	return data
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
