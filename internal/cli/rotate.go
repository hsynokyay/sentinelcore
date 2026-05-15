package cli

// rotate.go — `sentinelcore-cli rotate <kind>` family of commands.
//
// Three rotation targets map to three catalogs in the database:
//
//   aes/<purpose>      → auth.aes_keys        (SSO client_secret, webhook, ...)
//   hmac/audit         → audit.hmac_keys      (audit-log chain)
//   apikey-pepper      → auth.apikey_peppers  (API key HMAC salt)
//
// Rotation is a two-phase operation:
//
//   1. Generate fresh key material + INSERT a new row in the catalog
//      at version N+1, with vault_path pointing to the new secret
//      location. Binaries pick up the new version within the 60s
//      cache TTL.
//
//   2. (aes only) Re-encrypt rows that reference v<N> using v<N+1>
//      in a background sweep. v<N> stays readable until the sweep
//      completes — pending rows continue to validate.
//
// This CLI implements phase 1 as a one-shot. Phase 2 (the sweep) is
// deferred to a worker that runs after rotation and updates
// auth.aes_keys.rotated_at when it's done.
//
// Secret material itself is written to env-file fallback today
// (/opt/sentinelcore/env/secrets.env) and Vault in a future pass —
// pkg/secrets.Resolver handles the lookup transparently.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunRotateCommand dispatches sentinelcore-cli rotate subcommands.
func RunRotateCommand(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) == 0 {
		return errors.New(`usage: sentinelcore-cli rotate <target>

Targets:
  aes/<purpose>    Generate a new AES-256 key for a purpose (sso, webhook, ...)
  hmac/audit       Generate a new HMAC-SHA256 key for audit chain signing
  apikey-pepper    Generate a new API key HMAC pepper

Flags:
  --dry-run        Print actions without writing to the DB
  --print-secret   Emit the base64'd key material on stdout (USE WITH CARE)`)
	}

	target := args[0]
	rest := args[1:]

	dryRun := hasFlag(rest, "--dry-run")
	printSecret := hasFlag(rest, "--print-secret")

	switch {
	case strings.HasPrefix(target, "aes/"):
		purpose := strings.TrimPrefix(target, "aes/")
		return rotateAES(ctx, pool, purpose, dryRun, printSecret)
	case target == "hmac/audit":
		return rotateHMACAudit(ctx, pool, dryRun, printSecret)
	case target == "apikey-pepper":
		return rotateAPIKeyPepper(ctx, pool, dryRun, printSecret)
	default:
		return fmt.Errorf("unknown rotation target %q", target)
	}
}

// rotateAES generates a 32-byte AES-256 key, inserts a row in
// auth.aes_keys at version N+1 for the given purpose, and prints
// the vault path + fingerprint so the operator can wire the secret.
func rotateAES(ctx context.Context, pool *pgxpool.Pool, purpose string,
	dryRun, printSecret bool) error {

	if !validAESPurpose(purpose) {
		return fmt.Errorf("invalid aes purpose %q; one of: sso, webhook, auth_profile, integration, generic", purpose)
	}

	// Look up current version. A missing row for this purpose is fine —
	// we start the catalog at v1.
	var currentVer int
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM auth.aes_keys WHERE purpose = $1`,
		purpose).Scan(&currentVer)
	if err != nil {
		return fmt.Errorf("query current aes version: %w", err)
	}
	newVer := currentVer + 1

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate aes key: %w", err)
	}
	fingerprint := sha256Hex(key)
	vaultPath := fmt.Sprintf("env:SC_TIER0_AES_%s_V%d", strings.ToUpper(purpose), newVer)

	fmt.Printf("rotate aes/%s: v%d → v%d\n", purpose, currentVer, newVer)
	fmt.Printf("  vault_path:  %s\n", vaultPath)
	fmt.Printf("  fingerprint: %s\n", fingerprint)
	if printSecret {
		fmt.Printf("  material:    %s\n", base64.StdEncoding.EncodeToString(key))
	}

	if dryRun {
		fmt.Println("  DRY RUN — no DB write")
		return nil
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO auth.aes_keys (version, purpose, vault_path, fingerprint)
		 VALUES ($1, $2, $3, $4)`,
		newVer, purpose, vaultPath, fingerprint,
	); err != nil {
		return fmt.Errorf("insert aes_keys row: %w", err)
	}

	fmt.Printf("  ✓ auth.aes_keys row inserted\n")
	fmt.Printf("  NEXT STEP: set %s in the service env, then restart controlplane\n", vaultPath)
	return nil
}

// rotateHMACAudit generates a new HMAC-SHA256 key for audit chain
// signing. Unlike AES rotation, this does NOT require re-encryption
// — the audit verifier checks every version in hmac_keys, so new
// rows use the latest and old rows keep validating under their
// recorded version.
func rotateHMACAudit(ctx context.Context, pool *pgxpool.Pool,
	dryRun, printSecret bool) error {

	var currentVer int
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM audit.hmac_keys`,
	).Scan(&currentVer)
	if err != nil {
		return fmt.Errorf("query current hmac version: %w", err)
	}
	newVer := currentVer + 1

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate hmac key: %w", err)
	}
	fingerprint := sha256Hex(key)
	vaultPath := fmt.Sprintf("env:SC_TIER0_HMAC_AUDIT_V%d", newVer)

	fmt.Printf("rotate hmac/audit: v%d → v%d\n", currentVer, newVer)
	fmt.Printf("  vault_path:  %s\n", vaultPath)
	fmt.Printf("  fingerprint: %s\n", fingerprint)
	if printSecret {
		fmt.Printf("  material:    %s\n", base64.StdEncoding.EncodeToString(key))
	}

	if dryRun {
		fmt.Println("  DRY RUN — no DB write")
		return nil
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO audit.hmac_keys (version, vault_path, fingerprint)
		 VALUES ($1, $2, $3)`,
		newVer, vaultPath, fingerprint,
	); err != nil {
		return fmt.Errorf("insert hmac_keys row: %w", err)
	}

	fmt.Printf("  ✓ audit.hmac_keys row inserted\n")
	fmt.Printf("  NEXT STEP: set %s in the audit-service env, then restart audit-service\n", vaultPath)
	return nil
}

// rotateAPIKeyPepper generates a new pepper. Unlike AES/HMAC, the
// pepper change does NOT take effect gradually — once v2 is active,
// every existing key's key_verifier becomes invalid (MAC under old
// pepper). The plan's operator runbook §Appendix B describes a 7-day
// forced-reissue window: during rotation, both versions are loaded
// and Resolve() tries both. This CLI just provisions v2; the dual-
// read is handled by pkg/apikeys when SC_APIKEY_PEPPER_B64_V2 is set
// alongside the original SC_APIKEY_PEPPER_B64.
func rotateAPIKeyPepper(ctx context.Context, pool *pgxpool.Pool,
	dryRun, printSecret bool) error {

	var currentVer int
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM auth.apikey_peppers`,
	).Scan(&currentVer)
	if err != nil {
		return fmt.Errorf("query current pepper version: %w", err)
	}
	newVer := currentVer + 1

	pepper := make([]byte, 32)
	if _, err := rand.Read(pepper); err != nil {
		return fmt.Errorf("generate pepper: %w", err)
	}
	fingerprint := sha256Hex(pepper)
	vaultPath := fmt.Sprintf("env:SC_APIKEY_PEPPER_B64_V%d", newVer)

	fmt.Printf("rotate apikey-pepper: v%d → v%d\n", currentVer, newVer)
	fmt.Printf("  vault_path:  %s\n", vaultPath)
	fmt.Printf("  fingerprint: %s\n", fingerprint)
	if printSecret {
		fmt.Printf("  material:    %s\n", base64.StdEncoding.EncodeToString(pepper))
	}

	if dryRun {
		fmt.Println("  DRY RUN — no DB write")
		return nil
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO auth.apikey_peppers (version, vault_path, fingerprint)
		 VALUES ($1, $2, $3)`,
		newVer, vaultPath, fingerprint,
	); err != nil {
		return fmt.Errorf("insert apikey_peppers row: %w", err)
	}

	fmt.Printf("  ✓ auth.apikey_peppers row inserted\n")
	fmt.Println("  NEXT STEP:")
	fmt.Printf("    1. Set %s in env alongside the existing SC_APIKEY_PEPPER_B64.\n", vaultPath)
	fmt.Println("    2. Restart controlplane — dual-read period begins.")
	fmt.Println("    3. Announce 7-day forced-reissue window to users.")
	fmt.Println("    4. After window: drop SC_APIKEY_PEPPER_B64, restart.")
	fmt.Printf("    5. UPDATE auth.apikey_peppers SET rotated_at = now() WHERE version = %d.\n", currentVer)
	return nil
}

// --- helpers ---

func validAESPurpose(p string) bool {
	switch p {
	case "sso", "webhook", "auth_profile", "integration", "generic":
		return true
	}
	return false
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
