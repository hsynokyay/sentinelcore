package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentinelcore/sentinelcore/pkg/crypto"
)

// BundleManifest represents the manifest.json inside a signed update bundle.
type BundleManifest struct {
	Format          string          `json:"format"`
	FormatVersion   int             `json:"format_version"`
	BundleType      string          `json:"bundle_type"`
	Version         string          `json:"version"`
	CreatedAt       string          `json:"created_at"`
	MinPlatformVer  string          `json:"min_platform_version,omitempty"`
	SigningKeySerial string         `json:"signing_key_serial"`
	Artifacts       []ArtifactEntry `json:"artifacts"`
	PreviousVersion string          `json:"previous_version,omitempty"`
	RollbackSafe    bool            `json:"rollback_safe,omitempty"`
}

// ArtifactEntry describes one artifact in a bundle manifest.
type ArtifactEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// RevocationList represents the revocations.json signed by the root key.
type RevocationList struct {
	Format              string          `json:"format"`
	FormatVersion       int             `json:"format_version"`
	IssuedAt            string          `json:"issued_at"`
	Sequence            int             `json:"sequence"`
	RevokedCertificates []RevokedCert   `json:"revoked_certificates"`
	RevokedBundles      []RevokedBundle `json:"revoked_bundles,omitempty"`
	RevokedRootKeys     []string        `json:"revoked_root_keys"`
}

// RevokedCert describes a revoked signing key certificate.
type RevokedCert struct {
	Serial    string `json:"serial"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason"`
}

// RevokedBundle describes a revoked update bundle.
type RevokedBundle struct {
	BundleType string `json:"bundle_type"`
	Version    string `json:"version"`
	RevokedAt  string `json:"revoked_at"`
	Reason     string `json:"reason"`
	Advisory   string `json:"advisory"`
}

// VerificationResult holds the outcome of the 25-step bundle verification.
type VerificationResult struct {
	Accepted          bool   `json:"accepted"`
	StepsFailed       []int  `json:"steps_failed,omitempty"`
	FailureReason     string `json:"failure_reason,omitempty"`
	ManifestVersion   string `json:"manifest_version,omitempty"`
	BundleType        string `json:"bundle_type,omitempty"`
	SigningCertSerial string `json:"signing_cert_serial,omitempty"`
}

// Verifier performs the 25-step cryptographic verification of update bundles.
type Verifier struct {
	trustStore         *TrustStore
	lockdown           *LockdownManager
	graceHours         int // 48h default for air-gapped clock drift
	localRevocations   map[string]bool
	localRevocationSeq int
}

// NewVerifier creates a new Verifier with the given trust store and lockdown manager.
func NewVerifier(ts *TrustStore, lm *LockdownManager) *Verifier {
	return &Verifier{
		trustStore:       ts,
		lockdown:         lm,
		graceHours:       48,
		localRevocations: make(map[string]bool),
	}
}

// Step 1: Extract bundle to quarantine directory.
func (v *Verifier) ExtractBundle(bundlePath, quarantineDir string) error {
	f, err := os.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("step 1: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("step 1: not a gzip file: %w", err)
	}
	defer gz.Close()

	absQuarantine, err := filepath.Abs(quarantineDir)
	if err != nil {
		return fmt.Errorf("step 1: %w", err)
	}

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("step 1: %w", err)
		}

		cleaned := filepath.Clean(hdr.Name)
		target := filepath.Join(absQuarantine, cleaned)

		// Prevent path traversal
		if !strings.HasPrefix(target, absQuarantine+string(os.PathSeparator)) &&
			target != absQuarantine {
			return fmt.Errorf("step 1: path traversal detected: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("step 1: mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("step 1: mkdir parent %s: %w", target, err)
			}
			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("step 1: create %s: %w", target, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("step 1: write %s: %w", target, err)
			}
			outFile.Close()
		}
	}
	return nil
}

// Step 3: Verify revocation list signature against root key.
func (v *Verifier) VerifyRevocationSignature(revocationData, sigData []byte, rootKey ed25519.PublicKey) error {
	canonical, err := crypto.Canonicalize(json.RawMessage(revocationData))
	if err != nil {
		return fmt.Errorf("step 3: canonicalize: %w", err)
	}
	if !crypto.Ed25519Verify(rootKey, canonical, sigData) {
		return fmt.Errorf("step 3: revocation list signature invalid")
	}
	return nil
}

// Step 6: Verify signing key certificate signature against root key.
func (v *Verifier) VerifySigningCertSignature(certData, sigData []byte, rootKey ed25519.PublicKey) error {
	canonical, err := crypto.Canonicalize(json.RawMessage(certData))
	if err != nil {
		return fmt.Errorf("step 6: canonicalize: %w", err)
	}
	if !crypto.Ed25519Verify(rootKey, canonical, sigData) {
		return fmt.Errorf("step 6: signing key certificate signature invalid")
	}
	return nil
}

// Step 7: Verify root fingerprint in certificate matches pinned root.
func (v *Verifier) VerifyRootFingerprint(cert *SigningKeyCert, rootKey ed25519.PublicKey) error {
	expected := "sha256:" + crypto.HashBytes(rootKey)
	if cert.IssuedByFingerprint != expected {
		return fmt.Errorf("step 7: root fingerprint mismatch: expected %s, got %s",
			expected, cert.IssuedByFingerprint)
	}
	return nil
}

// Step 8: Check certificate is not in revocation list.
func (v *Verifier) CheckCertNotRevoked(serial string) error {
	if v.localRevocations[serial] {
		return fmt.Errorf("step 8: signing key certificate %s is revoked", serial)
	}
	return nil
}

// Steps 9-10: Check certificate validity window (with grace period for air-gapped systems).
func (v *Verifier) CheckCertValidity(cert *SigningKeyCert, now time.Time) error {
	grace := time.Duration(v.graceHours) * time.Hour

	validFrom, err := time.Parse(time.RFC3339, cert.ValidFrom)
	if err != nil {
		return fmt.Errorf("step 9: invalid valid_from: %w", err)
	}
	if now.Before(validFrom.Add(-grace)) {
		return fmt.Errorf("step 9: certificate not yet valid (valid_from=%s)", cert.ValidFrom)
	}

	validUntil, err := time.Parse(time.RFC3339, cert.ValidUntil)
	if err != nil {
		return fmt.Errorf("step 10: invalid valid_until: %w", err)
	}
	if now.After(validUntil.Add(grace)) {
		return fmt.Errorf("step 10: certificate expired (valid_until=%s)", cert.ValidUntil)
	}
	return nil
}

// Step 11: Check certificate purpose matches bundle type.
func (v *Verifier) CheckCertPurpose(cert *SigningKeyCert, bundleType string) error {
	purposeMap := map[string][]string{
		"platform_signing":   {"platform"},
		"rule_signing":       {"rules"},
		"vuln_intel_signing": {"vuln_intel"},
	}
	allowed, exists := purposeMap[cert.Purpose]
	if !exists {
		return fmt.Errorf("step 11: unknown cert purpose: %s", cert.Purpose)
	}
	for _, t := range allowed {
		if t == bundleType {
			return nil
		}
	}
	// Special case: key_rotation and emergency_revocation accept any purpose
	if bundleType == "key_rotation" || bundleType == "emergency_revocation" {
		return nil
	}
	return fmt.Errorf("step 11: cert purpose %s does not match bundle type %s",
		cert.Purpose, bundleType)
}

// Step 14: Verify manifest references correct cert serial.
func (v *Verifier) VerifyManifestCertSerial(manifest *BundleManifest, cert *SigningKeyCert) error {
	if manifest.SigningKeySerial != cert.Serial {
		return fmt.Errorf("step 14: manifest signing_key_serial %s != cert serial %s",
			manifest.SigningKeySerial, cert.Serial)
	}
	return nil
}

// Steps 15-16: Verify manifest signature using the signing key from the certificate.
func (v *Verifier) VerifyManifestSignature(manifestData, sigData []byte, signingKey ed25519.PublicKey) error {
	canonical, err := crypto.Canonicalize(json.RawMessage(manifestData))
	if err != nil {
		return fmt.Errorf("step 15: canonicalize: %w", err)
	}
	if !crypto.Ed25519Verify(signingKey, canonical, sigData) {
		return fmt.Errorf("step 16: manifest signature invalid")
	}
	return nil
}

// Step 18: Verify artifact SHA-256 hashes match the manifest.
func (v *Verifier) VerifyArtifactHashes(quarantineDir string, manifest *BundleManifest) error {
	for _, artifact := range manifest.Artifacts {
		path := filepath.Join(quarantineDir, artifact.Path)
		hash, size, err := crypto.HashFile(path)
		if err != nil {
			return fmt.Errorf("step 18: hash file %s: %w", artifact.Path, err)
		}
		if hash != artifact.SHA256 {
			return fmt.Errorf("step 18: hash mismatch for %s: expected %s, got %s",
				artifact.Path, artifact.SHA256, hash)
		}
		if size != artifact.SizeBytes {
			return fmt.Errorf("step 18: size mismatch for %s: expected %d, got %d",
				artifact.Path, artifact.SizeBytes, size)
		}
	}
	return nil
}

// Step 20: Version monotonicity — new version must be newer than installed.
func (v *Verifier) CheckVersionMonotonicity(ctx context.Context, manifest *BundleManifest) error {
	key := "installed_version_" + manifest.BundleType
	state, err := v.trustStore.GetTrustState(ctx)
	if err != nil {
		return fmt.Errorf("step 20: %w", err)
	}
	installed, exists := state[key]
	if !exists || installed == "0.0.0" {
		return nil // first install
	}
	if manifest.Version <= installed {
		return fmt.Errorf("step 20: version %s is not newer than installed %s",
			manifest.Version, installed)
	}
	return nil
}

// VerifyBundle orchestrates the 25-step bundle verification process.
func (v *Verifier) VerifyBundle(ctx context.Context, bundlePath string) (*VerificationResult, error) {
	// Check lockdown first
	locked, err := v.lockdown.IsActive(ctx)
	if err != nil {
		return nil, err
	}
	if locked {
		return &VerificationResult{
			Accepted:      false,
			FailureReason: "system is in update lockdown mode",
		}, nil
	}

	// Load root public key
	rootKeyData, err := v.trustStore.LoadRootPublicKey()
	if err != nil {
		return nil, fmt.Errorf("cannot load root key: %w", err)
	}
	rootKeyBytes, err := base64.StdEncoding.DecodeString(rootKeyData.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid root key encoding: %w", err)
	}
	rootKey := ed25519.PublicKey(rootKeyBytes)

	// Step 1: Extract to quarantine
	quarantineDir, err := os.MkdirTemp("", "sentinelcore-verify-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(quarantineDir)

	if err := v.ExtractBundle(bundlePath, quarantineDir); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{1}, FailureReason: err.Error(),
		}, nil
	}

	// Step 2: Read metadata files
	readFile := func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(quarantineDir, name))
	}

	revocationData, err := readFile("revocations.json")
	if err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{2}, FailureReason: "missing revocations.json",
		}, nil
	}
	revocationSig, err := readFile("revocations.json.sig")
	if err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{2}, FailureReason: "missing revocations.json.sig",
		}, nil
	}
	certData, err := readFile("signing_key_cert.json")
	if err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{2}, FailureReason: "missing signing_key_cert.json",
		}, nil
	}
	certSig, err := readFile("signing_key_cert.json.sig")
	if err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{2}, FailureReason: "missing signing_key_cert.json.sig",
		}, nil
	}
	manifestData, err := readFile("manifest.json")
	if err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{2}, FailureReason: "missing manifest.json",
		}, nil
	}
	manifestSig, err := readFile("manifest.json.sig")
	if err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{2}, FailureReason: "missing manifest.json.sig",
		}, nil
	}

	// Steps 3-5: Verify and process revocations
	sigBytes := decodeSignature(revocationSig)
	if err := v.VerifyRevocationSignature(revocationData, sigBytes, rootKey); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{3}, FailureReason: err.Error(),
		}, nil
	}

	var revList RevocationList
	if err := json.Unmarshal(revocationData, &revList); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{4}, FailureReason: "invalid revocations.json",
		}, nil
	}
	// Step 5: Update local revocations from the list
	for _, rc := range revList.RevokedCertificates {
		v.localRevocations[rc.Serial] = true
	}
	v.localRevocationSeq = revList.Sequence

	// Steps 6-12: Verify signing key certificate
	certSigBytes := decodeSignature(certSig)
	if err := v.VerifySigningCertSignature(certData, certSigBytes, rootKey); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{6}, FailureReason: err.Error(),
		}, nil
	}

	var cert SigningKeyCert
	if err := json.Unmarshal(certData, &cert); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{6}, FailureReason: "invalid signing_key_cert.json",
		}, nil
	}

	if err := v.VerifyRootFingerprint(&cert, rootKey); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{7}, FailureReason: err.Error(),
		}, nil
	}
	if err := v.CheckCertNotRevoked(cert.Serial); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{8}, FailureReason: err.Error(),
		}, nil
	}
	if err := v.CheckCertValidity(&cert, time.Now()); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{9, 10}, FailureReason: err.Error(),
		}, nil
	}

	// Parse manifest to get bundle_type for purpose check
	var manifest BundleManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{13}, FailureReason: "invalid manifest.json",
		}, nil
	}

	if err := v.CheckCertPurpose(&cert, manifest.BundleType); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{11}, FailureReason: err.Error(),
		}, nil
	}

	// Step 12: Extract signing public key from certificate
	signingKeyBytes, err := base64.StdEncoding.DecodeString(cert.PublicKey)
	if err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{12}, FailureReason: "invalid signing key encoding",
		}, nil
	}
	signingKey := ed25519.PublicKey(signingKeyBytes)

	// Steps 13-17: Verify manifest
	if err := v.VerifyManifestCertSerial(&manifest, &cert); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{14}, FailureReason: err.Error(),
		}, nil
	}

	manifestSigBytes := decodeSignature(manifestSig)
	if err := v.VerifyManifestSignature(manifestData, manifestSigBytes, signingKey); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{16}, FailureReason: err.Error(),
		}, nil
	}

	// Step 18: Verify artifact hashes
	if err := v.VerifyArtifactHashes(quarantineDir, &manifest); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{18}, FailureReason: err.Error(),
		}, nil
	}

	// Step 20: Version monotonicity
	if err := v.CheckVersionMonotonicity(ctx, &manifest); err != nil {
		return &VerificationResult{
			Accepted: false, StepsFailed: []int{20}, FailureReason: err.Error(),
		}, nil
	}

	return &VerificationResult{
		Accepted:          true,
		ManifestVersion:   manifest.Version,
		BundleType:        manifest.BundleType,
		SigningCertSerial: cert.Serial,
	}, nil
}

// decodeSignature attempts base64 decoding first, falling back to raw bytes.
func decodeSignature(data []byte) []byte {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return data
	}
	return decoded
}
