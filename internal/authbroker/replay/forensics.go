package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// ForensicsBucket is the MinIO bucket name where envelope-encrypted PNG
// screenshots are stored. The cleanup-worker enforces a 7-day retention
// against this bucket; see cmd/forensics-cleanup-worker.
const ForensicsBucket = "dast-forensics"

// MinIOClient is the subset of *minio.Client we depend on. Defining a
// minimal interface lets tests inject a fake without spinning up a real
// MinIO server. The signature mirrors *minio.Client exactly so a real
// client satisfies the interface implicitly.
type MinIOClient interface {
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	RemoveObject(ctx context.Context, bucket, object string, opts minio.RemoveObjectOptions) error
}

// Forensics captures, encrypts, and persists post-failure screenshots for
// the DAST replay engine. KMS provides envelope encryption; MinIO is the
// object store. Both fields are required — the zero value is unusable and
// Capture rejects it explicitly.
type Forensics struct {
	KMS   kms.Provider
	MinIO MinIOClient
}

// Capture grabs a PNG screenshot from the active chromedp context, envelope-
// encrypts it under bundleID as additional authenticated data, and PUTs the
// JSON-serialized envelope to MinIO. It returns the resulting object key on
// success.
//
// Object key format: `bundle/<uuid>/<RFC3339-compact-utc>-<actionIdx>.png.enc`.
//
// The caller MUST pass a chromedp-aware context (the same `timeoutCtx` the
// replay engine uses for its actions). Capture is best-effort: the engine
// already has a primary error to report when this is invoked, so the caller
// is expected to log capture failures and continue.
func (f *Forensics) Capture(ctx context.Context, bundleID uuid.UUID, actionIdx int) (string, error) {
	if f == nil || f.KMS == nil || f.MinIO == nil {
		return "", fmt.Errorf("forensics: not configured")
	}

	var png []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&png)); err != nil {
		return "", fmt.Errorf("forensics: screenshot: %w", err)
	}
	return f.captureWithPNG(ctx, bundleID, actionIdx, png)
}

// captureWithPNG envelope-encrypts an in-memory PNG and PUTs it to MinIO,
// returning the resulting object key. Split out from Capture so tests can
// drive the encrypt + upload pipeline without standing up a chromedp
// browser. The signature is intentionally lowercase — only the surrounding
// package and its tests should rely on it.
func (f *Forensics) captureWithPNG(ctx context.Context, bundleID uuid.UUID, actionIdx int, png []byte) (string, error) {
	if f == nil || f.KMS == nil || f.MinIO == nil {
		return "", fmt.Errorf("forensics: not configured")
	}
	env, err := kms.EncryptEnvelope(ctx, f.KMS, "dast.forensic", png, []byte(bundleID.String()))
	if err != nil {
		return "", fmt.Errorf("forensics: encrypt: %w", err)
	}

	payload, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("forensics: serialize envelope: %w", err)
	}

	key := fmt.Sprintf("bundle/%s/%s-%d.png.enc",
		bundleID,
		time.Now().UTC().Format("20060102T150405Z"),
		actionIdx,
	)

	_, err = f.MinIO.PutObject(ctx, ForensicsBucket, key,
		bytes.NewReader(payload), int64(len(payload)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return "", fmt.Errorf("forensics: upload: %w", err)
	}
	return key, nil
}
