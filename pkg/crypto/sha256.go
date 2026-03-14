package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// HashFile computes the SHA-256 hash of a file and returns (hex digest, file size, error).
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// HashBytes computes the SHA-256 hash of a byte slice and returns the hex digest.
func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
