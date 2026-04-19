package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// AESGCMKeyLen is the required length of the raw AES-256 key in bytes.
const AESGCMKeyLen = 32

// ErrInvalidKey is returned when an AES-GCM key is not 32 bytes long.
var ErrInvalidKey = errors.New("crypto: AES-GCM key must be 32 bytes")

// ErrCiphertextTooShort is returned when a ciphertext is shorter than the
// expected nonce + tag length.
var ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")

// DecodeHexKey parses a hex-encoded 32-byte key (64 hex characters) into a raw
// key suitable for NewAESGCM. Used to load AUTH_PROFILE_ENCRYPTION_KEY from env.
func DecodeHexKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid hex key: %w", err)
	}
	if len(key) != AESGCMKeyLen {
		return nil, ErrInvalidKey
	}
	return key, nil
}

// AESGCM is a reusable AES-256-GCM AEAD with a random nonce per encryption.
// Ciphertext layout is: nonce(12) || ciphertext || tag(16), all concatenated.
type AESGCM struct {
	aead cipher.AEAD
}

// NewAESGCM constructs an AESGCM from a 32-byte key.
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != AESGCMKeyLen {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESGCM{aead: aead}, nil
}

// Seal encrypts plaintext with an optional additional authenticated data
// (passing nil is fine). The returned blob contains the random nonce prepended.
func (a *AESGCM) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends ciphertext+tag to the first arg (which is nonce here) so
	// the output is already nonce||ciphertext||tag.
	return a.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open decrypts a blob produced by Seal. The same aad must be supplied.
func (a *AESGCM) Open(blob, aad []byte) ([]byte, error) {
	ns := a.aead.NonceSize()
	if len(blob) < ns+a.aead.Overhead() {
		return nil, ErrCiphertextTooShort
	}
	nonce := blob[:ns]
	ct := blob[ns:]
	return a.aead.Open(nil, nonce, ct, aad)
}
