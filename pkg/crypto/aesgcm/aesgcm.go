// Package aesgcm provides AES-256-GCM authenticated encryption for
// secrets at rest. Ciphertexts are emitted with the versioned prefix
// "enc:v1:" so the wire format can evolve without breaking old rows.
//
// Current format (v1):
//
//	enc:v1:<base64url(nonce(12) || ciphertext || tag)>
//
// Key must be 32 bytes. Nonce is drawn fresh from crypto/rand per encrypt.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	keySize     = 32
	nonceSize   = 12
	prefix      = "enc:v1:"
	prefixLen   = len(prefix)
)

// Encryptor wraps a single AES-256-GCM key. Safe for concurrent use.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor constructs an Encryptor from a 32-byte key.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("aesgcm: key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Encryptor{aead: aead}, nil
}

// Encrypt returns the versioned ciphertext string.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("aesgcm: nonce: %w", err)
	}
	ct := e.aead.Seal(nil, nonce, []byte(plaintext), nil)
	// Emit nonce||ct so decrypt can recover both in one blob.
	blob := append(nonce, ct...)
	return prefix + base64.RawURLEncoding.EncodeToString(blob), nil
}

// Decrypt accepts "enc:v1:<b64>" and returns the plaintext.
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, prefix) {
		return "", errors.New("aesgcm: ciphertext missing enc:v1: prefix")
	}
	blob, err := base64.RawURLEncoding.DecodeString(ciphertext[prefixLen:])
	if err != nil {
		return "", fmt.Errorf("aesgcm: b64 decode: %w", err)
	}
	if len(blob) < nonceSize {
		return "", errors.New("aesgcm: ciphertext too short")
	}
	nonce, ct := blob[:nonceSize], blob[nonceSize:]
	pt, err := e.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("aesgcm: open: %w", err)
	}
	return string(pt), nil
}
