package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// LocalProvider is a software-only KMS backend suitable for development and
// testing. It uses a 32-byte master key stored in memory.
//
// Security note: This provider is NOT suitable for production use. The master
// key is held in plaintext in process memory with no HSM protection.
type LocalProvider struct {
	masterKey [32]byte
}

// NewLocalProvider creates a LocalProvider from the given 32-byte master key.
// It panics if master is not exactly 32 bytes. A defensive copy is made so
// the caller may safely overwrite the original slice.
func NewLocalProvider(master []byte) *LocalProvider {
	if len(master) != 32 {
		panic(fmt.Sprintf("kms/local: master key must be 32 bytes, got %d", len(master)))
	}
	p := &LocalProvider{}
	copy(p.masterKey[:], master)
	return p
}

// Name returns "local".
func (p *LocalProvider) Name() string { return "local" }

// GenerateDataKey generates a random 32-byte DEK and wraps it under the
// master key using AES-256-GCM. The wrapped form is: nonce (12 bytes) ‖
// AES-GCM ciphertext+tag.
func (p *LocalProvider) GenerateDataKey(_ context.Context, _ string) (DataKey, error) {
	// Generate plaintext DEK.
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return DataKey{}, fmt.Errorf("kms/local: generate DEK: %w", err)
	}

	wrapped, err := p.wrapKey(dek)
	if err != nil {
		return DataKey{}, err
	}

	return DataKey{
		Plaintext:  dek,
		Wrapped:    wrapped,
		KeyVersion: "local-v1",
	}, nil
}

// Decrypt unwraps a wrapped DEK that was produced by GenerateDataKey.
// kekVersion is accepted but not validated (local provider has a single key).
func (p *LocalProvider) Decrypt(_ context.Context, wrapped []byte, _ string) ([]byte, error) {
	return p.unwrapKey(wrapped)
}

// HMAC derives an HMAC-SHA-256 subkey via HMAC(masterKey, "hmac:"+keyPath)
// and then computes HMAC-SHA-256(subkey, msg).
func (p *LocalProvider) HMAC(_ context.Context, keyPath string, msg []byte) ([]byte, error) {
	subkey := p.deriveHMACSubkey(keyPath)
	mac := p.computeHMAC(subkey, msg)
	return mac, nil
}

// HMACVerify derives the subkey and performs a constant-time comparison using
// hmac.Equal.
func (p *LocalProvider) HMACVerify(_ context.Context, keyPath string, msg []byte, mac []byte) (bool, error) {
	subkey := p.deriveHMACSubkey(keyPath)
	expected := p.computeHMAC(subkey, msg)
	return hmac.Equal(expected, mac), nil
}

// --- internal helpers ---

func (p *LocalProvider) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(p.masterKey[:])
	if err != nil {
		return nil, fmt.Errorf("kms/local: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms/local: cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

func (p *LocalProvider) wrapKey(plaintext []byte) ([]byte, error) {
	gcm, err := p.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("kms/local: generate nonce: %w", err)
	}
	// Format: nonce ‖ ciphertext+tag
	wrapped := gcm.Seal(nonce, nonce, plaintext, nil)
	return wrapped, nil
}

func (p *LocalProvider) unwrapKey(wrapped []byte) ([]byte, error) {
	gcm, err := p.gcm()
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, fmt.Errorf("kms/local: wrapped key too short")
	}
	nonce, ciphertext := wrapped[:nonceSize], wrapped[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("kms/local: decrypt wrapped key: %w", err)
	}
	return plaintext, nil
}

func (p *LocalProvider) deriveHMACSubkey(keyPath string) []byte {
	h := hmac.New(sha256.New, p.masterKey[:])
	h.Write([]byte("hmac:" + keyPath))
	return h.Sum(nil)
}

func (p *LocalProvider) computeHMAC(subkey, msg []byte) []byte {
	h := hmac.New(sha256.New, subkey)
	h.Write(msg)
	return h.Sum(nil)
}
