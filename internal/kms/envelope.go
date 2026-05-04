package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Envelope holds everything needed to decrypt a piece of data: the ciphertext
// (with appended AES-GCM authentication tag), the random IV used during
// encryption, the wrapped (KMS-encrypted) DEK, and the KEK version that was
// used to wrap the DEK.
type Envelope struct {
	// Ciphertext is the AES-256-GCM encrypted plaintext with the authentication
	// tag appended.
	Ciphertext []byte
	// IV is the 12-byte random nonce used with AES-GCM.
	IV []byte
	// WrappedDEK is the DEK encrypted by the KMS provider.
	WrappedDEK []byte
	// KeyVersion identifies the KEK version used to wrap the DEK.
	KeyVersion string
}

// EncryptEnvelope encrypts plaintext under a freshly generated DEK using
// AES-256-GCM with the supplied additional authenticated data (aad).
//
// The DEK is generated via p.GenerateDataKey and the wrapped copy is stored in
// the returned Envelope. The plaintext DEK is zeroized before the function
// returns.
func EncryptEnvelope(ctx context.Context, p Provider, purpose string, plaintext, aad []byte) (*Envelope, error) {
	dk, err := p.GenerateDataKey(ctx, purpose)
	if err != nil {
		return nil, fmt.Errorf("kms/envelope: generate data key: %w", err)
	}
	defer dk.Zeroize()

	block, err := aes.NewCipher(dk.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms/envelope: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms/envelope: cipher.NewGCM: %w", err)
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("kms/envelope: generate IV: %w", err)
	}

	// Seal appends the authentication tag to the ciphertext.
	ciphertext := gcm.Seal(nil, iv, plaintext, aad)

	return &Envelope{
		Ciphertext: ciphertext,
		IV:         iv,
		WrappedDEK: dk.Wrapped,
		KeyVersion: dk.KeyVersion,
	}, nil
}

// DecryptEnvelope decrypts an Envelope produced by EncryptEnvelope. The aad
// must match exactly what was supplied during encryption or decryption will
// fail with an authentication error.
//
// The plaintext DEK is zeroized after decryption.
func DecryptEnvelope(ctx context.Context, p Provider, env *Envelope, aad []byte) ([]byte, error) {
	dekBytes, err := p.Decrypt(ctx, env.WrappedDEK, env.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("kms/envelope: unwrap DEK: %w", err)
	}
	// Zeroize the DEK plaintext when we're done.
	defer func() {
		for i := range dekBytes {
			dekBytes[i] = 0
		}
	}()

	block, err := aes.NewCipher(dekBytes)
	if err != nil {
		return nil, fmt.Errorf("kms/envelope: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms/envelope: cipher.NewGCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, env.IV, env.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("kms/envelope: decrypt: %w", err)
	}
	return plaintext, nil
}
