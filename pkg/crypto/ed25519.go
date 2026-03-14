package crypto

import (
	"crypto/ed25519"
)

// Ed25519Sign signs a message with an Ed25519 private key.
func Ed25519Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

// Ed25519Verify verifies an Ed25519 signature on a message.
func Ed25519Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}
