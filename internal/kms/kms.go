// Package kms provides an abstraction layer for key management operations,
// supporting multiple backends including a local development provider and
// AWS KMS for production use.
package kms

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrUnknownProvider is returned when a requested provider is not registered.
var ErrUnknownProvider = errors.New("kms: unknown provider")

// Provider is the interface that all KMS backends must implement.
type Provider interface {
	// Name returns the unique identifier for this provider.
	Name() string

	// GenerateDataKey generates a new data encryption key (DEK) for the given
	// purpose. The returned DataKey contains both the plaintext DEK and a
	// wrapped (encrypted) copy suitable for storage.
	GenerateDataKey(ctx context.Context, purpose string) (DataKey, error)

	// Decrypt unwraps a previously wrapped DEK using the specified key version.
	Decrypt(ctx context.Context, wrapped []byte, kekVersion string) ([]byte, error)

	// HMAC computes an HMAC-SHA-256 over msg using a key derived from keyPath.
	HMAC(ctx context.Context, keyPath string, msg []byte) ([]byte, error)

	// HMACVerify verifies an HMAC over msg using a key derived from keyPath.
	// Returns true if and only if mac is a valid HMAC for msg under keyPath.
	HMACVerify(ctx context.Context, keyPath string, msg []byte, mac []byte) (bool, error)
}

// DataKey holds a plaintext DEK and its wrapped (encrypted) counterpart.
// Callers must call Zeroize when done to clear the plaintext from memory.
type DataKey struct {
	// Plaintext is the raw DEK bytes. Must be zeroized after use.
	Plaintext []byte
	// Wrapped is the encrypted DEK suitable for persistent storage.
	Wrapped []byte
	// KeyVersion identifies which KEK version was used to wrap this DEK.
	KeyVersion string
}

// Zeroize overwrites the Plaintext field with zeros to minimize the window
// during which the raw DEK sits in memory.
func (dk *DataKey) Zeroize() {
	for i := range dk.Plaintext {
		dk.Plaintext[i] = 0
	}
}

// Registry is a thread-safe map from provider name to Provider implementation.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry creates and returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register adds p to the registry under its name. It overwrites any existing
// entry with the same name.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

// Get returns the Provider registered under name, or ErrUnknownProvider if
// no such provider has been registered.
func (r *Registry) Get(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
	return p, nil
}
