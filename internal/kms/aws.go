package kms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSProvider implements Provider using AWS Key Management Service (KMS).
// It delegates all cryptographic operations to AWS KMS, keeping plaintext
// key material server-side.
type AWSProvider struct {
	client      *kms.Client
	masterKeyID string
}

// NewAWSProvider creates an AWSProvider that uses cfg to create a KMS client
// and masterKeyID as the key identifier for all KMS operations.
func NewAWSProvider(cfg aws.Config, masterKeyID string) *AWSProvider {
	return &AWSProvider{
		client:      kms.NewFromConfig(cfg),
		masterKeyID: masterKeyID,
	}
}

// Name returns "aws-kms".
func (p *AWSProvider) Name() string { return "aws-kms" }

// GenerateDataKey calls AWS KMS GenerateDataKey to produce a 256-bit DEK.
// The encryption context uses purpose as the value for the "purpose" key.
func (p *AWSProvider) GenerateDataKey(ctx context.Context, purpose string) (DataKey, error) {
	out, err := p.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(p.masterKeyID),
		KeySpec: kmstypes.DataKeySpecAes256,
		EncryptionContext: map[string]string{
			"purpose": purpose,
		},
	})
	if err != nil {
		return DataKey{}, fmt.Errorf("kms/aws: GenerateDataKey: %w", err)
	}

	keyVersion := ""
	if out.KeyId != nil {
		keyVersion = *out.KeyId
	}

	return DataKey{
		Plaintext:  out.Plaintext,
		Wrapped:    out.CiphertextBlob,
		KeyVersion: keyVersion,
	}, nil
}

// Decrypt calls AWS KMS Decrypt to unwrap a previously wrapped DEK.
// The kekVersion parameter is accepted but not used — the wrapped ciphertext
// blob contains the key reference natively.
func (p *AWSProvider) Decrypt(ctx context.Context, wrapped []byte, _ string) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(p.masterKeyID),
		CiphertextBlob: wrapped,
	})
	if err != nil {
		return nil, fmt.Errorf("kms/aws: Decrypt: %w", err)
	}
	return out.Plaintext, nil
}

// HMAC calls AWS KMS GenerateMac using HMAC-SHA-256 with the key identified by
// keyPath. keyPath is used as the KMS key ID (e.g. alias/my-hmac-key).
func (p *AWSProvider) HMAC(ctx context.Context, keyPath string, msg []byte) ([]byte, error) {
	out, err := p.client.GenerateMac(ctx, &kms.GenerateMacInput{
		KeyId:        aws.String(keyPath),
		MacAlgorithm: kmstypes.MacAlgorithmSpecHmacSha256,
		Message:      msg,
	})
	if err != nil {
		return nil, fmt.Errorf("kms/aws: GenerateMac: %w", err)
	}
	return out.Mac, nil
}

// HMACVerify calls AWS KMS VerifyMac. Returns true if the MAC is valid.
func (p *AWSProvider) HMACVerify(ctx context.Context, keyPath string, msg []byte, mac []byte) (bool, error) {
	out, err := p.client.VerifyMac(ctx, &kms.VerifyMacInput{
		KeyId:        aws.String(keyPath),
		MacAlgorithm: kmstypes.MacAlgorithmSpecHmacSha256,
		Message:      msg,
		Mac:          mac,
	})
	if err != nil {
		return false, fmt.Errorf("kms/aws: VerifyMac: %w", err)
	}
	return out.MacValid, nil
}
