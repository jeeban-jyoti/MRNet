// Package kms simulates a cloud KMS: secrets are stored wrapped (AES-256-GCM)
// under a master key that only the running service holds in memory.
// On a real deployment Wrap/Unwrap become calls to the provider's KMS.
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type KMS struct{ aead cipher.AEAD }

func New(masterKey []byte) (*KMS, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &KMS{aead: aead}, nil
}

func (k *KMS) Wrap(plain, label []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plain, label), nil
}

func (k *KMS) Unwrap(wrapped, label []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(wrapped) < n {
		return nil, errors.New("kms: wrapped key too short")
	}
	return k.aead.Open(nil, wrapped[:n], wrapped[n:], label)
}
