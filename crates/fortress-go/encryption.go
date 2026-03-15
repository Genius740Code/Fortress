package fortress

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptionAlgorithm represents an encryption algorithm
type EncryptionAlgorithm struct {
	algorithm string
	config    *Config
}

// NewEncryptionAlgorithm creates a new encryption algorithm instance
func NewEncryptionAlgorithm(algorithm string, config *Config) *EncryptionAlgorithm {
	return &EncryptionAlgorithm{
		algorithm: algorithm,
		config:    config,
	}
}

// Encrypt encrypts data using the specified algorithm
func (e *EncryptionAlgorithm) Encrypt(plaintext, key []byte, options *EncryptionOptions) ([]byte, error) {
	switch e.algorithm {
	case "aes256gcm":
		return e.encryptAES256GCM(plaintext, key, options)
	case "chacha20poly1305":
		return e.encryptChaCha20Poly1305(plaintext, key, options)
	case "aegis256":
		return e.encryptAegis256(plaintext, key, options)
	default:
		return nil, NewEncryptionError(fmt.Sprintf("unsupported algorithm: %s", e.algorithm), nil)
	}
}

// Decrypt decrypts data using the specified algorithm
func (e *EncryptionAlgorithm) Decrypt(ciphertext, key []byte) ([]byte, error) {
	switch e.algorithm {
	case "aes256gcm":
		return e.decryptAES256GCM(ciphertext, key)
	case "chacha20poly1305":
		return e.decryptChaCha20Poly1305(ciphertext, key)
	case "aegis256":
		return e.decryptAegis256(ciphertext, key)
	default:
		return nil, NewEncryptionError(fmt.Sprintf("unsupported algorithm: %s", e.algorithm), nil)
	}
}

// GetAlgorithm returns the algorithm name
func (e *EncryptionAlgorithm) GetAlgorithm() string {
	return e.algorithm
}

// GetMetadata returns algorithm metadata
func (e *EncryptionAlgorithm) GetMetadata() *AlgorithmMetadata {
	metadata := &AlgorithmMetadata{
		Name:                   e.algorithm,
		SupportsAssociatedData: true,
	}

	switch e.algorithm {
	case "aes256gcm":
		metadata.KeySize = 32
		metadata.NonceSize = 12
		metadata.TagSize = 16
	case "chacha20poly1305":
		metadata.KeySize = 32
		metadata.NonceSize = 12
		metadata.TagSize = 16
	case "aegis256":
		metadata.KeySize = 32
		metadata.NonceSize = 12
		metadata.TagSize = 16
	default:
		metadata.KeySize = 32
		metadata.NonceSize = 12
		metadata.TagSize = 16
	}

	return metadata
}

// encryptAES256GCM encrypts data using AES-256-GCM
func (e *EncryptionAlgorithm) encryptAES256GCM(plaintext, key []byte, options *EncryptionOptions) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, NewEncryptionError("failed to create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewEncryptionError("failed to create GCM", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, NewEncryptionError("failed to generate nonce", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, options.AssociatedData)
	return ciphertext, nil
}

// decryptAES256GCM decrypts data using AES-256-GCM
func (e *EncryptionAlgorithm) decryptAES256GCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, NewEncryptionError("failed to create AES cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewEncryptionError("failed to create GCM", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, NewEncryptionError("ciphertext too short", nil)
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt", err)
	}

	return plaintext, nil
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305
func (e *EncryptionAlgorithm) encryptChaCha20Poly1305(plaintext, key []byte, options *EncryptionOptions) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, NewEncryptionError("failed to create ChaCha20-Poly1305 AEAD", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, NewEncryptionError("failed to generate nonce", err)
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, options.AssociatedData)
	return ciphertext, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305
func (e *EncryptionAlgorithm) decryptChaCha20Poly1305(ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, NewEncryptionError("failed to create ChaCha20-Poly1305 AEAD", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, NewEncryptionError("ciphertext too short", nil)
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, NewEncryptionError("failed to decrypt", err)
	}

	return plaintext, nil
}

// encryptAegis256 encrypts data using AEGIS-256
// Note: AEGIS-256 is not natively supported in Go's crypto library
// This implementation falls back to AES-256-GCM for compatibility
func (e *EncryptionAlgorithm) encryptAegis256(plaintext, key []byte, options *EncryptionOptions) ([]byte, error) {
	log.Printf("AEGIS-256 encryption requested, falling back to AES-256-GCM for compatibility")
	return e.encryptAES256GCM(plaintext, key, options)
}

// decryptAegis256 decrypts data using AEGIS-256
// Note: AEGIS-256 is not natively supported in Go's crypto library
// This implementation falls back to AES-256-GCM for compatibility
func (e *EncryptionAlgorithm) decryptAegis256(ciphertext, key []byte) ([]byte, error) {
	log.Printf("AEGIS-256 decryption requested, falling back to AES-256-GCM for compatibility")
	return e.decryptAES256GCM(ciphertext, key)
}
