package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Wrap the cipher block in Galois Counter Mode.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a unique nonce containing 12 random bytes.
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// Encrypt plaintext using aesGCM.Seal(). By passing the nonce as the first
	// parameter, the ciphertext will be appended to the nonce so
	// that the encrypted message will be in the format
	// "{nonce}{encrypted message}".
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Wrap the cipher block in Galois Counter Mode.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	// Avoid potential index out of range panic in the next step.
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Split ciphertext in nonce and encrypted message and use gcm.Open() to
	// decrypt and authenticate the data.
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}
