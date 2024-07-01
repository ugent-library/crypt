package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// Encrypt encrypts data using 256-bit AES-GCM. The resulting ciphertext provides
// a check that the data hasn't been altered.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	// See https://github.com/gtank/cryptopasta/blob/master/encrypt.go and
	// https://www.alexedwards.net/blog/working-with-cookies-in-go#encrypted-cookies.

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

// Decrypt decrypts data encrypted with Encrypt using 256-bit AES-GCM and checks
// that the data wasn't altered.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
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

	// Split ciphertext in nonce and encrypted data and use gcm.Open() to
	// decrypt and authenticate the data.
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

func EncryptString(key []byte, plaintext string) (string, error) {
	ciphertext, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func DecryptString(key []byte, encodedtext string) (string, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(encodedtext)
	if err != nil {
		return "", err
	}
	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func EncryptValue(key []byte, v any) (string, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func DecryptValue(key []byte, encodedtext string, v any) error {
	ciphertext, err := base64.RawURLEncoding.DecodeString(encodedtext)
	if err != nil {
		return err
	}
	plaintext, err := Decrypt(key, ciphertext)
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, v)
}

type Crypt struct {
	key []byte
}

func New(key []byte) *Crypt {
	return &Crypt{key: key}
}

func (c *Crypt) Encrypt(plaintext []byte) ([]byte, error) {
	return Encrypt(c.key, plaintext)
}

func (c *Crypt) Decrypt(ciphertext []byte) ([]byte, error) {
	return Decrypt(c.key, ciphertext)
}

func (c *Crypt) EncryptString(plaintext string) (string, error) {
	return EncryptString(c.key, plaintext)
}

func (c *Crypt) DecryptString(encodedtext string) (string, error) {
	return DecryptString(c.key, encodedtext)
}

func (c *Crypt) EncryptValue(v any) (string, error) {
	return EncryptValue(c.key, v)
}

func (c *Crypt) DecryptValue(encodedtext string, v any) error {
	return DecryptValue(c.key, encodedtext, v)
}
