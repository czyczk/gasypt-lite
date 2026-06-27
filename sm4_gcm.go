package gasypt

import (
	"crypto/cipher"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
)

const sm4GCMTagSize = 16

func encryptSM4GCM(password, plaintext string, iterations int) (string, error) {
	pw := normalizePassword(password)
	defer zeroBytes(pw)

	salt := randomBytes(16)
	nonce := randomBytes(12)

	encKey, macKey := deriveSM4Keys(pw, salt, iterations)
	defer zeroBytes(encKey)
	defer zeroBytes(macKey)

	block, err := sm4.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("gasypt: sm4.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gasypt: cipher.NewGCM: %w", err)
	}

	plainBytes := []byte(plaintext)
	buf := make([]byte, 0, len(plainBytes)+gcm.Overhead())
	sealed := gcm.Seal(buf, nonce, plainBytes, salt)

	ciphertext := sealed[:len(sealed)-sm4GCMTagSize]
	tag := sealed[len(sealed)-sm4GCMTagSize:]

	commitment := sm3HMAC(macKey, salt, nonce, ciphertext, tag)

	result := make([]byte, 0, 16+12+len(sealed)+32)
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, sealed...)
	result = append(result, commitment...)

	return encodeBase64(result), nil
}

func decryptSM4GCM(password, encoded string, iterations int) (string, error) {
	data, err := decodeBase64(encoded)
	if err != nil {
		return "", fmt.Errorf("gasypt: base64 decode: %w", err)
	}

	if len(data) < 16+12+sm4GCMTagSize+32 {
		return "", ErrCiphertextTooShort
	}

	salt := data[:16]
	nonce := data[16:28]
	commitmentEnd := len(data) - 32
	sealed := data[28:commitmentEnd]
	commitment := data[commitmentEnd:]

	if len(sealed) < sm4GCMTagSize {
		return "", ErrCiphertextTooShort
	}
	ciphertext := sealed[:len(sealed)-sm4GCMTagSize]
	tag := sealed[len(sealed)-sm4GCMTagSize:]

	pw := normalizePassword(password)
	defer zeroBytes(pw)

	encKey, macKey := deriveSM4Keys(pw, salt, iterations)
	defer zeroBytes(encKey)
	defer zeroBytes(macKey)

	expected := sm3HMAC(macKey, salt, nonce, ciphertext, tag)
	if !constantTimeEq(commitment, expected) {
		return "", ErrDecryptionFailed
	}
	zeroBytes(expected)

	block, err := sm4.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("gasypt: sm4.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gasypt: cipher.NewGCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, sealed, salt)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}
