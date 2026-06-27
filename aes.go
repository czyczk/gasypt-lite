package gasypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func encryptAES256CBC(password, plaintext string, iterations int) (string, error) {
	pw := normalizePassword(password)
	defer zeroBytes(pw)

	salt := randomBytes(16)
	iv := randomBytes(aes.BlockSize)

	key := deriveAESKey(pw, salt, iterations)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("gasypt: aes.NewCipher: %w", err)
	}

	plainBytes := []byte(plaintext)
	padded := pkcs7Pad(plainBytes, aes.BlockSize)

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	zeroBytes(padded)

	result := make([]byte, 0, 16+aes.BlockSize+len(ciphertext))
	result = append(result, salt...)
	result = append(result, iv...)
	result = append(result, ciphertext...)

	return encodeBase64(result), nil
}

func decryptAES256CBC(password, encoded string, iterations int) (string, error) {
	data, err := decodeBase64(encoded)
	if err != nil {
		return "", fmt.Errorf("gasypt: base64 decode: %w", err)
	}

	if len(data) < 16+aes.BlockSize+1 {
		return "", ErrCiphertextTooShort
	}

	salt := data[:16]
	iv := data[16 : 16+aes.BlockSize]
	ciphertext := data[16+aes.BlockSize:]

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", ErrDecryptionFailed
	}

	pw := normalizePassword(password)
	defer zeroBytes(pw)

	key := deriveAESKey(pw, salt, iterations)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("gasypt: aes.NewCipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		zeroBytes(plaintext)
		return "", ErrDecryptionFailed
	}

	result := string(unpadded)
	zeroBytes(plaintext)
	return result, nil
}
