package gasypt

import (
	"crypto/cipher"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
)

func encryptSM4CBC(password, plaintext string, iterations int) (string, error) {
	pw := normalizePassword(password)
	defer zeroBytes(pw)

	salt := randomBytes(16)
	iv := randomBytes(sm4.BlockSize)

	encKey, macKey := deriveSM4Keys(pw, salt, iterations)
	defer zeroBytes(encKey)
	defer zeroBytes(macKey)

	block, err := sm4.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("gasypt: sm4.NewCipher: %w", err)
	}

	plainBytes := []byte(plaintext)
	padded := pkcs7Pad(plainBytes, sm4.BlockSize)

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	zeroBytes(padded)

	mac := sm3HMAC(macKey, iv, ciphertext)

	result := make([]byte, 0, 16+sm4.BlockSize+len(ciphertext)+32)
	result = append(result, salt...)
	result = append(result, iv...)
	result = append(result, ciphertext...)
	result = append(result, mac...)

	return encodeBase64(result), nil
}

func decryptSM4CBC(password, encoded string, iterations int) (string, error) {
	data, err := decodeBase64(encoded)
	if err != nil {
		return "", fmt.Errorf("gasypt: base64 decode: %w", err)
	}

	if len(data) < 16+sm4.BlockSize+1+32 {
		return "", ErrCiphertextTooShort
	}

	salt := data[:16]
	iv := data[16 : 16+sm4.BlockSize]
	macEnd := len(data) - 32
	ciphertext := data[16+sm4.BlockSize : macEnd]
	mac := data[macEnd:]

	if len(ciphertext) == 0 || len(ciphertext)%sm4.BlockSize != 0 {
		return "", ErrDecryptionFailed
	}

	pw := normalizePassword(password)
	defer zeroBytes(pw)

	encKey, macKey := deriveSM4Keys(pw, salt, iterations)
	defer zeroBytes(encKey)
	defer zeroBytes(macKey)

	expected := sm3HMAC(macKey, iv, ciphertext)
	if !constantTimeEq(mac, expected) {
		return "", ErrDecryptionFailed
	}
	zeroBytes(expected)

	block, err := sm4.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("gasypt: sm4.NewCipher: %w", err)
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
