package gasypt

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"runtime"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

func normalizePassword(password string) []byte {
	pw := norm.NFC.String(password)
	b := []byte(pw)
	zeroString(&pw)
	return b
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("gasypt: crypto/rand failed: %v", err))
	}
	return b
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func zeroString(s *string) {
	*s = ""
	runtime.KeepAlive(s)
}

func constantTimeEq(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func deriveAESKey(password []byte, salt []byte, iterations int) []byte {
	return pbkdf2.Key(password, salt, iterations, 32, sha512.New)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(data, padding...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7: empty data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > len(data) || padLen > 16 {
		return nil, fmt.Errorf("pkcs7: invalid padding")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("pkcs7: invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
