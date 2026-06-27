// Package gasypt provides password-based encryption with AES-256-CBC, SM4-GCM, and SM4-CBC.
//
// The default algorithm is PBEWithHMACSHA512AndAES_256 for Jasypt compatibility.
// SM4-based algorithms provide authenticated encryption and are compliant with GM/T 0091.
//
// Basic usage:
//
//	ct := gasypt.Encrypt("password", "hello world")
//	pt, err := gasypt.Decrypt("password", ct)
//
// Struct field decryption via tags:
//
//	type Config struct {
//	    Secret string `gasypt:"encrypted"`
//	}
//	gasypt.DecryptFields(&cfg, "master-password")
package gasypt

import "strings"

// Encrypt encrypts plaintext with the default algorithm PBEWithHMACSHA512AndAES_256
// (AES-256-CBC, 1000 PBKDF2 iterations, Jasypt-compatible).
func Encrypt(password, plaintext string) string {
	return EncryptWith(PBEWithHMACSHA512AndAES_256, password, plaintext)
}

// EncryptWith encrypts plaintext using the given algorithm with its default iteration count.
func EncryptWith(algo Algorithm, password, plaintext string) string {
	return EncryptWithIterations(algo, password, plaintext, algo.DefaultIterations())
}

// EncryptWithIterations encrypts plaintext using the given algorithm and a custom PBKDF2
// iteration count. Panics if the algorithm is invalid (programmer error).
func EncryptWithIterations(algo Algorithm, password, plaintext string, iterations int) string {
	switch algo {
	case PBEWithHMACSHA512AndAES_256:
		enc, err := encryptAES256CBC(password, plaintext, iterations)
		if err != nil {
			panic(err)
		}
		return enc
	case PBEWithHMACSM3AndSM4_GCM:
		enc, err := encryptSM4GCM(password, plaintext, iterations)
		if err != nil {
			panic(err)
		}
		return enc
	case PBEWithHMACSM3AndSM4_CBC:
		enc, err := encryptSM4CBC(password, plaintext, iterations)
		if err != nil {
			panic(err)
		}
		return enc
	default:
		panic("gasypt: unknown algorithm")
	}
}

// Decrypt decrypts encoded (Base64 ciphertext) with the default algorithm.
func Decrypt(password, encoded string) (string, error) {
	return DecryptWith(PBEWithHMACSHA512AndAES_256, password, encoded)
}

// DecryptWith decrypts encoded with the given algorithm and its default iterations.
func DecryptWith(algo Algorithm, password, encoded string) (string, error) {
	return DecryptWithIterations(algo, password, encoded, algo.DefaultIterations())
}

// DecryptWithIterations decrypts encoded with the given algorithm and a custom PBKDF2
// iteration count. Returns ErrDecryptionFailed on wrong password or tampered data;
// ErrCiphertextTooShort if the input is truncated.
func DecryptWithIterations(algo Algorithm, password, encoded string, iterations int) (string, error) {
	switch algo {
	case PBEWithHMACSHA512AndAES_256:
		return decryptAES256CBC(password, encoded, iterations)
	case PBEWithHMACSM3AndSM4_GCM:
		return decryptSM4GCM(password, encoded, iterations)
	case PBEWithHMACSM3AndSM4_CBC:
		return decryptSM4CBC(password, encoded, iterations)
	default:
		return "", ErrDecryptionFailed
	}
}

const encPrefix = "ENC("
const encSuffix = ")"

// IsEncValue reports whether value is wrapped in ENC(…).
// Leading and trailing whitespace is tolerated.
func IsEncValue(value string) bool {
	t := strings.TrimSpace(value)
	return strings.HasPrefix(t, encPrefix) && strings.HasSuffix(t, encSuffix)
}

func unwrapEnc(value string) (string, error) {
	t := strings.TrimSpace(value)
	if !strings.HasPrefix(t, encPrefix) || !strings.HasSuffix(t, encSuffix) {
		return "", ErrNotEncValue
	}
	inner := t[len(encPrefix) : len(t)-len(encSuffix)]
	return inner, nil
}

// DecryptEnc unwraps an ENC(…) value and decrypts it with the default algorithm.
// Returns ErrNotEncValue if value does not start with ENC( and end with ).
func DecryptEnc(value, password string) (string, error) {
	return DecryptEncWith(PBEWithHMACSHA512AndAES_256, value, password)
}

// DecryptEncWith unwraps an ENC(…) value and decrypts it with the given algorithm.
func DecryptEncWith(algo Algorithm, value, password string) (string, error) {
	inner, err := unwrapEnc(value)
	if err != nil {
		return "", err
	}
	return DecryptWithIterations(algo, password, inner, algo.DefaultIterations())
}

// WrapEnc wraps a Base64-encoded ciphertext in ENC(…).
func WrapEnc(encoded string) string {
	return encPrefix + encoded + encSuffix
}

// ClearString zeroes s by replacing it with an empty string.
// In Go, the original backing array may persist until GC; see the README security notes.
func ClearString(s *string) {
	if s != nil {
		zeroString(s)
	}
}
