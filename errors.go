package gasypt

import "errors"

// Sentinel errors returned by decrypt functions.
var (
	// ErrCiphertextTooShort is returned when the input is too short to contain
	// the required salt, IV/nonce, and authentication tag.
	ErrCiphertextTooShort = errors.New("gasypt: ciphertext too short")

	// ErrNotEncValue is returned when a value is expected to be wrapped in
	// ENC(…) but is not.
	ErrNotEncValue = errors.New("gasypt: not an ENC(...) value")

	// ErrDecryptionFailed is the generic error for authentication failures:
	// wrong password, tampered ciphertext, or corrupted data. A single error
	// type prevents oracle attacks.
	ErrDecryptionFailed = errors.New("gasypt: decryption failed")
)
