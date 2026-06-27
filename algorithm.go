package gasypt

// Algorithm identifies a supported password-based encryption scheme.
type Algorithm int

const (
	// PBEWithHMACSHA512AndAES_256 is the default algorithm: AES-256-CBC with
	// PBKDF2-HMAC-SHA512 (1,000 iterations). Compatible with Jasypt 3.x.
	PBEWithHMACSHA512AndAES_256 Algorithm = iota

	// PBEWithHMACSM3AndSM4_GCM is SM4-GCM AEAD with HMAC-SM3 key commitment
	// (10,000 iterations). Defends against partitioning oracle attacks.
	PBEWithHMACSM3AndSM4_GCM

	// PBEWithHMACSM3AndSM4_CBC is SM4-CBC with Encrypt-then-HMAC-SM3
	// (10,000 iterations). GM/T 0091-2020.
	PBEWithHMACSM3AndSM4_CBC
)

func (a Algorithm) String() string {
	switch a {
	case PBEWithHMACSHA512AndAES_256:
		return "PBEWithHMACSHA512AndAES_256"
	case PBEWithHMACSM3AndSM4_GCM:
		return "PBEWithHMACSM3AndSM4_GCM"
	case PBEWithHMACSM3AndSM4_CBC:
		return "PBEWithHMACSM3AndSM4_CBC"
	default:
		return "Unknown"
	}
}

// DefaultIterations returns the recommended PBKDF2 iteration count for this algorithm
// (1,000 for AES, 10,000 for SM4 per GM/T 0091-2020).
func (a Algorithm) DefaultIterations() int {
	switch a {
	case PBEWithHMACSHA512AndAES_256:
		return 1000
	default:
		return 10000
	}
}

// ParseAlgorithm returns the Algorithm for the given name, or false if unrecognized.
func ParseAlgorithm(s string) (Algorithm, bool) {
	switch s {
	case "PBEWithHMACSHA512AndAES_256":
		return PBEWithHMACSHA512AndAES_256, true
	case "PBEWithHMACSM3AndSM4_GCM":
		return PBEWithHMACSM3AndSM4_GCM, true
	case "PBEWithHMACSM3AndSM4_CBC":
		return PBEWithHMACSM3AndSM4_CBC, true
	default:
		return 0, false
	}
}

// ValidAlgorithmNames returns all recognised algorithm name strings.
func ValidAlgorithmNames() []string {
	return []string{
		"PBEWithHMACSHA512AndAES_256",
		"PBEWithHMACSM3AndSM4_GCM",
		"PBEWithHMACSM3AndSM4_CBC",
	}
}
