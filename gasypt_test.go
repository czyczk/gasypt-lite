package gasypt

import (
	"errors"
	"strings"
	"testing"
)

func TestEncryptDecryptAES(t *testing.T) {
	password := "test-password"
	plaintext := "hello world"

	enc := Encrypt(password, plaintext)
	dec, err := Decrypt(password, enc)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if dec != plaintext {
		t.Fatalf("round-trip failed: got %q, want %q", dec, plaintext)
	}
}

func TestEncryptNonDeterministic(t *testing.T) {
	password := "test-password"
	plaintext := "hello world"

	enc1 := Encrypt(password, plaintext)
	enc2 := Encrypt(password, plaintext)
	if enc1 == enc2 {
		t.Fatal("two encryptions produced identical output (salt reuse?)")
	}
}

func TestDecryptWrongPasswordAES(t *testing.T) {
	enc := Encrypt("correct", "secret")
	_, err := Decrypt("wrong", enc)
	if err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestDecryptGarbledInput(t *testing.T) {
	_, err := Decrypt("password", "not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error with garbled input")
	}
}

func TestDecryptTooShort(t *testing.T) {
	_, err := Decrypt("password", "YQ==") // base64 of "a" (1 byte)
	if !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("expected ErrCiphertextTooShort, got %v", err)
	}
}

func TestSM4GCMRoundTrip(t *testing.T) {
	tests := []string{
		"hello world",
		"",
		strings.Repeat("x", 10000),
		"hello 世界 🔒",
	}
	password := "sm4-password"

	for _, plaintext := range tests {
		enc := EncryptWith(PBEWithHMACSM3AndSM4_GCM, password, plaintext)
		dec, err := DecryptWith(PBEWithHMACSM3AndSM4_GCM, password, enc)
		if err != nil {
			t.Fatalf("SM4-GCM decrypt failed for plaintext len=%d: %v", len(plaintext), err)
		}
		if dec != plaintext {
			t.Fatalf("SM4-GCM round-trip failed: got %q, want %q", dec, plaintext)
		}
	}
}

func TestSM4CBCRoundTrip(t *testing.T) {
	tests := []string{
		"hello world",
		"",
		"hello 世界 🔒",
	}
	password := "sm4-password"

	for _, plaintext := range tests {
		enc := EncryptWith(PBEWithHMACSM3AndSM4_CBC, password, plaintext)
		dec, err := DecryptWith(PBEWithHMACSM3AndSM4_CBC, password, enc)
		if err != nil {
			t.Fatalf("SM4-CBC decrypt failed for plaintext len=%d: %v", len(plaintext), err)
		}
		if dec != plaintext {
			t.Fatalf("SM4-CBC round-trip failed: got %q, want %q", dec, plaintext)
		}
	}
}

func TestSM4GCMWrongPassword(t *testing.T) {
	enc := EncryptWith(PBEWithHMACSM3AndSM4_GCM, "correct", "secret")
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_GCM, "wrong", enc)
	if err == nil {
		t.Fatal("SM4-GCM: expected error with wrong password")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("SM4-GCM: expected ErrDecryptionFailed, got %v", err)
	}
}

func TestSM4CBCWrongPassword(t *testing.T) {
	enc := EncryptWith(PBEWithHMACSM3AndSM4_CBC, "correct", "secret")
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_CBC, "wrong", enc)
	if err == nil {
		t.Fatal("SM4-CBC: expected error with wrong password")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("SM4-CBC: expected ErrDecryptionFailed, got %v", err)
	}
}

func TestSM4GCMTampered(t *testing.T) {
	enc := EncryptWith(PBEWithHMACSM3AndSM4_GCM, "password", "secret")
	data, _ := decodeBase64(enc)
	data[len(data)/2] ^= 0xFF
	tampered := encodeBase64(data)
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_GCM, "password", tampered)
	if err == nil {
		t.Fatal("SM4-GCM: expected error with tampered ciphertext")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("SM4-GCM: expected ErrDecryptionFailed, got %v", err)
	}
}

func TestSM4CBCTampered(t *testing.T) {
	enc := EncryptWith(PBEWithHMACSM3AndSM4_CBC, "password", "secret")
	data, _ := decodeBase64(enc)
	data[len(data)/2] ^= 0xFF
	tampered := encodeBase64(data)
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_CBC, "password", tampered)
	if err == nil {
		t.Fatal("SM4-CBC: expected error with tampered ciphertext")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("SM4-CBC: expected ErrDecryptionFailed, got %v", err)
	}
}

func TestCrossAlgorithmRejection(t *testing.T) {
	aesEnc := Encrypt("password", "secret")
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_GCM, "password", aesEnc)
	if err == nil {
		t.Fatal("SM4-GCM should reject AES ciphertext")
	}

	gcmEnc := EncryptWith(PBEWithHMACSM3AndSM4_GCM, "password", "secret")
	_, err = DecryptWith(PBEWithHMACSM3AndSM4_CBC, "password", gcmEnc)
	if err == nil {
		t.Fatal("SM4-CBC should reject SM4-GCM ciphertext")
	}
}

func TestUnicodePassword(t *testing.T) {
	password := "パスワード🔒"
	plaintext := "secret data"
	algorithms := []Algorithm{
		PBEWithHMACSHA512AndAES_256,
		PBEWithHMACSM3AndSM4_GCM,
		PBEWithHMACSM3AndSM4_CBC,
	}

	for _, algo := range algorithms {
		enc := EncryptWith(algo, password, plaintext)
		dec, err := DecryptWith(algo, password, enc)
		if err != nil {
			t.Fatalf("%s: unicode password decrypt failed: %v", algo, err)
		}
		if dec != plaintext {
			t.Fatalf("%s: unicode password round-trip failed", algo)
		}
	}
}

func TestCustomIterations(t *testing.T) {
	password := "password"
	plaintext := "secret"

	enc := EncryptWithIterations(PBEWithHMACSHA512AndAES_256, password, plaintext, 10000)
	dec, err := DecryptWithIterations(PBEWithHMACSHA512AndAES_256, password, enc, 10000)
	if err != nil {
		t.Fatalf("custom iterations decrypt failed: %v", err)
	}
	if dec != plaintext {
		t.Fatal("custom iterations round-trip failed")
	}
}

func TestIterationMismatch(t *testing.T) {
	password := "password"
	plaintext := "secret"

	enc := EncryptWithIterations(PBEWithHMACSHA512AndAES_256, password, plaintext, 5000)
	_, err := DecryptWithIterations(PBEWithHMACSHA512AndAES_256, password, enc, 6000)
	if err == nil {
		t.Fatal("expected error with iteration mismatch")
	}
}

func TestEncRoundTrip(t *testing.T) {
	password := "password"
	plaintext := "secret"

	enc := WrapEnc(Encrypt(password, plaintext))
	dec, err := DecryptEnc(enc, password)
	if err != nil {
		t.Fatalf("DecryptEnc failed: %v", err)
	}
	if dec != plaintext {
		t.Fatalf("ENC round-trip failed: got %q, want %q", dec, plaintext)
	}
}

func TestIsEncValue(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ENC(xxx)", true},
		{"ENC()", true},
		{"ENC(xxx", false},
		{"xxx)", false},
		{"enc(xxx)", false},
		{"", false},
		{"not-enc", false},
	}

	for _, tt := range tests {
		got := IsEncValue(tt.input)
		if got != tt.want {
			t.Errorf("IsEncValue(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDecryptEncNotEncValue(t *testing.T) {
	_, err := DecryptEnc("not-enc", "password")
	if !errors.Is(err, ErrNotEncValue) {
		t.Fatalf("expected ErrNotEncValue, got %v", err)
	}
}

func TestClearString(t *testing.T) {
	s := "sensitive-data"
	ClearString(&s)
	if s != "" {
		t.Fatal("ClearString did not clear the string")
	}
}

func TestSM4GCMNonDeterministic(t *testing.T) {
	e1 := EncryptWith(PBEWithHMACSM3AndSM4_GCM, "password", "data")
	e2 := EncryptWith(PBEWithHMACSM3AndSM4_GCM, "password", "data")
	if e1 == e2 {
		t.Fatal("SM4-GCM: two encryptions produced identical output")
	}
}

func TestSM4CBCNonDeterministic(t *testing.T) {
	e1 := EncryptWith(PBEWithHMACSM3AndSM4_CBC, "password", "data")
	e2 := EncryptWith(PBEWithHMACSM3AndSM4_CBC, "password", "data")
	if e1 == e2 {
		t.Fatal("SM4-CBC: two encryptions produced identical output")
	}
}

func TestSM4GCMRejectsTooShort(t *testing.T) {
	tooShort := encodeBase64(make([]byte, 16+12)) // salt + nonce only
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_GCM, "password", tooShort)
	if !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("SM4-GCM: expected ErrCiphertextTooShort, got %v", err)
	}
}

func TestSM4CBCRejectsTooShort(t *testing.T) {
	tooShort := encodeBase64(make([]byte, 16+16)) // salt + iv only
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_CBC, "password", tooShort)
	if !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("SM4-CBC: expected ErrCiphertextTooShort, got %v", err)
	}
}

func TestSM4GCMRejectsCBCCiphertext(t *testing.T) {
	cbcEnc := EncryptWith(PBEWithHMACSM3AndSM4_CBC, "password", "data")
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_GCM, "password", cbcEnc)
	if err == nil {
		t.Fatal("SM4-GCM should reject SM4-CBC ciphertext")
	}
}

func TestSM4CBCRejectsGCMCiphertext(t *testing.T) {
	gcmEnc := EncryptWith(PBEWithHMACSM3AndSM4_GCM, "password", "data")
	_, err := DecryptWith(PBEWithHMACSM3AndSM4_CBC, "password", gcmEnc)
	if err == nil {
		t.Fatal("SM4-CBC should reject SM4-GCM ciphertext")
	}
}

func TestCustomIterationsAllAlgorithms(t *testing.T) {
	algorithms := []Algorithm{
		PBEWithHMACSHA512AndAES_256,
		PBEWithHMACSM3AndSM4_GCM,
		PBEWithHMACSM3AndSM4_CBC,
	}
	password := "password"
	plaintext := "secret"

	for _, algo := range algorithms {
		enc := EncryptWithIterations(algo, password, plaintext, 5000)
		dec, err := DecryptWithIterations(algo, password, enc, 5000)
		if err != nil {
			t.Fatalf("%s: custom iterations decrypt failed: %v", algo, err)
		}
		if dec != plaintext {
			t.Fatalf("%s: custom iterations round-trip failed", algo)
		}
	}
}

func TestIsEncValueWhitespace(t *testing.T) {
	if !IsEncValue("  ENC(foo)  ") {
		t.Error("IsEncValue should tolerate surrounding whitespace")
	}
	if !IsEncValue("\tENC(bar)\n") {
		t.Error("IsEncValue should tolerate tabs and newlines")
	}
}

func TestErrorMessages(t *testing.T) {
	if ErrCiphertextTooShort.Error() == "" {
		t.Error("ErrCiphertextTooShort has no message")
	}
	if ErrNotEncValue.Error() == "" {
		t.Error("ErrNotEncValue has no message")
	}
	if ErrDecryptionFailed.Error() == "" {
		t.Error("ErrDecryptionFailed has no message")
	}
}
