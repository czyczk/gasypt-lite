package gasypt_test

import (
	"testing"

	"github.com/czyczk/gasypt-lite"
)

type TestConfig struct {
	Username  string `gasypt:"encrypted"`
	Password  string `gasypt:"encrypted,algorithm=PBEWithHMACSM3AndSM4_GCM"`
	PlainText string
	OptSecret *string `gasypt:"encrypted"`
}

func TestDecryptFields(t *testing.T) {
	password := "test-password"
	plainUser := "admin"
	plainPass := "super-secret"
	plainOpt := "optional-secret"

	encUser := gasypt.WrapEnc(gasypt.Encrypt(password, plainUser))
	encPass := gasypt.WrapEnc(gasypt.EncryptWith(gasypt.PBEWithHMACSM3AndSM4_GCM, password, plainPass))
	encOpt := gasypt.WrapEnc(gasypt.Encrypt(password, plainOpt))

	cfg := &TestConfig{
		Username:  encUser,
		Password:  encPass,
		PlainText: "plain-value",
		OptSecret: &encOpt,
	}

	if err := gasypt.DecryptFields(cfg, password); err != nil {
		t.Fatalf("DecryptFields failed: %v", err)
	}

	if cfg.Username != plainUser {
		t.Errorf("Username: got %q, want %q", cfg.Username, plainUser)
	}
	if cfg.Password != plainPass {
		t.Errorf("Password: got %q, want %q", cfg.Password, plainPass)
	}
	if cfg.PlainText != "plain-value" {
		t.Errorf("PlainText: got %q, want %q", cfg.PlainText, "plain-value")
	}
	if cfg.OptSecret == nil || *cfg.OptSecret != plainOpt {
		t.Errorf("OptSecret: got %v, want %q", cfg.OptSecret, plainOpt)
	}
}

func TestDecryptFieldsNonEnc(t *testing.T) {
	cfg := &TestConfig{
		Username: "already-plain",
		Password: "already-plain",
	}

	if err := gasypt.DecryptFields(cfg, "password"); err != nil {
		t.Fatalf("DecryptFields failed: %v", err)
	}

	if cfg.Username != "already-plain" {
		t.Error("non-enc field was modified")
	}
	if cfg.Password != "already-plain" {
		t.Error("non-enc field was modified")
	}
}

func TestDecryptFieldsWrongPassword(t *testing.T) {
	encUser := gasypt.WrapEnc(gasypt.Encrypt("correct", "admin"))
	cfg := &TestConfig{Username: encUser}

	err := gasypt.DecryptFields(cfg, "wrong")
	if err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestDecryptFieldsNilPointer(t *testing.T) {
	cfg := &TestConfig{
		Username:  "plain",
		Password:  "plain",
		OptSecret: nil,
	}

	if err := gasypt.DecryptFields(cfg, "password"); err != nil {
		t.Fatalf("DecryptFields with nil pointer field failed: %v", err)
	}
}

func TestClearSensitiveFields(t *testing.T) {
	optVal := "sensitive"
	cfg := &TestConfig{
		Username:  "user",
		Password:  "pass",
		PlainText: "plain",
		OptSecret: &optVal,
	}

	gasypt.ClearSensitiveFields(cfg)

	if cfg.Username != "" {
		t.Errorf("Username not cleared: %q", cfg.Username)
	}
	if cfg.Password != "" {
		t.Errorf("Password not cleared: %q", cfg.Password)
	}
	if cfg.PlainText != "plain" {
		t.Error("untagged PlainText was cleared incorrectly")
	}
	if cfg.OptSecret == nil || *cfg.OptSecret != "" {
		t.Error("OptSecret not cleared")
	}
}

func TestDecryptFieldsWithAlgorithm(t *testing.T) {
	password := "test-password"
	plainUser := "admin"

	encUser := gasypt.WrapEnc(gasypt.EncryptWith(gasypt.PBEWithHMACSM3AndSM4_CBC, password, plainUser))

	cfg := &TestConfig{Username: encUser}

	// Override with SM4-CBC
	if err := gasypt.DecryptFieldsWith(cfg, gasypt.PBEWithHMACSM3AndSM4_CBC, password); err != nil {
		t.Fatalf("DecryptFieldsWith failed: %v", err)
	}

	if cfg.Username != plainUser {
		t.Errorf("Username: got %q, want %q", cfg.Username, plainUser)
	}
}
