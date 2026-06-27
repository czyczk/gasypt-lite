//go:build windows

package gasypt

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSourceGenEndToEnd(t *testing.T) {
	dir := t.TempDir()

	goMod := `module integration

go 1.24

require github.com/czyczk/gasypt-lite v0.0.0

replace github.com/czyczk/gasypt-lite => ` + projectRoot() + `
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}

	configGo := `package config

type AppConfig struct {
	DBPassword string  ` + "`gasypt:\"encrypted\"`" + `
	APIKey     string  ` + "`gasypt:\"encrypted,algorithm=PBEWithHMACSM3AndSM4_GCM\"`" + `
	LicenceKey *string ` + "`gasypt:\"encrypted,algorithm=PBEWithHMACSM3AndSM4_CBC\"`" + `
	AppName    string
	DebugMode  string  ` + "`gasypt:\"encrypted\"`" + `
}
`
	configPath := filepath.Join(configDir, "config.go")
	if err := os.WriteFile(configPath, []byte(configGo), 0644); err != nil {
		t.Fatal(err)
	}

	genBin := filepath.Join(projectRoot(), "build", "gasypt-gen.exe")
	if _, err := os.Stat(genBin); err != nil {
		t.Fatalf("gasypt-gen binary not found at %s — run `just build` first", genBin)
	}
	out, err := exec.Command(genBin, configPath).CombinedOutput()
	if err != nil {
		t.Fatalf("gasypt-gen failed: %v\n%s", err, out)
	}

	if _, err := os.Stat(filepath.Join(configDir, "config_gasypt.go")); err != nil {
		t.Fatalf("generated file not found: %v", err)
	}

	mainGo := `package main

import (
	"fmt"
	"os"

	"integration/config"
	"github.com/czyczk/gasypt-lite"
)

func main() {
	masterPass := "master-password-123"
	dbSecret := "postgres://localhost:5432/mydb"
	apiSecret := "sk-1234567890abcdef"
	licSecret := "LIC-ABCD-EFGH-IJKL"
	licVal := licSecret

	cfg := &config.AppConfig{
		AppName:    "MyApp",
		DBPassword: gasypt.WrapEnc(gasypt.Encrypt(masterPass, dbSecret)),
		APIKey:     gasypt.WrapEnc(gasypt.EncryptWith(gasypt.PBEWithHMACSM3AndSM4_GCM, masterPass, apiSecret)),
		LicenceKey: &licVal,
		DebugMode:  "true",
	}
	*cfg.LicenceKey = gasypt.WrapEnc(gasypt.EncryptWith(gasypt.PBEWithHMACSM3AndSM4_CBC, masterPass, licSecret))

	if err := cfg.DecryptEncFields(masterPass); err != nil {
		fmt.Fprintf(os.Stderr, "DecryptEncFields failed: %v\n", err)
		os.Exit(1)
	}

	if cfg.DBPassword != dbSecret {
		fmt.Fprintf(os.Stderr, "DBPassword: got %q, want %q\n", cfg.DBPassword, dbSecret)
		os.Exit(2)
	}
	if cfg.APIKey != apiSecret {
		fmt.Fprintf(os.Stderr, "APIKey: got %q, want %q\n", cfg.APIKey, apiSecret)
		os.Exit(3)
	}
	if *cfg.LicenceKey != licSecret {
		fmt.Fprintf(os.Stderr, "LicenceKey: got %q, want %q\n", *cfg.LicenceKey, licSecret)
		os.Exit(4)
	}
	if cfg.AppName != "MyApp" {
		fmt.Fprintf(os.Stderr, "AppName was modified: %q\n", cfg.AppName)
		os.Exit(5)
	}
	if cfg.DebugMode != "true" {
		fmt.Fprintf(os.Stderr, "DebugMode was modified: %q\n", cfg.DebugMode)
		os.Exit(6)
	}

	cfg2 := &config.AppConfig{
		DBPassword: gasypt.WrapEnc(gasypt.Encrypt(masterPass, dbSecret)),
	}
	if err := cfg2.DecryptEncFields("wrong-password"); err == nil {
		fmt.Fprintln(os.Stderr, "expected error with wrong password")
		os.Exit(7)
	}

	cfg3 := &config.AppConfig{
		DBPassword: gasypt.WrapEnc(gasypt.EncryptWith(gasypt.PBEWithHMACSM3AndSM4_CBC, masterPass, dbSecret)),
	}
	if err := cfg3.DecryptEncFieldsWith(gasypt.PBEWithHMACSM3AndSM4_CBC, masterPass); err != nil {
		fmt.Fprintf(os.Stderr, "DecryptEncFieldsWith failed: %v\n", err)
		os.Exit(8)
	}
	if cfg3.DBPassword != dbSecret {
		fmt.Fprintf(os.Stderr, "DecryptEncFieldsWith: got %q, want %q\n", cfg3.DBPassword, dbSecret)
		os.Exit(9)
	}

	cfg.ClearSensitiveFields()
	if cfg.DBPassword != "" {
		fmt.Fprintf(os.Stderr, "DBPassword not cleared: %q\n", cfg.DBPassword)
		os.Exit(10)
	}
	if *cfg.LicenceKey != "" {
		fmt.Fprintf(os.Stderr, "LicenceKey not cleared: %q\n", *cfg.LicenceKey)
		os.Exit(11)
	}
	if cfg.AppName != "MyApp" {
		fmt.Fprintf(os.Stderr, "AppName cleared incorrectly: %q\n", cfg.AppName)
		os.Exit(12)
	}

	fmt.Println("ALL OK")
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy failed: %v\n%s", err, out)
	}

	cmd = exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("integration test failed: %v\n%s", err, out)
	}
	t.Logf("source-gen integration: %s", out)
}

func projectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("cannot find project root")
		}
		dir = parent
	}
}
