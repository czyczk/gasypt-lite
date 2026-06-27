//go:build windows

package gasypt

import (
	"os/exec"
	"strings"
	"testing"
)

const rustCLI = `C:\Users\czycz\Source\Rust_Projects\rasypt_lite\target\release\rasypt-lite.exe`
const goCLI = `C:\Users\czycz\Source\Go_Projects\gasypt-lite\gasypt-lite.exe`

type algoSpec struct {
	name       string
	goAlgo     Algorithm
	rustAlgo   string
}

var allAlgos = []algoSpec{
	{"PBEWithHMACSHA512AndAES_256", PBEWithHMACSHA512AndAES_256, "PBEWithHMACSHA512AndAES_256"},
	{"PBEWithHMACSM3AndSM4_GCM", PBEWithHMACSM3AndSM4_GCM, "PBEWithHMACSM3AndSM4_GCM"},
	{"PBEWithHMACSM3AndSM4_CBC", PBEWithHMACSM3AndSM4_CBC, "PBEWithHMACSM3AndSM4_CBC"},
}

func runCLI(bin string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func TestCrossRoundTripGoEncryptRustDecrypt(t *testing.T) {
	password := "cross-test-password"
	plaintext := "Hello from Go → Rust cross test! 🔒"

	for _, algo := range allAlgos {
		t.Run(algo.name+"/go→rust", func(t *testing.T) {
			enc := EncryptWith(algo.goAlgo, password, plaintext)

			dec, err := runCLI(rustCLI, "decrypt", "-i", enc, "-p", password, "-a", algo.rustAlgo, "-q")
			if err != nil {
				t.Fatalf("Rust decrypt failed: %v (output: %q)", err, dec)
			}
			if dec != plaintext {
				t.Fatalf("round-trip mismatch: got %q, want %q", dec, plaintext)
			}
		})
	}
}

func TestCrossRoundTripRustEncryptGoDecrypt(t *testing.T) {
	password := "cross-test-password"
	plaintext := "Hello from Rust → Go cross test! 🔒"

	for _, algo := range allAlgos {
		t.Run(algo.name+"/rust→go", func(t *testing.T) {
			enc, err := runCLI(rustCLI, "encrypt", "-i", plaintext, "-p", password, "-a", algo.rustAlgo, "-q")
			if err != nil {
				t.Fatalf("Rust encrypt failed: %v (output: %q)", err, enc)
			}
			if enc == "" {
				t.Fatal("Rust encrypt produced empty output")
			}

			dec, err := DecryptWith(algo.goAlgo, password, enc)
			if err != nil {
				t.Fatalf("Go decrypt failed: %v", err)
			}
			if dec != plaintext {
				t.Fatalf("round-trip mismatch: got %q, want %q", dec, plaintext)
			}
		})
	}
}

func TestCrossRoundTripEncWrapper(t *testing.T) {
	password := "cross-test-password"
	plaintext := "ENC wrapper test"

	enc, err := runCLI(rustCLI, "encrypt", "-i", plaintext, "-p", password, "--wrap", "-q")
	if err != nil {
		t.Fatalf("Rust encrypt --wrap failed: %v (output: %q)", err, enc)
	}
	if !IsEncValue(enc) {
		t.Fatalf("Rust --wrap output is not ENC(...): %q", enc)
	}

	dec, err := DecryptEnc(enc, password)
	if err != nil {
		t.Fatalf("Go DecryptEnc failed: %v", err)
	}
	if dec != plaintext {
		t.Fatalf("ENC round-trip mismatch: got %q, want %q", dec, plaintext)
	}

	wrapped := WrapEnc(Encrypt(password, plaintext))
	dec, err = runCLI(rustCLI, "decrypt", "-i", wrapped, "-p", password, "-q")
	if err != nil {
		t.Fatalf("Rust decrypt ENC failed: %v (output: %q)", err, dec)
	}
	if dec != plaintext {
		t.Fatalf("ENC Go→Rust mismatch: got %q, want %q", dec, plaintext)
	}
}

func TestCrossRoundTripCustomIterations(t *testing.T) {
	password := "cross-iter-password"
	plaintext := "custom iteration test"

	for _, algo := range allAlgos {
		t.Run(algo.name+"/iter=5000", func(t *testing.T) {
			enc, err := runCLI(rustCLI, "encrypt", "-i", plaintext, "-p", password, "-a", algo.rustAlgo, "--iterations", "5000", "-q")
			if err != nil {
				t.Fatalf("Rust encrypt failed: %v (output: %q)", err, enc)
			}

			dec, err := DecryptWithIterations(algo.goAlgo, password, enc, 5000)
			if err != nil {
				t.Fatalf("Go decrypt with custom iterations failed: %v", err)
			}
			if dec != plaintext {
				t.Fatalf("custom iterations mismatch: got %q, want %q", dec, plaintext)
			}
		})
	}
}
