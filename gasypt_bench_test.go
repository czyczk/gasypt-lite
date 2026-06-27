package gasypt

import (
	"strings"
	"testing"
)

func BenchmarkEncryptAES_1KB(b *testing.B)   { benchEncrypt(b, 1024, PBEWithHMACSHA512AndAES_256) }
func BenchmarkEncryptAES_100KB(b *testing.B) { benchEncrypt(b, 100*1024, PBEWithHMACSHA512AndAES_256) }
func BenchmarkEncryptAES_1MB(b *testing.B)   { benchEncrypt(b, 1024*1024, PBEWithHMACSHA512AndAES_256) }

func BenchmarkEncryptSM4GCM_1KB(b *testing.B)   { benchEncrypt(b, 1024, PBEWithHMACSM3AndSM4_GCM) }
func BenchmarkEncryptSM4GCM_100KB(b *testing.B) { benchEncrypt(b, 100*1024, PBEWithHMACSM3AndSM4_GCM) }
func BenchmarkEncryptSM4GCM_1MB(b *testing.B)   { benchEncrypt(b, 1024*1024, PBEWithHMACSM3AndSM4_GCM) }

func BenchmarkEncryptSM4CBC_1KB(b *testing.B)   { benchEncrypt(b, 1024, PBEWithHMACSM3AndSM4_CBC) }
func BenchmarkEncryptSM4CBC_100KB(b *testing.B) { benchEncrypt(b, 100*1024, PBEWithHMACSM3AndSM4_CBC) }
func BenchmarkEncryptSM4CBC_1MB(b *testing.B)   { benchEncrypt(b, 1024*1024, PBEWithHMACSM3AndSM4_CBC) }

func BenchmarkDecryptAES_1MB(b *testing.B)   { benchDecrypt(b, 1024*1024, PBEWithHMACSHA512AndAES_256) }
func BenchmarkDecryptSM4GCM_1MB(b *testing.B) { benchDecrypt(b, 1024*1024, PBEWithHMACSM3AndSM4_GCM) }
func BenchmarkDecryptSM4CBC_1MB(b *testing.B) { benchDecrypt(b, 1024*1024, PBEWithHMACSM3AndSM4_CBC) }

func benchEncrypt(b *testing.B, size int, algo Algorithm) {
	pt := strings.Repeat("X", size)
	pass := "bench-pass"
	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		EncryptWith(algo, pass, pt)
	}
}

func benchDecrypt(b *testing.B, size int, algo Algorithm) {
	pt := strings.Repeat("X", size)
	pass := "bench-pass"
	ct := EncryptWith(algo, pass, pt)
	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		DecryptWith(algo, pass, ct)
	}
}
