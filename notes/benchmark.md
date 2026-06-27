# Benchmark: gasypt-lite vs rasypt-lite vs nasypt-lite

Performance comparison between Go (`gasypt-lite`), Rust (`rasypt-lite`), and
.NET NativeAOT (`nasypt-lite`). All three implement the same wire format and
algorithms.

**Test environment:**
- Rust & .NET: Linux x86-64, Rust 1.92.0 release, .NET 10.0.108 NativeAOT
- Go: Windows 11 x86-64, Go 1.26 release

**Methodology:** 3 warm-up runs + 10 measured runs per data point. CLI timing
via `time.perf_counter` (Python, Linux) / Go `time.Since` (Windows), includes
full process launch + encrypt/decrypt. Library benchmarks via `cargo bench` /
`go test -bench` — crypto only, no I/O.

---

## Startup latency

Encrypt 16 B plaintext, default AES. Measures process-launch-to-exit time.

| Tool | Mean | Min | Max | vs Rust |
|---|---|---|---|---|
| `rasypt-lite` (Rust, Linux) | 2.1 ms | 1.3 ms | 4.2 ms | baseline |
| `rasypt-lite` (Rust, Win) | 7.8 ms | 7.2 ms | 9.4 ms | 3.7× (platform) |
| `nasypt-lite` (JIT, Linux) | 62.1 ms | 55.1 ms | 70.4 ms | 30× |
| `nasypt-lite` (AOT, Linux) | 6.1 ms | 3.9 ms | 11.4 ms | 2.9× |
| `gasypt-lite` (Go, Win) | **28.6 ms** | 27.0 ms | 32.7 ms | — |

Go's startup is dominated by runtime init (~20 ms) + GC bootstrap. NativeAOT
eliminates the CLR/JIT cost. Rust has the smallest runtime overhead.

---

## Encrypt throughput

### CLI — 1 KB plaintext (startup-dominated)

| Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|
| Rust (Linux) | 662 KB/s | 125 KB/s | 110 KB/s |
| .NET AOT (Linux) | 165 KB/s | 42 KB/s | 41 KB/s |
| Rust (Win) | 6.6 ms | 11.7 ms | 11.8 ms |
| Go (Win) | 29.7 ms | 35.0 ms | 35.1 ms |

At 1 KB, startup dominates all tools. Go's 28 ms baseline is visible.

### Library-level — 1 MB plaintext (crypto only)

| Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|
| Rust (Linux) | 594 MB/s | 94 MB/s | 96 MB/s |
| .NET AOT (Linux) | 146 MB/s | 42 MB/s | 43 MB/s |
| Go (Win) | **395 MB/s** | **82 MB/s** | **58 MB/s** |

At 1 MB, startup is negligible and throughput plateaus at raw crypto speed.

Rust's AES advantage comes from AES-NI in the `aes` crate. Go's `crypto/aes`
also uses AES-NI (395 vs 594 MB/s). For SM4, Go's `emmansun/gmsm` has amd64
assembly — 82 MB/s vs Rust's 94 MB/s for GCM, 58 vs 96 MB/s for CBC. .NET's
BouncyCastle SM4 is a managed implementation without hardware acceleration.

---

## Decrypt throughput (1 MB, library-level)

| Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|
| Rust (Linux) | 513 MB/s | 110 MB/s | 111 MB/s |
| .NET AOT (Linux) | 142 MB/s | 48 MB/s | 46 MB/s |
| Go (Win) | **368 MB/s** | **93 MB/s** | **95 MB/s** |

Decrypt follows the same pattern. SM4-GCM decrypt includes a GCM tag
verification pass; the difference vs encrypt is within measurement noise.

---

## PBKDF2 iteration scaling

Encrypt 1 KB plaintext, default AES. Higher iteration counts stress key
derivation independently of the cipher.

| Iterations | Rust (Linux) | .NET AOT | Go (Win) | Rust (Win) | Winner |
|---|---|---|---|---|---|
| 1,000 | 2.3 ms | 6.7 ms | 29.4 ms | 6.9 ms | Rust |
| 10,000 | 7.7 ms | 11.2 ms | 32.9 ms | 10.3 ms | Rust (1.5× vs AOT) |
| 100,000 | 56.5 ms | **52.2 ms** | 66.1 ms | 42.6 ms | .NET AOT (by 8% vs Linux) |

At 100,000 iterations, .NET AOT overtakes Rust (Linux). .NET's
`Rfc2898DeriveBytes` with SHA-512 is SIMD-accelerated, while Rust's
`pbkdf2_hmac::<Sha512>` does not use SHA-512-specific SIMD. For Go, the HMAC
overhead is constant (~28 ms startup); PBKDF2 itself scales linearly.

---

## Binary size

| Build | Size | Self-contained |
|---|---|---|
| Rust release | 650 KB | Yes |
| .NET NativeAOT | 3.0 MB | Yes |
| .NET JIT (framework-dep) | 5.0 MB | No (needs .NET 10) |
| .NET JIT (self-contained) | ~65 MB | Yes |
| Go build | 4.8 MB | Yes |

Go binaries embed the runtime, GC, and goroutine scheduler. No CGO, no
external runtime required. Comparable to NativeAOT in the "single binary,
no runtime" category, though ~60% larger.

---

## Summary

- **Startup:** Go is the slowest (28 ms) due to runtime init. Rust (2–8 ms) and
  NativeAOT (6 ms) lead. For interactive CLI use, all are acceptable.
- **AES crypto:** Go (395 MB/s) is competitive with Rust (594 MB/s) — both use
  AES-NI. Go's `crypto/aes` has a ~1.5× overhead vs Rust's `aes` crate.
- **SM4 crypto:** Go (58–82 MB/s) is close to Rust (94–96 MB/s) — both use
  native/assembly SM4. .NET's managed BouncyCastle trails at ~42 MB/s.
- **PBKDF2 at scale:** .NET AOT pulls ahead at 100k+ iterations (.NET SIMD
  SHA-512). Rust and Go are similar.
- **For CLI:** Rust is fastest for cold-start scripts. NativeAOT bridges
  the managed-code gap. Go is viable for interactive use.
- **For library:** All three are production-viable. Rust leads AES, Go and
  Rust are close on SM4, .NET trails on SM4 but leads at high-iteration PBKDF2.
