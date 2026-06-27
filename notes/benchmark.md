# Benchmark: gasypt-lite vs rasypt-lite vs nasypt-lite

Performance comparison between Go (`gasypt-lite`), Rust (`rasypt-lite`), and
.NET NativeAOT (`nasypt-lite`). All three implement the same wire format and
algorithms.

**Test environment:** Linux x86-64
- Rust: 1.92.0 release
- .NET: 10.0.108 NativeAOT
- Go: 1.26 release

**Methodology:** 3 warm-up runs + 10 measured runs per data point. CLI timing
via `time.perf_counter` (Python), includes full process launch + encrypt/decrypt.
Library benchmarks via `cargo bench` / `go test -bench` — crypto only, no I/O.

---

## Startup latency

Encrypt 16 B plaintext, default AES. Measures process-launch-to-exit time.

| Tool | Mean | Min | Max | vs Rust |
|---|---|---|---|---|
| `rasypt-lite` (Rust) | 2.1 ms | 1.3 ms | 4.2 ms | baseline |
| `nasypt-lite` (JIT) | 62.1 ms | 55.1 ms | 70.4 ms | 30× |
| `nasypt-lite` (AOT) | 6.1 ms | 3.9 ms | 11.4 ms | 2.9× |
| `gasypt-lite` (Go) | **3.3 ms** | 3.1 ms | 3.7 ms | 1.6× |

On Linux, Go startup is 3.3 ms — faster than NativeAOT (6.1 ms) and close to
Rust (2.1 ms). The Go runtime init overhead is minimal on Linux.

---

## Encrypt throughput

### CLI — 1 KB plaintext (startup-dominated)

| Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|
| rasypt-lite (Rust) | 662 KB/s | 125 KB/s | 110 KB/s |
| nasypt-lite (AOT) | 165 KB/s | 42 KB/s | 41 KB/s |
| gasypt-lite (Go) | 284 KB/s | 88 KB/s | 88 KB/s |

At 1 KB, startup dominates all tools.

### Library-level — 1 MB plaintext (crypto only)

| Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|
| rasypt-lite (Rust) | 594 MB/s | 94 MB/s | 96 MB/s |
| nasypt-lite (AOT) | 146 MB/s | 42 MB/s | 43 MB/s |
| gasypt-lite (Go) | **147 MB/s** | **58 MB/s** | **45 MB/s** |

At 1 MB, startup is negligible and throughput plateaus at raw crypto speed.

Rust's AES advantage comes from AES-NI in the `aes` crate. Go's `crypto/aes`
also uses AES-NI. For SM4, Go's `emmansun/gmsm` has amd64 assembly —
58 MB/s vs Rust's 94 MB/s for GCM, 45 vs 96 MB/s for CBC. .NET's
BouncyCastle SM4 is a managed implementation without hardware acceleration.

---

## Decrypt throughput (1 MB, library-level)

| Tool | AES-256-CBC | SM4-GCM | SM4-CBC |
|---|---|---|---|
| rasypt-lite (Rust) | 513 MB/s | 110 MB/s | 111 MB/s |
| nasypt-lite (AOT) | 142 MB/s | 48 MB/s | 46 MB/s |
| gasypt-lite (Go) | **283 MB/s** | **67 MB/s** | **74 MB/s** |

Go AES decrypt (283 MB/s) is notably faster than encrypt (147 MB/s), likely
due to differences in the Go `crypto/aes` CBC encrypt vs decrypt codepath.
SM4 GCM decrypt includes a tag verification pass; encrypt/decrypt asymmetry
is smaller for SM4.

---

## PBKDF2 iteration scaling

Encrypt 1 KB plaintext, default AES. Higher iteration counts stress key
derivation independently of the cipher.

| Iterations | rasypt-lite (Rust) | nasypt-lite (AOT) | gasypt-lite (Go) | Winner |
|---|---|---|---|---|---|
| 1,000 | 2.3 ms | 6.7 ms | 3.1 ms | Rust (1.3× vs Go) |
| 10,000 | 7.7 ms | 11.2 ms | 7.8 ms | Rust (1.01× vs Go) |
| 100,000 | 56.5 ms | 52.2 ms | **51.1 ms** | Go (2% vs AOT) |

Rust leads at low iteration counts with the leanest PBKDF2 implementation. At
100,000 iterations, Go edges ahead of .NET AOT by a narrow margin. All three
scale linearly with iteration count; the differences come from SHA-512/SM3
HMAC implementation quality.

---

## Binary size

| Build | Size | Self-contained |
|---|---|---|
| rasypt-lite release | 650 KB | Yes |
| nasypt-lite NativeAOT | 3.0 MB | Yes |
| nasypt-lite JIT (framework-dep) | 5.0 MB | No (needs .NET 10) |
| nasypt-lite JIT (self-contained) | ~65 MB | Yes |
| gasypt-lite build | 4.7 MB | Yes |

Go binaries embed the runtime, GC, and goroutine scheduler. No CGO, no
external runtime required. Comparable to NativeAOT in the "single binary,
no runtime" category, though ~60% larger.

---

## Summary

- **Startup:** Go (3.3 ms) is competitive with Rust (2.1 ms) and faster than
  NativeAOT (6.1 ms). On Linux, Go's runtime init overhead is minimal.
- **AES crypto:** Rust leads at 594 MB/s. Go (147 MB/s) and .NET AOT (146 MB/s)
  are comparable. Go's `crypto/aes` uses AES-NI but has overhead vs Rust's `aes`
  crate.
- **SM4 crypto:** Rust leads at ~95 MB/s. Go (45–58 MB/s) uses `emmansun/gmsm`
  amd64 assembly. .NET's managed BouncyCastle trails at ~42 MB/s.
- **PBKDF2 at scale:** Rust leads at low iterations. All three converge at 100k,
  with Go (51.1 ms) narrowly ahead of .NET AOT (52.2 ms) and Rust (56.5 ms).
- **For CLI:** All three are acceptable for interactive use. Rust is fastest for
  cold-start scripts, Go and NativeAOT are close behind.
- **For library:** All three are production-viable. Rust leads overall. Go is
  competitive with NativeAOT on crypto, and leads on PBKDF2.
