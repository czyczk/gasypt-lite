# gasypt-lite

Password-based encryption library and CLI for Go, supporting three algorithms:

| Algorithm | Default | Cipher | Auth | Standard |
|---|---|---|---|---|
| `PBEWithHMACSHA512AndAES_256` | yes | AES-256-CBC | — | Jasypt 3.x |
| `PBEWithHMACSM3AndSM4_GCM` | — | SM4-GCM | AEAD + HMAC-SM3 key commit | GM/T 0091† |
| `PBEWithHMACSM3AndSM4_CBC` | — | SM4-CBC | Encrypt-then-HMAC-SM3 | GM/T 0091-2020 |

† GCM mode is a modern extension to the PBES2 framework.

Zero CGO. Go 1.24+. SM3/SM4 via [emmansun/gmsm](https://github.com/emmansun/gmsm) (pure Go + asm).

---

## Library

```
go get github.com/czyczk/gasypt-lite
```

```go
import "github.com/czyczk/gasypt-lite"

// AES-256-CBC (default, Jasypt-compatible)
ct := gasypt.Encrypt("password", "hello world")
pt, _ := gasypt.Decrypt("password", ct)

// SM4-GCM (authenticated encryption)
ct := gasypt.EncryptWith(gasypt.PBEWithHMACSM3AndSM4_GCM, "password", "data")

// Custom iterations
ct := gasypt.EncryptWithIterations(gasypt.PBEWithHMACSHA512AndAES_256, "password", "data", 600_000)
```

### Algorithm defaults

| Algorithm | Iterations | Key size |
|---|---|---|
| `PBEWithHMACSHA512AndAES_256` | 1,000 | 256-bit |
| `PBEWithHMACSM3AndSM4_GCM` | 10,000 | 128-bit |
| `PBEWithHMACSM3AndSM4_CBC` | 10,000 | 128-bit |

### ENC(…) wrapper (Jasypt / Spring Boot interop)

```go
if gasypt.IsEncValue("ENC(base64...)") {
    plain, _ := gasypt.DecryptEnc("ENC(base64...)", "password")
}
wrapped := gasypt.WrapEnc(ct) // → "ENC(base64...)"
```

### Struct field decryption

Tag fields with `gasypt:"encrypted"` — zero code generation needed:

```go
type Config struct {
    Password string  `gasypt:"encrypted"`
    ApiKey   string  `gasypt:"encrypted,algorithm=PBEWithHMACSM3AndSM4_GCM"`
    Token    *string `gasypt:"encrypted"`
}

cfg := &Config{Password: gasypt.WrapEnc(encryptedValue), ...}
gasypt.DecryptFields(cfg, "master-password")
defer gasypt.ClearSensitiveFields(cfg)
```

`DecryptFields` respects per-field `algorithm` tags. Override with `DecryptFieldsWith` to force a single algorithm for all fields.

Supported types: `string` and `*string`. Untagged fields are ignored. Non-`ENC(…)` values on tagged fields are silently skipped.

---

## Code generation

For compile-time dispatch (no reflection), use `gasypt-gen`:

```
go install github.com/czyczk/gasypt-lite/cmd/gasypt-gen@latest
```

```go
type Config struct {
    Password string `gasypt:"encrypted"`
    ApiKey   string `gasypt:"encrypted,algorithm=PBEWithHMACSM3AndSM4_GCM"`
}
```

```sh
gasypt-gen config.go  # → config_gasypt.go
```

The generated file provides the same `DecryptEncFields`, `DecryptEncFieldsWith`, and `ClearSensitiveFields` methods as compile-time functions. No implicit `Drop` — Go has no destructors — so call `ClearSensitiveFields` explicitly (or `defer` it).

---

## CLI

```
go install github.com/czyczk/gasypt-lite/cmd/cli@latest
```

```sh
# AES-256-CBC (default, Jasypt-compatible)
gasypt-lite encrypt -i "top secret" -p "mypassword"
gasypt-lite decrypt -i "base64..." -p "mypassword"

# SM4-GCM (authenticated encryption)
gasypt-lite encrypt -i "hello" -p "mypass" -a PBEWithHMACSM3AndSM4_GCM
gasypt-lite decrypt -i "base64..." -p "mypass" -a PBEWithHMACSM3AndSM4_GCM

# Custom iterations
gasypt-lite encrypt -i "secret" -p "pass" --iterations 600000

# ENC(…) wrapping (AES only)
gasypt-lite encrypt -i "secret" -p "mypass" --wrap
# → ENC(base64...)
```

| Flag | Short | Description |
|---|---|---|
| `--algorithm` | `-a` | Algorithm (default: `PBEWithHMACSHA512AndAES_256`) |
| `--iterations` | — | Override PBKDF2 iteration count |
| `--wrap` | — | Wrap output in `ENC(…)` (AES only) |
| `--quiet` | `-q` | Silence password-length warnings |

Valid algorithms: `PBEWithHMACSHA512AndAES_256`, `PBEWithHMACSM3AndSM4_GCM`, `PBEWithHMACSM3AndSM4_CBC`.

---

## Security

- **SM4-GCM**: AEAD with 128-bit GCM tag. HMAC-SM3 key commitment over `salt ‖ nonce ‖ ciphertext ‖ tag` — defends against partitioning oracle attacks.
- **SM4-CBC**: Encrypt-then-HMAC-SM3 over `IV ‖ ciphertext`. MAC verified before any decryption (constant-time). Separate encryption and MAC keys.
- **Constant-time**: All MAC/tag comparisons via `crypto/subtle.ConstantTimeCompare`. Single `ErrDecryptionFailed` for all authentication failures — no oracle leakage.
- **Key derivation**: PBKDF2-HMAC-SHA512 (AES) or PBKDF2-HMAC-SM3 (SM4). NFC-normalized passwords. 10,000 iterations default for SM4 (GM/T 0091-2020 minimum). Key material zeroed after use.
- **Salt**: 16 bytes from `crypto/rand`, fresh per encryption.

### Memory hygiene

Go's GC and immutable strings mean guaranteed key zeroization is not possible at the language level. This library zeroes derived keys and decrypted plaintext on a best-effort basis (`defer zeroBytes`). For high-assurance use, minimise the lifetime of `string` values and prefer `[]byte` where feasible. Explicitly call `ClearString` / `ClearSensitiveFields` after use.

### Compatibility

- `PBEWithHMACSHA512AndAES_256` produces output interoperable with Jasypt 3.x.
- SM4-based algorithms have no Jasypt equivalent and are not cross-compatible.

Performance comparison with Rust (`rasypt-lite`) and .NET (`nasypt-lite`) is in [`notes/benchmark.md`](notes/benchmark.md).

---

## License

MIT OR Apache-2.0
