# utp-tls-provider

A small crypto provider for [rustls](https://github.com/rustls/rustls) 0.23 that can **verify but not
sign**: enough for a TLS 1.3 *client* that checks a server's certificate and talks to it. It is built
straight on the [RustCrypto](https://github.com/RustCrypto) crates, is `no_std` plus `alloc`, and is
small enough to read in an afternoon (about a thousand lines of library code, plus tests).

**Unaudited.** Nobody independent has reviewed this code. It is tested hard (below), but "tested" is
not "audited". It is a project of the Unicorn Tears Project, written for Rusty Bucket's TLS client; it
is **not** affiliated with, endorsed by, or part of rustls or RustCrypto, and its name does not claim
otherwise.

## What it does

| Part | What | Built on |
| --- | --- | --- |
| Cipher suites | `TLS13_CHACHA20_POLY1305_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_AES_128_GCM_SHA256` (offered in that order) | `chacha20poly1305`, `aes-gcm`, `sha2`, `hmac` |
| Key exchange | X25519 only; a result of all zeros (a point of small order) is refused | `x25519-dalek` |
| Certificate and `CertificateVerify` signatures | ECDSA P-256 and P-384 (SHA-256, SHA-384), Ed25519 (strict), RSA-PSS (SHA-256/384/512) and RSA PKCS#1 v1.5 (SHA-256/384/512), **verify only** | `p256`, `p384`, `ed25519-dalek`, `num-bigint` (see below) |
| Randomness | `getrandom` | `getrandom` |

`utp_tls_provider::provider()` returns a `rustls::crypto::CryptoProvider` to hand to
`ClientConfig::builder_with_provider` (or `builder_with_details`).

```rust
use std::sync::Arc;
use rustls::{ClientConfig, RootCertStore};

let provider = Arc::new(utp_tls_provider::provider());
let mut roots = RootCertStore::empty();
// roots.add(your_root_certificate)?;
let config = ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])? // TLS 1.2 is not provided
    .with_root_certificates(roots)
    .with_no_client_auth();
```

See `examples/`.

## What it does not do

- **No signing.** `provider().key_provider` refuses every private key, so a client configured with a
  client certificate fails when it is built. There are no server-side features: it cannot be a TLS
  server.
- **No RSA private-key code at all.** RSA signatures are checked with a small amount of code in this
  crate: a strict DER reader for the public key, one modular power from `num-bigint` (public numbers
  only, so it is not constant-time and need not be), and the PKCS#1 v1.5 and PSS padding checks of
  RFC 8017. The `rsa` crate is not a dependency, which `ci.sh` checks (`cargo tree`) and `deny.toml`
  forbids. This keeps clear of [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)
  (the Marvin timing attack), which is about RSA private-key operations. RSA keys must be 2048 to 8192
  bits with an odd exponent from 65537 up (the limits other verifiers use).
- **TLS 1.3 only.** No TLS 1.2, no `tls12` feature.
- **X25519 only.** No P-256/P-384 key exchange, no post-quantum hybrids; every TLS 1.3 server accepts
  X25519.
- No QUIC suites, no secret extraction (`extract_keys` says "unsupported"), no FIPS claim, no
  ECDSA P-521, no Ed448.
- The P-256 and P-384 crates are built with their `ecdsa` feature, which includes signing code. It is
  never called here, and a linker that drops unused code drops it, but it is in the dependency.
- **Constant time** is whatever the RustCrypto crates give; this crate adds no secret-dependent
  branches of its own, and its own handling of secrets (the X25519 private key, the shared secret) is
  zeroized after use. That is a statement of intent, not a proof.

## Targets without an operating system

`getrandom` needs a source on bare-metal targets: enable this crate's `getrandom-custom` feature and
register one with `getrandom::register_custom_getrandom!`. Where the CPU has no vector registers, the
RustCrypto crates need their portable code selected, and `curve25519-dalek` its serial backend:

```text
RUSTFLAGS='--cfg aes_force_soft --cfg polyval_force_soft --cfg chacha20_force_soft
           --cfg poly1305_force_soft --cfg curve25519_dalek_backend="serial"'
cargo build --release --target x86_64-unknown-none --features getrandom-custom
```

The soft AES is constant-time. ChaCha20-Poly1305 is first in the offer order because in portable
code it is several times faster than AES-GCM.

## How it is tested

(The test data and where it comes from: [tests/data/README.md](tests/data/README.md).)

- **RFC 8448** (the TLS 1.3 example handshake): X25519 from the RFC's keys, the whole key schedule
  (early, handshake and master secrets, traffic keys and IVs) computed through this crate's HKDF,
  the server's four encrypted handshake messages decrypted and re-encrypted to the same bytes, both
  Finished messages' verify data, and the application data in both directions.
- **Project Wycheproof** ([C2SP/wycheproof](https://github.com/C2SP/wycheproof), Apache-2.0): about
  3,000 signature cases for ECDSA P-256/P-384, Ed25519, RSA PKCS#1 v1.5 (2048 and 3072 bits) and
  RSA-PSS, and 500 X25519 cases. Every valid case verifies, every invalid case is refused.
- **Records from an independent implementation** (Python `cryptography`, `tools/records.py`) for all
  three suites: lengths from 0 to 16,384, large and small sequence numbers; sealing gives identical
  bytes, and a flipped bit, a wrong sequence number or a cut record is refused.
- **Whole handshakes** against a `ring` server (which does the signing), for every suite and every
  pairing of CA and server key type (P-256, P-384, Ed25519), and the failures: wrong name, expired,
  unknown root, wrong signing key, server without X25519, client certificate.
- **RSA key reading**: truncated, padded, negative and non-minimal DER; bad moduli and exponents.
- `./ci.sh` runs formatting, `clippy -D warnings`, the tests, a bare-metal build, the "no RSA crate"
  check, and `cargo deny` when installed.

## Layout

```text
src/lib.rs          the suites and provider()
src/hash.rs hmac.rs SHA-256/384 and HMAC for rustls's HKDF
src/aead.rs         record protection, one implementation for the three ciphers
src/kx.rs           X25519
src/keys.rs         randomness; the key provider that refuses keys
src/verify/         signature verification (ecdsa, eddsa, rsa, rsa_key)
tests/              Wycheproof, records, handshakes, RSA keys; tests/data holds the vectors
tools/              scripts that make the test data
```

## Versions

rustls is pinned to `=0.23.45`: the provider traits are rustls's, and a rustls update is a change to
this crate to be tested, not a drift.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option. Contributions are accepted under the same terms. The test vectors from Wycheproof are
Apache-2.0.
