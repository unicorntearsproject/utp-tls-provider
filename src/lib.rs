// SPDX-License-Identifier: MIT OR Apache-2.0

//! **A small, verify-only crypto provider for rustls 0.23.** Unaudited.
//!
//! [`provider()`] gives a [`CryptoProvider`] for a TLS 1.3 *client* that checks a server's
//! certificate chain and talks to it. It is built straight on the RustCrypto crates and nothing
//! else, and it is small enough to read in an afternoon. See the README for what it does and does
//! not do.
//!
//! ```
//! use std::sync::Arc;
//! # fn main() {
//! let provider = utp_tls_provider::provider();
//! assert_eq!(provider.cipher_suites.len(), 3);
//! let _ = Arc::new(provider);
//! # }
//! ```

#![no_std]
#![forbid(unsafe_code)]
// The library proper never panics on its own account; the few `expect`s are invariants and say so.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::std_instead_of_core,
        clippy::std_instead_of_alloc
    )
)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{CipherSuiteCommon, CryptoProvider};
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

mod aead;
mod hash;
mod hmac;
mod keys;
mod kx;
pub mod verify;

pub use self::keys::{NoKeys, Random};

/// Records one key may protect with AES-GCM before the keys must change (RFC 8446, section 5.5).
const AES_GCM_LIMIT: u64 = 1 << 24;

/// TLS 1.3 with AES-128-GCM and SHA-256.
pub const TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &aead::AES_128_GCM,
        quic: None,
    });

/// TLS 1.3 with AES-256-GCM and SHA-384.
pub const TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &hash::SHA384,
            confidentiality_limit: AES_GCM_LIMIT,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA384),
        aead_alg: &aead::AES_256_GCM,
        quic: None,
    });

/// TLS 1.3 with ChaCha20-Poly1305 and SHA-256.
pub const TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&hmac::HMAC_SHA256),
        aead_alg: &aead::CHACHA20_POLY1305,
        quic: None,
    });

/// The suites, in the order they are offered: ChaCha20-Poly1305 first. (Where the CPU has no AES
/// instructions, as with software-only builds, it is several times faster than AES-GCM; where it
/// has them, either is fine. A caller who wants another order sorts `cipher_suites`.)
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
];

/// The provider: the three TLS 1.3 suites, X25519, the signature checks in [`verify`], randomness
/// from `getrandom`, and no way to load a private key.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: alloc::vec![&kx::X25519_GROUP],
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &keys::Random,
        key_provider: &keys::NoKeys,
    }
}

#[cfg(test)]
mod tests;
