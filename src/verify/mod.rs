// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature verification: what the certificate verifier (`rustls-webpki`) calls to check a
//! certificate's signature, and what rustls calls to check the server's `CertificateVerify`.
//!
//! Only verification exists. Public keys and signatures come from the network, so every function
//! here treats its input as hostile: lengths are checked, encodings must be exactly DER (no
//! alternative spellings of the same number), and a failure of any kind is the one answer
//! `InvalidSignature`.
//!
//! | Algorithm | Keys | Checks |
//! | --- | --- | --- |
//! | [`ECDSA_P256_SHA256`], [`ECDSA_P256_SHA384`] | P-256, uncompressed point | DER signature |
//! | [`ECDSA_P384_SHA256`], [`ECDSA_P384_SHA384`] | P-384, uncompressed point | DER signature |
//! | [`ED25519`] | 32 bytes | RFC 8032, strict (small-order keys refused) |
//! | [`RSA_PSS_SHA256`], `_SHA384`, `_SHA512` | RSA 2048 to 8192 bits, e from 65537 up | RFC 8017 PSS, salt as long as the hash |
//! | [`RSA_PKCS1_SHA256`], `_SHA384`, `_SHA512` | the same | RFC 8017 PKCS#1 v1.5 |

use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;

mod ecdsa;
mod eddsa;
mod rsa;
mod rsa_key;

pub use self::ecdsa::{ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256, ECDSA_P384_SHA384};
pub use self::eddsa::ED25519;
pub use self::rsa::{
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
    RSA_PSS_SHA512,
};

/// Every algorithm, and which signature schemes each one serves.
pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &ECDSA_P256_SHA256,
        &ECDSA_P256_SHA384,
        &ECDSA_P384_SHA256,
        &ECDSA_P384_SHA384,
        &ED25519,
        &RSA_PSS_SHA256,
        &RSA_PSS_SHA384,
        &RSA_PSS_SHA512,
        &RSA_PKCS1_SHA256,
        &RSA_PKCS1_SHA384,
        &RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&ECDSA_P384_SHA384, &ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&ECDSA_P256_SHA256, &ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[&ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[&RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[&RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[&RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&RSA_PKCS1_SHA256]),
    ],
};
