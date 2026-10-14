// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ed25519 (RFC 8032).

use ed25519_dalek::{Signature, VerifyingKey};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

/// Ed25519 signatures, checked strictly: a public key of small order is refused.
#[derive(Debug)]
pub struct Ed25519;

/// Ed25519.
pub static ED25519: Ed25519 = Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        rustls::pki_types::alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        rustls::pki_types::alg_id::ED25519
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key: &[u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let key = VerifyingKey::from_bytes(key).map_err(|_| InvalidSignature)?;
        let signature = Signature::from_slice(signature).map_err(|_| InvalidSignature)?;
        key.verify_strict(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}
