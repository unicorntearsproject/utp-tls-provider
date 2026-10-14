// SPDX-License-Identifier: MIT OR Apache-2.0

//! ECDSA over P-256 and P-384, signatures in DER.

use digest::Digest;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::{Sha256, Sha384};
use signature::hazmat::PrehashVerifier;

/// One curve and hash pairing.
#[derive(Debug)]
pub struct Ecdsa {
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
    curve: Curve,
    hash: Hash,
}

#[derive(Debug, Clone, Copy)]
enum Curve {
    P256,
    P384,
}

#[derive(Debug, Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
}

/// ECDSA on P-256 with SHA-256.
pub static ECDSA_P256_SHA256: Ecdsa = Ecdsa {
    public_key: rustls::pki_types::alg_id::ECDSA_P256,
    signature: rustls::pki_types::alg_id::ECDSA_SHA256,
    curve: Curve::P256,
    hash: Hash::Sha256,
};
/// ECDSA on P-256 with SHA-384.
pub static ECDSA_P256_SHA384: Ecdsa = Ecdsa {
    public_key: rustls::pki_types::alg_id::ECDSA_P256,
    signature: rustls::pki_types::alg_id::ECDSA_SHA384,
    curve: Curve::P256,
    hash: Hash::Sha384,
};
/// ECDSA on P-384 with SHA-256.
pub static ECDSA_P384_SHA256: Ecdsa = Ecdsa {
    public_key: rustls::pki_types::alg_id::ECDSA_P384,
    signature: rustls::pki_types::alg_id::ECDSA_SHA256,
    curve: Curve::P384,
    hash: Hash::Sha256,
};
/// ECDSA on P-384 with SHA-384.
pub static ECDSA_P384_SHA384: Ecdsa = Ecdsa {
    public_key: rustls::pki_types::alg_id::ECDSA_P384,
    signature: rustls::pki_types::alg_id::ECDSA_SHA384,
    curve: Curve::P384,
    hash: Hash::Sha384,
};

impl SignatureVerificationAlgorithm for Ecdsa {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let digest: alloc::vec::Vec<u8> = match self.hash {
            Hash::Sha256 => Sha256::digest(message).to_vec(),
            Hash::Sha384 => Sha384::digest(message).to_vec(),
        };
        match self.curve {
            Curve::P256 => {
                // The key is an uncompressed point: 0x04, x, y. (Compressed points are refused.)
                if public_key.len() != 65 || public_key.first() != Some(&0x04) {
                    return Err(InvalidSignature);
                }
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let sig =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }
            Curve::P384 => {
                if public_key.len() != 97 || public_key.first() != Some(&0x04) {
                    return Err(InvalidSignature);
                }
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let sig =
                    p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&digest, &sig)
                    .map_err(|_| InvalidSignature)
            }
        }
    }
}
