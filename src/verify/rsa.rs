// SPDX-License-Identifier: MIT OR Apache-2.0

//! RSA signature checks: PKCS#1 v1.5 and PSS (RFC 8017), public key only.

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use digest::Digest;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::{Sha256, Sha384, Sha512};

use super::rsa_key::PublicKey;

/// The `DigestInfo` header that goes before the hash in a PKCS#1 v1.5 signature.
const SHA256_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_INFO: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_INFO: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// RSASSA-PKCS1-v1_5 with the hash `D`.
pub struct Pkcs1<D> {
    signature: AlgorithmIdentifier,
    info: &'static [u8],
    hash: PhantomData<fn() -> D>,
}

/// RSASSA-PSS with the hash `D`, the same hash for the mask, and a salt as long as the hash (the
/// only parameters TLS 1.3 allows).
pub struct Pss<D> {
    signature: AlgorithmIdentifier,
    hash: PhantomData<fn() -> D>,
}

impl<D> fmt::Debug for Pkcs1<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs1").finish_non_exhaustive()
    }
}

impl<D> fmt::Debug for Pss<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pss").finish_non_exhaustive()
    }
}

/// RSA PKCS#1 v1.5 with SHA-256.
pub static RSA_PKCS1_SHA256: Pkcs1<Sha256> =
    Pkcs1::new(rustls::pki_types::alg_id::RSA_PKCS1_SHA256, SHA256_INFO);
/// RSA PKCS#1 v1.5 with SHA-384.
pub static RSA_PKCS1_SHA384: Pkcs1<Sha384> =
    Pkcs1::new(rustls::pki_types::alg_id::RSA_PKCS1_SHA384, SHA384_INFO);
/// RSA PKCS#1 v1.5 with SHA-512.
pub static RSA_PKCS1_SHA512: Pkcs1<Sha512> =
    Pkcs1::new(rustls::pki_types::alg_id::RSA_PKCS1_SHA512, SHA512_INFO);
/// RSA-PSS with SHA-256.
pub static RSA_PSS_SHA256: Pss<Sha256> = Pss::new(rustls::pki_types::alg_id::RSA_PSS_SHA256);
/// RSA-PSS with SHA-384.
pub static RSA_PSS_SHA384: Pss<Sha384> = Pss::new(rustls::pki_types::alg_id::RSA_PSS_SHA384);
/// RSA-PSS with SHA-512.
pub static RSA_PSS_SHA512: Pss<Sha512> = Pss::new(rustls::pki_types::alg_id::RSA_PSS_SHA512);

impl<D> Pkcs1<D> {
    const fn new(signature: AlgorithmIdentifier, info: &'static [u8]) -> Self {
        Self {
            signature,
            info,
            hash: PhantomData,
        }
    }
}

impl<D> Pss<D> {
    const fn new(signature: AlgorithmIdentifier) -> Self {
        Self {
            signature,
            hash: PhantomData,
        }
    }
}

impl<D: Digest> SignatureVerificationAlgorithm for Pkcs1<D> {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        rustls::pki_types::alg_id::RSA_ENCRYPTION
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
        let key = PublicKey::from_der(public_key).ok_or(InvalidSignature)?;
        let k = key.len();
        if signature.len() != k {
            return Err(InvalidSignature);
        }
        let em = key.apply(signature, k).ok_or(InvalidSignature)?;
        // 0x00 0x01 FF..FF 0x00 DigestInfo hash, with at least eight bytes of FF.
        let tail = self.info.len() + <D as Digest>::output_size();
        let pad = k
            .checked_sub(tail + 3)
            .filter(|&p| p >= 8)
            .ok_or(InvalidSignature)?;
        let mut expected = Vec::with_capacity(k);
        expected.extend_from_slice(&[0x00, 0x01]);
        expected.resize(2 + pad, 0xff);
        expected.push(0x00);
        expected.extend_from_slice(self.info);
        expected.extend_from_slice(&D::digest(message));
        if em == expected {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}

impl<D: Digest> SignatureVerificationAlgorithm for Pss<D> {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        rustls::pki_types::alg_id::RSA_ENCRYPTION
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
        let key = PublicKey::from_der(public_key).ok_or(InvalidSignature)?;
        if signature.len() != key.len() {
            return Err(InvalidSignature);
        }
        // EMSA-PSS-VERIFY (RFC 8017, section 9.1.2) on the em_bits = bits - 1 low bits.
        let em_bits = key.bits - 1;
        let em_len = usize::try_from(em_bits.div_ceil(8)).map_err(|_| InvalidSignature)?;
        let em = key.apply(signature, em_len).ok_or(InvalidSignature)?;
        pss_check::<D>(&em, em_bits, &D::digest(message)).ok_or(InvalidSignature)
    }
}

/// The checks on the encoded message `em` of `em_bits` bits for the message hash `m_hash`.
fn pss_check<D: Digest>(em: &[u8], em_bits: u64, m_hash: &[u8]) -> Option<()> {
    let h_len = <D as Digest>::output_size();
    let s_len = h_len;
    let db_len = em.len().checked_sub(h_len + 1)?;
    // Room for the 0x01 byte as well as the salt.
    if db_len < s_len + 1 || em.last() != Some(&0xbc) {
        return None;
    }
    let (masked_db, rest) = em.split_at(db_len);
    let h = rest.get(..h_len)?;
    // The bits above em_bits must be zero.
    let spare = u32::try_from(8 * em.len() as u64 - em_bits).ok()?;
    let top_mask = 0xffu8.checked_shl(8 - spare).unwrap_or(0);
    if masked_db.first()? & top_mask != 0 {
        return None;
    }
    let mut db = mgf1::<D>(h, db_len);
    for (d, m) in db.iter_mut().zip(masked_db) {
        *d ^= m;
    }
    *db.first_mut()? &= !top_mask;
    let (zeros, salt_part) = db.split_at(db_len - s_len - 1);
    let (one, salt) = salt_part.split_first()?;
    if *one != 0x01 || zeros.iter().any(|&b| b != 0) {
        return None;
    }
    let mut hasher = D::new();
    hasher.update([0u8; 8]);
    hasher.update(m_hash);
    hasher.update(salt);
    (hasher.finalize().as_slice() == h).then_some(())
}

/// MGF1 (RFC 8017, appendix B.2.1): `len` bytes of mask from `seed`.
fn mgf1<D: Digest>(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + <D as Digest>::output_size());
    let mut counter = 0u32;
    while out.len() < len {
        let mut hasher = D::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}
