// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading an RSA public key (PKCS#1 `RSAPublicKey`, strict DER) and doing the one operation a
//! signature check needs, `s^e mod n`. The numbers are public, so this is not constant-time and
//! does not need to be.

use alloc::vec::Vec;

use num_bigint::BigUint;

/// Smallest modulus accepted, in bits.
pub(super) const MIN_BITS: u64 = 2048;
/// Largest modulus accepted, in bits.
pub(super) const MAX_BITS: u64 = 8192;
/// Smallest public exponent accepted.
const MIN_EXPONENT: u64 = 65_537;
/// Largest public exponent accepted (2^33 - 1, the limit other verifiers use).
const MAX_EXPONENT: u64 = (1 << 33) - 1;

/// A public key that passed the checks.
pub(super) struct PublicKey {
    n: BigUint,
    e: BigUint,
    /// Bits in `n`.
    pub(super) bits: u64,
}

impl PublicKey {
    /// Reads `SEQUENCE { INTEGER n, INTEGER e }`, which must be exactly DER, fill the input, and
    /// give an odd modulus of 2048 to 8192 bits and an odd exponent from 65537 to 2^33 - 1.
    pub(super) fn from_der(der: &[u8]) -> Option<Self> {
        let (body, rest) = take(der, 0x30)?;
        if !rest.is_empty() {
            return None;
        }
        let (n, rest) = take(body, 0x02)?;
        let (e, rest) = take(rest, 0x02)?;
        if !rest.is_empty() {
            return None;
        }
        let (n, e) = (unsigned(n)?, unsigned(e)?);
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        let bits = n.bits();
        let exponent_ok = u64::try_from(&e)
            .is_ok_and(|e| (MIN_EXPONENT..=MAX_EXPONENT).contains(&e) && e & 1 == 1);
        let modulus_ok = (MIN_BITS..=MAX_BITS).contains(&bits) && n.bit(0);
        (exponent_ok && modulus_ok).then_some(Self { n, e, bits })
    }

    /// The length of a signature in bytes.
    pub(super) fn len(&self) -> usize {
        usize::try_from(self.bits.div_ceil(8)).unwrap_or(usize::MAX)
    }

    /// `s^e mod n` as `width` big-endian bytes, or `None` if `s` is not below `n` or the
    /// result does not fit.
    pub(super) fn apply(&self, s: &[u8], width: usize) -> Option<Vec<u8>> {
        let s = BigUint::from_bytes_be(s);
        if s >= self.n {
            return None;
        }
        let m = s.modpow(&self.e, &self.n).to_bytes_be();
        let pad = width.checked_sub(m.len())?;
        let mut out = alloc::vec![0u8; pad];
        out.extend_from_slice(&m);
        Some(out)
    }
}

/// One DER element with tag `tag`: its contents, and what follows it. Lengths must be the
/// shortest form, and no element may be longer than the input.
fn take(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = input.split_first()?;
    if t != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 {
            return None;
        }
        let bytes = rest.get(..count)?;
        let len = bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        // The short form must be used when it fits, and no leading zero length byte.
        if len < 0x80 || bytes.first() == Some(&0) || (count == 2 && len < 0x100) {
            return None;
        }
        (len, rest.get(count..)?)
    };
    (len <= rest.len()).then(|| rest.split_at(len))
}

/// The magnitude of a positive DER INTEGER: no leading zero except the one that keeps a high bit
/// from reading as a sign, and not negative or empty.
fn unsigned(int: &[u8]) -> Option<&[u8]> {
    match int {
        [] => None,
        [first, ..] if first & 0x80 != 0 => None,
        [0, next, rest @ ..] if next & 0x80 != 0 => {
            let _ = rest;
            int.get(1..)
        }
        [0, _, ..] => None,
        _ => Some(int),
    }
}
