// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RSA public key reader: a good key verifies, and every kind of damage to its encoding, size
//! or exponent is refused before any arithmetic is done.

use rustls::pki_types::SignatureVerificationAlgorithm;
use utp_tls_provider::verify::{RSA_PKCS1_SHA256, RSA_PSS_SHA256};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// The first valid line of the 2048-bit SHA-256 file: key, message, signature.
fn good() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let line = include_str!("data/rsa_pkcs1_2048_sha256.txt")
        .lines()
        .find(|l| l.starts_with("valid "))
        .expect("a valid line");
    let f: Vec<&str> = line.split(' ').collect();
    (
        hex(f[2]),
        if f[3] == "-" { vec![] } else { hex(f[3]) },
        hex(f[4]),
    )
}

fn ok(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    RSA_PKCS1_SHA256.verify_signature(key, msg, sig).is_ok()
}

/// DER `INTEGER` for a big-endian magnitude (adds the sign byte when needed).
fn int(magnitude: &[u8]) -> Vec<u8> {
    let mut body = magnitude.to_vec();
    if body.first().is_some_and(|b| b & 0x80 != 0) {
        body.insert(0, 0);
    }
    der(0x02, &body)
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else if body.len() < 0x100 {
        out.extend([0x81, body.len() as u8]);
    } else {
        out.extend([0x82, (body.len() >> 8) as u8, body.len() as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn key(n: &[u8], e: &[u8]) -> Vec<u8> {
    der(0x30, &[int(n), int(e)].concat())
}

/// Splits a good key into its modulus and exponent magnitudes.
fn parts(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let n = key[9..9 + 256].to_vec();
    assert_eq!(&key[4..8], &[0x02, 0x82, 0x01, 0x01], "layout");
    let e = key[key.len() - 3..].to_vec();
    (n, e)
}

#[test]
fn the_good_key_verifies_and_a_rebuilt_copy_does_too() {
    let (k, msg, sig) = good();
    assert!(ok(&k, &msg, &sig));
    let (n, e) = parts(&k);
    let rebuilt = key(&n, &e);
    assert_eq!(rebuilt, k, "the helper builds the same DER");
    assert!(ok(&rebuilt, &msg, &sig));
}

#[test]
fn damaged_encodings_are_refused() {
    let (k, msg, sig) = good();
    let (n, e) = parts(&k);
    // Trailing data, a missing byte, an extra byte, a changed tag.
    assert!(!ok(&[&k[..], &[0]].concat(), &msg, &sig));
    assert!(!ok(&k[..k.len() - 1], &msg, &sig));
    let mut bad = k.clone();
    bad[0] = 0x31;
    assert!(!ok(&bad, &msg, &sig));
    // The length of the SEQUENCE spelled the long way (or with a leading zero) is not DER.
    let mut long = vec![0x30, 0x82, 0x01, 0x0a + 5];
    long.extend_from_slice(&k[4..]);
    assert!(!ok(&long, &msg, &sig));
    let mut padded = vec![0x30, 0x83, 0x00];
    padded.extend_from_slice(&k[2..]);
    assert!(!ok(&padded, &msg, &sig));
    // Integers: a needless leading zero, negative values, empty.
    let n_zero = [vec![0u8], n.clone()].concat();
    assert!(!ok(
        &der(
            0x30,
            &[der(0x02, &[vec![0u8], n_zero.clone()].concat()), int(&e)].concat()
        ),
        &msg,
        &sig
    ));
    assert!(
        !ok(&der(0x30, &[der(0x02, &n), int(&e)].concat()), &msg, &sig),
        "negative modulus"
    );
    assert!(
        !ok(&der(0x30, &[int(&n), der(0x02, &[])].concat()), &msg, &sig),
        "empty exponent"
    );
    // Only one number, three numbers, a bit string in place of an integer.
    assert!(!ok(&der(0x30, &int(&n)), &msg, &sig));
    assert!(!ok(
        &der(0x30, &[int(&n), int(&e), int(&e)].concat()),
        &msg,
        &sig
    ));
    assert!(!ok(
        &der(0x30, &[int(&n), der(0x03, &e)].concat()),
        &msg,
        &sig
    ));
    // Nothing at all, and junk.
    assert!(!ok(&[], &msg, &sig));
    assert!(!ok(&[0x30, 0x80, 0, 0], &msg, &sig));
    assert!(!ok(&vec![0xff; 600], &msg, &sig));
}

#[test]
fn bad_exponents_and_sizes_are_refused() {
    let (k, msg, sig) = good();
    let (n, _) = parts(&k);
    for (what, e) in [
        ("e = 0", vec![0u8]),
        ("e = 1", vec![1]),
        ("e = 3", vec![3]),
        ("e = 65536", vec![1, 0, 0]),
        ("e even", vec![1, 0, 2]),
        ("e = 2^33 + 1", vec![2, 0, 0, 0, 1]),
        ("e as long as n", n.clone()),
    ] {
        assert!(!ok(&key(&n, &e), &msg, &sig), "{what}");
        assert!(
            RSA_PSS_SHA256
                .verify_signature(&key(&n, &e), &msg, &sig)
                .is_err(),
            "{what} (PSS)"
        );
    }
    // The largest exponent that is allowed passes the key checks (the signature does not match).
    assert!(!ok(&key(&n, &[1, 0xff, 0xff, 0xff, 0xff]), &msg, &sig));
    // An even modulus, a modulus under 2048 bits, and one over 8192 bits.
    let mut even = n.clone();
    *even.last_mut().unwrap() &= !1;
    assert!(!ok(&key(&even, &[1, 0, 1]), &msg, &sig));
    assert!(!ok(&key(&n[..255], &[1, 0, 1]), &msg, &sig));
    let mut big = vec![0x80u8];
    big.extend(vec![0xffu8; 1024]);
    assert!(!ok(&key(&big, &[1, 0, 1]), &msg, &sig));
}

#[test]
fn bad_signature_lengths_and_values_are_refused() {
    let (k, msg, sig) = good();
    let (n, _) = parts(&k);
    assert!(!ok(&k, &msg, &sig[1..]));
    assert!(!ok(&k, &msg, &[&sig[..], &[0]].concat()));
    assert!(!ok(&k, &msg, &[]));
    // A signature value that is not below the modulus.
    assert!(!ok(&k, &msg, &n));
    assert!(!ok(&k, &msg, &vec![0xff; 256]));
    // Zero and one.
    assert!(!ok(&k, &msg, &vec![0; 256]));
    let mut one = vec![0; 256];
    one[255] = 1;
    assert!(!ok(&k, &msg, &one));
    // Another message.
    assert!(!ok(&k, b"another message", &sig));
}
