// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature verification against Project Wycheproof's test vectors (Apache-2.0, see
//! `tests/data/README.md`): every `valid` signature must verify, every `invalid` one must be
//! refused, and the few `acceptable` ones (legal but unusual) may go either way and are counted.

use rustls::pki_types::SignatureVerificationAlgorithm;
use utp_tls_provider::verify::*;

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Runs a data file against an algorithm; returns (valid, invalid, acceptable-accepted,
/// acceptable-refused).
fn run(alg: &dyn SignatureVerificationAlgorithm, data: &str) -> (usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0);
    for line in data.lines() {
        let mut f = line.split(' ');
        let (result, id, key, msg, sig) = (
            f.next().expect("result"),
            f.next().expect("tcId"),
            hex(f.next().expect("key")),
            hex(f.next().expect("msg")),
            hex(f.next().expect("sig")),
        );
        let ok = alg.verify_signature(&key, &msg, &sig).is_ok();
        match result {
            // Keys with the exponent 3 are legal RSA, but refused by policy (exponents start at
            // 65537, as in every other TLS verifier), so their valid signatures must not verify.
            "valid" if key.ends_with(&[0x02, 0x01, 0x03]) => {
                assert!(!ok, "test {id}: a signature under e = 3 was accepted");
            }
            "valid" => {
                assert!(ok, "test {id}: a valid signature was refused");
                counts.0 += 1;
            }
            "invalid" => {
                assert!(!ok, "test {id}: an invalid signature was accepted");
                counts.1 += 1;
            }
            "acceptable" if ok => counts.2 += 1,
            "acceptable" => counts.3 += 1,
            other => panic!("unknown result {other}"),
        }
    }
    counts
}

macro_rules! vectors {
    ($name:ident, $alg:expr, $file:literal, valid >= $v:expr, invalid >= $i:expr) => {
        #[test]
        fn $name() {
            let (valid, invalid, accepted, refused) = run(
                &$alg,
                include_str!(concat!("data/", $file, ".txt")),
            );
            println!(
                "{}: {valid} valid, {invalid} invalid, acceptable: {accepted} accepted / {refused} refused",
                $file
            );
            assert!(valid >= $v && invalid >= $i);
        }
    };
}

vectors!(
    ecdsa_p256_sha256,
    ECDSA_P256_SHA256,
    "ecdsa_p256_sha256",
    valid >= 100,
    invalid >= 200
);
vectors!(
    ecdsa_p384_sha384,
    ECDSA_P384_SHA384,
    "ecdsa_p384_sha384",
    valid >= 100,
    invalid >= 200
);
vectors!(
    ecdsa_p384_sha256,
    ECDSA_P384_SHA256,
    "ecdsa_p384_sha256",
    valid >= 100,
    invalid >= 200
);
vectors!(ed25519, ED25519, "ed25519", valid >= 50, invalid >= 50);
vectors!(
    rsa_pkcs1_2048_sha256,
    RSA_PKCS1_SHA256,
    "rsa_pkcs1_2048_sha256",
    valid >= 5,
    invalid >= 200
);
vectors!(
    rsa_pkcs1_2048_sha384,
    RSA_PKCS1_SHA384,
    "rsa_pkcs1_2048_sha384",
    valid >= 5,
    invalid >= 100
);
vectors!(
    rsa_pkcs1_2048_sha512,
    RSA_PKCS1_SHA512,
    "rsa_pkcs1_2048_sha512",
    valid >= 5,
    invalid >= 200
);
vectors!(
    rsa_pkcs1_3072_sha256,
    RSA_PKCS1_SHA256,
    "rsa_pkcs1_3072_sha256",
    valid >= 5,
    invalid >= 200
);
vectors!(
    rsa_pss_2048_sha256,
    RSA_PSS_SHA256,
    "rsa_pss_2048_sha256",
    valid >= 20,
    invalid >= 40
);
vectors!(
    rsa_pss_2048_sha384,
    RSA_PSS_SHA384,
    "rsa_pss_2048_sha384",
    valid >= 20,
    invalid >= 40
);
vectors!(
    rsa_pss_3072_sha256,
    RSA_PSS_SHA256,
    "rsa_pss_3072_sha256",
    valid >= 20,
    invalid >= 40
);
