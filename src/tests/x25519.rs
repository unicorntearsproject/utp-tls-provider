// SPDX-License-Identifier: MIT OR Apache-2.0

//! X25519 against Wycheproof's vectors (RFC 7748 edge cases: non-canonical points, low-order
//! points, twist points).

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::std_instead_of_alloc
)]

use std::boxed::Box;
use std::println;

use rustls::crypto::ActiveKeyExchange;

use super::hex;
use crate::kx::Started;

#[test]
fn wycheproof_x25519() {
    let (mut valid, mut refused_zero) = (0, 0);
    for line in include_str!("../../tests/data/x25519.txt").lines() {
        let mut f = line.split(' ');
        let (result, id) = (f.next().expect("result"), f.next().expect("tcId"));
        let public = hex(f.next().expect("public"));
        let private: [u8; 32] = hex(f.next().expect("private"))
            .try_into()
            .expect("32 bytes");
        let shared = hex(f.next().expect("shared"));
        let outcome = Box::new(Started::from_private(private)).complete(&public);
        match outcome {
            Ok(secret) => {
                assert_eq!(secret.secret_bytes(), &shared[..], "test {id} ({result})");
                valid += 1;
            }
            Err(_) => {
                // Only an all-zero result (a point of small order) is refused.
                assert!(
                    shared.iter().all(|&b| b == 0),
                    "test {id}: refused a good exchange"
                );
                refused_zero += 1;
            }
        }
    }
    assert!(valid > 400, "{valid}");
    println!("x25519: {valid} computed, {refused_zero} refused as all-zero");
}

#[test]
fn a_short_or_long_peer_key_is_refused() {
    for len in [0usize, 31, 33, 64] {
        let kx = Box::new(Started::from_private([7; 32]));
        assert!(kx.complete(&std::vec![9u8; len]).is_err(), "{len}");
    }
}

#[test]
fn the_public_key_is_the_base_point_product() {
    // RFC 7748, section 6.1: Alice's key pair.
    let private: [u8; 32] = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .try_into()
        .expect("32 bytes");
    let kx = Started::from_private(private);
    assert_eq!(
        kx.pub_key(),
        &hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")[..]
    );
    let bob = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let secret = Box::new(kx).complete(&bob).expect("a good exchange");
    assert_eq!(
        secret.secret_bytes(),
        &hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")[..]
    );
}
