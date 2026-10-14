// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests that need the crate's inside: known-answer tests for the key exchange and the key
//! schedule, from the RFC 8448 example handshake and Project Wycheproof.

#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

mod rfc8448;
mod x25519;

use std::vec::Vec;

/// Hex to bytes. Test data only: it panics on a malformed file.
#[allow(clippy::expect_used, clippy::indexing_slicing)]
pub(crate) fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}
