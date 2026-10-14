// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prints what the provider offers: `cargo run --example inspect`.

fn main() {
    let provider = utp_tls_provider::provider();
    println!("cipher suites (offered in this order):");
    for suite in &provider.cipher_suites {
        println!("  {:?}", suite.suite());
    }
    println!("key exchange groups:");
    for group in &provider.kx_groups {
        println!("  {:?}", group.name());
    }
    println!("signature schemes the server may use:");
    for scheme in provider
        .signature_verification_algorithms
        .supported_schemes()
    {
        println!("  {scheme:?}");
    }
    println!("can load private keys: no (it only verifies)");
}
