// SPDX-License-Identifier: MIT OR Apache-2.0

//! A client built on this provider talks to a `ring` server in the same process, with a
//! certificate made on the spot: `cargo run --example in_memory_handshake`.

use std::io::{Read, Write};
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

fn main() {
    // A certificate authority and a server certificate for "server.example".
    let ca_key = KeyPair::generate().expect("a key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Example CA");
    let ca = ca_params.self_signed(&ca_key).expect("a CA");
    let leaf_key = KeyPair::generate().expect("a key");
    let leaf = CertificateParams::new(vec!["server.example".to_string()])
        .expect("params")
        .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
        .expect("a certificate");

    // The server signs with ring. The client verifies with this crate.
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::try_from(leaf_key.serialize_der()).expect("a key"),
            )
            .expect("a certificate");
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).expect("a root");
    let client_config = ClientConfig::builder_with_provider(Arc::new(utp_tls_provider::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("server.example").expect("a name"),
    )
    .expect("a client");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("a server");
    client.writer().write_all(b"hello").expect("write");
    while client.is_handshaking() || client.wants_write() || server.wants_write() {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).expect("write");
        if !bytes.is_empty() {
            server.read_tls(&mut &bytes[..]).expect("read");
            server.process_new_packets().expect("the server accepts");
        }
        bytes.clear();
        server.write_tls(&mut bytes).expect("write");
        if !bytes.is_empty() {
            client.read_tls(&mut &bytes[..]).expect("read");
            client.process_new_packets().expect("the client accepts");
        }
    }
    let mut got = [0u8; 16];
    let n = server.reader().read(&mut got).expect("read");
    println!(
        "negotiated {:?}; the server read {:?}",
        client.negotiated_cipher_suite().map(|s| s.suite()),
        String::from_utf8_lossy(&got[..n])
    );
}
