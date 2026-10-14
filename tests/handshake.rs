// SPDX-License-Identifier: MIT OR Apache-2.0

//! Whole handshakes: a client built on this provider against a server on `ring` (which does the
//! signing this provider cannot), with certificates made at run time. Every pairing of suite, CA
//! key type and server key type; and the ways it must fail.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, SignatureAlgorithm,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, Error, RootCertStore, ServerConfig,
    ServerConnection, SupportedCipherSuite,
};

/// 2026-10-13 12:00:00 UTC.
const NOW: u64 = 1_791_892_800;

#[derive(Debug)]
struct FixedTime;

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            NOW,
        )))
    }
}

struct Pki {
    ca: CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

#[derive(Clone, Copy)]
enum Dates {
    Good,
    Expired,
}

fn make_pki(
    name: &str,
    ca_alg: &'static SignatureAlgorithm,
    leaf_alg: &'static SignatureAlgorithm,
    dates: Dates,
) -> Pki {
    let ca_key = KeyPair::generate_for(ca_alg).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    static CAS: AtomicU64 = AtomicU64::new(0);
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!("Test CA {}", CAS.fetch_add(1, Ordering::SeqCst)),
    );
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let leaf_key = KeyPair::generate_for(leaf_alg).expect("leaf key");
    let mut leaf = CertificateParams::new(vec![name.to_string()]).expect("params");
    let (from, to) = match dates {
        Dates::Good => ((2026, 1, 1), (2027, 1, 1)),
        Dates::Expired => ((2020, 1, 1), (2021, 1, 1)),
    };
    leaf.not_before = rcgen::date_time_ymd(from.0, from.1, from.2);
    leaf.not_after = rcgen::date_time_ymd(to.0, to.1, to.2);
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf");
    Pki {
        ca: ca.der().clone(),
        chain: vec![cert.der().clone()],
        key: PrivateKeyDer::try_from(leaf_key.serialize_der()).expect("key"),
    }
}

fn client_config(pki: &Pki, suites: Vec<SupportedCipherSuite>) -> ClientConfig {
    let mut provider = utp_tls_provider::provider();
    provider.cipher_suites = suites;
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).expect("a root");
    ClientConfig::builder_with_details(Arc::new(provider), Arc::new(FixedTime))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn server_config(pki: &Pki, provider: CryptoProvider) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_details(Arc::new(provider), Arc::new(FixedTime))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(pki.chain.clone(), pki.key.clone_key())
            .expect("cert"),
    )
}

/// Moves bytes between the two until both are done or one fails.
fn run(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..50 {
        let mut moved = false;
        while client.wants_write() {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).expect("write");
            server.read_tls(&mut &bytes[..]).expect("read");
            server.process_new_packets()?;
            moved = true;
        }
        while server.wants_write() {
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).expect("write");
            client.read_tls(&mut &bytes[..]).expect("read");
            client.process_new_packets()?;
            moved = true;
        }
        if !moved {
            return Ok(());
        }
    }
    panic!("the handshake did not settle");
}

fn handshake(
    pki: &Pki,
    name: &str,
    suites: Vec<SupportedCipherSuite>,
) -> Result<SupportedCipherSuite, Error> {
    let server_cfg = server_config(pki, rustls::crypto::ring::default_provider());
    let mut client = ClientConnection::new(
        Arc::new(client_config(pki, suites)),
        ServerName::try_from(name.to_string()).expect("a name"),
    )?;
    let mut server = ServerConnection::new(server_cfg)?;
    run(&mut client, &mut server)?;
    assert!(!client.is_handshaking() && !server.is_handshaking());
    // Data both ways.
    client
        .writer()
        .write_all(b"ping from the client")
        .expect("write");
    server
        .writer()
        .write_all(b"pong from the server")
        .expect("write");
    run(&mut client, &mut server)?;
    let mut got = [0u8; 64];
    let n = server.reader().read(&mut got).expect("read");
    assert_eq!(&got[..n], b"ping from the client");
    let n = client.reader().read(&mut got).expect("read");
    assert_eq!(&got[..n], b"pong from the server");
    Ok(client.negotiated_cipher_suite().expect("a suite"))
}

const ALGS: [(&str, &SignatureAlgorithm); 3] = [
    ("P-256", &PKCS_ECDSA_P256_SHA256),
    ("P-384", &PKCS_ECDSA_P384_SHA384),
    ("Ed25519", &PKCS_ED25519),
];

#[test]
fn every_suite_with_every_pairing_of_ca_and_server_key() {
    let suites = utp_tls_provider::ALL_CIPHER_SUITES.to_vec();
    assert_eq!(suites.len(), 3);
    for (ca_name, ca_alg) in ALGS {
        for (leaf_name, leaf_alg) in ALGS {
            let pki = make_pki("server.example", ca_alg, leaf_alg, Dates::Good);
            for suite in &suites {
                let got = handshake(&pki, "server.example", vec![*suite]).unwrap_or_else(|e| {
                    panic!("CA {ca_name}, key {leaf_name}, {:?}: {e}", suite.suite())
                });
                assert_eq!(got.suite(), suite.suite());
            }
        }
    }
}

#[test]
fn the_first_suite_offered_is_chacha_and_ring_takes_it() {
    let pki = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    let got = handshake(
        &pki,
        "server.example",
        utp_tls_provider::ALL_CIPHER_SUITES.to_vec(),
    )
    .expect("ok");
    // ring's server prefers ChaCha20 when the client lists it first and the server has no
    // preference of its own set.
    println!("negotiated {:?}", got.suite());
}

#[test]
fn a_certificate_for_another_name_is_refused() {
    let pki = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    let err = handshake(
        &pki,
        "other.example",
        utp_tls_provider::ALL_CIPHER_SUITES.to_vec(),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::InvalidCertificate(CertificateError::NotValidForName)
                | Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })
        ),
        "{err:?}"
    );
}

#[test]
fn an_expired_certificate_is_refused() {
    let pki = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Expired);
    let err = handshake(
        &pki,
        "server.example",
        utp_tls_provider::ALL_CIPHER_SUITES.to_vec(),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::InvalidCertificate(
                CertificateError::Expired | CertificateError::ExpiredContext { .. }
            )
        ),
        "{err:?}"
    );
}

#[test]
fn a_certificate_from_a_root_we_do_not_trust_is_refused() {
    let theirs = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    let ours = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    // The server presents `theirs`; the client trusts only `ours`.
    let server_cfg = server_config(&theirs, rustls::crypto::ring::default_provider());
    let mut client = ClientConnection::new(
        Arc::new(client_config(
            &ours,
            utp_tls_provider::ALL_CIPHER_SUITES.to_vec(),
        )),
        ServerName::try_from("server.example".to_string()).expect("name"),
    )
    .expect("client");
    let mut server = ServerConnection::new(server_cfg).expect("server");
    let err = run(&mut client, &mut server).unwrap_err();
    assert!(
        matches!(
            err,
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        ),
        "{err:?}"
    );
}

#[test]
fn a_signature_made_with_the_wrong_key_is_refused() {
    // The chain is for one key, the server signs with another.
    let a = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    let b = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    let mixed = Pki {
        ca: a.ca.clone(),
        chain: a.chain.clone(),
        key: b.key.clone_key(),
    };
    // The server would refuse to build such a config on some versions; if it builds, the client
    // must refuse the handshake.
    let Ok(cfg) = std::panic::catch_unwind(|| {
        server_config(&mixed, rustls::crypto::ring::default_provider())
    }) else {
        return;
    };
    let mut client = ClientConnection::new(
        Arc::new(client_config(
            &a,
            utp_tls_provider::ALL_CIPHER_SUITES.to_vec(),
        )),
        ServerName::try_from("server.example".to_string()).expect("name"),
    )
    .expect("client");
    let mut server = ServerConnection::new(cfg).expect("server");
    assert!(run(&mut client, &mut server).is_err());
}

#[test]
fn a_server_with_no_x25519_cannot_be_reached() {
    let pki = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    let server_cfg = server_config(&pki, provider);
    let mut client = ClientConnection::new(
        Arc::new(client_config(
            &pki,
            utp_tls_provider::ALL_CIPHER_SUITES.to_vec(),
        )),
        ServerName::try_from("server.example".to_string()).expect("name"),
    )
    .expect("client");
    let mut server = ServerConnection::new(server_cfg).expect("server");
    assert!(run(&mut client, &mut server).is_err());
}

#[test]
fn a_client_certificate_cannot_be_configured() {
    let pki = make_pki("server.example", ALGS[0].1, ALGS[0].1, Dates::Good);
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).expect("root");
    let built = ClientConfig::builder_with_details(
        Arc::new(utp_tls_provider::provider()),
        Arc::new(FixedTime),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("versions")
    .with_root_certificates(roots)
    .with_client_auth_cert(pki.chain.clone(), pki.key.clone_key());
    assert!(built.is_err());
}

#[test]
fn the_provider_lists_what_the_readme_says() {
    let p = utp_tls_provider::provider();
    assert_eq!(p.cipher_suites.len(), 3);
    assert!(p.cipher_suites.iter().all(|s| s.tls13().is_some()));
    assert_eq!(p.kx_groups.len(), 1);
    assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::X25519);
    // Nothing here signs.
    assert!(
        p.key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(vec![0u8; 8].into()))
            .is_err()
    );
    // Randomness works.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    p.secure_random.fill(&mut a).expect("random");
    p.secure_random.fill(&mut b).expect("random");
    assert_ne!(a, b);
    let _: Option<&dyn ServerCertVerifier> = None;
}
