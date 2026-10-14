// SPDX-License-Identifier: MIT OR Apache-2.0

//! The example handshake of RFC 8448, section 3 ("Simple 1-RTT Handshake", TLS_AES_128_GCM_SHA256),
//! replayed through this provider's pieces: X25519, SHA-256, HMAC and HKDF (the key schedule of RFC
//! 8446, section 7.1), and AES-128-GCM record protection. Everything the client and the server
//! computed in the RFC has to come out the same: the shared secret and both sides' traffic keys
//! (checked by decrypting the server's encrypted flight and the client's Finished), the Finished
//! messages' verify data, and the ciphertext of the application data both ways.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::std_instead_of_alloc
)]

use std::boxed::Box;
use std::collections::BTreeMap;
use std::vec::Vec;

use rustls::ContentType;
use rustls::ProtocolVersion;
use rustls::crypto::ActiveKeyExchange;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, OutboundChunks,
    OutboundPlainMessage,
};
use rustls::crypto::hash::Hash;
use rustls::crypto::hmac::Hmac;
use rustls::crypto::tls13::{Hkdf, HkdfUsingHmac, OkmBlock};

use super::hex;
use crate::kx::Started;
use crate::{TLS13_AES_128_GCM_SHA256, hash, hmac};

fn trace() -> BTreeMap<&'static str, Vec<u8>> {
    include_str!("../../tests/data/rfc8448.txt")
        .lines()
        .map(|l| {
            let (k, v) = l.split_once(' ').expect("key and value");
            (k, hex(v))
        })
        .collect()
}

/// RFC 8446 section 7.1: `HKDF-Expand-Label(secret, label, context, length)`.
fn expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let hkdf = HkdfUsingHmac(&hmac::HMAC_SHA256);
    let expander = hkdf.expander_for_okm(&OkmBlock::new(secret));
    let len16 = u16::try_from(len).expect("short").to_be_bytes();
    let full_label = [b"tls13 ".as_slice(), label.as_bytes()].concat();
    let mut out = std::vec![0u8; len];
    expander
        .expand_slice(
            &[
                &len16,
                &[u8::try_from(full_label.len()).expect("short")],
                &full_label,
                &[u8::try_from(context.len()).expect("short")],
                context,
            ],
            &mut out,
        )
        .expect("a short output");
    out
}

fn sha256(data: &[u8]) -> Vec<u8> {
    hash::SHA256.hash(data).as_ref().to_vec()
}

fn hmac256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::HMAC_SHA256
        .with_key(key)
        .sign(&[data])
        .as_ref()
        .to_vec()
}

fn aead_pair(secret: &[u8]) -> (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>) {
    let key = expand_label(secret, "key", b"", 16);
    let iv = expand_label(secret, "iv", b"", 12);
    let make_key = || {
        let mut k = [0u8; 32];
        k[..16].copy_from_slice(&key);
        AeadKey::from(k)
    };
    let suite = TLS13_AES_128_GCM_SHA256.tls13().expect("a TLS 1.3 suite");
    (
        suite.aead_alg.encrypter(
            make_key(),
            Iv::from(<[u8; 12]>::try_from(iv.as_slice()).expect("12 bytes")),
        ),
        suite.aead_alg.decrypter(
            make_key(),
            Iv::from(<[u8; 12]>::try_from(iv.as_slice()).expect("12 bytes")),
        ),
    )
}

/// Opens a record (header included) and returns the inner plaintext without the content type, and
/// the content type.
fn open(decrypter: &mut dyn MessageDecrypter, record: &[u8], seq: u64) -> (Vec<u8>, ContentType) {
    let mut bytes = record.to_vec();
    let (header, body) = bytes.split_at_mut(5);
    assert_eq!(header[0], 0x17);
    let msg =
        InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
    let plain = decrypter.decrypt(msg, seq).expect("the record opens");
    (plain.payload.to_vec(), plain.typ)
}

fn seal(encrypter: &mut dyn MessageEncrypter, typ: ContentType, plain: &[u8], seq: u64) -> Vec<u8> {
    let msg = OutboundPlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_3,
        payload: OutboundChunks::Single(plain),
    };
    encrypter
        .encrypt(msg, seq)
        .expect("the record seals")
        .encode()
}

#[test]
fn the_whole_example_handshake() {
    let t = trace();
    let client_hello = &t["Record_ClientHello_1"][5..];
    let server_hello = &t["Message_ServerHello"];
    assert_eq!(&t["Record_ServerHello"][5..], &server_hello[..]);

    // The key exchange. The client's private key is the second half of its random pool; the server's
    // public key is the last 32 bytes of its key share, which ends the ServerHello's extensions.
    let client_private: [u8; 32] = t["Client_RNG_Pool"][32..64].try_into().expect("32 bytes");
    let server_private: [u8; 32] = t["Server_RNG_Pool"][32..64].try_into().expect("32 bytes");
    let server_public: [u8; 32] = server_hello[server_hello.len() - 6 - 32..server_hello.len() - 6]
        .try_into()
        .expect("32 bytes");
    let client = Started::from_private(client_private);
    let server = Started::from_private(server_private);
    assert_eq!(
        server.pub_key(),
        &server_public,
        "the key share in the ServerHello"
    );
    assert!(
        client_hello.windows(32).any(|w| w == client.pub_key()),
        "the client's public key is in its ClientHello"
    );
    let from_client = Box::new(client).complete(&server_public).expect("exchange");
    let client_public = t["Record_ClientHello_1"]
        .windows(32)
        .find(|w| *w == Started::from_private(client_private).pub_key())
        .expect("found above")
        .to_vec();
    let from_server = Box::new(server).complete(&client_public).expect("exchange");
    assert_eq!(from_client.secret_bytes(), from_server.secret_bytes());
    let ecdhe = from_client.secret_bytes().to_vec();

    // The key schedule.
    let hkdf = HkdfUsingHmac(&hmac::HMAC_SHA256);
    let empty = sha256(b"");
    let early = hkdf.extract_from_zero_ikm(None);
    let _ = early;
    let early_secret = hmac256(&[0u8; 32], &[0u8; 32]);
    let derived = expand_label(&early_secret, "derived", &empty, 32);
    let handshake_secret = hmac256(&derived, &ecdhe);
    let hello_hash = sha256(&[client_hello, &server_hello[..]].concat());
    let c_hs = expand_label(&handshake_secret, "c hs traffic", &hello_hash, 32);
    let s_hs = expand_label(&handshake_secret, "s hs traffic", &hello_hash, 32);

    // The server's flight, encrypted with the server handshake keys: four messages and the inner type.
    let (mut server_enc, mut server_dec) = aead_pair(&s_hs);
    let (flight, typ) = open(&mut *server_dec, &t["Record_ServerHandshakeMessages"], 0);
    assert_eq!(typ, ContentType::Handshake);
    let messages = [
        &t["Message_EncryptedExtensions"],
        &t["Message_Server_Certificate"],
        &t["Message_Server_CertificateVerify"],
        &t["Message_Server_Finished"],
    ];
    let sent: Vec<u8> = messages.iter().flat_map(|m| m.iter().copied()).collect();
    assert_eq!(flight, sent);
    // And sealing it again gives the very same bytes.
    assert_eq!(
        seal(&mut *server_enc, ContentType::Handshake, &flight, 0),
        t["Record_ServerHandshakeMessages"]
    );

    // The server's Finished: HMAC over the transcript up to the CertificateVerify.
    let through_verify = [
        client_hello,
        &server_hello[..],
        messages[0],
        messages[1],
        messages[2],
    ]
    .concat();
    let finished_key = expand_label(&s_hs, "finished", b"", 32);
    let verify_data = hmac256(&finished_key, &sha256(&through_verify));
    assert_eq!(
        &messages[3][4..],
        &verify_data[..],
        "the server's verify data"
    );

    // The client's Finished, under the client handshake keys: HMAC over the transcript through the
    // server's Finished.
    let through_finished = [&through_verify[..], messages[3]].concat();
    let (_, mut client_dec) = aead_pair(&c_hs);
    let (client_finished, typ) = open(&mut *client_dec, &t["Record_ClientFinished"], 0);
    assert_eq!(typ, ContentType::Handshake);
    let client_finished_key = expand_label(&c_hs, "finished", b"", 32);
    let want = hmac256(&client_finished_key, &sha256(&through_finished));
    assert_eq!(&client_finished[..4], &[0x14, 0, 0, 0x20]);
    assert_eq!(&client_finished[4..], &want[..], "the client's verify data");

    // The application keys, from the master secret.
    let derived = expand_label(&handshake_secret, "derived", &empty, 32);
    let master = hmac256(&derived, &[0u8; 32]);
    let transcript = sha256(&through_finished);
    let c_ap = expand_label(&master, "c ap traffic", &transcript, 32);
    let s_ap = expand_label(&master, "s ap traffic", &transcript, 32);
    let (mut client_enc, mut client_dec) = aead_pair(&c_ap);
    let (mut server_enc, mut server_dec) = aead_pair(&s_ap);
    let from_client = &t["Client_AppData"];
    let from_server = &t["Server_AppData"];
    assert_eq!(from_client.len(), 50);
    assert_eq!(
        seal(
            &mut *client_enc,
            ContentType::ApplicationData,
            from_client,
            0
        ),
        t["Record_Client_AppData"]
    );
    assert_eq!(
        // The server's first record under these keys was its NewSessionTicket, so this is number 1.
        seal(
            &mut *server_enc,
            ContentType::ApplicationData,
            from_server,
            1
        ),
        t["Record_Server_AppData"]
    );
    assert_eq!(
        open(&mut *client_dec, &t["Record_Client_AppData"], 0),
        (from_client.clone(), ContentType::ApplicationData)
    );
    assert_eq!(
        open(&mut *server_dec, &t["Record_Server_AppData"], 1),
        (from_server.clone(), ContentType::ApplicationData)
    );
}

#[test]
fn a_record_with_a_changed_bit_or_the_wrong_sequence_number_does_not_open() {
    let t = trace();
    let secret = [0x42u8; 32];
    let (_, mut dec) = aead_pair(&secret);
    let (mut enc, _) = aead_pair(&secret);
    let record = seal(&mut *enc, ContentType::ApplicationData, b"hello", 5);
    // The right number opens it.
    let mut ok = record.clone();
    let (head, body) = ok.split_at_mut(5);
    assert_eq!(head[0], 0x17);
    let msg =
        InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
    assert!(dec.decrypt(msg, 5).is_ok());
    // Another sequence number, a flipped bit anywhere, and a record cut short do not.
    for bad_seq in [4u64, 6, 0] {
        let mut r = record.clone();
        let (_, body) = r.split_at_mut(5);
        let msg =
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
        assert!(dec.decrypt(msg, bad_seq).is_err());
    }
    for i in 5..record.len() {
        let mut r = record.clone();
        r[i] ^= 1;
        let (_, body) = r.split_at_mut(5);
        let msg =
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
        assert!(dec.decrypt(msg, 5).is_err(), "byte {i}");
    }
    for keep in 0..21 {
        let mut r = record[..5 + keep.min(record.len() - 5)].to_vec();
        let (_, body) = r.split_at_mut(5);
        let msg =
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, body);
        assert!(dec.decrypt(msg, 5).is_err(), "cut to {keep}");
    }
    let _ = t;
}
