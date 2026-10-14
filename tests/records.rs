// SPDX-License-Identifier: MIT OR Apache-2.0

//! The record protection of all three suites against records made by an independent
//! implementation (Python's `cryptography`, `tools/records.py`): sealing gives the same bytes,
//! opening gives the plaintext back, and damage of any kind is refused.

use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, OutboundChunks, OutboundPlainMessage,
};
use rustls::{ContentType, ProtocolVersion, SupportedCipherSuite};

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn suite(name: &str) -> SupportedCipherSuite {
    match name {
        "aes128gcm" => utp_tls_provider::TLS13_AES_128_GCM_SHA256,
        "aes256gcm" => utp_tls_provider::TLS13_AES_256_GCM_SHA384,
        "chacha20poly1305" => utp_tls_provider::TLS13_CHACHA20_POLY1305_SHA256,
        other => panic!("unknown suite {other}"),
    }
}

fn key_for(bytes: &[u8]) -> AeadKey {
    let mut k = [0u8; 32];
    k[..bytes.len()].copy_from_slice(bytes);
    AeadKey::from(k)
}

fn content_type(b: u8) -> ContentType {
    ContentType::from(b)
}

#[test]
fn sealing_and_opening_match_the_independent_records() {
    let mut count = 0;
    for line in include_str!("data/records.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let aead = &suite(f[0]).tls13().expect("a TLS 1.3 suite").aead_alg;
        let (key, iv) = (hex(f[1]), hex(f[2]));
        let seq: u64 = f[3].parse().expect("seq");
        let typ = content_type(hex(f[4])[0]);
        let (plain, record) = (hex(f[5]), hex(f[6]));
        let iv = Iv::from(<[u8; 12]>::try_from(iv.as_slice()).expect("12 bytes"));

        let mut enc = aead.encrypter(
            key_for(&key),
            Iv::from(<[u8; 12]>::try_from(iv.as_ref()).unwrap()),
        );
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ,
                    version: ProtocolVersion::TLSv1_3,
                    payload: OutboundChunks::Single(&plain),
                },
                seq,
            )
            .expect("seals")
            .encode();
        assert_eq!(sealed, record, "{line:.60}");

        let mut dec = aead.decrypter(key_for(&key), iv);
        let mut bytes = record.clone();
        let (_, body) = bytes.split_at_mut(5);
        let opened = dec
            .decrypt(
                InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    body,
                ),
                seq,
            )
            .expect("opens");
        assert_eq!((opened.typ, opened.payload), (typ, &plain[..]));
        count += 1;
    }
    assert_eq!(count, 3 * (7 * 4 + 1));
}

#[test]
fn damaged_records_are_refused() {
    for name in ["aes128gcm", "aes256gcm", "chacha20poly1305"] {
        let aead = &suite(name).tls13().expect("a TLS 1.3 suite").aead_alg;
        let key = vec![0x33u8; 16];
        let iv = [0x44u8; 12];
        let mut enc = aead.encrypter(key_for(&key), Iv::from(iv));
        let record = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: ContentType::ApplicationData,
                    version: ProtocolVersion::TLSv1_3,
                    payload: OutboundChunks::Single(b"attack at dawn"),
                },
                9,
            )
            .expect("seals")
            .encode();
        let mut dec = aead.decrypter(key_for(&key), Iv::from(iv));
        let open =
            |dec: &mut Box<dyn rustls::crypto::cipher::MessageDecrypter>, bytes: &[u8], seq| {
                let mut b = bytes.to_vec();
                let (_, body) = b.split_at_mut(5);
                dec.decrypt(
                    InboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        body,
                    ),
                    seq,
                )
                .is_ok()
            };
        assert!(open(&mut dec, &record, 9), "{name}");
        assert!(!open(&mut dec, &record, 8), "{name}: wrong sequence number");
        for i in 5..record.len() {
            let mut r = record.clone();
            r[i] ^= 0x80;
            assert!(!open(&mut dec, &r, 9), "{name}: byte {i}");
        }
        for keep in 0..record.len() - 5 {
            assert!(
                !open(&mut dec, &record[..5 + keep], 9),
                "{name}: cut to {keep}"
            );
        }
    }
}
