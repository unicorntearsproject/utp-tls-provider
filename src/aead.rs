// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TLS 1.3 record protection: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
//!
//! One implementation, generic over the cipher. A record is the plaintext, then its real content
//! type, then the 16-byte tag; the nonce is the traffic IV xor the sequence number; the additional
//! data is the record header (RFC 8446 section 5.2).

use alloc::boxed::Box;

use aead::consts::{U12, U16};
use aead::{AeadInPlace, KeyInit};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

/// The length of the tag at the end of every record.
const TAG_LEN: usize = 16;

/// A cipher of the RustCrypto family with a 12-byte nonce and a 16-byte tag.
pub(crate) struct Cipher<A>(core::marker::PhantomData<fn() -> A>);

impl<A> Cipher<A> {
    pub(crate) const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

pub(crate) type Aes128Gcm = aes_gcm::Aes128Gcm;
pub(crate) type Aes256Gcm = aes_gcm::Aes256Gcm;
pub(crate) type ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;

pub(crate) static AES_128_GCM: Cipher<Aes128Gcm> = Cipher::new();
pub(crate) static AES_256_GCM: Cipher<Aes256Gcm> = Cipher::new();
pub(crate) static CHACHA20_POLY1305: Cipher<ChaCha20Poly1305> = Cipher::new();

impl<A> Tls13AeadAlgorithm for Cipher<A>
where
    A: AeadInPlace<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static,
{
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Record::<A>::new(&key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Record::<A>::new(&key, iv))
    }

    fn key_len(&self) -> usize {
        A::key_size()
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // Handing the keys to the kernel's TLS is not something this provider does.
        Err(UnsupportedOperationError)
    }
}

/// One direction of a connection: the cipher keyed, and the IV.
struct Record<A> {
    cipher: A,
    iv: Iv,
}

impl<A: KeyInit> Record<A> {
    fn new(key: &AeadKey, iv: Iv) -> Self {
        // rustls hands over a key of the length `key_len` said; if a longer one ever came, the
        // first bytes are the key. A shorter one cannot be: stopping beats a key of zeros.
        let bytes = key.as_ref().get(..A::key_size());
        #[allow(clippy::expect_used)]
        let cipher = A::new_from_slice(bytes.expect("invariant: the key is key_len() bytes"))
            .expect("invariant: the key is key_len() bytes");
        Self { cipher, iv }
    }
}

impl<A> Record<A>
where
    A: AeadInPlace<NonceSize = U12, TagSize = U16>,
{
    fn nonce(&self, seq: u64) -> aead::Nonce<A> {
        aead::Nonce::<A>::from(Nonce::new(&self.iv, seq).0)
    }
}

impl<A> MessageEncrypter for Record<A>
where
    A: AeadInPlace<NonceSize = U12, TagSize = U16> + Send + Sync,
{
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                &self.nonce(seq),
                &make_tls13_aad(total_len),
                payload.as_mut(),
            )
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl<A> MessageDecrypter for Record<A>
where
    A: AeadInPlace<NonceSize = U12, TagSize = U16> + Send + Sync,
{
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let total_len = payload.len();
        let body_len = total_len
            .checked_sub(TAG_LEN)
            .ok_or(rustls::Error::DecryptError)?;
        let aad = make_tls13_aad(total_len);
        let nonce = self.nonce(seq);
        let (body, tag) = payload.split_at_mut(body_len);
        let tag: [u8; TAG_LEN] = (&*tag)
            .try_into()
            .map_err(|_| rustls::Error::DecryptError)?;
        let tag = aead::Tag::<A>::from(tag);
        self.cipher
            .decrypt_in_place_detached(&nonce, &aad, body, &tag)
            .map_err(|_| rustls::Error::DecryptError)?;
        payload.truncate(body_len);
        m.into_tls13_unpadded_message()
    }
}
