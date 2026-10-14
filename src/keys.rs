// SPDX-License-Identifier: MIT OR Apache-2.0

//! Randomness, and the refusal to load a private key.

use alloc::sync::Arc;

use rustls::crypto::{GetRandomFailed, KeyProvider, SecureRandom};
use rustls::sign::SigningKey;
use rustls::{Error, pki_types::PrivateKeyDer};

/// Randomness from the `getrandom` crate.
#[derive(Debug)]
pub struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::getrandom(buf).map_err(|_| GetRandomFailed)
    }
}

/// The key provider of a provider that cannot sign: every key is refused, so a client configured
/// with a client certificate fails when it is built, not in the middle of a handshake.
#[derive(Debug)]
pub struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "utp-tls-provider cannot sign: it verifies only".into(),
        ))
    }
}
