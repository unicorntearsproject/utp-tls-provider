// SPDX-License-Identifier: MIT OR Apache-2.0

//! X25519 key exchange (RFC 7748). The only group offered: every TLS 1.3 server has it.

use alloc::boxed::Box;

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use zeroize::Zeroize;

/// The X25519 group.
#[derive(Debug)]
pub(crate) struct X25519;

/// The group, for the provider's list.
pub(crate) static X25519_GROUP: X25519 = X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut private = [0u8; 32];
        getrandom::getrandom(&mut private).map_err(|_| Error::FailedToGetRandomBytes)?;
        Ok(Box::new(Started::from_private(private)))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// A key pair made for one handshake.
pub(crate) struct Started {
    private: [u8; 32],
    public: [u8; 32],
}

impl Started {
    /// The key pair for `private` (the scalar is clamped as the RFC says, by the library).
    pub(crate) fn from_private(private: [u8; 32]) -> Self {
        let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
        Self { private, public }
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl ActiveKeyExchange for Started {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let mut shared = x25519_dalek::x25519(self.private, peer);
        // A point of small order gives all zeros whatever our key is (RFC 7748, section 6.1): the
        // peer picked the secret, so the exchange is refused.
        let zero = shared.iter().fold(0u8, |all, b| all | b) == 0;
        let secret = SharedSecret::from(&shared[..]);
        shared.zeroize();
        if zero {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
