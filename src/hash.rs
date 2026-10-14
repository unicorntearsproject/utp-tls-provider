// SPDX-License-Identifier: MIT OR Apache-2.0

//! SHA-256 and SHA-384 for the handshake transcript and the key schedule.

use alloc::boxed::Box;
use core::marker::PhantomData;

use digest::Digest;
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha2::{Sha256, Sha384};

/// A hash function of the `sha2` crate, as rustls wants it.
pub(crate) struct Sha<D>(HashAlgorithm, PhantomData<fn() -> D>);

impl<D> Sha<D> {
    const fn new(algorithm: HashAlgorithm) -> Self {
        Self(algorithm, PhantomData)
    }
}

pub(crate) static SHA256: Sha<Sha256> = Sha::new(HashAlgorithm::SHA256);
pub(crate) static SHA384: Sha<Sha384> = Sha::new(HashAlgorithm::SHA384);

impl<D: Digest + Clone + Send + Sync + 'static> Hash for Sha<D> {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Running(D::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&D::digest(data)[..])
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.0
    }
}

/// A transcript hash in progress.
struct Running<D>(D);

impl<D: Digest + Clone + Send + Sync + 'static> Context for Running<D> {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Running(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }
}
