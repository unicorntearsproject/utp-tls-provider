// SPDX-License-Identifier: MIT OR Apache-2.0

//! HMAC over SHA-256 and SHA-384, which rustls turns into HKDF.

use alloc::boxed::Box;

use hmac::Mac;
use rustls::crypto::hmac::{Hmac, Key, Tag};
use sha2::{Sha256, Sha384};

macro_rules! hmac_for {
    ($alg:ident, $name:ident, $key:ident, $hash:ty, $len:expr) => {
        pub(crate) struct $name;

        pub(crate) static $alg: $name = $name;

        impl Hmac for $name {
            fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
                Box::new($key(
                    hmac::Hmac::<$hash>::new_from_slice(key)
                        .expect("invariant: HMAC takes a key of any length"),
                ))
            }

            fn hash_output_len(&self) -> usize {
                $len
            }
        }

        struct $key(hmac::Hmac<$hash>);

        impl Key for $key {
            fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
                let mut mac = self.0.clone();
                mac.update(first);
                for part in middle {
                    mac.update(part);
                }
                mac.update(last);
                Tag::new(&mac.finalize().into_bytes()[..])
            }

            fn tag_len(&self) -> usize {
                $len
            }
        }
    };
}

hmac_for!(HMAC_SHA256, HmacSha256, KeySha256, Sha256, 32);
hmac_for!(HMAC_SHA384, HmacSha384, KeySha384, Sha384, 48);
