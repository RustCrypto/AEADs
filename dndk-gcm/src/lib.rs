#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use dndk_gcm::{
//!     aead::{Aead, AeadCore, Key, KeyInit},
//!     DndkGcm, Nonce
//! };
//!
//! let key = Key::<DndkGcm>::from_slice(&[0u8; 32]);
//! let cipher = DndkGcm::new(key);
//! let nonce = Nonce::from_slice(&[0u8; 24]); // 192-bits; MUST be unique per message
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```

pub use aead;
pub use aes;
pub use aes_gcm;

use aead::{
    AeadCore, AeadInOut, Error, KeyInit, KeySizeUser, TagPosition, array::Array, inout::InOutBuf,
};
use aes::Aes256;
use aes_gcm::Aes256Gcm;
use cipher::{BlockCipherEncrypt, BlockSizeUser, consts::U12};

/// DNDK-GCM with a 24-byte nonce (KC_Choice = 0).
#[derive(Clone)]
pub struct DndkGcm {
    aes: Aes256,
}

type KeySize = <Aes256Gcm as KeySizeUser>::KeySize;

/// DNDK-GCM nonce (24 bytes).
pub type Nonce = aes_gcm::Nonce<cipher::consts::U24>;

/// DNDK-GCM key.
pub type Key<B = Aes256> = aes_gcm::Key<B>;

/// DNDK-GCM tag.
pub type Tag<Size = <Aes256Gcm as AeadCore>::TagSize> = aes_gcm::Tag<Size>;

/// Maximum length of plaintext.
pub const P_MAX: u64 = (1 << 36) - 32;

/// Maximum length of associated data.
pub const A_MAX: u64 = (1 << 61) - 1;

/// Maximum length of ciphertext.
pub const C_MAX: u64 = (1 << 36) - 32;

impl AeadCore for DndkGcm {
    type NonceSize = cipher::consts::U24;
    type TagSize = <Aes256Gcm as AeadCore>::TagSize;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl KeySizeUser for DndkGcm {
    type KeySize = KeySize;
}

impl KeyInit for DndkGcm {
    fn new(key: &Key) -> Self {
        Self {
            aes: Aes256::new(key),
        }
    }
}

impl AeadInOut for DndkGcm {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let (gcm_iv, key) = derive_key_and_iv::<24>(&self.aes, nonce.as_slice());
        Aes256Gcm::new(&key).encrypt_inout_detached(&gcm_iv, associated_data, buffer)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let (gcm_iv, key) = derive_key_and_iv::<24>(&self.aes, nonce.as_slice());
        Aes256Gcm::new(&key).decrypt_inout_detached(&gcm_iv, associated_data, buffer, tag)
    }
}

type Block = Array<u8, <Aes256 as BlockSizeUser>::BlockSize>;

type GcmIv = aes_gcm::Nonce<U12>;

type DerivedKey = Key<Aes256Gcm>;

fn derive_key_and_iv<const LN: usize>(aes: &Aes256, nonce: &[u8]) -> (GcmIv, DerivedKey) {
    debug_assert_eq!(nonce.len(), LN);

    // Algorithm 1 (KC_Choice = 0): pad nonce, split into head/tail, derive DK and 12-byte IV.
    let mut npadded = [0u8; 27];
    npadded[..LN].copy_from_slice(nonce);

    let mut gcm_iv = GcmIv::default();
    gcm_iv.copy_from_slice(&npadded[15..27]);

    let config_byte = 8u8 * ((LN - 12) as u8);

    let mut b0 = Block::default();
    b0[..15].copy_from_slice(&npadded[..15]);
    b0[15] = config_byte;

    let mut b1 = b0;
    b1[15] = config_byte.wrapping_add(1);

    let mut b2 = b0;
    b2[15] = config_byte.wrapping_add(2);

    let mut x0 = b0;
    let mut x1 = b1;
    let mut x2 = b2;
    aes.encrypt_block(&mut x0);
    aes.encrypt_block(&mut x1);
    aes.encrypt_block(&mut x2);

    let mut y1 = x1;
    let mut y2 = x2;
    for i in 0..y1.len() {
        y1[i] ^= x0[i];
        y2[i] ^= x0[i];
    }

    let mut key = DerivedKey::default();
    key[..16].copy_from_slice(&y1);
    key[16..].copy_from_slice(&y2);

    (gcm_iv, key)
}
