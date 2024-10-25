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
#![cfg_attr(
    all(feature = "getrandom", feature = "heapless", feature = "std"),
    doc = "```"
)]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "heapless", feature = "std")),
    doc = "```ignore"
)]
//! use xaes_256_gcm::{
//!     Xaes256Gcm, Nonce, Key,
//!     aead::{Aead, AeadCore, KeyInit, OsRng},
//! };
//!
//! # fn gen_key() -> Result<(), core::array::TryFromSliceError> {
//! // The encryption key can be generated randomly:
//! # #[cfg(all(feature = "getrandom", feature = "std"))] {
//! let key = Xaes256Gcm::generate_key().expect("generate key");
//! # }
//!
//! // Transformed from a byte array:
//! let key: &[u8; 32] = &[42; 32];
//! let key: &Key = key.into();
//!
//! // Note that you can get byte array from slice using the `TryInto` trait:
//! let key: &[u8] = &[42; 32];
//! let key: [u8; 32] = key.try_into()?;
//! # Ok(()) }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Alternatively, the key can be transformed directly from a byte slice
//! // (panics on length mismatch):
//! # let key: &[u8] = &[42; 32];
//! let key = <Key>::from_slice(key);
//!
//! let cipher = Xaes256Gcm::new(&key);
//! let nonce = Xaes256Gcm::generate_nonce()?; // 192-bits
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```

pub use aead;
pub use aes;
pub use aes_gcm;

use core::ops::{Div, Mul};

use aead::{array::Array, AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser};
use aes::Aes256;
use aes_gcm::Aes256Gcm;
use cipher::{consts::U2, BlockCipherEncrypt, BlockSizeUser};

/// XAES-256-GCM
#[derive(Clone)]
pub struct Xaes256Gcm {
    aes: Aes256,
    k1: Block,
}

type KeySize = <Aes256Gcm as KeySizeUser>::KeySize;
type NonceSize = <<Aes256Gcm as AeadCore>::NonceSize as Mul<U2>>::Output;
type TagSize = <Aes256Gcm as AeadCore>::TagSize;
type CiphertextOverhead = <Aes256Gcm as AeadCore>::CiphertextOverhead;
type Block = Array<u8, <Aes256 as BlockSizeUser>::BlockSize>;

/// XAES-256-GCM nonce.
pub type Nonce<Size = NonceSize> = aes_gcm::Nonce<Size>;

/// XAES-256-GCM key.
pub type Key<B = Aes256> = aes_gcm::Key<B>;

/// XAES-256-GCM tag.
pub type Tag<Size = TagSize> = aes_gcm::Tag<Size>;

/// Maximum length of plaintext.
pub const P_MAX: u64 = 1 << 36;

/// Maximum length of associated data.
// pub const A_MAX: u64 = 1 << 61;
pub const A_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext.
pub const C_MAX: u64 = (1 << 36) + 16;

impl AeadCore for Xaes256Gcm {
    type NonceSize = NonceSize;
    type TagSize = TagSize;
    type CiphertextOverhead = CiphertextOverhead;
}

impl KeySizeUser for Xaes256Gcm {
    type KeySize = KeySize;
}

impl KeyInit for Xaes256Gcm {
    // Implements step 1 and 2 of the spec.
    fn new(key: &Key) -> Self {
        let aes = Aes256::new(key);

        // L = AES-256ₖ(0¹²⁸)
        let mut k1 = Block::default();
        aes.encrypt_block(&mut k1);

        // If MSB₁(L) = 0 then K1 = L << 1 Else K1 = (L << 1) ⊕ 0¹²⁰10000111
        let mut msb = 0;
        for i in (0..k1.len()).rev() {
            let new_msb = k1[i] >> 7;
            k1[i] = (k1[i] << 1) | msb;
            msb = new_msb;
        }

        let b = k1.len() - 1;
        k1[b] ^= msb * 0b10000111;

        Self { aes, k1 }
    }
}

impl AeadInPlace for Xaes256Gcm {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let (n1, n) = nonce.split_ref::<<NonceSize as Div<U2>>::Output>();
        let k = self.derive_key(n1);
        Aes256Gcm::new(&k).encrypt_in_place_detached(n, associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(Error);
        }

        let (n1, n) = nonce.split_ref::<<NonceSize as Div<U2>>::Output>();
        let k = self.derive_key(n1);
        Aes256Gcm::new(&k).decrypt_in_place_detached(n, associated_data, buffer, tag)
    }
}

impl Xaes256Gcm {
    // Implements steps 3 - 5 of the spec.
    fn derive_key(&self, n1: &Nonce<<NonceSize as Div<U2>>::Output>) -> Key<Aes256Gcm> {
        // M1 = 0x00 || 0x01 || X || 0x00 || N[:12]
        let mut m1 = Block::default();
        m1[..4].copy_from_slice(&[0, 1, b'X', 0]);
        m1[4..].copy_from_slice(n1);

        // M2 = 0x00 || 0x02 || X || 0x00 || N[:12]
        let mut m2 = Block::default();
        m2[..4].copy_from_slice(&[0, 2, b'X', 0]);
        m2[4..].copy_from_slice(n1);

        // Kₘ = AES-256ₖ(M1 ⊕ K1)
        // Kₙ = AES-256ₖ(M2 ⊕ K1)
        // Kₓ = Kₘ || Kₙ = AES-256ₖ(M1 ⊕ K1) || AES-256ₖ(M2 ⊕ K1)
        let mut key: Key<Aes256Gcm> = Array::default();
        let (km, kn) = key.split_ref_mut::<<KeySize as Div<U2>>::Output>();
        for i in 0..km.len() {
            km[i] = m1[i] ^ self.k1[i];
        }
        for i in 0..kn.len() {
            kn[i] = m2[i] ^ self.k1[i];
        }

        self.aes.encrypt_block(km);
        self.aes.encrypt_block(kn);
        key
    }
}
