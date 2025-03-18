#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
#![cfg_attr(feature = "os_rng", doc = "```")]
#![cfg_attr(not(feature = "os_rng"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use deoxys::{
//!     aead::{Aead, AeadCore, KeyInit, rand_core::OsRng},
//!     DeoxysII256, // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//!     Nonce // Or `Aes128Gcm`
//! };
//!
//! let key = DeoxysII256::generate_key().expect("Generate key");
//! let cipher = DeoxysII256::new(&key);
//! let nonce = DeoxysII256::generate_nonce().expect("Generate nonce"); // 120-bits; unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! ## Usage with AAD
//! Deoxys can authenticate additional data that is not encrypted alongside with the ciphertext.
//! ```
//! use deoxys::{DeoxysII256, Nonce}; // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//! use deoxys::aead::{Aead, AeadCore, KeyInit, Payload, rand_core::OsRng};
//!
//! let key = DeoxysII256::generate_key().expect("generate key");
//! let cipher = DeoxysII256::new(&key);
//!
//! let nonce = DeoxysII256::generate_nonce().expect("generate nonce"); // 120-bits; unique per message
//!
//! let payload = Payload {
//!    msg: &b"this will be encrypted".as_ref(),
//!    aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let ciphertext = cipher.encrypt(&nonce, payload)
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let payload = Payload {
//!    msg: &ciphertext,
//!    aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let plaintext = cipher.decrypt(&nonce, payload)
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"this will be encrypted");
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`AeadInOut::encrypt_in_place`] and [`AeadInOut::decrypt_in_place`]
//! methods accept any type that impls the [`aead::Buffer`] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of [`aead::Buffer`] for `heapless::Vec`
//! (re-exported from the [`aead`] crate as [`aead::heapless::Vec`]),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```
//! # #[cfg(feature = "heapless")]
//! # {
//! use deoxys::{DeoxysII256, Nonce}; // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//! use deoxys::aead::{AeadCore, AeadInOut, KeyInit, rand_core::OsRng, heapless::Vec};
//!
//! let key = DeoxysII256::generate_key().expect("generate key");
//! let cipher = DeoxysII256::new(&key);
//!
//! let nonce = DeoxysII256::generate_nonce().expect("generate nonce"); // 120-bits; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! Similarly, enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]), and enabling the `bytes` feature of this crate will
//! provide an impl of [`aead::Buffer`] for `bytes::BytesMut` (re-exported from the
//! [`aead`] crate as [`aead::bytes::BytesMut`]).

/// Deoxys-BC implementations.
mod deoxys_bc;

/// Operation modes for Deoxys.
mod modes;

pub use aead::{self, AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, consts};

use aead::{
    TagPosition,
    array::{Array, ArraySize},
    consts::U16,
    inout::{InOut, InOutBuf},
};
use core::marker::PhantomData;

/// Deoxys-I with 128-bit keys
pub type DeoxysI128 = Deoxys<modes::DeoxysI<deoxys_bc::DeoxysBc256>, deoxys_bc::DeoxysBc256>;

/// Deoxys-I with 256-bit keys
pub type DeoxysI256 = Deoxys<modes::DeoxysI<deoxys_bc::DeoxysBc384>, deoxys_bc::DeoxysBc384>;

/// Deoxys-II with 128-bit keys
#[allow(clippy::upper_case_acronyms)]
pub type DeoxysII128 = Deoxys<modes::DeoxysII<deoxys_bc::DeoxysBc256>, deoxys_bc::DeoxysBc256>;

/// Deoxys-II with 256-bit keys
#[allow(clippy::upper_case_acronyms)]
pub type DeoxysII256 = Deoxys<modes::DeoxysII<deoxys_bc::DeoxysBc384>, deoxys_bc::DeoxysBc384>;

/// Deoxys nonces
pub type Nonce<NonceSize> = Array<u8, NonceSize>;

/// Deoxys tags
pub type Tag = Array<u8, U16>;

type Block = Array<u8, U16>;

type Tweak = Array<u8, U16>;

type DeoxysKey = Array<u8, U16>;

/// Deoxys encryption modes.
/// This type contains the public API for a Deoxys mode, like Deoxys-I and Deoxys-II.
pub trait DeoxysMode<B>: modes::DeoxysModeInternal<B>
where
    B: DeoxysBcType,
{
    /// The size of the required nonce
    type NonceSize: ArraySize;

    /// Encrypts the data in place with the specified parameters
    /// Returns the tag
    fn encrypt_inout(
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
    ) -> Tag;

    /// Decrypts the data in place with the specified parameters
    /// Returns an error if the tag verification fails
    fn decrypt_inout(
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag,
        subkeys: &Array<DeoxysKey, B::SubkeysSize>,
    ) -> Result<(), aead::Error>;
}

/// Deoxys-BC trait.
/// This type contains the public API for Deoxys-BC implementations, which varies depending on the size of the key.
pub trait DeoxysBcType: deoxys_bc::DeoxysBcInternal {
    /// The size of the required tweakey.
    type KeySize: ArraySize;

    /// Precompute the subkeys
    fn precompute_subkeys(key: &Array<u8, Self::KeySize>) -> Array<DeoxysKey, Self::SubkeysSize>;

    /// Encrypts a block of data in place.
    fn encrypt_inout(
        mut block: InOut<'_, '_, Block>,
        tweak: &Tweak,
        subkeys: &Array<DeoxysKey, Self::SubkeysSize>,
    ) {
        let keys = Self::key_schedule(tweak, subkeys);

        block.xor_in2out(&keys[0]);

        for k in &keys[1..] {
            aes::hazmat::cipher_round(block.get_out(), k);
        }
    }

    /// Decrypts a block of data in place.
    fn decrypt_inout(
        mut block: InOut<'_, '_, Block>,
        tweak: &Tweak,
        subkeys: &Array<DeoxysKey, Self::SubkeysSize>,
    ) {
        let mut keys = Self::key_schedule(tweak, subkeys);

        let r = keys.len();

        block.xor_in2out(&keys[r - 1]);

        aes::hazmat::inv_mix_columns(block.get_out());

        for k in keys[..r - 1].iter_mut().rev() {
            aes::hazmat::inv_mix_columns(k);
            aes::hazmat::equiv_inv_cipher_round(block.get_out(), k);
        }

        aes::hazmat::mix_columns(block.get_out());
    }
}

/// Generic Deoxys implementation.
///
/// This type is generic to support multiple Deoxys modes(namely Deoxys-I and Deoxys-II) and key size.
pub struct Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    subkeys: Array<DeoxysKey, B::SubkeysSize>,
    mode: PhantomData<M>,
}

impl<M, B> KeySizeUser for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    type KeySize = B::KeySize;
}

impl<M, B> KeyInit for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn new(key: &Key<Self>) -> Self {
        Self {
            subkeys: B::precompute_subkeys(key),
            mode: PhantomData,
        }
    }
}

impl<M, B> AeadCore for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    type NonceSize = M::NonceSize;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl<M, B> AeadInOut for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<M::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag, Error> {
        Ok(Tag::from(M::encrypt_inout(
            nonce,
            associated_data,
            buffer,
            &self.subkeys,
        )))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<M::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag,
    ) -> Result<(), Error> {
        M::decrypt_inout(nonce, associated_data, buffer, tag, &self.subkeys)
    }
}

impl<M, B> Drop for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            for s in self.subkeys.iter_mut() {
                s.zeroize();
            }
        }
    }
}

#[cfg(feature = "zeroize")]
impl<M, B> zeroize::ZeroizeOnDrop for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
}
