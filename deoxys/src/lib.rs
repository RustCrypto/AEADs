#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
#![cfg_attr(all(feature = "getrandom", feature = "std"), doc = "```")]
#![cfg_attr(not(all(feature = "getrandom", feature = "std")), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use deoxys::{
//!     aead::{Aead, AeadCore, KeyInit, OsRng},
//!     DeoxysII256, // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//!     Nonce // Or `Aes128Gcm`
//! };
//!
//! let key = DeoxysII256::generate_key(&mut OsRng);
//! let cipher = DeoxysII256::new(&key);
//! let nonce = DeoxysII256::generate_nonce(&mut OsRng); // 120-bits; unique per message
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
//! use deoxys::aead::{Aead, AeadCore, KeyInit, Payload, OsRng};
//!
//! let key = DeoxysII256::generate_key(&mut OsRng);
//! let cipher = DeoxysII256::new(&key);
//!
//! let nonce = DeoxysII256::generate_nonce(&mut OsRng); // 120-bits; unique per message
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
//! The [`AeadInPlace::encrypt_in_place`] and [`AeadInPlace::decrypt_in_place`]
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
//! use deoxys::aead::{AeadCore, AeadInPlace, KeyInit, OsRng, heapless::Vec};
//!
//! let key = DeoxysII256::generate_key(&mut OsRng);
//! let cipher = DeoxysII256::new(&key);
//!
//! let nonce = DeoxysII256::generate_nonce(&mut OsRng); // 120-bits; unique per message
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
//! [`aead::arrayvec::ArrayVec`]).

/// Deoxys-BC implementations.
mod deoxys_bc;

/// Operation modes for Deoxys.
mod modes;

pub use aead::{self, consts, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};

use aead::{
    consts::{U0, U16},
    generic_array::{ArrayLength, GenericArray},
};
use core::marker::PhantomData;

use zeroize::Zeroize;

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
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// Deoxys tags
pub type Tag = GenericArray<u8, U16>;

/// Deoxys encryption modes.
/// This type contains the public API for a Deoxys mode, like Deoxys-I and Deoxys-II.
pub trait DeoxysMode<B>: modes::DeoxysModeInternal<B>
where
    B: DeoxysBcType,
{
    /// The size of the required nonce
    type NonceSize: ArrayLength<u8>;

    /// Encrypts the data in place with the specified parameters
    /// Returns the tag
    fn encrypt_in_place(
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        subkeys: &GenericArray<[u8; 16], B::SubkeysSize>,
    ) -> [u8; 16];

    /// Decrypts the data in place with the specified parameters
    /// Returns an error if the tag verification fails
    fn decrypt_in_place(
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
        subkeys: &GenericArray<[u8; 16], B::SubkeysSize>,
    ) -> Result<(), aead::Error>;
}

/// Deoxys-BC trait.
/// This type contains the public API for Deoxys-BC implementations, which varies depending on the size of the key.
pub trait DeoxysBcType: deoxys_bc::DeoxysBcInternal {
    /// The size of the required tweakey.
    type KeySize: ArrayLength<u8>;

    /// Precompute the subkeys
    fn precompute_subkeys(
        key: &GenericArray<u8, Self::KeySize>,
    ) -> GenericArray<[u8; 16], Self::SubkeysSize>;

    /// Encrypts a block of data in place.
    fn encrypt_in_place(
        block: &mut [u8; 16],
        tweak: &[u8; 16],
        subkeys: &GenericArray<[u8; 16], Self::SubkeysSize>,
    ) {
        let keys = Self::key_schedule(tweak, subkeys);

        for (b, k) in block.iter_mut().zip(keys[0].iter()) {
            *b ^= k;
        }

        for k in &keys[1..] {
            aes::hazmat::cipher_round(block.into(), k.into());
        }
    }

    /// Decrypts a block of data in place.
    fn decrypt_in_place(
        block: &mut [u8; 16],
        tweak: &[u8; 16],
        subkeys: &GenericArray<[u8; 16], Self::SubkeysSize>,
    ) {
        let mut keys = Self::key_schedule(tweak, subkeys);

        let r = keys.len();

        for (b, k) in block.iter_mut().zip(keys[r - 1].iter()) {
            *b ^= k;
        }

        aes::hazmat::inv_mix_columns(block.into());

        for k in keys[..r - 1].iter_mut().rev() {
            aes::hazmat::inv_mix_columns(k.into());
            aes::hazmat::equiv_inv_cipher_round(block.into(), (&*k).into());
        }

        aes::hazmat::mix_columns(block.into());
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
    subkeys: GenericArray<[u8; 16], B::SubkeysSize>,
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
    type CiphertextOverhead = U0;
}

impl<M, B> AeadInPlace for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<M::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Ok(Tag::from(M::encrypt_in_place(
            nonce,
            associated_data,
            buffer,
            &self.subkeys,
        )))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<M::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        M::decrypt_in_place(nonce, associated_data, buffer, tag, &self.subkeys)
    }
}

impl<M, B> Drop for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn drop(&mut self) {
        for s in self.subkeys.iter_mut() {
            s.zeroize();
        }
    }
}
