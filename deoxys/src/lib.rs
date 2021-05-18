//! The [Deoxys][2] [Authenticated Encryption and Associated Data (AEAD)][1].
//! The Deoxys-II variant has been selected as the first choice for defense in-depth scenario during the [CAESAR competition][3].
//!
//! ## Performance Notes
//!
//! By default this crate will use software implementations of AES.
//!
//! When targeting modern x86/x86_64 CPUs, use the following `RUSTFLAGS` to
//! take advantage of high performance AES-NI and CLMUL CPU intrinsics:
//!
//! ```text
//! RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
//! ```
//!
//! ## Security Notes
//!
//! This crate has NOT received any security audit and is still in pretty early stage.
//! Although encryption and secryption passes the test vector, there is no guarantee that operations happens in constant time.
//!
//! **USE AT YOUR OWN RISK.**
//!
//! # Usage
//! ```
//! use deoxys::{DeoxysII256, Key, Nonce}; // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//! use deoxys::aead::{Aead, NewAead};
//!
//! let key = Key::from_slice(b"an example very very secret key.");
//! let cipher = DeoxysII256::new(key);
//!
//! let nonce = Nonce::from_slice(b"unique nonce123"); // 64-bits for Deoxys-I or 120-bits for Deoxys-II; unique per message
//!
//! let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
//!     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//!
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! ## Usage with AAD
//! Deoxys can authenticate additionnal data that is not encrypted alongside with the ciphertext.
//! ```
//! use deoxys::{DeoxysII256, Key, Nonce}; // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//! use deoxys::aead::{Aead, NewAead, Payload};
//!
//! let key = Key::from_slice(b"an example very very secret key.");
//! let cipher = DeoxysII256::new(key);
//!
//! let nonce = Nonce::from_slice(b"unique nonce123"); // 64-bits for Deoxys-I or 120-bits for Deoxys-II; unique per message
//!
//!let payload = Payload {
//!    msg: &b"this will be encrypted".as_ref(),
//!    aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//!};
//!
//! let ciphertext = cipher.encrypt(nonce, payload)
//!     .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
//!
//!let payload = Payload {
//!    msg: &ciphertext,
//!    aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//!};
//!
//! let plaintext = cipher.decrypt(nonce, payload)
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
//! use deoxys::{DeoxysII256, Key, Nonce}; // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//! use deoxys::aead::{AeadInPlace, NewAead};
//! use deoxys::aead::heapless::Vec;
//!
//! let key = Key::from_slice(b"an example very very secret key.");
//! let cipher = DeoxysII256::new(key);
//!
//! let nonce = Nonce::from_slice(b"unique nonce123"); // 64-bits for Deoxys-I or 120-bits for Deoxys-II; unique per message
//!
//! let mut buffer: Vec<u8, 128> = Vec::new(); // Buffer needs 16-bytes overhead for tag
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! # }
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [2]: https://sites.google.com/view/deoxyscipher
//! [3]: https://competitions.cr.yp.to/caesar-submissions.html

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

/// Deoxys-BC implementations.
mod deoxys_bc;

/// Operation modes for Deoxys.
mod modes;

/// Reference implementation of AES. Should be replaced with the `aes` crate whenever it exposes its round function
mod aes_ref;

use core::marker::PhantomData;

pub use aead;

use aead::{
    consts::{U0, U16},
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, Error, NewAead,
};

use zeroize::Zeroize;

/// Deoxys-I with 128-bit keys
pub type DeoxysI128 = Deoxys<modes::DeoxysI, deoxys_bc::DeoxysBc256>;

/// Deoxys-I with 256-bit keys
pub type DeoxysI256 = Deoxys<modes::DeoxysI, deoxys_bc::DeoxysBc384>;

/// Deoxys-II with 128-bit keys
#[allow(clippy::upper_case_acronyms)]
pub type DeoxysII128 = Deoxys<modes::DeoxysII, deoxys_bc::DeoxysBc256>;

/// Deoxys-II with 256-bit keys
#[allow(clippy::upper_case_acronyms)]
pub type DeoxysII256 = Deoxys<modes::DeoxysII, deoxys_bc::DeoxysBc384>;

/// Deoxys keys
pub type Key<KeySize> = GenericArray<u8, KeySize>;

/// Deoxys nonces
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// Deoxys tags
pub type Tag = GenericArray<u8, U16>;

/// Deoxys encryption modes.
/// This type contains the public API for a Deoxys mode, like Deoxys-I and Deoxys-II.
pub trait DeoxysMode<B>
where
    B: DeoxysBcType,
{
    /// The size of the required nonce
    type NonceSize: ArrayLength<u8>;

    /// Encrypts the data in place with the specified parameters
    /// Returns the tag
    fn encrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> [u8; 16];

    /// Decrypts the data in place with the specified parameters
    /// Returns an error if the tag verification fails
    fn decrypt_in_place(
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
        key: &GenericArray<u8, B::KeySize>,
    ) -> Result<(), aead::Error>;
}

/// Deoxys-BC trait.
/// This type contains the public API for Deoxys-BC implementations, which varies depending on the size of the key.
pub trait DeoxysBcType: deoxys_bc::DeoxysBcInternal {
    /// The size of the required tweakey.
    type KeySize: ArrayLength<u8>;

    /// Encrypts a block of data in place.
    fn encrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>) {
        let keys: GenericArray<[u8; 16], Self::SubkeysSize> = Self::key_schedule(tweakey);

        aes_ref::add_round_key(block, &keys[0]);

        for k in &keys[1..] {
            aes_ref::encrypt_round(block, k)
        }
    }

    /// Decrypts a block of data in place.
    fn decrypt_in_place(block: &mut [u8], tweakey: &GenericArray<u8, Self::TweakKeySize>) {
        let keys: GenericArray<[u8; 16], Self::SubkeysSize> = Self::key_schedule(tweakey);

        for k in keys[1..].iter().rev() {
            aes_ref::decrypt_round(block, k)
        }

        aes_ref::add_round_key(block, &keys[0]);
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
    key: Key<B::KeySize>,
    mode: PhantomData<M>,
}

impl<M, B> NewAead for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    type KeySize = B::KeySize;

    fn new(key: &Key<B::KeySize>) -> Self {
        Self {
            key: key.clone(),
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
            nonce.as_slice(),
            associated_data,
            buffer,
            &self.key,
        )))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<M::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        M::decrypt_in_place(nonce, associated_data, buffer, tag, &self.key)
    }
}

impl<M, B> Drop for Deoxys<M, B>
where
    M: DeoxysMode<B>,
    B: DeoxysBcType,
{
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
