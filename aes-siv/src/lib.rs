//! [AES-SIV][1] ([RFC 5297][2]): high-performance
//! [Authenticated Encryption with Associated Data (AEAD)][3] cipher which also
//! provides [nonce reuse misuse resistance][4].
//!
//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
//! ```
//! use aes_siv::Aes128SivAead; // Or `Aes256Siv`
//! use aead::{Aead, NewAead, generic_array::GenericArray};
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let aead = Aes128SivAead::new(key);
//!
//! let nonce = GenericArray::from_slice(b"any unique nonce"); // 128-bits; unique per message
//! let ciphertext = aead.encrypt(nonce, b"plaintext message".as_ref()).expect("encryption failure!");
//! let plaintext = aead.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//!
//! ## In-place Usage (eliminates `alloc` requirement)
//!
//! This crate has an optional `alloc` feature which can be disabled in e.g.
//! microcontroller environments that don't have a heap.
//!
//! The [`Aead::encrypt_in_place`][5] and [`Aead::decrypt_in_place`][6]
//! methods accept any type that impls the [`aead::Buffer`][7] trait which
//! contains the plaintext for encryption or ciphertext for decryption.
//!
//! Note that if you enable the `heapless` feature of this crate,
//! you will receive an impl of `aead::Buffer` for [`heapless::Vec`][8]
//! (re-exported from the `aead` crate as `aead::heapless::Vec`),
//! which can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
//! ```
//! use aes_siv::Aes128SivAead; // Or `Aes256SivAead`
//! use aead::{AeadInPlace, NewAead};
//! use aead::generic_array::{GenericArray, typenum::U128};
//! use aead::heapless::Vec;
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let aead = Aes128SivAead::new(key);
//!
//! let nonce = GenericArray::from_slice(b"any unique nonce"); // 128-bits; unique per message
//!
//! let mut buffer: Vec<u8, U128> = Vec::new();
//! buffer.extend_from_slice(b"plaintext message");
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! aead.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(&buffer, b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! aead.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
//! assert_eq!(&buffer, b"plaintext message");
//! ```
//!
//! [1]: https://github.com/miscreant/meta/wiki/AES-SIV
//! [2]: https://tools.ietf.org/html/rfc5297
//! [3]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [4]: https://github.com/miscreant/meta/wiki/Nonce-Reuse-Misuse-Resistance
//! [5]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.encrypt_in_place
//! [6]: https://docs.rs/aead/latest/aead/trait.Aead.html#method.decrypt_in_place
//! [7]: https://docs.rs/aead/latest/aead/trait.Buffer.html
//! [8]: https://docs.rs/heapless/latest/heapless/struct.Vec.html

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use aead;

pub mod siv;

use crate::siv::Siv;
use aead::{
    consts::{U0, U16, U32, U64},
    generic_array::{ArrayLength, GenericArray},
    AeadInPlace, Buffer, Error, NewAead,
};
use aes::{Aes128, Aes256};
use cmac::Cmac;
use core::marker::PhantomData;
use core::ops::Add;
use crypto_mac::{Mac, NewMac};
use ctr::Ctr128;
#[cfg(feature = "pmac")]
use pmac::Pmac;
use stream_cipher::{NewStreamCipher, SyncStreamCipher};

/// Size of an AES-SIV key given a particular cipher
pub type KeySize<C> = <<C as NewStreamCipher>::KeySize as Add>::Output;

/// AES-SIV tags (i.e. the Synthetic Initialization Vector value)
pub type Tag = GenericArray<u8, U16>;

/// The `SivAead` type wraps the more powerful `Siv` interface in a more
/// commonly used Authenticated Encryption with Associated Data (AEAD) API,
/// which accepts a key, nonce, and associated data when encrypting/decrypting.
pub struct SivAead<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
    <C as NewStreamCipher>::KeySize: Add,
    KeySize<C>: ArrayLength<u8>,
{
    key: GenericArray<u8, KeySize<C>>,
    mac: PhantomData<M>, // TODO(tarcieri): include `M` in `KeySize` calculation
}

/// SIV AEAD modes based on CMAC
pub type CmacSivAead<BlockCipher> = SivAead<Ctr128<BlockCipher>, Cmac<BlockCipher>>;

/// SIV AEAD modes based on PMAC
#[cfg(feature = "pmac")]
pub type PmacSivAead<BlockCipher> = SivAead<Ctr128<BlockCipher>, Pmac<BlockCipher>>;

/// AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128SivAead = CmacSivAead<Aes128>;

/// AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256SivAead = CmacSivAead<Aes256>;

/// AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
#[cfg(feature = "pmac")]
pub type Aes128PmacSivAead = PmacSivAead<Aes128>;

/// AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
#[cfg(feature = "pmac")]
pub type Aes256PmacSivAead = PmacSivAead<Aes256>;

impl<M> NewAead for SivAead<Ctr128<Aes128>, M>
where
    M: Mac<OutputSize = U16>,
{
    type KeySize = U32;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            key: *key,
            mac: PhantomData,
        }
    }
}

impl<M> NewAead for SivAead<Ctr128<Aes256>, M>
where
    M: Mac<OutputSize = U16>,
{
    type KeySize = U64;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            key: *key,
            mac: PhantomData,
        }
    }
}

impl<C, M> AeadInPlace for SivAead<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16> + NewMac,
    <C as NewStreamCipher>::KeySize: Add,
    KeySize<C>: ArrayLength<u8>,
{
    // "If the nonce is random, it SHOULD be at least 128 bits in length"
    // https://tools.ietf.org/html/rfc5297#section-3
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt_in_place(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        // "SIV performs nonce-based authenticated encryption when a component of
        // the associated data is a nonce.  For purposes of interoperability the
        // final component -- i.e., the string immediately preceding the
        // plaintext in the vector input to S2V -- is used for the nonce."
        // https://tools.ietf.org/html/rfc5297#section-3
        Siv::<C, M>::new(self.key.clone())
            .encrypt_in_place(&[associated_data, nonce.as_slice()], buffer)
    }

    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error> {
        Siv::<C, M>::new(self.key.clone())
            .encrypt_in_place_detached(&[associated_data, nonce.as_slice()], buffer)
    }

    fn decrypt_in_place(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error> {
        Siv::<C, M>::new(self.key.clone())
            .decrypt_in_place(&[associated_data, nonce.as_slice()], buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        Siv::<C, M>::new(self.key.clone()).decrypt_in_place_detached(
            &[associated_data, nonce.as_slice()],
            buffer,
            tag,
        )
    }
}
