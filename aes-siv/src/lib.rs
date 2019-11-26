//! [AES-SIV][1] ([RFC 5297][2]): high-performance
//! [Authenticated Encryption with Associated Data (AEAD)][3] cipher which also
//! provides [nonce reuse misuse resistance][4].
//!
//! [1]: https://github.com/miscreant/meta/wiki/AES-SIV
//! [2]: https://tools.ietf.org/html/rfc5297
//! [3]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [4]: https://github.com/miscreant/meta/wiki/Nonce-Reuse-Misuse-Resistance

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use aead;

pub mod siv;

use crate::siv::Siv;
use aead::generic_array::{
    typenum::{U0, U16, U32, U64},
    GenericArray,
};
use aead::{AeadMut, Buffer, Error, NewAead};
use aes::{Aes128, Aes256};
use cmac::Cmac;
use crypto_mac::Mac;
use ctr::Ctr128;
#[cfg(feature = "pmac")]
use pmac::Pmac;
use stream_cipher::{NewStreamCipher, SyncStreamCipher};

/// AES-SIV tags (i.e. the Synthetic Initialization Vector value)
pub type Tag = GenericArray<u8, U16>;

/// The `SivAead` type wraps the more powerful `Siv` interface in a more
/// commonly used Authenticated Encryption with Associated Data (AEAD) API,
/// which accepts a key, nonce, and associated data when encrypting/decrypting.
pub struct SivAead<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
{
    siv: Siv<C, M>,
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

    fn new(key: GenericArray<u8, Self::KeySize>) -> Self {
        Self { siv: Siv::new(key) }
    }
}

impl<M> NewAead for SivAead<Ctr128<Aes256>, M>
where
    M: Mac<OutputSize = U16>,
{
    type KeySize = U64;

    fn new(key: GenericArray<u8, Self::KeySize>) -> Self {
        Self { siv: Siv::new(key) }
    }
}

impl<C, M> AeadMut for SivAead<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
{
    // "If the nonce is random, it SHOULD be at least 128 bits in length"
    // https://tools.ietf.org/html/rfc5297#section-3
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;

    fn encrypt_in_place(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<(), Error> {
        // "SIV performs nonce-based authenticated encryption when a component of
        // the associated data is a nonce.  For purposes of interoperability the
        // final component -- i.e., the string immediately preceding the
        // plaintext in the vector input to S2V -- is used for the nonce."
        // https://tools.ietf.org/html/rfc5297#section-3
        self.siv
            .encrypt_in_place(&[associated_data, nonce.as_slice()], buffer)
    }

    fn encrypt_in_place_detached(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error> {
        self.siv
            .encrypt_in_place_detached(&[associated_data, nonce.as_slice()], buffer)
    }

    fn decrypt_in_place(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<(), Error> {
        self.siv
            .decrypt_in_place(&[associated_data, nonce.as_slice()], buffer)
    }

    fn decrypt_in_place_detached(
        &mut self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        self.siv
            .decrypt_in_place_detached(&[associated_data, nonce.as_slice()], buffer, tag)
    }
}
