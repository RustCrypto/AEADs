#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

//! # Usage
//!
//! Simple usage (allocating, no associated data):
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use aes_siv::{
//!     aead::{Aead, AeadCore, Generate, Key, KeyInit},
//!     Aes256SivAead, Nonce // Or `Aes128SivAead`
//! };
//!
//! let key = Key::<Aes256SivAead>::generate();
//! let cipher = Aes256SivAead::new(&key);
//!
//! let nonce = Nonce::generate(); // MUST be unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//!
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod siv;

pub use aead::{self, AeadCore, AeadTagPosition, Error, Key, KeyInit, KeySizeUser};

use crate::siv::Siv;
use aead::{
    TagPosition,
    array::Array,
    consts::{U1, U16, U32, U64},
    inout::InOutBuf,
};
use aes::{Aes128, Aes256};
use cipher::{BlockCipherEncrypt, BlockSizeUser, array::ArraySize, typenum::IsGreaterOrEqual};
use cmac::Cmac;
use core::{marker::PhantomData, ops::Add};
use digest::{FixedOutputReset, Mac};

#[cfg(feature = "pmac")]
use pmac::Pmac;

/// AES-SIV nonces
pub type Nonce<NonceSize = U16> = Array<u8, NonceSize>;

/// AES-SIV tags (i.e. the Synthetic Initialization Vector value)
pub type Tag = Array<u8, U16>;

/// Convenience wrapper around `Siv` interface.
///
/// The `SivAead` type wraps the more powerful `Siv` interface in a more
/// commonly used Authenticated Encryption with Associated Data (AEAD) API,
/// which accepts a key, nonce, and associated data when encrypting/decrypting.
/// See the [`Siv`](mod@siv) module documentation for more information and examples.
pub struct SivAead<C, M, NonceSize = U16>
where
    Self: KeySizeUser,
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
    NonceSize: ArraySize + IsGreaterOrEqual<U1>,
{
    key: Array<u8, <Self as KeySizeUser>::KeySize>,
    mac: PhantomData<M>, // TODO(tarcieri): include `M` in `KeySize` calculation
}

/// SIV AEAD modes based on CMAC
pub type CmacSivAead<BlockCipher> = SivAead<BlockCipher, Cmac<BlockCipher>>;

/// SIV AEAD modes based on PMAC
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type PmacSivAead<BlockCipher> = SivAead<BlockCipher, Pmac<BlockCipher>>;

/// AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128SivAead = CmacSivAead<Aes128>;

/// AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256SivAead = CmacSivAead<Aes256>;

/// AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type Aes128PmacSivAead = PmacSivAead<Aes128>;

/// AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type Aes256PmacSivAead = PmacSivAead<Aes256>;

impl<M, NonceSize> KeySizeUser for SivAead<Aes128, M, NonceSize>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    NonceSize: ArraySize + IsGreaterOrEqual<U1>,
{
    type KeySize = U32;
}

impl<M, NonceSize> KeySizeUser for SivAead<Aes256, M, NonceSize>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    NonceSize: ArraySize + IsGreaterOrEqual<U1>,
{
    type KeySize = U64;
}

impl<M, NonceSize> KeyInit for SivAead<Aes128, M, NonceSize>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    NonceSize: ArraySize + IsGreaterOrEqual<U1>,
{
    fn new(key: &Array<u8, Self::KeySize>) -> Self {
        Self {
            key: *key,
            mac: PhantomData,
        }
    }
}

impl<M, NonceSize> KeyInit for SivAead<Aes256, M, NonceSize>
where
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    NonceSize: ArraySize + IsGreaterOrEqual<U1>,
{
    fn new(key: &Array<u8, Self::KeySize>) -> Self {
        Self {
            key: *key,
            mac: PhantomData,
        }
    }
}

impl<C, M, NonceSize> AeadCore for SivAead<C, M, NonceSize>
where
    Self: KeySizeUser,
    Siv<C, M>: KeyInit + KeySizeUser<KeySize = <Self as KeySizeUser>::KeySize>,
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
    NonceSize: ArraySize + IsGreaterOrEqual<U1>,
{
    // "If the nonce is random, it SHOULD be at least 128 bits in length"
    // https://tools.ietf.org/html/rfc5297#section-3
    // "N_MIN  is 1 octet."
    // https://tools.ietf.org/html/rfc5297#section-6
    type NonceSize = NonceSize;
    type TagSize = U16;

    fn encrypt_inout_detached(
        &self,
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Array<u8, Self::TagSize>, Error> {
        Siv::<C, M>::new(&self.key)
            .encrypt_inout_detached([associated_data, nonce.as_slice()], buffer)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Array<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Array<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        Siv::<C, M>::new(&self.key).decrypt_inout_detached(
            [associated_data, nonce.as_slice()],
            buffer,
            tag,
        )
    }
}

impl<C, M, NonceSize> AeadTagPosition for SivAead<C, M, NonceSize>
where
    Self: KeySizeUser,
    Siv<C, M>: KeyInit + KeySizeUser<KeySize = <Self as KeySizeUser>::KeySize>,
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
    NonceSize: ArraySize + IsGreaterOrEqual<U1>,
{
    const TAG_POSITION: TagPosition = TagPosition::Prefix;
}
