#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

//! # Usage
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use deoxys::{
//!     aead::{Aead, AeadCore, Generate, Key, KeyInit},
//!     DeoxysII256, // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//!     Nonce
//! };
//!
//! let key = Key::<DeoxysII256>::generate();
//! let cipher = DeoxysII256::new(&key);
//!
//! let nonce = Nonce::generate(); // MUST be unique per message
//! let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;
//!
//! let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
//! assert_eq!(&plaintext, b"plaintext message");
//! # Ok(())
//! # }
//! ```
//!
//! ## Usage with AAD
//! Deoxys can authenticate additional data that is not encrypted alongside with the ciphertext.
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use deoxys::{
//!     aead::{Aead, AeadCore, Generate, Key, KeyInit, Payload},
//!     DeoxysII256, // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//!     Nonce
//! };
//!
//! let key = Key::<DeoxysII256>::generate();
//! let cipher = DeoxysII256::new(&key);
//!
//! let nonce = Nonce::generate(); // MUST be unique per message
//!
//! let payload = Payload {
//!    msg: &b"this will be encrypted".as_ref(),
//!    aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let ciphertext = cipher.encrypt(&nonce, payload)?;
//!
//! let payload = Payload {
//!    msg: &ciphertext,
//!    aad: &b"this will NOT be encrypted, but will be authenticated".as_ref(),
//! };
//!
//! let plaintext = cipher.decrypt(&nonce, payload)?;
//! assert_eq!(&plaintext, b"this will be encrypted");
//! # Ok(())
//! # }
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
//! Enabling the `arrayvec` feature of this crate will provide an impl of
//! [`aead::Buffer`] for `arrayvec::ArrayVec` (re-exported from the [`aead`] crate as
//! [`aead::arrayvec::ArrayVec`]), and enabling the `bytes` feature of this crate will
//! provide an impl of [`aead::Buffer`] for `bytes::BytesMut` (re-exported from the
//! [`aead`] crate as [`aead::bytes::BytesMut`]).
//!
//! It can then be passed as the `buffer` parameter to the in-place encrypt
//! and decrypt methods:
//!
#![cfg_attr(all(feature = "getrandom", feature = "arrayvec"), doc = "```")]
#![cfg_attr(
    not(all(feature = "getrandom", feature = "arrayvec")),
    doc = "```ignore"
)]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! // NOTE: requires the `arrayvec` and `getrandom` features are enabled
//!
//! use deoxys::{
//!     aead::{AeadCore, AeadInOut, Generate, Key, KeyInit, arrayvec::ArrayVec},
//!     DeoxysII256, // Can be `DeoxysI128`, `DeoxysI256`, `DeoxysII128` of `DeoxysII256`
//!     Nonce
//! };
//!
//! let key = Key::<DeoxysII256>::generate();
//! let cipher = DeoxysII256::new(&key);
//!
//! let nonce = Nonce::generate(); // MUST be unique per message
//!
//! let mut buffer: ArrayVec<u8, 128> = ArrayVec::new(); // Buffer needs 16-bytes overhead for tag
//! buffer.try_extend_from_slice(b"plaintext message").unwrap();
//!
//! // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
//! cipher.encrypt_in_place(&nonce, b"", &mut buffer)?;
//!
//! // `buffer` now contains the message ciphertext
//! assert_ne!(buffer.as_ref(), b"plaintext message");
//!
//! // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
//! cipher.decrypt_in_place(&nonce, b"", &mut buffer)?;
//! assert_eq!(buffer.as_ref(), b"plaintext message");
//! # Ok(())
//! # }
//! ```

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

#[cfg(test)]
mod tests {
    //! this module is here to test the inout behavior which is not currently exposed.
    //! it will be once we port over to the API made in RustCrypto/traits#1793.
    //!
    //! This is to drop once https://github.com/RustCrypto/traits/pull/1797 is made available.
    //!
    //! It duplicates test vectors from `tests/deoxys_i_128.rs` and provides a mock buffer backing
    //! for InOut.

    use hex_literal::hex;

    use super::*;

    struct MockBuffer {
        in_buf: [u8; 33],
        out_buf: [u8; 33],
    }

    impl From<&[u8]> for MockBuffer {
        fn from(buf: &[u8]) -> Self {
            let mut in_buf = [0u8; 33];
            in_buf.copy_from_slice(buf);
            Self {
                in_buf,
                out_buf: [0u8; 33],
            }
        }
    }

    impl MockBuffer {
        /// Get an [`InOutBuf`] from a [`MockBuffer`]
        pub fn as_in_out_buf(&mut self) -> InOutBuf<'_, '_, u8> {
            InOutBuf::new(self.in_buf.as_slice(), self.out_buf.as_mut_slice())
                .expect("Invariant violation")
        }
    }

    impl AsRef<[u8]> for MockBuffer {
        fn as_ref(&self) -> &[u8] {
            &self.out_buf
        }
    }

    #[test]
    fn test_deoxys_i_128_5() {
        let plaintext = hex!("5a4c652cb880808707230679224b11799b5883431292973215e9bd03cf3bc32fe4");
        let mut buffer = MockBuffer::from(&plaintext[..]);

        let aad = [];

        let key = hex!("101112131415161718191a1b1c1d1e1f");
        let key = Array(key);

        let nonce = hex!("202122232425262728292a2b2c2d2e2f");
        let nonce = Array::try_from(&nonce[..8]).unwrap();

        let ciphertext_expected =
            hex!("cded5a43d3c76e942277c2a1517530ad66037897c985305ede345903ed7585a626");

        let tag_expected: [u8; 16] = hex!("cbf5faa6b8398c47f4278d2019161776");

        type M = modes::DeoxysI<deoxys_bc::DeoxysBc256>;
        let cipher = DeoxysI128::new(&key);
        let tag: Tag = M::encrypt_inout(&nonce, &aad, buffer.as_in_out_buf(), &cipher.subkeys);

        let ciphertext = buffer.as_ref();
        assert_eq!(ciphertext, ciphertext_expected);
        assert_eq!(tag, tag_expected);

        let mut buffer = MockBuffer::from(buffer.as_ref());
        M::decrypt_inout(&nonce, &aad, buffer.as_in_out_buf(), &tag, &cipher.subkeys)
            .expect("decryption failed");

        assert_eq!(&plaintext[..], buffer.as_ref());
    }

    #[test]
    fn test_deoxys_ii_128_5() {
        let plaintext = hex!("06ac1756eccece62bd743fa80c299f7baa3872b556130f52265919494bdc136db3");
        let mut buffer = MockBuffer::from(&plaintext[..]);

        let aad = [];

        let key = hex!("101112131415161718191a1b1c1d1e1f");
        let key = Array(key);

        let nonce = hex!("202122232425262728292a2b2c2d2e2f");
        let nonce = Array::try_from(&nonce[..15]).unwrap();

        let ciphertext_expected =
            hex!("82bf241958b324ed053555d23315d3cc20935527fc970ff34a9f521a95e302136d");

        let tag_expected: [u8; 16] = hex!("0eadc8612d5208c491e93005195e9769");

        type M = modes::DeoxysII<deoxys_bc::DeoxysBc256>;
        let cipher = DeoxysII128::new(&key);
        let tag: Tag = M::encrypt_inout(&nonce, &aad, buffer.as_in_out_buf(), &cipher.subkeys);

        let ciphertext = buffer.as_ref();
        assert_eq!(ciphertext, ciphertext_expected);
        assert_eq!(tag, tag_expected);

        let mut buffer = MockBuffer::from(buffer.as_ref());
        M::decrypt_inout(&nonce, &aad, buffer.as_in_out_buf(), &tag, &cipher.subkeys)
            .expect("decryption failed");

        assert_eq!(&plaintext[..], buffer.as_ref());
    }
}
