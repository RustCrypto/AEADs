//! The Synthetic Initialization Vector (SIV) misuse-resistant block cipher
//! mode of operation ([RFC 5297][1]). The interface is based on the [Rogaway paper][2].
//!
//! # Deterministic Authenticated Encryption Example
//! Deterministic encryption with additional data. Suitable for example for key wrapping.
//! Based on the test vector in [RFC 5297 Appendix: A1][3]
#![cfg_attr(feature = "alloc", doc = "```")]
#![cfg_attr(not(feature = "alloc"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use aes_siv::{siv::Aes128Siv, KeyInit};
//! use hex_literal::hex;
//!
//! let key = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
//! let ad = hex!("101112131415161718191a1b1c1d1e1f2021222324252627");
//! let plain_text = hex!("112233445566778899aabbccddee");
//!
//! let header = [&ad];
//! let encrypt = Aes128Siv::new(&key.into())
//!     .encrypt(&header, &plain_text)?;
//!
//! assert_eq!(
//!     hex!("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c").to_vec(),
//!     encrypt
//! );
//! let decrypted = Aes128Siv::new(&key.into())
//!        .decrypt(&header, &encrypt)?;
//!
//! assert_eq!(plain_text.to_vec(), decrypted);
//! # Ok(())
//! # }
//! ```
//!
//! # Nonce-Based Authenticated Encryption Example
//! Nonce-based encryption with multiple additional data vectors.
//! Based on the test vector in [RFC 5297 Appendix: A2][4]
#![cfg_attr(feature = "alloc", doc = "```")]
#![cfg_attr(not(feature = "alloc"), doc = "```ignore")]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use aes_siv::{siv::Aes128Siv, KeyInit};
//! use hex_literal::hex;
//!
//! let key = hex!("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
//! let ad1 = hex!("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
//! let ad2 = hex!("102030405060708090a0");
//! // Note that for production the nonce should be generated by for example: Aes256SivAead::generate_nonce
//! let nonce = hex!("09f911029d74e35bd84156c5635688c0");
//!
//! let plain_text = hex!("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553");
//!
//! let header: [&[u8]; 3] = [&ad1, &ad2, &nonce];
//! let encrypt = Aes128Siv::new(&key.into())
//!     .encrypt(&header, &plain_text)?;
//!
//! assert_eq!(
//!     hex!("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d").to_vec(),
//!     encrypt
//! );
//!
//! let decrypted = Aes128Siv::new(&key.into())
//!        .decrypt(&header, &encrypt)?;
//!
//! assert_eq!(plain_text.to_vec(), decrypted);
//! # Ok(())
//! # }
//! ```
//! [1]: https://tools.ietf.org/html/rfc5297
//! [2]: https://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
//! [3]: https://datatracker.ietf.org/doc/html/rfc5297#appendix-A.1
//! [4]: https://datatracker.ietf.org/doc/html/rfc5297#appendix-A.2

use crate::Tag;
use aead::{
    Buffer, Error,
    array::{Array, ArraySize, typenum::U16},
    inout::InOutBuf,
};
use aes::{Aes128, Aes256};
use cipher::{
    BlockCipherEncrypt, BlockSizeUser, InnerIvInit, Key, KeyInit, KeySizeUser, StreamCipherCore,
};
use cmac::Cmac;
use core::ops::Add;
use dbl::Dbl;
use digest::{CtOutput, FixedOutputReset, Mac};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "pmac")]
use pmac::Pmac;

/// Size of the (synthetic) initialization vector in bytes
pub const IV_SIZE: usize = 16;

/// Maximum number of header items on the encrypted message
pub const MAX_HEADERS: usize = 126;

/// Counter mode with a 128-bit big endian counter.
type Ctr128BE<C> = ctr::CtrCore<C, ctr::flavors::Ctr128BE>;

/// Size of an AES-SIV key given a particular cipher
pub type KeySize<C> = <<C as KeySizeUser>::KeySize as Add>::Output;

/// Synthetic Initialization Vector (SIV) mode, providing misuse-resistant
/// authenticated encryption (MRAE).
pub struct Siv<C, M>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16>,
{
    encryption_key: Key<C>,
    mac: M,
}

/// SIV modes based on CMAC
pub type CmacSiv<BlockCipher> = Siv<BlockCipher, Cmac<BlockCipher>>;

/// SIV modes based on PMAC
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type PmacSiv<BlockCipher> = Siv<BlockCipher, Pmac<BlockCipher>>;

/// AES-CMAC-SIV with a 128-bit key
pub type Aes128Siv = CmacSiv<Aes128>;

/// AES-CMAC-SIV with a 256-bit key
pub type Aes256Siv = CmacSiv<Aes256>;

/// AES-PMAC-SIV with a 128-bit key
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type Aes128PmacSiv = PmacSiv<Aes128>;

/// AES-PMAC-SIV with a 256-bit key
#[cfg(feature = "pmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "pmac")))]
pub type Aes256PmacSiv = PmacSiv<Aes256>;

impl<C, M> KeySizeUser for Siv<C, M>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
    KeySize<C>: ArraySize,
{
    type KeySize = KeySize<C>;
}

impl<C, M> KeyInit for Siv<C, M>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
    <C as KeySizeUser>::KeySize: Add,
    KeySize<C>: ArraySize,
{
    /// Create a new AES-SIV instance
    fn new(key: &Array<u8, KeySize<C>>) -> Self {
        // Use the first half of the key as the MAC key and
        // the second one as the encryption key
        let (mac_key, enc_key) = key.split_at(M::key_size());

        Self {
            encryption_key: enc_key.try_into().expect("encryption key size mismatch"),
            mac: <M as KeyInit>::new(mac_key.try_into().expect("MAC key size mismatch")),
        }
    }
}

impl<C, M> Siv<C, M>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16> + FixedOutputReset + KeyInit,
{
    /// Encrypt the given plaintext, allocating and returning a `Vec<u8>` for
    /// the ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `plaintext.len()` is less than `M::OutputSize`.
    /// Returns [`Error`] if `headers.len()` is greater than [`MAX_HEADERS`].
    #[cfg(feature = "alloc")]
    pub fn encrypt<I, T>(&mut self, headers: I, plaintext: &[u8]) -> Result<Vec<u8>, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buffer = Vec::with_capacity(plaintext.len() + IV_SIZE);
        buffer.extend_from_slice(plaintext);
        self.encrypt_in_place(headers, &mut buffer)?;
        Ok(buffer)
    }

    /// Encrypt the given buffer containing a plaintext message in-place.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `plaintext.len()` is less than `M::OutputSize`.
    /// Returns [`Error`] if `headers.len()` is greater than [`MAX_HEADERS`].
    pub fn encrypt_in_place<I, T>(
        &mut self,
        headers: I,
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let pt_len = buffer.len();

        // Make room in the buffer for the SIV tag. It needs to be prepended.
        buffer.extend_from_slice(Tag::default().as_slice())?;

        // TODO(tarcieri): add offset param to `encrypt_inout_detached`
        buffer.as_mut().copy_within(..pt_len, IV_SIZE);

        let tag = self.encrypt_inout_detached(headers, &mut buffer.as_mut()[IV_SIZE..])?;
        buffer.as_mut()[..IV_SIZE].copy_from_slice(tag.as_slice());
        Ok(())
    }

    /// Encrypt the given plaintext in-place, returning the SIV tag on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `plaintext.len()` is less than `M::OutputSize`.
    /// Returns [`Error`] if `headers.len()` is greater than [`MAX_HEADERS`].
    pub fn encrypt_inout_detached<I, T>(
        &mut self,
        headers: I,
        plaintext: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        // Compute the synthetic IV for this plaintext
        let siv_tag = s2v(&mut self.mac, headers, plaintext)?;
        self.xor_with_keystream(siv_tag, plaintext);
        Ok(siv_tag)
    }

    /// Decrypt the given ciphertext, allocating and returning a `Vec<u8>` for the plaintext.
    /// Or returning an error in the event the provided authentication tag does not match the given ciphertext.
    #[cfg(feature = "alloc")]
    pub fn decrypt<I, T>(&mut self, headers: I, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buffer = ciphertext.to_vec();
        self.decrypt_in_place(headers, &mut buffer)?;
        Ok(buffer)
    }

    /// Decrypt the message in-place, returning an error in the event the
    /// provided authentication tag does not match the given ciphertext.
    ///
    /// The buffer will be truncated to the length of the original plaintext
    /// message upon success.
    pub fn decrypt_in_place<I, T>(
        &mut self,
        headers: I,
        buffer: &mut dyn Buffer,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if buffer.len() < IV_SIZE {
            return Err(Error);
        }

        let siv_tag = Tag::try_from(&buffer.as_ref()[..IV_SIZE]).expect("tag size mismatch");
        self.decrypt_inout_detached(headers, &mut buffer.as_mut()[IV_SIZE..], &siv_tag)?;

        let pt_len = buffer.len() - IV_SIZE;

        // TODO(tarcieri): add offset param to `encrypt_inout_detached`
        buffer.as_mut().copy_within(IV_SIZE.., 0);
        buffer.truncate(pt_len);
        Ok(())
    }

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// provided SIV tag.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the ciphertext is not authentic
    pub fn decrypt_inout_detached<I, T>(
        &mut self,
        headers: I,
        ciphertext: InOutBuf<'_, '_, u8>,
        siv_tag: &Tag,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.xor_with_keystream(*siv_tag, ciphertext);
        let computed_siv_tag = s2v(&mut self.mac, headers, ciphertext)?;

        // Note: `CtOutput` provides constant-time equality
        if CtOutput::<M>::new(computed_siv_tag) == CtOutput::new(*siv_tag) {
            Ok(())
        } else {
            // Re-encrypt the decrypted plaintext to avoid revealing it
            self.xor_with_keystream(*siv_tag, ciphertext);
            Err(Error)
        }
    }

    /// XOR the given buffer with the keystream for the given IV
    fn xor_with_keystream(&mut self, mut iv: Tag, msg: &mut [u8]) {
        // "We zero-out the top bit in each of the last two 32-bit words
        // of the IV before assigning it to Ctr"
        //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
        iv[8] &= 0x7f;
        iv[12] &= 0x7f;

        Ctr128BE::<C>::inner_iv_init(C::new(&self.encryption_key), &iv)
            .apply_keystream_partial(msg.into());
    }
}

impl<C, M> Drop for Siv<C, M>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16>,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.encryption_key.zeroize()
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C, M> zeroize::ZeroizeOnDrop for Siv<C, M>
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + KeySizeUser,
    M: Mac<OutputSize = U16>,
{
}

/// "S2V" is a vectorized pseudorandom function (sometimes referred to as a
/// vector MAC or "vMAC") which performs a "dbl"-and-xor operation on the
/// outputs of a pseudo-random function (CMAC or PMAC).
///
/// In the RFC 5297 SIV construction (see Section 2.4), message headers
/// (e.g. nonce, associated data) and the plaintext are used as inputs to
/// S2V, together with a message authentication key. The output is the
/// eponymous "synthetic IV" (SIV), which has a dual role as both
/// initialization vector (for AES-CTR encryption) and MAC.
fn s2v<M, I, T>(mac: &mut M, headers: I, message: &[u8]) -> Result<Tag, Error>
where
    M: Mac<OutputSize = U16> + FixedOutputReset,
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    Mac::update(mac, &Tag::default());
    let mut state = mac.finalize_reset().into_bytes();

    for (i, header) in headers.into_iter().enumerate() {
        if i >= MAX_HEADERS {
            return Err(Error);
        }

        state = state.dbl();
        Mac::update(mac, header.as_ref());
        let code = mac.finalize_reset().into_bytes();
        xor_in_place(&mut state, &code);
    }

    if message.len() >= IV_SIZE {
        let n = message.len().checked_sub(IV_SIZE).unwrap();

        Mac::update(mac, &message[..n]);
        xor_in_place(&mut state, &message[n..]);
    } else {
        state = state.dbl();
        xor_in_place(&mut state, message);
        state[message.len()] ^= 0x80;
    };

    Mac::update(mac, state.as_ref());
    Ok(mac.finalize_reset().into_bytes())
}

/// XOR the second argument into the first in-place. Slices do not have to be
/// aligned in memory.
///
/// Panics if the destination slice is smaller than the source.
#[inline]
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (a, b) in dst[..src.len()].iter_mut().zip(src) {
        *a ^= *b;
    }
}
