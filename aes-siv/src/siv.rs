//! The Synthetic Initialization Vector (SIV) misuse-resistant block cipher
//! mode of operation ([RFC 5297][1]).
//!
//! [1]: https://tools.ietf.org/html/rfc5297

use crate::{KeySize, Tag};
use aead::generic_array::{
    typenum::{Unsigned, U16},
    ArrayLength, GenericArray,
};
use aead::{Buffer, Error};
use aes::{Aes128, Aes256};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use cmac::Cmac;
use core::ops::Add;
use crypto_mac::{Mac, MacResult};
use ctr::Ctr128;
use dbl::Dbl;
#[cfg(feature = "pmac")]
use pmac::Pmac;
use stream_cipher::{NewStreamCipher, SyncStreamCipher};
use zeroize::Zeroize;

/// Size of the (synthetic) initialization vector in bytes
pub const IV_SIZE: usize = 16;

/// Maximum number of header items on the encrypted message
pub const MAX_HEADERS: usize = 126;

/// Synthetic Initialization Vector (SIV) mode, providing misuse-resistant
/// authenticated encryption (MRAE).
pub struct Siv<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
{
    encryption_key: GenericArray<u8, <C as NewStreamCipher>::KeySize>,
    mac: M,
}

/// SIV modes based on CMAC
pub type CmacSiv<BlockCipher> = Siv<Ctr128<BlockCipher>, Cmac<BlockCipher>>;

/// SIV modes based on PMAC
#[cfg(feature = "pmac")]
pub type PmacSiv<BlockCipher> = Siv<Ctr128<BlockCipher>, Pmac<BlockCipher>>;

/// AES-CMAC-SIV with a 128-bit key
pub type Aes128Siv = CmacSiv<Aes128>;

/// AES-CMAC-SIV with a 256-bit key
pub type Aes256Siv = CmacSiv<Aes256>;

/// AES-PMAC-SIV with a 128-bit key
#[cfg(feature = "pmac")]
pub type Aes128PmacSiv = PmacSiv<Aes128>;

/// AES-PMAC-SIV with a 256-bit key
#[cfg(feature = "pmac")]
pub type Aes256PmacSiv = PmacSiv<Aes256>;

impl<C, M> Siv<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
    <C as NewStreamCipher>::KeySize: Add,
    KeySize<C>: ArrayLength<u8>,
{
    /// Create a new AES-SIV instance
    pub fn new(key: GenericArray<u8, KeySize<C>>) -> Self {
        // Use the first half of the key as the encryption key
        let encryption_key = GenericArray::clone_from_slice(&key[M::KeySize::to_usize()..]);

        // Use the second half of the key as the MAC key
        let mac = M::new(GenericArray::from_slice(&key[..M::KeySize::to_usize()]));

        Self {
            encryption_key,
            mac,
        }
    }
}

impl<C, M> Siv<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
{
    /// Encrypt the given plaintext, allocating and returning a `Vec<u8>` for
    /// the ciphertext.
    ///
    /// # Errors
    ///
    /// Returns `Error` if `plaintext.len()` is less than `M::OutputSize`.
    /// Returns `Error` if `headers.len()` is greater than `MAX_ASSOCIATED_DATA`.
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
    /// Returns `Error` if `plaintext.len()` is less than `M::OutputSize`.
    /// Returns `Error` if `headers.len()` is greater than `MAX_ASSOCIATED_DATA`.
    pub fn encrypt_in_place<I, T>(
        &mut self,
        headers: I,
        buffer: &mut impl Buffer,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let pt_len = buffer.len();

        // Make room in the buffer for the SIV tag. It needs to be prepended.
        buffer.extend_from_slice(Tag::default().as_slice())?;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        for i in (0..pt_len).rev() {
            let byte = buffer.as_ref()[i];
            buffer.as_mut()[i + IV_SIZE] = byte;
        }

        let tag = self.encrypt_in_place_detached(headers, &mut buffer.as_mut()[IV_SIZE..])?;
        buffer.as_mut()[..IV_SIZE].copy_from_slice(tag.as_slice());
        Ok(())
    }

    /// Encrypt the given plaintext in-place, returning the SIV tag on success.
    ///
    /// # Errors
    ///
    /// Returns `Error` if `plaintext.len()` is less than `M::OutputSize`.
    /// Returns `Error` if `headers.len()` is greater than `MAX_ASSOCIATED_DATA`.
    pub fn encrypt_in_place_detached<I, T>(
        &mut self,
        headers: I,
        plaintext: &mut [u8],
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

    /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
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
        buffer: &mut impl Buffer,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if buffer.len() < IV_SIZE {
            return Err(Error);
        }

        let siv_tag = Tag::clone_from_slice(&buffer.as_ref()[..IV_SIZE]);
        self.decrypt_in_place_detached(headers, &mut buffer.as_mut()[IV_SIZE..], &siv_tag)?;

        let pt_len = buffer.len() - IV_SIZE;

        // TODO(tarcieri): add offset param to `encrypt_in_place_detached`
        for i in 0..pt_len {
            let byte = buffer.as_ref()[i + IV_SIZE];
            buffer.as_mut()[i] = byte;
        }

        buffer.truncate(pt_len);
        Ok(())
    }

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// provided SIV tag.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the ciphertext is not authentic
    pub fn decrypt_in_place_detached<I, T>(
        &mut self,
        headers: I,
        ciphertext: &mut [u8],
        siv_tag: &Tag,
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.xor_with_keystream(*siv_tag, ciphertext);
        let computed_siv_tag = s2v(&mut self.mac, headers, ciphertext)?;

        // Note: constant-time comparison of `MacResult` values
        if MacResult::new(computed_siv_tag) == MacResult::new(*siv_tag) {
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

        C::new(GenericArray::from_slice(&self.encryption_key), &iv).apply_keystream(msg);
    }
}

impl<C, M> Drop for Siv<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
{
    fn drop(&mut self) {
        self.encryption_key.zeroize()
    }
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
    M: Mac<OutputSize = U16>,
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    mac.input(&Tag::default());
    let mut state = mac.result_reset().code();

    for (i, header) in headers.into_iter().enumerate() {
        if i >= MAX_HEADERS {
            return Err(Error);
        }

        state = state.dbl();
        mac.input(header.as_ref());
        let code = mac.result_reset().code();
        xor_in_place(&mut state, &code);
    }

    if message.len() >= IV_SIZE {
        let n = message.len().checked_sub(IV_SIZE).unwrap();

        mac.input(&message[..n]);
        xor_in_place(&mut state, &message[n..]);
    } else {
        state = state.dbl();
        xor_in_place(&mut state, message);
        state[message.len()] ^= 0x80;
    };

    mac.input(state.as_ref());
    Ok(mac.result_reset().code())
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
