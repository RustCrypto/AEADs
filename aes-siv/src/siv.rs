//! The Synthetic Initialization Vector (SIV) misuse-resistant block cipher
//! mode of operation ([RFC 5297][1]).
//!
//! [1]: https://tools.ietf.org/html/rfc5297

use aead::generic_array::{
    typenum::{Unsigned, U16},
    GenericArray,
};
use aead::Error;
use aes::{Aes128, Aes256};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use cmac::Cmac;
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

/// GenericArray of bytes which is the size of a synthetic IV
type SivArray = GenericArray<u8, U16>;

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
{
    /// Create a new AES-SIV instance
    ///
    /// Panics if the key is the wrong length
    // TODO(tarcieri): use `GenericArray` to eliminate panic conditions
    pub fn new(key: &[u8]) -> Self {
        let key_size = M::KeySize::to_usize() * 2;

        assert_eq!(
            key.len(),
            key_size,
            "expected {}-byte key, got {}",
            key_size,
            key.len()
        );

        // Use the first half of the key as the encryption key
        let encryption_key = GenericArray::clone_from_slice(&key[(key_size / 2)..]);

        // Use the second half of the key as the MAC key
        let mac = M::new(GenericArray::from_slice(&key[..(key_size / 2)]));

        Self {
            encryption_key,
            mac,
        }
    }

    /// Encrypt the given plaintext in-place, replacing it with the SIV tag and
    /// ciphertext. Requires a buffer with 16-bytes additional space.
    ///
    /// # Usage
    ///
    /// It's important to note that only the *end* of the buffer will be
    /// treated as the input plaintext:
    ///
    /// ```rust
    /// let buffer = [0u8; 21];
    /// let plaintext = &buffer[..buffer.len() - 16];
    /// ```
    ///
    /// In this case, only the *last* 5 bytes are treated as the plaintext,
    /// since `21 - 16 = 5` (the AES block size is 16-bytes).
    ///
    /// The buffer must include an additional 16-bytes of space in which to
    /// write the SIV tag (at the beginning of the buffer).
    /// Failure to account for this will leave you with plaintext messages that
    /// are missing their first 16-bytes!
    ///
    /// # Panics
    ///
    /// Panics if `plaintext.len()` is less than `M::OutputSize`.
    /// Panics if `headers.len()` is greater than `MAX_ASSOCIATED_DATA`.
    pub fn encrypt_in_place<I, T>(&mut self, headers: I, plaintext: &mut [u8])
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if plaintext.len() < IV_SIZE {
            panic!("plaintext buffer too small to hold MAC tag!");
        }

        let (siv_tag, msg) = plaintext.split_at_mut(IV_SIZE);

        // Compute the synthetic IV for this plaintext
        siv_tag.copy_from_slice(s2v(&mut self.mac, headers, msg).code().as_slice());
        self.xor_with_keystream(siv_tag, msg);
    }

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// synthetic IV included in the message.
    ///
    /// Returns a slice containing a decrypted message on success.
    pub fn decrypt_in_place<'a, I, T>(
        &mut self,
        headers: I,
        ciphertext: &'a mut [u8],
    ) -> Result<&'a [u8], Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if ciphertext.len() < IV_SIZE {
            return Err(Error);
        }

        let (siv_tag, msg) = ciphertext.split_at_mut(IV_SIZE);
        self.xor_with_keystream(siv_tag, msg);

        let computed_siv_tag = s2v(&mut self.mac, headers, msg);

        // Note: constant-time comparison of `MacResult` values
        if computed_siv_tag == MacResult::new(*GenericArray::from_slice(siv_tag)) {
            Ok(msg)
        } else {
            // Re-encrypt the decrypted plaintext to avoid revealing it
            self.xor_with_keystream(siv_tag, msg);
            Err(Error)
        }
    }

    /// Encrypt the given plaintext, allocating and returning a Vec<u8> for the ciphertext
    #[cfg(feature = "alloc")]
    pub fn encrypt<I, T>(&mut self, associated_data: I, plaintext: &[u8]) -> Vec<u8>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buffer = vec![0; IV_SIZE + plaintext.len()];
        buffer[IV_SIZE..].copy_from_slice(plaintext);
        self.encrypt_in_place(associated_data, &mut buffer);
        buffer
    }

    /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
    #[cfg(feature = "alloc")]
    pub fn decrypt<I, T>(&mut self, associated_data: I, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut buffer = Vec::from(ciphertext);
        self.decrypt_in_place(associated_data, &mut buffer)?;
        buffer.drain(..IV_SIZE);
        Ok(buffer)
    }

    /// XOR the given buffer with the keystream for the given IV
    fn xor_with_keystream(&mut self, iv: &[u8], msg: &mut [u8]) {
        let mut zeroed_iv = SivArray::clone_from_slice(iv);

        // "We zero-out the top bit in each of the last two 32-bit words
        // of the IV before assigning it to Ctr"
        //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
        zeroed_iv[8] &= 0x7f;
        zeroed_iv[12] &= 0x7f;

        C::new(GenericArray::from_slice(&self.encryption_key), &zeroed_iv).apply_keystream(msg);
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
fn s2v<M, I, T>(mac: &mut M, headers: I, message: &[u8]) -> MacResult<U16>
where
    M: Mac<OutputSize = U16>,
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    mac.input(&SivArray::default());
    let mut state = mac.result_reset().code();

    for (i, header) in headers.into_iter().enumerate() {
        if i >= MAX_HEADERS {
            panic!("too many associated data items!");
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
    mac.result_reset()
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
