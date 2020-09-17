//! Online[<sup>1</sup>] variant of the EAX mode.
//!
//! # Authentication
//! Due to *AE* (authenticated encryption) nature of EAX, it is vital to verify
//! that both public (also called *associated*) and privacy-protected
//! (encrypted) data has not been tampered with.
//!
//! Because of this, it is required for the consumers to explicitly call
//! [`finish`] after the encryption/decryption operation is complete.
//! This will either return a *tag* (when encrypting) used to authenticate data
//! or a `Result` (when decrypting) that signifies whether the data is authentic,
//! which is when the resulting tag is equal to the one created during encryption.
//!
//! ## Example
//! ```
//! use eax::{Error, online::{Eax, Decrypt, Encrypt}};
//! use aes::Aes256;
//! use block_cipher::generic_array::GenericArray;
//!
//! let key = GenericArray::from_slice(b"an example very very secret key.");
//! let nonce = GenericArray::from_slice(b"my unique nonces"); // 128-bits; unique per message
//! let assoc = b"my associated data";
//! let plaintext = b"plaintext message";
//! let mut buffer: [u8; 17] = *plaintext;
//!
//!// Encrypt a simple message
//! let mut cipher = Eax::<Aes256, Encrypt>::with_key_and_nonce(key, nonce);
//! cipher.update_assoc(&assoc[..]);
//! cipher.encrypt(&mut buffer[..9]);
//! cipher.encrypt(&mut buffer[9..]);
//! let tag = cipher.finish();
//!
//! assert_ne!(buffer, *plaintext);
//!
//! let mut cloned = buffer;
//!
//! // Now decrypt it, using the same key and nonce
//! let mut cipher = Eax::<Aes256, Decrypt>::with_key_and_nonce(key, nonce);
//! cipher.update_assoc(&assoc[..]);
//! cipher.decrypt(&mut buffer[..5]);
//! cipher.decrypt(&mut buffer[5..10]);
//! cipher.decrypt(&mut buffer[10..]);
//! let res = cipher.finish(&tag);
//!
//! assert_eq!(res, Ok(()));
//! assert_eq!(buffer, *plaintext);
//!
//! // Decrypting the ciphertext with tampered associated data should fail
//! let mut cipher = Eax::<Aes256, Decrypt>::with_key_and_nonce(key, nonce);
//! cipher.update_assoc(b"tampered");
//! cipher.decrypt(&mut cloned);
//! let res = cipher.finish(&tag);
//!
//! assert_eq!(res, Err(Error));
//! ```
//! [<sup>1</sup>]: https://en.wikipedia.org/wiki/Online_algorithm
//! [`Eax`]: struct.Eax.html
//! [`Decrypt`]: struct.Decrypt.html
//! [`finish`]: #method.finish

use crate::*;

use core::marker::PhantomData;

pub use Eax as EaxOnline;

/// Marker trait denoting whether the EAX stream is used for encryption/decryption.
pub trait CipherOp {}
/// Marker struct for EAX stream used in encryption mode.
pub struct Encrypt;
impl CipherOp for Encrypt {}
/// Marker struct for EAX stream used in decryption mode.
pub struct Decrypt;
impl CipherOp for Decrypt {}

/// Online[<sup>1</sup>] variant of the EAX mode.
///
/// This type is generic to support substituting alternative cipher
/// implementations.
///
/// In contrast to [`Eax`], can be used in an online[<sup>1</sup>] fashion and
/// operates in-place.
///
/// # Authentication
/// Due to *AE* (authenticated encryption) nature of EAX, it is vital to verify
/// that both public (also called *associated*) and privacy-protected
/// (encrypted) data has not been tampered with.
///
/// Because of this, it is required for the consumers to explicitly call
/// [`finish`] after the encryption/decryption operation is complete.
/// This will either return a *tag* (when encrypting) used to authenticate data
/// or a `Result` (when decrypting) that signifies whether the data is authentic,
/// which is when the resulting tag is equal to the one created during encryption.
///
/// ## Example
/// ```
/// use eax::{Error, online::{Eax, Decrypt, Encrypt}};
/// use aes::Aes256;
/// use block_cipher::generic_array::GenericArray;
///
/// let key = GenericArray::from_slice(b"an example very very secret key.");
///
/// let nonce = GenericArray::from_slice(b"my unique nonces"); // 128-bits; unique per message
///
/// let assoc = b"my associated data";
/// let plaintext = b"plaintext message";
///
/// let mut buffer: [u8; 17] = *plaintext;
///
/// // Encrypt a simple message
/// let mut cipher = Eax::<Aes256, Encrypt>::with_key_and_nonce(key, nonce);
/// cipher.update_assoc(&assoc[..]);
/// cipher.encrypt(&mut buffer[..9]);
/// cipher.encrypt(&mut buffer[9..]);
/// let tag = cipher.finish();
///
/// assert_ne!(buffer, *plaintext);
///
/// let mut cloned = buffer;
///
/// // Now decrypt it, using the same key and nonce
/// let mut cipher = Eax::<Aes256, Decrypt>::with_key_and_nonce(key, nonce);
/// cipher.update_assoc(&assoc[..]);
/// cipher.decrypt(&mut buffer[..5]);
/// cipher.decrypt(&mut buffer[5..10]);
/// cipher.decrypt(&mut buffer[10..]);
/// let res = cipher.finish(&tag);
///
/// assert_eq!(res, Ok(()));
/// assert_eq!(buffer, *plaintext);
///
/// // Decrypting the ciphertext with tampered associated data should fail
/// let mut cipher = Eax::<Aes256, Decrypt>::with_key_and_nonce(key, nonce);
///
/// cipher.update_assoc(b"tampered");
/// cipher.decrypt(&mut cloned);
/// let res = cipher.finish(&tag);
///
/// assert_eq!(res, Err(Error));
/// ```
///
/// [<sup>1</sup>]: https://en.wikipedia.org/wiki/Online_algorithm
/// [`Eax`]: ../struct.Eax.html
/// [`Decrypt`]: struct.Decrypt.html
/// [`finish`]: #method.finish
pub struct Eax<Cipher, Op>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
    Op: CipherOp,
{
    nonce: Nonce<Cipher::BlockSize>,
    data: Cmac<Cipher>,
    message: Cmac<Cipher>,
    ctr: ctr::Ctr128<Cipher>,
    /// Denotes whether this stream is used for encryption or decryption.
    marker: PhantomData<Op>,
}

impl<Cipher, Op> Eax<Cipher, Op>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
    Op: CipherOp,
{
    /// Creates a stateful EAX instance that is capable of processing both
    /// the associated data and the plaintext in an "on-line" fashion.
    pub fn with_key_and_nonce(key: &Key<Cipher>, nonce: &Nonce<Cipher::BlockSize>) -> Self {
        let prepend_cmac = |key, init_val, data| {
            let mut cmac = Cmac::<Cipher>::new(key);
            cmac.update(&[0; 15]);
            cmac.update(&[init_val]);
            cmac.update(data);
            cmac
        };

        // https://crypto.stackexchange.com/questions/26948/eax-cipher-mode-with-nonce-equal-header
        // has an explanation of eax.

        // l = block cipher size = 128 (for AES-128) = 16 byte
        // 1. n ← OMAC(0 || Nonce)
        // (the 0 means the number zero in l bits)
        let n = prepend_cmac(&key, 0, nonce);
        let n = n.finalize().into_bytes();

        // NOTE: These can be updated online later
        // 2. h ← OMAC(1 || associated data)
        let h = prepend_cmac(&key, 1, &[]);
        // 3. c ← OMAC(2 || enc)
        let c = prepend_cmac(&key, 2, &[]);

        let cipher = ctr::Ctr128::<Cipher>::from_block_cipher(Cipher::new(&key), &n);

        Eax {
            nonce: n,
            data: h,
            message: c,
            ctr: cipher,
            marker: PhantomData,
        }
    }
}

impl<Cipher, Op> Eax<Cipher, Op>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
    Op: CipherOp,
{
    /// Process the associated data (AD).
    #[inline]
    pub fn update_assoc(&mut self, aad: &[u8]) {
        self.data.update(aad);
    }

    /// Derives the tag from the encrypted/decrypted message so far.
    ///
    /// NOTE: This has to be called when the value is consumed.
    #[inline]
    fn finish_inner(self) -> Tag {
        let h = self.data.finalize().into_bytes();
        let c = self.message.finalize().into_bytes();

        self.nonce.zip(h, |a, b| a ^ b).zip(c, |a, b| a ^ b)
    }

    /// Derives the tag from the encrypted/decrypted message so far.
    ///
    /// If the encryption/decryption operation is finished, [`finish`] method
    /// *must* be called instead.
    ///
    ///[`finish`]: #method.finish
    #[inline]
    pub fn tag_clone(&self) -> Tag {
        let h = self.data.clone().finalize().into_bytes();
        let c = self.message.clone().finalize().into_bytes();

        self.nonce.zip(h, |a, b| a ^ b).zip(c, |a, b| a ^ b)
    }
}

impl<Cipher> Eax<Cipher, Encrypt>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
{
    /// Applies encryption to the plaintext.
    #[inline]
    pub fn encrypt(&mut self, msg: &mut [u8]) {
        self.ctr.apply_keystream(msg);
        self.message.update(msg);
    }

    /// Finishes the encryption stream, returning the derived tag.
    ///
    /// This *must* be called after the stream encryption is finished.
    #[must_use = "tag must be saved to later verify decrypted data"]
    #[inline]
    pub fn finish(self) -> Tag {
        self.finish_inner()
    }
}

impl<Cipher> Eax<Cipher, Decrypt>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
{
    /// Applies decryption to the ciphertext.
    #[inline]
    pub fn decrypt(&mut self, msg: &mut [u8]) {
        self.message.update(msg);
        self.ctr.apply_keystream(msg);
    }

    /// Finishes the decryption stream, verifying whether the associated and
    /// decrypted data stream has not been tampered with.
    ///
    /// This *must* be called after the stream decryption is finished.
    #[must_use = "decrypted data stream must be verified for authenticity"]
    pub fn finish(self, expected: &Tag) -> Result<(), Error> {
        // Check mac using secure comparison
        use subtle::ConstantTimeEq;

        let resulting_tag = &self.finish_inner()[..expected.len()];
        if resulting_tag.ct_eq(expected).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(Error)
        }
    }
}
