#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(non_snake_case)]

use core::marker::PhantomData;

pub use aead::{
    self, generic_array::GenericArray, AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser,
};
use aes::{self, Aes128, Aes256, Block};
use cipher::{
    consts::{U0, U12, U16},
    BlockDecrypt, BlockEncrypt, BlockSizeUser,
};

mod util;
use crate::util::{double, inplace_xor, ntz};
use subtle::ConstantTimeEq;

/// Number of L values to be precomputed. Precomputing m values, allows
/// processing inputs of length up to 2^m blocks (2^m * 16 bytes) without
/// needing to calculate L values at runtime.
///
/// By setting this to 32, we can process inputs of length up to 1 terabyte.
const L_TABLE_SIZE: usize = 32;

/// Max associated data.
pub const A_MAX: usize = 1 << (L_TABLE_SIZE + 4);
/// Max plaintext.
pub const P_MAX: usize = 1 << (L_TABLE_SIZE + 4);
/// Max ciphertext.
pub const C_MAX: usize = 1 << (L_TABLE_SIZE + 4);

/// OCB3 nonce
pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

/// OCB3 tag
pub type Tag<TagSize> = GenericArray<u8, TagSize>;

/// AES-OCB3 with a 128-bit key, 96-bit nonce, and 128-bit tag.
pub type Aes128Ocb3 = AesOcb3<Aes128, U12>;

/// AES-OCB3 with a 256-bit key, 96-bit nonce, and 128-bit tag.
pub type Aes256Ocb3 = AesOcb3<Aes256, U12>;

/// Trait implemented for valid tag sizes
pub trait TagSize: private::SealedTagSize {}
impl<T: private::SealedTagSize> TagSize for T {}
/// Trait implemented for valid nonce sizes
pub trait NonceSize: private::SealedNonceSize {}
impl<T: private::SealedNonceSize> NonceSize for T {}

// Adapted from https://github.com/sgmenda/AEADs/blob/2209bcaa9edc65e9a60498e7ece5b50e66f32ebf/aes-gcm/src/lib.rs#L143-L157
mod private {
    use aead::generic_array::ArrayLength;
    use cipher::{consts, Unsigned};

    // Sealed traits stop other crates from implementing any traits that use it.
    pub trait SealedTagSize: ArrayLength<u8> + Unsigned {}
    pub trait SealedNonceSize: ArrayLength<u8> + Unsigned {}

    // Tags are <= 128 bits
    impl SealedTagSize for consts::U8 {}
    impl SealedTagSize for consts::U12 {}
    impl SealedTagSize for consts::U16 {}

    // Nonces are <= 120 bits
    impl SealedNonceSize for consts::U12 {}
}
/// AES-OCB3: generic over an AES implementation, nonce size, and tag size.
///
/// WARNING: Unless absolutely necessary, prefer the aliases Aes128Ocb3 and
/// Aes256Ocb3.
#[derive(Clone)]
pub struct AesOcb3<Aes, NonceSize = U12, TagSize = U16>
where
    NonceSize: self::NonceSize,
    TagSize: self::TagSize,
{
    cipher: Aes,
    nonce_size: PhantomData<NonceSize>,
    tag_size: PhantomData<TagSize>,
    // precomputed key-dependent variables
    Lstar: Block,
    Ldollar: Block,
    // list of pre-computed L values
    L: [Block; L_TABLE_SIZE],
}

/// Output of the HASH function defined in https://www.rfc-editor.org/rfc/rfc7253.html#section-4.1
type SumSize = U16;
type Sum = GenericArray<u8, SumSize>;

impl<Aes, NonceSize, TagSize> KeySizeUser for AesOcb3<Aes, NonceSize, TagSize>
where
    Aes: KeySizeUser,
    TagSize: self::TagSize,
    NonceSize: self::NonceSize,
{
    type KeySize = Aes::KeySize;
}

impl<Aes, NonceSize, TagSize> KeyInit for AesOcb3<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit + BlockDecrypt,
    TagSize: self::TagSize,
    NonceSize: self::NonceSize,
{
    fn new(key: &aead::Key<Self>) -> Self {
        Aes::new(key).into()
    }
}

impl<Aes, NonceSize, TagSize> AeadCore for AesOcb3<Aes, NonceSize, TagSize>
where
    NonceSize: self::NonceSize,
    TagSize: self::TagSize,
{
    type NonceSize = NonceSize;
    type TagSize = TagSize;
    type CiphertextOverhead = U0;
}

impl<Aes, NonceSize, TagSize> From<Aes> for AesOcb3<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    TagSize: self::TagSize,
    NonceSize: self::NonceSize,
{
    fn from(cipher: Aes) -> Self {
        let (Lstar, Ldollar, L) = key_dependent_variables(&cipher);

        Self {
            cipher,
            nonce_size: PhantomData,
            tag_size: PhantomData,
            Lstar,
            Ldollar,
            L,
        }
    }
}

/// Computes key-dependent variables defined in
/// https://www.rfc-editor.org/rfc/rfc7253.html#section-4.1
fn key_dependent_variables<Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt>(
    cipher: &Aes,
) -> (Block, Block, [Block; L_TABLE_SIZE]) {
    let mut zeros = [0u8; 16];
    let Lstar = Block::from_mut_slice(&mut zeros);
    cipher.encrypt_block(Lstar);
    let Ldollar = double(Lstar);

    let mut L = [Block::default(); L_TABLE_SIZE];
    let mut Li = Ldollar;
    #[allow(clippy::needless_range_loop)]
    for i in 0..L_TABLE_SIZE {
        Li = double(&Li);
        L[i] = Li
    }
    (*Lstar, Ldollar, L)
}

impl<Aes, NonceSize, TagSize> AeadInPlace for AesOcb3<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    TagSize: self::TagSize,
    NonceSize: self::NonceSize,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        if (buffer.len() > P_MAX) || (associated_data.len() > A_MAX) {
            unimplemented!()
        }

        // First, try to process many blocks at once.
        let (processed_bytes, mut Offset_i, mut Checksum_i) = self.wide_encrypt(nonce, buffer);

        let mut i = (processed_bytes / 16) + 1;

        // Then, process the remaining blocks.
        for P_i in buffer[processed_bytes..].chunks_exact_mut(16) {
            let P_i = Block::from_mut_slice(P_i);
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            inplace_xor(&mut Offset_i, &self.L[ntz(i)]);
            // Checksum_i = Checksum_{i-1} xor P_i
            inplace_xor(&mut Checksum_i, P_i);
            // C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)
            let C_i = P_i;
            inplace_xor(C_i, &Offset_i);
            self.cipher.encrypt_block(C_i);
            inplace_xor(C_i, &Offset_i);

            i += 1;
        }

        // Process any partial blocks.
        if (buffer.len() % 16) != 0 {
            let processed_bytes = (i - 1) * 16;
            let remaining_bytes = buffer.len() - processed_bytes;

            // Offset_* = Offset_m xor L_*
            inplace_xor(&mut Offset_i, &self.Lstar);
            // Pad = ENCIPHER(K, Offset_*)
            let mut Pad = Block::default();
            inplace_xor(&mut Pad, &Offset_i);
            self.cipher.encrypt_block(&mut Pad);
            // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
            let Checksum_rhs = &mut [0u8; 16];
            Checksum_rhs[..remaining_bytes].copy_from_slice(&buffer[processed_bytes..]);
            Checksum_rhs[remaining_bytes] = 0b1000_0000;
            inplace_xor(&mut Checksum_i, Block::from_slice(Checksum_rhs));
            // C_* = P_* xor Pad[1..bitlen(P_*)]
            let P_star = &mut buffer[processed_bytes..];
            let Pad = &mut Pad[..P_star.len()];
            for (aa, bb) in P_star.iter_mut().zip(Pad) {
                *aa ^= *bb;
            }
        }

        let tag = self.compute_tag(associated_data, &mut Checksum_i, &Offset_i);

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        let expected_tag = self.decrypt_in_place_return_tag(nonce, associated_data, buffer);
        if expected_tag.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<Aes, NonceSize, TagSize> AesOcb3<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
    TagSize: self::TagSize,
    NonceSize: self::NonceSize,
{
    /// Decrypts in place and returns expected tag.
    pub(crate) fn decrypt_in_place_return_tag(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Tag<Self> {
        if (buffer.len() > C_MAX) || (associated_data.len() > A_MAX) {
            unimplemented!()
        }

        // First, try to process many blocks at once.
        let (processed_bytes, mut Offset_i, mut Checksum_i) = self.wide_decrypt(nonce, buffer);

        let mut i = (processed_bytes / 16) + 1;

        // Then, process the remaining blocks.
        for C_i in buffer[processed_bytes..].chunks_exact_mut(16) {
            let C_i = Block::from_mut_slice(C_i);
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            inplace_xor(&mut Offset_i, &self.L[ntz(i)]);
            // P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)
            let P_i = C_i;
            inplace_xor(P_i, &Offset_i);
            self.cipher.decrypt_block(P_i);
            inplace_xor(P_i, &Offset_i);
            // Checksum_i = Checksum_{i-1} xor P_i
            inplace_xor(&mut Checksum_i, P_i);

            i += 1;
        }

        // Process any partial blocks.
        if (buffer.len() % 16) != 0 {
            let processed_bytes = (i - 1) * 16;
            let remaining_bytes = buffer.len() - processed_bytes;

            // Offset_* = Offset_m xor L_*
            inplace_xor(&mut Offset_i, &self.Lstar);
            // Pad = ENCIPHER(K, Offset_*)
            let mut Pad = Block::default();
            inplace_xor(&mut Pad, &Offset_i);
            self.cipher.encrypt_block(&mut Pad);
            // P_* = C_* xor Pad[1..bitlen(C_*)]
            let C_star = &mut buffer[processed_bytes..];
            let Pad = &mut Pad[..C_star.len()];
            for (aa, bb) in C_star.iter_mut().zip(Pad) {
                *aa ^= *bb;
            }
            // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
            let Checksum_rhs = &mut [0u8; 16];
            Checksum_rhs[..remaining_bytes].copy_from_slice(&buffer[processed_bytes..]);
            Checksum_rhs[remaining_bytes] = 0b1000_0000;
            inplace_xor(&mut Checksum_i, Block::from_slice(Checksum_rhs));
        }

        self.compute_tag(associated_data, &mut Checksum_i, &Offset_i)
    }

    /// Encrypts plaintext in groups of WIDTH.
    ///
    /// Adapted from https://www.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
    #[inline(never)]
    fn wide_encrypt(&self, nonce: &Nonce<NonceSize>, buffer: &mut [u8]) -> (usize, Block, Block) {
        #[cfg(not(target_feature = "avx512vaes"))]
        const WIDTH: usize = 2;
        #[cfg(not(target_feature = "avx512vaes"))]
        let split_into_blocks = crate::util::split_into_two_blocks;

        #[cfg(target_feature = "avx512vaes")]
        const WIDTH: usize = 4;
        #[cfg(target_feature = "avx512vaes")]
        let split_into_blocks = crate::util::split_into_four_blocks;

        let mut i = 1;

        let mut Offset_i = [Block::default(); WIDTH];
        Offset_i[Offset_i.len() - 1] = initial_offset(&self.cipher, nonce, TagSize::to_u32());
        let mut Checksum_i = Block::default();
        #[allow(unsafe_code)]
        unsafe {
            for wide_blocks in buffer.chunks_exact_mut(16 * WIDTH) {
                let P_i = split_into_blocks(wide_blocks);

                // Checksum_i = Checksum_{i-1} xor P_i
                for P_ij in &P_i {
                    inplace_xor(&mut Checksum_i, P_ij);
                }

                // Offset_i = Offset_{i-1} xor L_{ntz(i)}
                Offset_i[0] = Offset_i[Offset_i.len() - 1];
                inplace_xor(&mut Offset_i[0], &self.L[ntz(i)]);
                for j in 1..P_i.len() {
                    Offset_i[j] = Offset_i[j - 1];
                    inplace_xor(&mut Offset_i[j], &self.L[ntz(i + j)]);
                }

                // C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)
                for j in 0..P_i.len() {
                    inplace_xor(P_i[j], &Offset_i[j]);
                    self.cipher.encrypt_block(P_i[j]);
                    inplace_xor(P_i[j], &Offset_i[j])
                }

                i += WIDTH;
            }
        }

        let processed_bytes = (buffer.len() / (WIDTH * 16)) * (WIDTH * 16);

        (processed_bytes, Offset_i[Offset_i.len() - 1], Checksum_i)
    }

    /// Decrypts plaintext in groups of WIDTH.
    ///
    /// Adapted from https://www.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
    #[inline(never)]
    fn wide_decrypt(&self, nonce: &Nonce<NonceSize>, buffer: &mut [u8]) -> (usize, Block, Block) {
        #[cfg(not(target_feature = "avx512vaes"))]
        const WIDTH: usize = 2;
        #[cfg(not(target_feature = "avx512vaes"))]
        let split_into_blocks = crate::util::split_into_two_blocks;

        #[cfg(target_feature = "avx512vaes")]
        const WIDTH: usize = 4;
        #[cfg(target_feature = "avx512vaes")]
        let split_into_blocks = crate::util::split_into_four_blocks;

        let mut i = 1;

        let mut Offset_i = [Block::default(); WIDTH];
        Offset_i[Offset_i.len() - 1] = initial_offset(&self.cipher, nonce, TagSize::to_u32());
        let mut Checksum_i = Block::default();
        #[allow(unsafe_code)]
        unsafe {
            for wide_blocks in buffer.chunks_exact_mut(16 * WIDTH) {
                let C_i = split_into_blocks(wide_blocks);

                // Offset_i = Offset_{i-1} xor L_{ntz(i)}
                Offset_i[0] = Offset_i[Offset_i.len() - 1];
                inplace_xor(&mut Offset_i[0], &self.L[ntz(i)]);
                for j in 1..C_i.len() {
                    Offset_i[j] = Offset_i[j - 1];
                    inplace_xor(&mut Offset_i[j], &self.L[ntz(i + j)]);
                }

                // P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)
                // Checksum_i = Checksum_{i-1} xor P_i
                for j in 0..C_i.len() {
                    inplace_xor(C_i[j], &Offset_i[j]);
                    self.cipher.decrypt_block(C_i[j]);
                    inplace_xor(C_i[j], &Offset_i[j]);
                    inplace_xor(&mut Checksum_i, C_i[j]);
                }

                i += WIDTH;
            }
        }

        let processed_bytes = (buffer.len() / (WIDTH * 16)) * (WIDTH * 16);

        (processed_bytes, Offset_i[Offset_i.len() - 1], Checksum_i)
    }
}

/// Computes nonce-dependent variables as defined
/// in https://www.rfc-editor.org/rfc/rfc7253.html#section-4.2
///
/// Assumes a 96-bit nonce and 128-bit tag.
fn nonce_dependent_variables<
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: self::NonceSize,
>(
    cipher: &Aes,
    N: &Nonce<NonceSize>,
    tag_len: u32,
) -> (usize, [u8; 24]) {
    let mut Nonce = [0u8; 16];
    Nonce[4..16].copy_from_slice(N.as_slice());
    let mut Nonce = u128::from_be_bytes(Nonce);
    // Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
    Nonce |= 1 << 96;
    if tag_len == 16 {
        // do nothing because 128 mod 128 = 0
    } else if tag_len < 16 {
        Nonce |= (u128::from(tag_len) * 8) << (128 - 7);
    } else {
        unreachable!();
    }

    // Separate the last 6 bits into `bottom`, and the rest into `top`.
    let bottom = usize::try_from(Nonce & 0b111111).unwrap();
    let top = Nonce & !0b111111;

    let mut Ktop = Block::from(top.to_be_bytes());
    cipher.encrypt_block(&mut Ktop);
    let Ktop = Ktop.as_mut_slice();

    // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
    let mut Stretch = [0u8; 24];
    Stretch[..16].copy_from_slice(Ktop);
    for i in 0..8 {
        Ktop[i] ^= Ktop[i + 1];
    }
    Stretch[16..].copy_from_slice(&Ktop[..8]);

    (bottom, Stretch)
}

/// Computes the initial offset as defined
/// in https://www.rfc-editor.org/rfc/rfc7253.html#section-4.2
///
/// Assumes a 96-bit nonce and 128-bit tag.
fn initial_offset<
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: self::NonceSize,
>(
    cipher: &Aes,
    N: &Nonce<NonceSize>,
    tag_size: u32,
) -> Block {
    let (bottom, Stretch) = nonce_dependent_variables(cipher, N, tag_size);
    let Stretch_low = u128::from_be_bytes((&Stretch[..16]).try_into().unwrap());
    let Stretch_hi = u64::from_be_bytes((&Stretch[16..24]).try_into().unwrap());
    let Stretch_hi = u128::from(Stretch_hi);

    // Offset_0 = Stretch[1+bottom..128+bottom]
    let Offset = (Stretch_low << bottom) | (Stretch_hi >> (64 - bottom));
    Offset.to_be_bytes().into()
}

impl<Aes, NonceSize, TagSize> AesOcb3<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    TagSize: self::TagSize,
    NonceSize: self::NonceSize,
{
    /// Computes HASH function defined in https://www.rfc-editor.org/rfc/rfc7253.html#section-4.1
    fn hash(&self, associated_data: &[u8]) -> Sum {
        let mut Offset_i = Block::default();
        let mut Sum_i = Block::default();

        let mut i = 1;
        for A_i in associated_data.chunks_exact(16) {
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            inplace_xor(&mut Offset_i, &self.L[ntz(i)]);
            // Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)
            let mut A_i = *Block::from_slice(A_i);
            inplace_xor(&mut A_i, &Offset_i);
            self.cipher.encrypt_block(&mut A_i);
            inplace_xor(&mut Sum_i, &A_i);

            i += 1;
        }

        // Process any partial blocks.
        if (associated_data.len() % 16) != 0 {
            let processed_bytes = (i - 1) * 16;
            let remaining_bytes = associated_data.len() - processed_bytes;

            // Offset_* = Offset_m xor L_*
            inplace_xor(&mut Offset_i, &self.Lstar);
            // CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_*
            let CipherInput = &mut [0u8; 16];
            CipherInput[..remaining_bytes].copy_from_slice(&associated_data[processed_bytes..]);
            CipherInput[remaining_bytes] = 0b1000_0000;
            let CipherInput = Block::from_mut_slice(CipherInput);
            inplace_xor(CipherInput, &Offset_i);
            // Sum = Sum_m xor ENCIPHER(K, CipherInput)
            self.cipher.encrypt_block(CipherInput);
            inplace_xor(&mut Sum_i, CipherInput);
        }

        Sum_i
    }

    fn compute_tag(
        &self,
        associated_data: &[u8],
        Checksum_m: &mut Block,
        Offset_m: &Block,
    ) -> Tag<TagSize> {
        // Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K,A)
        let full_tag = Checksum_m;
        inplace_xor(full_tag, Offset_m);
        inplace_xor(full_tag, &self.Ldollar);
        self.cipher.encrypt_block(full_tag);
        inplace_xor(full_tag, &self.hash(associated_data));

        // truncate the tag to the required length
        Tag::clone_from_slice(&full_tag[..TagSize::to_usize()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn double_basic_test() {
        let zero = Block::from(hex!("00000000000000000000000000000000"));
        assert_eq!(zero, double(&zero));
        let one = Block::from(hex!("00000000000000000000000000000001"));
        let two = Block::from(hex!("00000000000000000000000000000002"));
        assert_eq!(two, double(&one));
    }

    #[test]
    fn rfc7253_key_dependent_constants() {
        // Test vector from page 17 of https://www.rfc-editor.org/rfc/rfc7253.html
        let key = hex!("000102030405060708090A0B0C0D0E0F");
        let expected_Lstar = Block::from(hex!("C6A13B37878F5B826F4F8162A1C8D879"));
        let expected_Ldollar = Block::from(hex!("8D42766F0F1EB704DE9F02C54391B075"));
        let expected_L0 = Block::from(hex!("1A84ECDE1E3D6E09BD3E058A8723606D"));
        let expected_L1 = Block::from(hex!("3509D9BC3C7ADC137A7C0B150E46C0DA"));

        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let (Lstar, Ldollar, L) = key_dependent_variables(&cipher);

        assert_eq!(Lstar, expected_Lstar);
        assert_eq!(Ldollar, expected_Ldollar);
        assert_eq!(L[0], expected_L0);
        assert_eq!(L[1], expected_L1);
    }

    #[test]
    fn rfc7253_nonce_dependent_constants() {
        // Test vector from page 17 of https://www.rfc-editor.org/rfc/rfc7253.html
        let key = hex!("000102030405060708090A0B0C0D0E0F");
        let nonce = hex!("BBAA9988776655443322110F");
        let expected_bottom = usize::try_from(15).unwrap();
        let expected_Stretch = hex!("9862B0FDEE4E2DD56DBA6433F0125AA2FAD24D13A063F8B8");
        let expected_Offset_0 = Block::from(hex!("587EF72716EAB6DD3219F8092D517D69"));

        const TAGLEN: u32 = 16;

        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let (bottom, Stretch) = nonce_dependent_variables(&cipher, &Nonce::from(nonce), TAGLEN);
        let Offset_0 = initial_offset(&cipher, &Nonce::from(nonce), TAGLEN);

        assert_eq!(bottom, expected_bottom);
        assert_eq!(Stretch, expected_Stretch);
        assert_eq!(Offset_0, expected_Offset_0);
    }
}
