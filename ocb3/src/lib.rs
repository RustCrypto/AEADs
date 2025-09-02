#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

/// Constants used, reexported for convenience.
pub mod consts {
    pub use cipher::consts::{U0, U6, U12, U15, U16};
}

pub use aead::{
    self, AeadCore, AeadInOut, Error, KeyInit, KeySizeUser,
    array::{Array, AsArrayRef, AssocArraySize},
};

use aead::{
    TagPosition,
    array::ArraySize,
    inout::{InOut, InOutBuf},
};
use cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser,
    consts::{U2, U12, U16},
    typenum::Prod,
};
use core::marker::PhantomData;
use dbl::Dbl;
use subtle::ConstantTimeEq;

/// Number of L values to be precomputed. Precomputing m values, allows
/// processing inputs of length up to 2^m blocks (2^m * 16 bytes) without
/// needing to calculate L values at runtime.
///
/// By setting this to 32, we can process inputs of length up to 1 terabyte.
#[cfg(target_pointer_width = "64")]
const L_TABLE_SIZE: usize = 32;

/// Number of L values to be precomputed. Precomputing m values, allows
/// processing inputs of length up to 2^m blocks (2^m * 16 bytes) without
/// needing to calculate L values at runtime.
#[cfg(target_pointer_width = "32")]
const L_TABLE_SIZE: usize = 16;

/// Max associated data.
pub const A_MAX: usize = 1 << (L_TABLE_SIZE + 4);
/// Max plaintext.
pub const P_MAX: usize = 1 << (L_TABLE_SIZE + 4);
/// Max ciphertext.
pub const C_MAX: usize = 1 << (L_TABLE_SIZE + 4);

/// OCB3 nonce
pub type Nonce<NonceSize> = Array<u8, NonceSize>;

/// OCB3 tag
pub type Tag<TagSize> = Array<u8, TagSize>;

type BlockSize = U16;
pub(crate) type Block = Array<u8, BlockSize>;
type DoubleBlock = Array<u8, Prod<BlockSize, U2>>;

mod sealed {
    use aead::array::{
        ArraySize,
        typenum::{GrEq, IsGreaterOrEqual, IsLessOrEqual, LeEq, NonZero, U6, U15, U16},
    };

    /// Sealed trait for nonce sizes in the range of `6..=15` bytes.
    pub trait NonceSizes: ArraySize {}

    impl<T> NonceSizes for T
    where
        T: ArraySize + IsGreaterOrEqual<U6> + IsLessOrEqual<U15>,
        GrEq<T, U6>: NonZero,
        LeEq<T, U15>: NonZero,
    {
    }

    /// Sealed trait for tag sizes in the range of `1..=16` bytes.
    pub trait TagSizes: ArraySize {}

    impl<T> TagSizes for T
    where
        T: ArraySize + NonZero + IsLessOrEqual<U16>,
        LeEq<T, U16>: NonZero,
    {
    }
}

/// OCB3: generic over a block cipher implementation, nonce size, and tag size.
///
/// - `NonceSize`: max of 15-bytes, default and recommended size of 12-bytes (96-bits).
///   We further restrict the minimum nonce size to 6-bytes to prevent an attack described in
///   the following paper: <https://eprint.iacr.org/2023/326.pdf>.
/// - `TagSize`: non-zero, max of 16-bytes, default and recommended size of 16-bytes.
///
/// Compilation will fail if the size conditions are not satisfied:
///
/// ```rust,compile_fail
/// # use aes::Aes128;
/// # use ocb3::{aead::{consts::U5, KeyInit}, Ocb3};
/// # let key = [42; 16].into();
/// // Invalid nonce size equal to 5 bytes
/// let cipher = Ocb3::<Aes128, U5>::new(&key);
/// ```
///
/// ```rust,compile_fail
/// # use aes::Aes128;
/// # use ocb3::{aead::{consts::U16, KeyInit}, Ocb3};
/// # let key = [42; 16].into();
/// // Invalid nonce size equal to 16 bytes
/// let cipher = Ocb3::<Aes128, U16>::new(&key);
/// ```
///
/// ```rust,compile_fail
/// # use aes::Aes128;
/// # use ocb3::{aead::{consts::{U12, U0}, KeyInit}, Ocb3};
/// # let key = [42; 16].into();
/// // Invalid tag size equal to 0 bytes
/// let cipher = Ocb3::<Aes128, U12, U0>::new(&key);
/// ```
///
/// ```rust,compile_fail
/// # use aes::Aes128;
/// # use ocb3::{aead::{consts::{U12, U20}, KeyInit}, Ocb3};
/// # let key = [42; 16].into();
/// // Invalid tag size equal to 20 bytes
/// let cipher = Ocb3::<Aes128, U12, U20>::new(&key);
/// ```
#[derive(Clone)]
pub struct Ocb3<Cipher, NonceSize = U12, TagSize = U16>
where
    NonceSize: sealed::NonceSizes,
    TagSize: sealed::TagSizes,
{
    cipher: Cipher,
    nonce_size: PhantomData<NonceSize>,
    tag_size: PhantomData<TagSize>,
    // precomputed key-dependent variables
    ll_star: Block,
    ll_dollar: Block,
    // list of pre-computed L values
    ll: [Block; L_TABLE_SIZE],
}

impl<Cipher, NonceSize, TagSize> KeySizeUser for Ocb3<Cipher, NonceSize, TagSize>
where
    Cipher: KeySizeUser,
    NonceSize: sealed::NonceSizes,
    TagSize: sealed::TagSizes,
{
    type KeySize = Cipher::KeySize;
}

impl<Cipher, NonceSize, TagSize> KeyInit for Ocb3<Cipher, NonceSize, TagSize>
where
    Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit + BlockCipherDecrypt,
    NonceSize: sealed::NonceSizes,
    TagSize: sealed::TagSizes,
{
    fn new(key: &aead::Key<Self>) -> Self {
        Cipher::new(key).into()
    }
}

impl<Cipher, NonceSize, TagSize> AeadCore for Ocb3<Cipher, NonceSize, TagSize>
where
    NonceSize: sealed::NonceSizes,
    TagSize: sealed::TagSizes,
{
    type NonceSize = NonceSize;
    type TagSize = TagSize;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl<Cipher, NonceSize, TagSize> From<Cipher> for Ocb3<Cipher, NonceSize, TagSize>
where
    Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    NonceSize: sealed::NonceSizes,
    TagSize: sealed::TagSizes,
{
    fn from(cipher: Cipher) -> Self {
        let (ll_star, ll_dollar, ll) = key_dependent_variables(&cipher);

        Self {
            cipher,
            nonce_size: PhantomData,
            tag_size: PhantomData,
            ll_star,
            ll_dollar,
            ll,
        }
    }
}

impl<Cipher, NonceSize, TagSize> AeadInOut for Ocb3<Cipher, NonceSize, TagSize>
where
    Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    NonceSize: sealed::NonceSizes,
    TagSize: sealed::TagSizes,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<aead::Tag<Self>> {
        if (buffer.len() > P_MAX) || (associated_data.len() > A_MAX) {
            unimplemented!()
        }

        // First, try to process many blocks at once.
        let (tail, index, mut offset_i, mut checksum_i) = self.wide_encrypt(nonce, buffer);

        let mut i = index;

        // Then, process the remaining blocks.
        let (blocks, mut tail): (InOutBuf<'_, '_, Block>, _) = tail.into_chunks();

        for p_i in blocks {
            // offset_i = offset_{i-1} xor L_{ntz(i)}
            inplace_xor(&mut offset_i, &self.ll[ntz(i)]);
            // checksum_i = checksum_{i-1} xor p_i
            inplace_xor(&mut checksum_i, p_i.get_in());
            // c_i = offset_i xor ENCIPHER(K, p_i xor offset_i)
            let mut c_i = p_i;
            c_i.xor_in2out(&offset_i);
            self.cipher.encrypt_block(c_i.get_out());
            inplace_xor(c_i.get_out(), &offset_i);

            i += 1;
        }

        // Process any partial blocks.
        if !tail.is_empty() {
            let remaining_bytes = tail.len();

            // offset_* = offset_m xor L_*
            inplace_xor(&mut offset_i, &self.ll_star);
            // Pad = ENCIPHER(K, offset_*)
            let mut pad = Block::default();
            inplace_xor(&mut pad, &offset_i);
            self.cipher.encrypt_block(&mut pad);
            // checksum_* = checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
            let checksum_rhs = &mut [0u8; 16];
            checksum_rhs[..remaining_bytes].copy_from_slice(tail.get_in());
            checksum_rhs[remaining_bytes] = 0b1000_0000;
            inplace_xor(&mut checksum_i, checksum_rhs.as_array_ref());
            // C_* = P_* xor Pad[1..bitlen(P_*)]
            let p_star = tail.get_out();
            let pad = &mut pad[..p_star.len()];
            tail.xor_in2out(pad);
        }

        let tag = self.compute_tag(associated_data, &mut checksum_i, &offset_i);

        Ok(tag)
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        let expected_tag = self.decrypt_inout_return_tag(nonce, associated_data, buffer);
        if expected_tag.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<Cipher, NonceSize, TagSize> Ocb3<Cipher, NonceSize, TagSize>
where
    Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    NonceSize: sealed::NonceSizes,
    TagSize: sealed::TagSizes,
{
    /// Decrypts in place and returns expected tag.
    pub(crate) fn decrypt_inout_return_tag(
        &self,
        nonce: &Nonce<NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Tag<Self> {
        if (buffer.len() > C_MAX) || (associated_data.len() > A_MAX) {
            unimplemented!()
        }

        // First, try to process many blocks at once.
        let (tail, index, mut offset_i, mut checksum_i) = self.wide_decrypt(nonce, buffer);

        let mut i = index;

        // Then, process the remaining blocks.
        let (blocks, mut tail): (InOutBuf<'_, '_, Block>, _) = tail.into_chunks();
        for c_i in blocks {
            // offset_i = offset_{i-1} xor L_{ntz(i)}
            inplace_xor(&mut offset_i, &self.ll[ntz(i)]);
            // p_i = offset_i xor DECIPHER(K, c_i xor offset_i)
            let mut p_i = c_i;
            p_i.xor_in2out(&offset_i);
            self.cipher.decrypt_block(p_i.get_out());
            inplace_xor(p_i.get_out(), &offset_i);
            // checksum_i = checksum_{i-1} xor p_i
            inplace_xor(&mut checksum_i, p_i.get_out());

            i += 1;
        }

        // Process any partial blocks.
        if !tail.is_empty() {
            let remaining_bytes = tail.len();

            // offset_* = offset_m xor L_*
            inplace_xor(&mut offset_i, &self.ll_star);
            // Pad = ENCIPHER(K, offset_*)
            let mut pad = Block::default();
            inplace_xor(&mut pad, &offset_i);
            self.cipher.encrypt_block(&mut pad);
            // P_* = C_* xor Pad[1..bitlen(C_*)]
            let c_star = tail.get_in();
            let pad = &mut pad[..c_star.len()];
            tail.xor_in2out(pad);
            // checksum_* = checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
            let checksum_rhs = &mut [0u8; 16];
            checksum_rhs[..remaining_bytes].copy_from_slice(tail.get_out());
            checksum_rhs[remaining_bytes] = 0b1000_0000;
            inplace_xor(&mut checksum_i, checksum_rhs.as_array_ref());
        }

        self.compute_tag(associated_data, &mut checksum_i, &offset_i)
    }

    /// Encrypts plaintext in groups of two.
    ///
    /// Adapted from https://www.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
    fn wide_encrypt<'i, 'o>(
        &self,
        nonce: &Nonce<NonceSize>,
        buffer: InOutBuf<'i, 'o, u8>,
    ) -> (InOutBuf<'i, 'o, u8>, usize, Block, Block) {
        const WIDTH: usize = 2;

        let mut i = 1;

        let mut offset_i = [Block::default(); WIDTH];
        offset_i[1] = initial_offset(&self.cipher, nonce, TagSize::to_u32());
        let mut checksum_i = Block::default();

        let (wide_blocks, tail): (InOutBuf<'_, '_, DoubleBlock>, _) = buffer.into_chunks();
        for wide_block in wide_blocks.into_iter() {
            let mut p_i = split_into_two_blocks(wide_block);
            // checksum_i = checksum_{i-1} xor p_i
            for p_ij in &p_i {
                inplace_xor(&mut checksum_i, p_ij.get_in());
            }

            // offset_i = offset_{i-1} xor L_{ntz(i)}
            offset_i[0] = offset_i[1];
            inplace_xor(&mut offset_i[0], &self.ll[ntz(i)]);
            offset_i[1] = offset_i[0];
            inplace_xor(&mut offset_i[1], &self.ll[ntz(i + 1)]);

            // c_i = offset_i xor ENCIPHER(K, p_i xor offset_i)
            for j in 0..p_i.len() {
                p_i[j].xor_in2out(&offset_i[j]);
                self.cipher.encrypt_block(p_i[j].get_out());
                inplace_xor(p_i[j].get_out(), &offset_i[j]);
            }

            i += WIDTH;
        }

        (tail, i, offset_i[offset_i.len() - 1], checksum_i)
    }

    /// Decrypts plaintext in groups of two.
    ///
    /// Adapted from https://www.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
    fn wide_decrypt<'i, 'o>(
        &self,
        nonce: &Nonce<NonceSize>,
        buffer: InOutBuf<'i, 'o, u8>,
    ) -> (InOutBuf<'i, 'o, u8>, usize, Block, Block) {
        const WIDTH: usize = 2;

        let mut i = 1;

        let mut offset_i = [Block::default(); WIDTH];
        offset_i[1] = initial_offset(&self.cipher, nonce, TagSize::to_u32());
        let mut checksum_i = Block::default();

        let (wide_blocks, tail): (InOutBuf<'_, '_, DoubleBlock>, _) = buffer.into_chunks();
        for wide_block in wide_blocks.into_iter() {
            let mut c_i = split_into_two_blocks(wide_block);

            // offset_i = offset_{i-1} xor L_{ntz(i)}
            offset_i[0] = offset_i[1];
            inplace_xor(&mut offset_i[0], &self.ll[ntz(i)]);
            offset_i[1] = offset_i[0];
            inplace_xor(&mut offset_i[1], &self.ll[ntz(i + 1)]);

            // p_i = offset_i xor DECIPHER(K, c_i xor offset_i)
            // checksum_i = checksum_{i-1} xor p_i
            for j in 0..c_i.len() {
                c_i[j].xor_in2out(&offset_i[j]);
                self.cipher.decrypt_block(c_i[j].get_out());
                inplace_xor(c_i[j].get_out(), &offset_i[j]);
                inplace_xor(&mut checksum_i, c_i[j].get_out());
            }

            i += WIDTH;
        }

        (tail, i, offset_i[offset_i.len() - 1], checksum_i)
    }

    /// Computes HASH function defined in https://www.rfc-editor.org/rfc/rfc7253.html#section-4.1
    fn hash(&self, associated_data: &[u8]) -> Block {
        let mut offset_i = Block::default();
        let mut sum_i = Block::default();

        let mut i = 1;
        let (blocks, remaining) = Block::slice_as_chunks(associated_data);
        for a_i in blocks {
            // offset_i = offset_{i-1} xor L_{ntz(i)}
            inplace_xor(&mut offset_i, &self.ll[ntz(i)]);
            // Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor offset_i)
            let mut a_i = *a_i;
            inplace_xor(&mut a_i, &offset_i);
            self.cipher.encrypt_block(&mut a_i);
            inplace_xor(&mut sum_i, &a_i);

            i += 1;
        }

        // Process any partial blocks.
        if !remaining.is_empty() {
            let processed_bytes = (i - 1) * 16;
            let remaining_bytes = associated_data.len() - processed_bytes;

            // offset_* = offset_m xor L_*
            inplace_xor(&mut offset_i, &self.ll_star);
            // CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor offset_*
            let mut cipher_input = Block::default();
            cipher_input[..remaining_bytes].copy_from_slice(&associated_data[processed_bytes..]);
            cipher_input[remaining_bytes] = 0b1000_0000;
            //let cipher_input = Block::from_mut_slice(cipher_input);
            inplace_xor(&mut cipher_input, &offset_i);
            // Sum = Sum_m xor ENCIPHER(K, CipherInput)
            self.cipher.encrypt_block(&mut cipher_input);
            inplace_xor(&mut sum_i, &cipher_input);
        }

        sum_i
    }

    fn compute_tag(
        &self,
        associated_data: &[u8],
        checksum_m: &mut Block,
        offset_m: &Block,
    ) -> Tag<TagSize> {
        // Tag = ENCIPHER(K, checksum_m xor offset_m xor L_$) xor HASH(K,A)
        let full_tag = checksum_m;
        inplace_xor(full_tag, offset_m);
        inplace_xor(full_tag, &self.ll_dollar);
        self.cipher.encrypt_block(full_tag);
        inplace_xor(full_tag, &self.hash(associated_data));

        // truncate the tag to the required length
        Tag::try_from(&full_tag[..TagSize::to_usize()]).expect("tag size mismatch")
    }
}

/// Computes key-dependent variables defined in
/// https://www.rfc-editor.org/rfc/rfc7253.html#section-4.1
fn key_dependent_variables<Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt>(
    cipher: &Cipher,
) -> (Block, Block, [Block; L_TABLE_SIZE]) {
    let mut ll_star = Block::default();
    cipher.encrypt_block(&mut ll_star);
    let ll_dollar = ll_star.dbl();

    let mut ll = [Block::default(); L_TABLE_SIZE];
    let mut ll_i = ll_dollar;
    #[allow(clippy::needless_range_loop)]
    for i in 0..L_TABLE_SIZE {
        ll_i = ll_i.dbl();
        ll[i] = ll_i
    }
    (ll_star, ll_dollar, ll)
}

/// Computes nonce-dependent variables as defined
/// in https://www.rfc-editor.org/rfc/rfc7253.html#section-4.2
fn nonce_dependent_variables<
    Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    NonceSize: sealed::NonceSizes,
>(
    cipher: &Cipher,
    nn: &Nonce<NonceSize>,
    tag_len: u32,
) -> (usize, [u8; 24]) {
    // Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
    let mut nonce = [0u8; 16];
    nonce[0] = (((tag_len * 8) % 128) << 1) as u8;

    let start = 16 - NonceSize::to_usize();
    nonce[start..16].copy_from_slice(nn.as_slice());
    nonce[16 - NonceSize::to_usize() - 1] |= 1;

    // Separate the last 6 bits into `bottom`, and the rest into `top`.
    let bottom = nonce[15] & 0b111111;

    let nonce = u128::from_be_bytes(nonce);
    let top = nonce & !0b111111;

    let mut ktop = Block::from(top.to_be_bytes());
    cipher.encrypt_block(&mut ktop);
    let ktop = ktop.as_mut_slice();

    // stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
    let mut stretch = [0u8; 24];
    stretch[..16].copy_from_slice(ktop);
    for i in 0..8 {
        ktop[i] ^= ktop[i + 1];
    }
    stretch[16..].copy_from_slice(&ktop[..8]);

    (bottom as usize, stretch)
}

/// Computes the initial offset as defined
/// in https://www.rfc-editor.org/rfc/rfc7253.html#section-4.2
fn initial_offset<
    Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    NonceSize: sealed::NonceSizes,
>(
    cipher: &Cipher,
    nn: &Nonce<NonceSize>,
    tag_size: u32,
) -> Block {
    let (bottom, stretch) = nonce_dependent_variables(cipher, nn, tag_size);
    let stretch_low = u128::from_be_bytes((&stretch[..16]).try_into().unwrap());
    let stretch_hi = u64::from_be_bytes((&stretch[16..24]).try_into().unwrap());
    let stretch_hi = u128::from(stretch_hi);

    // offset_0 = stretch[1+bottom..128+bottom]
    let offset = (stretch_low << bottom) | (stretch_hi >> (64 - bottom));
    offset.to_be_bytes().into()
}

#[inline]
pub(crate) fn inplace_xor<T, U>(a: &mut Array<T, U>, b: &Array<T, U>)
where
    U: ArraySize,
    T: core::ops::BitXor<Output = T> + Copy,
{
    for (aa, bb) in a.as_mut_slice().iter_mut().zip(b.as_slice()) {
        *aa = *aa ^ *bb;
    }
}

/// Counts the number of non-trailing zeros in the binary representation.
///
/// Defined in https://www.rfc-editor.org/rfc/rfc7253.html#section-2
#[inline]
pub(crate) fn ntz(n: usize) -> usize {
    n.trailing_zeros() as usize
}

#[inline]
pub(crate) fn split_into_two_blocks<'i, 'o>(
    two_blocks: InOut<'i, 'o, DoubleBlock>,
) -> [InOut<'i, 'o, Block>; 2] {
    Array::<InOut<'i, 'o, Block>, U2>::from(two_blocks).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aead::array::Array;
    use dbl::Dbl;
    use hex_literal::hex;

    #[test]
    fn double_basic_test() {
        let zero = Block::from(hex!("00000000000000000000000000000000"));
        assert_eq!(zero, zero.dbl());
        let one = Block::from(hex!("00000000000000000000000000000001"));
        let two = Block::from(hex!("00000000000000000000000000000002"));
        assert_eq!(two, one.dbl());
    }

    #[test]
    fn rfc7253_key_dependent_constants() {
        // Test vector from page 17 of https://www.rfc-editor.org/rfc/rfc7253.html
        let key = hex!("000102030405060708090A0B0C0D0E0F");
        let expected_ll_star = Block::from(hex!("C6A13B37878F5B826F4F8162A1C8D879"));
        let expected_ll_dollar = Block::from(hex!("8D42766F0F1EB704DE9F02C54391B075"));
        let expected_ll0 = Block::from(hex!("1A84ECDE1E3D6E09BD3E058A8723606D"));
        let expected_ll1 = Block::from(hex!("3509D9BC3C7ADC137A7C0B150E46C0DA"));

        let cipher = aes::Aes128::new(&Array(key));
        let (ll_star, ll_dollar, ll) = key_dependent_variables(&cipher);

        assert_eq!(ll_star, expected_ll_star);
        assert_eq!(ll_dollar, expected_ll_dollar);
        assert_eq!(ll[0], expected_ll0);
        assert_eq!(ll[1], expected_ll1);
    }

    #[test]
    fn rfc7253_nonce_dependent_constants() {
        // Test vector from page 17 of https://www.rfc-editor.org/rfc/rfc7253.html
        let key = hex!("000102030405060708090A0B0C0D0E0F");
        let nonce = hex!("BBAA9988776655443322110F");
        let expected_bottom = usize::try_from(15).unwrap();
        let expected_stretch = hex!("9862B0FDEE4E2DD56DBA6433F0125AA2FAD24D13A063F8B8");
        let expected_offset_0 = Block::from(hex!("587EF72716EAB6DD3219F8092D517D69"));

        const TAGLEN: u32 = 16;

        let cipher = aes::Aes128::new(&Array(key));
        let (bottom, stretch) =
            nonce_dependent_variables::<aes::Aes128, U12>(&cipher, &Nonce::from(nonce), TAGLEN);
        let offset_0 = initial_offset::<aes::Aes128, U12>(&cipher, &Nonce::from(nonce), TAGLEN);

        assert_eq!(bottom, expected_bottom, "bottom");
        assert_eq!(stretch, expected_stretch, "stretch");
        assert_eq!(offset_0, expected_offset_0, "offset");
    }
}
