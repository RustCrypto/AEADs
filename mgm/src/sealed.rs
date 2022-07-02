use aead::{
    generic_array::{
        typenum::{U16, U8},
        ArrayLength, GenericArray,
    },
    Error,
};
use cipher::BlockCipher;

pub type Counter<C> = [<<C as BlockCipher>::BlockSize as Sealed>::Counter; 2];

pub trait Sealed: ArrayLength<u8> {
    type Counter;

    fn block2ctr(block: &GenericArray<u8, Self>) -> [Self::Counter; 2];
    fn ctr2block(ctr: &[Self::Counter; 2]) -> GenericArray<u8, Self>;
    fn incr_l(ctr: &mut [Self::Counter; 2]);
    fn incr_r(ctr: &mut [Self::Counter; 2]);
    fn lengths2block(adata_len: usize, data_len: usize) -> Result<GenericArray<u8, Self>, Error>;
}

impl Sealed for U16 {
    type Counter = u64;

    #[inline(always)]
    fn block2ctr(block: &GenericArray<u8, Self>) -> [Self::Counter; 2] {
        let (a, b) = block.split_at(8);
        [
            u64::from_be_bytes(a.try_into().unwrap()),
            u64::from_be_bytes(b.try_into().unwrap()),
        ]
    }

    #[inline(always)]
    fn ctr2block(ctr: &[Self::Counter; 2]) -> GenericArray<u8, Self> {
        let a = ctr[0].to_be_bytes();
        let b = ctr[1].to_be_bytes();
        let mut block = GenericArray::<u8, Self>::default();
        block[..8].copy_from_slice(&a);
        block[8..].copy_from_slice(&b);
        block
    }

    #[inline(always)]
    fn incr_l(ctr: &mut [Self::Counter; 2]) {
        ctr[0] = ctr[0].wrapping_add(1);
    }

    #[inline(always)]
    fn incr_r(ctr: &mut [Self::Counter; 2]) {
        ctr[1] = ctr[1].wrapping_add(1);
    }

    #[inline(always)]
    fn lengths2block(adata_len: usize, data_len: usize) -> Result<GenericArray<u8, Self>, Error> {
        let adata_len = adata_len
            .checked_mul(8)
            .ok_or(Error)?
            .try_into()
            .map_err(|_| Error)?;
        let data_len = data_len
            .checked_mul(8)
            .ok_or(Error)?
            .try_into()
            .map_err(|_| Error)?;
        Ok(Self::ctr2block(&[adata_len, data_len]))
    }
}

impl Sealed for U8 {
    type Counter = u32;

    #[inline(always)]
    fn block2ctr(block: &GenericArray<u8, Self>) -> [Self::Counter; 2] {
        let (a, b) = block.split_at(4);
        [
            u32::from_be_bytes(a.try_into().unwrap()),
            u32::from_be_bytes(b.try_into().unwrap()),
        ]
    }

    #[inline(always)]
    fn ctr2block(ctr: &[Self::Counter; 2]) -> GenericArray<u8, Self> {
        let a = ctr[0].to_be_bytes();
        let b = ctr[1].to_be_bytes();
        let mut block = GenericArray::<u8, Self>::default();
        block[..4].copy_from_slice(&a);
        block[4..].copy_from_slice(&b);
        block
    }

    #[inline(always)]
    fn incr_l(ctr: &mut [Self::Counter; 2]) {
        ctr[0] = ctr[0].wrapping_add(1);
    }

    #[inline(always)]
    fn incr_r(ctr: &mut [Self::Counter; 2]) {
        ctr[1] = ctr[1].wrapping_add(1);
    }

    #[inline(always)]
    fn lengths2block(adata_len: usize, data_len: usize) -> Result<GenericArray<u8, Self>, Error> {
        let adata_len = adata_len
            .checked_mul(8)
            .ok_or(Error)?
            .try_into()
            .map_err(|_| Error)?;
        let data_len = data_len
            .checked_mul(8)
            .ok_or(Error)?
            .try_into()
            .map_err(|_| Error)?;
        Ok(Self::ctr2block(&[adata_len, data_len]))
    }
}
