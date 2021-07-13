use crate::gf::GfElement;
use aead::{
    generic_array::{
        typenum::{U16, U8},
        ArrayLength, GenericArray,
    },
    Error,
};
use cipher::BlockCipher;
use core::{convert::TryInto, num::Wrapping};

pub type Counter<C> = [<<C as BlockCipher>::BlockSize as Sealed>::Counter; 2];

pub trait Sealed: ArrayLength<u8> {
    type Counter;
    type Element: GfElement<N = Self>;

    fn block2ctr(block: &GenericArray<u8, Self>) -> [Self::Counter; 2];
    fn ctr2block(ctr: &[Self::Counter; 2]) -> GenericArray<u8, Self>;
    fn incr_l(ctr: &mut [Self::Counter; 2]);
    fn incr_r(ctr: &mut [Self::Counter; 2]);
    fn lengths2block(adata_len: usize, data_len: usize) -> Result<GenericArray<u8, Self>, Error>;
}

impl Sealed for U16 {
    type Counter = Wrapping<u64>;
    type Element = crate::gf::Element128;

    fn block2ctr(block: &GenericArray<u8, Self>) -> [Self::Counter; 2] {
        let (a, b) = block.split_at(8);
        [
            Wrapping(u64::from_be_bytes(a.try_into().unwrap())),
            Wrapping(u64::from_be_bytes(b.try_into().unwrap())),
        ]
    }

    fn ctr2block(ctr: &[Self::Counter; 2]) -> GenericArray<u8, Self> {
        let a = ctr[0].0.to_be_bytes();
        let b = ctr[1].0.to_be_bytes();
        let mut block = GenericArray::<u8, Self>::default();
        block[..8].copy_from_slice(&a);
        block[8..].copy_from_slice(&b);
        block
    }

    fn incr_l(ctr: &mut [Self::Counter; 2]) {
        ctr[0] += Wrapping(1);
    }

    fn incr_r(ctr: &mut [Self::Counter; 2]) {
        ctr[1] += Wrapping(1);
    }

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
        Ok(Self::ctr2block(&[Wrapping(adata_len), Wrapping(data_len)]))
    }
}

impl Sealed for U8 {
    type Counter = Wrapping<u32>;
    type Element = crate::gf::Element64;

    fn block2ctr(block: &GenericArray<u8, Self>) -> [Self::Counter; 2] {
        let (a, b) = block.split_at(4);
        [
            Wrapping(u32::from_be_bytes(a.try_into().unwrap())),
            Wrapping(u32::from_be_bytes(b.try_into().unwrap())),
        ]
    }

    fn ctr2block(ctr: &[Self::Counter; 2]) -> GenericArray<u8, Self> {
        let a = ctr[0].0.to_be_bytes();
        let b = ctr[1].0.to_be_bytes();
        let mut block = GenericArray::<u8, Self>::default();
        block[..4].copy_from_slice(&a);
        block[4..].copy_from_slice(&b);
        block
    }

    fn incr_l(ctr: &mut [Self::Counter; 2]) {
        ctr[0] += Wrapping(1);
    }

    fn incr_r(ctr: &mut [Self::Counter; 2]) {
        ctr[1] += Wrapping(1);
    }

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
        Ok(Self::ctr2block(&[Wrapping(adata_len), Wrapping(data_len)]))
    }
}
