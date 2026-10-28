use aead::{
    Error,
    array::{Array, ArraySize},
    consts::{U8, U16},
};
use cipher::BlockSizeUser;

pub type Counter<C> = [<<C as BlockSizeUser>::BlockSize as Sealed>::Counter; 2];

pub trait Sealed: ArraySize {
    type Counter;

    fn block2ctr(block: &Array<u8, Self>) -> [Self::Counter; 2];
    fn ctr2block(ctr: &[Self::Counter; 2]) -> Array<u8, Self>;
    fn incr_l(ctr: &mut [Self::Counter; 2]);
    fn incr_r(ctr: &mut [Self::Counter; 2]);
    fn lengths2block(adata_len: usize, data_len: usize) -> Result<Array<u8, Self>, Error>;
}

macro_rules! impl_sealed {
    ($size:ty, $counter:ty, $half:literal) => {
        impl Sealed for $size {
            type Counter = $counter;

            #[inline(always)]
            fn block2ctr(block: &Array<u8, Self>) -> [Self::Counter; 2] {
                let (a, b) = block.split_at($half);
                [
                    <$counter>::from_be_bytes(a.try_into().unwrap()),
                    <$counter>::from_be_bytes(b.try_into().unwrap()),
                ]
            }

            #[inline(always)]
            fn ctr2block(ctr: &[Self::Counter; 2]) -> Array<u8, Self> {
                let mut block = Array::<u8, Self>::default();
                block[..$half].copy_from_slice(&ctr[0].to_be_bytes());
                block[$half..].copy_from_slice(&ctr[1].to_be_bytes());
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
            fn lengths2block(adata_len: usize, data_len: usize) -> Result<Array<u8, Self>, Error> {
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
    };
}

impl_sealed!(U16, u64, 8);
impl_sealed!(U8, u32, 4);
