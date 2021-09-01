use aead::generic_array::{ArrayLength, GenericArray};

mod utils;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    not(feature = "force-soft")
))]
pub(crate) mod gf128_pclmul;

pub(crate) mod gf128_soft64;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    not(feature = "force-soft")
))]
pub(crate) mod gf64_pclmul;

pub(crate) mod gf64_soft64;

pub trait GfElement {
    type N: ArrayLength<u8>;

    fn new() -> Self;
    fn into_bytes(self) -> GenericArray<u8, Self::N>;
    fn mul_sum(&mut self, a: &GenericArray<u8, Self::N>, b: &GenericArray<u8, Self::N>);
}
