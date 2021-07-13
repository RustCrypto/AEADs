use aead::generic_array::{ArrayLength, GenericArray};

mod utils;

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[path = "gf/gf128_pclmul.rs"]
mod imp128;

#[cfg(not(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
#[path = "gf/gf128_soft64.rs"]
mod imp128;

#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[path = "gf/gf64_pclmul.rs"]
mod imp64;

#[cfg(not(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
#[path = "gf/gf64_soft64.rs"]
mod imp64;

pub use imp128::Element128;
pub use imp64::Element64;

pub trait GfElement {
    type N: ArrayLength<u8>;

    fn new() -> Self;
    fn into_bytes(self) -> GenericArray<u8, Self::N>;
    fn mul_sum(&mut self, a: &GenericArray<u8, Self::N>, b: &GenericArray<u8, Self::N>);
}
