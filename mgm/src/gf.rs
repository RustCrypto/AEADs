use aead::array::{Array, ArraySize};

mod utils;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    not(feature = "force-soft")
))]
#[allow(
    unsafe_code,
    clippy::undocumented_unsafe_blocks,
    clippy::cast_possible_wrap,
    clippy::unwrap_used,
    reason = "CPU intrinsics"
)]
pub(crate) mod gf128_pclmul;

#[allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    reason = "splitting into fixed-size words"
)]
pub(crate) mod gf128_soft64;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    not(feature = "force-soft")
))]
#[allow(
    unsafe_code,
    clippy::undocumented_unsafe_blocks,
    clippy::cast_possible_wrap,
    clippy::unwrap_used,
    reason = "CPU intrinsics"
)]
pub(crate) mod gf64_pclmul;

#[allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    reason = "splitting into fixed-size words"
)]
pub(crate) mod gf64_soft64;

pub trait GfElement {
    type N: ArraySize;

    fn new() -> Self;
    fn into_bytes(self) -> Array<u8, Self::N>;
    fn mul_sum(&mut self, a: &Array<u8, Self::N>, b: &Array<u8, Self::N>);
}
