#[cfg(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[path = "gf/pclmulqdq.rs"]
mod imp;

#[cfg(not(all(
    target_feature = "pclmulqdq",
    target_feature = "sse2",
    target_feature = "ssse3",
    any(target_arch = "x86", target_arch = "x86_64")
)))]
#[path = "gf/u64_soft.rs"]
mod imp;

pub(crate) use imp::Element;
