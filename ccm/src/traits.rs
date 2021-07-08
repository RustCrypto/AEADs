use aead::consts::{U10, U11, U12, U13, U14, U16, U4, U6, U7, U8, U9};

mod private {
    use aead::generic_array::typenum::Unsigned;

    // Sealed traits stop other crates from implementing any traits that use it.
    pub trait SealedTag: Unsigned {
        fn get_m_tick() -> u8 {
            (Self::to_u8() - 2) / 2
        }
    }
    pub trait SealedNonce: Unsigned {
        fn get_l() -> u8 {
            15 - Self::to_u8()
        }

        fn get_max_len() -> usize {
            // a somewhat ugly code to prevent overlfow.
            // compiler should be able to completely optimize it out
            let l = Self::get_l() as u128;
            let v = (1 << (8 * l)) - 1;
            core::cmp::min(v, core::usize::MAX as u128) as usize
        }
    }

    impl SealedTag for super::U4 {}
    impl SealedTag for super::U6 {}
    impl SealedTag for super::U8 {}
    impl SealedTag for super::U10 {}
    impl SealedTag for super::U12 {}
    impl SealedTag for super::U14 {}
    impl SealedTag for super::U16 {}

    impl SealedNonce for super::U7 {}
    impl SealedNonce for super::U8 {}
    impl SealedNonce for super::U9 {}
    impl SealedNonce for super::U10 {}
    impl SealedNonce for super::U11 {}
    impl SealedNonce for super::U12 {}
    impl SealedNonce for super::U13 {}
}

/// Trait implemented for valid tag sizes, i.e. [`U4`], [`U6`], [`U8`],
/// [`U10`], [`U12`], [`U14`], and [`U12`].
pub trait TagSize: private::SealedTag {}

impl<T: private::SealedTag> TagSize for T {}

/// Trait implemented for valid nonce sizes, i.e. [`U7`], [`U8`], [`U9`],
/// [`U10`], [`U11`], [`U12`], and [`U13`].
pub trait NonceSize: private::SealedNonce {}

impl<T: private::SealedNonce> NonceSize for T {}
