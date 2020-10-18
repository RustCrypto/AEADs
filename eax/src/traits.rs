use aead::consts::{U16, U4};
use aead::generic_array::typenum::type_operators::{IsGreaterOrEqual, IsLessOrEqual};
use aead::generic_array::typenum::Unsigned;
use aead::generic_array::ArrayLength;

mod private {
    // Sealed traits stop other crates from implementing any traits that use it.
    pub trait SealedTag {}

    impl<T> SealedTag for T where
        T: super::IsGreaterOrEqual<super::U4> + super::IsLessOrEqual<super::U16>
    {
    }
}

pub trait TagSize: ArrayLength<u8> + Unsigned + private::SealedTag {}

impl<T> TagSize for T where T: ArrayLength<u8> + IsGreaterOrEqual<U4> + IsLessOrEqual<U16> {}
