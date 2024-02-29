use aead::array::typenum::type_operators::{IsGreaterOrEqual, IsLessOrEqual};
use aead::array::typenum::Unsigned;
use aead::array::ArraySize;
use aead::consts::{U16, U4};

mod private {
    // Sealed traits stop other crates from implementing any traits that use it.
    pub trait SealedTag {}

    impl<T> SealedTag for T where
        T: super::IsGreaterOrEqual<super::U4> + super::IsLessOrEqual<super::U16>
    {
    }
}

pub trait TagSize: ArraySize + Unsigned + private::SealedTag {}

impl<T> TagSize for T where T: ArraySize + IsGreaterOrEqual<U4> + IsLessOrEqual<U16> {}
