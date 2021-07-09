use aead::{consts, generic_array::typenum::Unsigned};

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

impl SealedTag for consts::U4 {}
impl SealedTag for consts::U6 {}
impl SealedTag for consts::U8 {}
impl SealedTag for consts::U10 {}
impl SealedTag for consts::U12 {}
impl SealedTag for consts::U14 {}
impl SealedTag for consts::U16 {}

impl SealedNonce for consts::U7 {}
impl SealedNonce for consts::U8 {}
impl SealedNonce for consts::U9 {}
impl SealedNonce for consts::U10 {}
impl SealedNonce for consts::U11 {}
impl SealedNonce for consts::U12 {}
impl SealedNonce for consts::U13 {}
