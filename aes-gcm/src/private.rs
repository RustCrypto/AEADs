use aead::generic_array::ArrayLength;
use cipher::{consts, Unsigned};

// Sealed traits stop other crates from implementing any traits that use it.
pub trait SealedTag: ArrayLength<u8> + Unsigned {}

impl SealedTag for consts::U12 {}
impl SealedTag for consts::U13 {}
impl SealedTag for consts::U14 {}
impl SealedTag for consts::U15 {}
impl SealedTag for consts::U16 {}
