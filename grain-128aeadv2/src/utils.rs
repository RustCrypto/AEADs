use core::ops::{BitAnd, Shr};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use num_traits::identities::One;
use num_traits::sign::Unsigned;

/// Extract the next 16 bits starting from a given position.
pub(crate) fn get_2bytes_at_bit<
    T: Unsigned + BitAnd<Output = T> + One + ToPrimitive + FromPrimitive,
>(
    value: &T,
    index: usize,
) -> u16
where
    for<'a> &'a T: Shr<usize, Output = T>,
{
    ((value >> index) & T::from_u16(0xffff).expect("Unable to get the given byte"))
        .to_u16()
        .expect("Unable extract the given byte index")
}

/// Extract the next 32 bits starting from a given position.
pub(crate) fn get_4bytes_at_bit<
    T: Unsigned + BitAnd<Output = T> + One + ToPrimitive + FromPrimitive,
>(
    value: &T,
    index: usize,
) -> u32
where
    for<'a> &'a T: Shr<usize, Output = T>,
{
    ((value >> index) & T::from_u32(0xffffffff).expect("Unable to get the given byte"))
        .to_u32()
        .expect("Unable extract the given byte index")
}

/// Deinterleave 32 bits of pre-output,
/// output the keystream (at even indexes)
/// and the authentication stream (at odd ones)
pub(crate) fn deinterleave32(input: &u32) -> (u16, u16) {
    let input = *input as u64;
    let mut output = (((input) << 31) | input) & 0x5555555555555555;
    output = (output | (output >> 1)) & 0x3333333333333333;
    output = (output | (output >> 2)) & 0x0f0f0f0f0f0f0f0f;
    output = (output | (output >> 4)) & 0x00ff00ff00ff00ff;
    output = output | (output >> 8);

    ((output & 0xffff) as u16, (output >> 32) as u16)
}

/// Deinterleave 16 bits of pre-output,
/// output the keystream (at even indexes)
/// and the authentication stream (at odd ones)
pub fn deinterleave16(input: &u16) -> (u8, u8) {
    let input = *input as u32;
    let mut output = (((input) << 15) | input) & 0x55555555;
    output = (output | (output >> 1)) & 0x33333333;
    output = (output | (output >> 2)) & 0x0f0f0f0f;
    output = output | (output >> 4);

    ((output & 0xff) as u8, (output >> 16) as u8)
}

/// Encode a length according to Grain spec
pub fn len_encode(length: usize) -> (usize, [u8; 9]) {
    let mut output = [0u8; 9];

    if length <= 127 {
        output[0] = length as u8;

        (1usize, output)
    } else {
        let length_bytes = length.to_be_bytes();
        let mut size_len = 0usize;

        while length_bytes[size_len] == 0 {
            size_len += 1
        }

        output[0] = 0x80u8 + ((8 - size_len) as u8);
        for (i, e) in length_bytes[size_len..].iter().enumerate() {
            output[i + 1] = *e;
        }

        ((8 - size_len) + 1, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    extern crate std;
    use std::mem;

    // ********************************
    // Tests for `get_2bytes_at_bit` function
    // ********************************
    // Define a macro to generate a test function based on proptest module
    // to perform unit/property tests of evaluate_poly.
    macro_rules! test_get_2bytes_at_bit_for {
        ($name:tt, $type: ty) => {
            proptest! {
                #[test]
                fn $name(value in 0..(<$type>::MAX), pos in 0..(mem::size_of::<$type>())) {
                    assert_eq!(get_2bytes_at_bit(&value, pos), ((value >> pos) & 0xffff) as u16);
                }
            }
        };
    }

    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u16, u16);
    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u32, u32);
    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u64, u64);
    test_get_2bytes_at_bit_for!(test_get_2bytes_at_bit_u128, u128);

    proptest! {
        #[test]
        fn test_len_encode_le_127(l in 0..=127usize) {
            let (size, arr) = len_encode(l);

            assert_eq!(&arr[0..size], &[l as u8]);
        }
    }

    proptest! {
        #[test]
        fn test_len_encode_ge_127(l in 128..4294967296usize) {
            let (size, arr) = len_encode(l);
            let encoded = &arr[0..size];

            // Ensure first bit is set to 1
            assert_eq!((encoded[0] >> 7) & 1, 1);

            // Ensure the remaining first byte bits encode
            // the byte length of the size
            assert_eq!(encoded[0] & 0x7f, l.to_be_bytes().into_iter().skip_while(|&x| x == 0).count() as u8);

            // Ensure the remaining bytes represents the len
            let encoded_size: usize = {
                let mut s = 0;
                for i in 1..(encoded.len()) {
                    s += (encoded[i] as usize) << (encoded.len() - i - 1) * 8
                }
                s
            };
            assert_eq!(encoded_size, l);
        }
    }

    // Test deinterleave16
    #[test]
    fn test_deinterleave16() {
        let i = 0b1010101010101010;
        let (x, y) = deinterleave16(&i);

        assert_eq!(x, 0);
        assert_eq!(y, 255);

        let j = 0b0101010101010101;
        let (x, y) = deinterleave16(&j);

        assert_eq!(y, 0);
        assert_eq!(x, 255);
    }

    // Test deinterleave32
    #[test]
    fn test_deinterleave32() {
        let i = 0b10101010101010101010101010101010;
        let (x, y) = deinterleave32(&i);

        assert_eq!(x, 0);
        assert_eq!(y, 0xffff);

        let j = 0b01010101010101010101010101010101;
        let (x, y) = deinterleave32(&j);

        assert_eq!(y, 0);
        assert_eq!(x, 0xffff);
    }
}
