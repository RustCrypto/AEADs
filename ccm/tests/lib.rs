use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use ccm::{
    consts::{U10, U13, U8},
    Ccm,
};
use hex_literal::hex;
use aes::Aes128;

// Test vectors from https://tools.ietf.org/html/rfc3610
aead::new_test!(
    ccm_aes128_8_13_rfc3610,
    "ccm_aes128_8_13_rfc3610",
    Ccm<Aes128, U8, U13>,
);
aead::new_test!(
    ccm_aes128_10_13_rfc3610,
    "ccm_aes128_10_13_rfc3610",
    Ccm<Aes128, U10, U13>,
);

#[test]
fn test_data_len_check() {
    let key = hex!("D7828D13B2B0BDC325A76236DF93CC6B");
    let nonce = hex!("2F1DBD38CE3EDA7C23F04DD650");

    type Cipher = Ccm<aes::Aes128, U10, U13>;
    let key = GenericArray::from_slice(&key);
    let nonce = GenericArray::from_slice(&nonce);
    let c = Cipher::new(key);

    let mut buf1 = [1; core::u16::MAX as usize];
    let res = c.encrypt_in_place_detached(nonce, &[], &mut buf1);
    assert!(res.is_ok());

    let mut buf2 = [1; core::u16::MAX as usize + 1];
    let res = c.encrypt_in_place_detached(nonce, &[], &mut buf2);
    assert!(res.is_err());
}
