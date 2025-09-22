#![cfg(feature = "alloc")]

use aead::{Aead, AeadInOut, KeyInit, Payload, array::Array};
use aes::{Aes128, Aes192, Aes256};
use ccm::{
    Ccm,
    consts::{U4, U6, U7, U8, U9, U10, U11, U12, U13, U14, U16},
};
use hex_literal::hex;

#[test]
fn test_data_len_check() {
    let key = hex!("D7828D13B2B0BDC325A76236DF93CC6B");
    let nonce = hex!("2F1DBD38CE3EDA7C23F04DD650");

    type Cipher = Ccm<aes::Aes128, U10, U13>;
    let key = Array(key);
    let nonce = Array(nonce);
    let c = Cipher::new(&key);

    let mut buf1 = [1; u16::MAX as usize];
    let res = c.encrypt_inout_detached(&nonce, &[], buf1.as_mut_slice().into());
    assert!(res.is_ok());

    let mut buf2 = [1; u16::MAX as usize + 1];
    let res = c.encrypt_inout_detached(&nonce, &[], buf2.as_mut_slice().into());
    assert!(res.is_err());
}

/// Example test vectors from NIST SP 800-38C
#[test]
#[rustfmt::skip]
fn sp800_38c_examples() {
    macro_rules! check {
        (
            $key:expr, $m:ty, $n:ty,
            nonce: $nonce:expr, adata: $adata:expr, pt: $pt:expr, ct: $ct:expr,
        ) => {
            let key = Array($key);
            let c = Ccm::<aes::Aes128, $m, $n>::new(&key);
            let nonce = Array($nonce);
            let res = c.encrypt(&nonce, Payload { aad: &$adata, msg: &$pt })
                .unwrap();
            assert_eq!(res, &$ct);
            let res = c.decrypt(&nonce, Payload { aad: &$adata, msg: &$ct })
                .unwrap();
            assert_eq!(res, &$pt);
        };
    }

    let key = hex!("40414243 44454647 48494a4b 4c4d4e4f");

    check!(
        key, U4, U7,
        nonce: hex!("10111213 141516"),
        adata: hex!("00010203 04050607"),
        pt: hex!("20212223"),
        ct: hex!("7162015b 4dac255d"),
    );

    check!(
        key, U6, U8,
        nonce: hex!("10111213 14151617"),
        adata: hex!("00010203 04050607 08090a0b 0c0d0e0f"),
        pt: hex!("20212223 24252627 28292a2b 2c2d2e2f"),
        ct: hex!("d2a1f0e0 51ea5f62 081a7792 073d593d 1fc64fbf accd"),
    );

    check!(
        key, U8, U12,
        nonce: hex!("10111213 14151617 18191a1b"),
        adata: hex!("00010203 04050607 08090a0b 0c0d0e0f 10111213"),
        pt: hex!("
            20212223 24252627 28292a2b 2c2d2e2f
            30313233 34353637
        "),
        ct: hex!("
            e3b201a9 f5b71a7a 9b1ceaec cd97e70b
            6176aad9 a4428aa5 484392fb c1b09951
        "),
    );

    let adata = (0..524288 / 8).map(|i| i as u8).collect::<Vec<u8>>();
    check!(
        key, U14, U13,
        nonce: hex!("10111213 14151617 18191a1b 1c"),
        adata: adata,
        pt: hex!("
            20212223 24252627 28292a2b 2c2d2e2f
            30313233 34353637 38393a3b 3c3d3e3f
        "),
        ct: hex!("
            69915dad 1e84c637 6a68c296 7e4dab61
            5ae0fd1f aec44cc4 84828529 463ccf72
            b4ac6bec 93e8598e 7f0dadbc ea5b
        "),
    );
}

// Test vectors from https://tools.ietf.org/html/rfc3610
aead::new_pass_test!(rfc3610_ccm_aes128_8_13_pass, "rfc3610_ccm_aes128_8_13_pass", Ccm<Aes128, U8, U13>);
aead::new_fail_test!(rfc3610_ccm_aes128_8_13_fail, "rfc3610_ccm_aes128_8_13_fail", Ccm<Aes128, U8, U13>);
aead::new_pass_test!(rfc3610_ccm_aes128_10_13_pass, "rfc3610_ccm_aes128_10_13_pass", Ccm<Aes128, U10, U13>);
aead::new_fail_test!(rfc3610_ccm_aes128_10_13_fail, "rfc3610_ccm_aes128_10_13_fail", Ccm<Aes128, U10, U13>);

// Test vectors from CAVP:
// https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES
aead::new_pass_test!(cavp_ccm_aes128_4_7_pass, "cavp_ccm_aes128_4_7_pass", Ccm<Aes128, U4, U7>);
aead::new_fail_test!(cavp_ccm_aes128_4_7_fail, "cavp_ccm_aes128_4_7_fail", Ccm<Aes128, U4, U7>);
aead::new_pass_test!(cavp_ccm_aes128_4_13_pass, "cavp_ccm_aes128_4_13_pass", Ccm<Aes128, U4, U13>);
aead::new_fail_test!(cavp_ccm_aes128_4_13_fail, "cavp_ccm_aes128_4_13_fail", Ccm<Aes128, U4, U13>);
aead::new_pass_test!(cavp_ccm_aes128_6_13_pass, "cavp_ccm_aes128_6_13_pass", Ccm<Aes128, U6, U13>);
aead::new_fail_test!(cavp_ccm_aes128_6_13_fail, "cavp_ccm_aes128_6_13_fail", Ccm<Aes128, U6, U13>);
aead::new_pass_test!(cavp_ccm_aes128_8_13_pass, "cavp_ccm_aes128_8_13_pass", Ccm<Aes128, U8, U13>);
aead::new_fail_test!(cavp_ccm_aes128_8_13_fail, "cavp_ccm_aes128_8_13_fail", Ccm<Aes128, U8, U13>);
aead::new_pass_test!(cavp_ccm_aes128_10_13_pass, "cavp_ccm_aes128_10_13_pass", Ccm<Aes128, U10, U13>);
aead::new_fail_test!(cavp_ccm_aes128_10_13_fail, "cavp_ccm_aes128_10_13_fail", Ccm<Aes128, U10, U13>);
aead::new_pass_test!(cavp_ccm_aes128_12_13_pass, "cavp_ccm_aes128_12_13_pass", Ccm<Aes128, U12, U13>);
aead::new_fail_test!(cavp_ccm_aes128_12_13_fail, "cavp_ccm_aes128_12_13_fail", Ccm<Aes128, U12, U13>);
aead::new_pass_test!(cavp_ccm_aes128_14_13_pass, "cavp_ccm_aes128_14_13_pass", Ccm<Aes128, U14, U13>);
aead::new_fail_test!(cavp_ccm_aes128_14_13_fail, "cavp_ccm_aes128_14_13_fail", Ccm<Aes128, U14, U13>);
aead::new_pass_test!(cavp_ccm_aes128_16_7_pass, "cavp_ccm_aes128_16_7_pass", Ccm<Aes128, U16, U7>);
aead::new_fail_test!(cavp_ccm_aes128_16_7_fail, "cavp_ccm_aes128_16_7_fail", Ccm<Aes128, U16, U7>);
aead::new_pass_test!(cavp_ccm_aes128_16_8_pass, "cavp_ccm_aes128_16_8_pass", Ccm<Aes128, U16, U8>);
aead::new_fail_test!(cavp_ccm_aes128_16_8_fail, "cavp_ccm_aes128_16_8_fail", Ccm<Aes128, U16, U8>);
aead::new_pass_test!(cavp_ccm_aes128_16_9_pass, "cavp_ccm_aes128_16_9_pass", Ccm<Aes128, U16, U9>);
aead::new_fail_test!(cavp_ccm_aes128_16_9_fail, "cavp_ccm_aes128_16_9_fail", Ccm<Aes128, U16, U9>);
aead::new_pass_test!(cavp_ccm_aes128_16_10_pass, "cavp_ccm_aes128_16_10_pass", Ccm<Aes128, U16, U10>);
aead::new_fail_test!(cavp_ccm_aes128_16_10_fail, "cavp_ccm_aes128_16_10_fail", Ccm<Aes128, U16, U10>);
aead::new_pass_test!(cavp_ccm_aes128_16_11_pass, "cavp_ccm_aes128_16_11_pass", Ccm<Aes128, U16, U11>);
aead::new_fail_test!(cavp_ccm_aes128_16_11_fail, "cavp_ccm_aes128_16_11_fail", Ccm<Aes128, U16, U11>);
aead::new_pass_test!(cavp_ccm_aes128_16_12_pass, "cavp_ccm_aes128_16_12_pass", Ccm<Aes128, U16, U12>);
aead::new_fail_test!(cavp_ccm_aes128_16_12_fail, "cavp_ccm_aes128_16_12_fail", Ccm<Aes128, U16, U12>);
aead::new_pass_test!(cavp_ccm_aes128_16_13_pass, "cavp_ccm_aes128_16_13_pass", Ccm<Aes128, U16, U13>);
aead::new_fail_test!(cavp_ccm_aes128_16_13_fail, "cavp_ccm_aes128_16_13_fail", Ccm<Aes128, U16, U13>);

aead::new_pass_test!(cavp_ccm_aes192_4_7_pass, "cavp_ccm_aes192_4_7_pass", Ccm<Aes192, U4, U7>);
aead::new_fail_test!(cavp_ccm_aes192_4_7_fail, "cavp_ccm_aes192_4_7_fail", Ccm<Aes192, U4, U7>);
aead::new_pass_test!(cavp_ccm_aes192_4_13_pass, "cavp_ccm_aes192_4_13_pass", Ccm<Aes192, U4, U13>);
aead::new_fail_test!(cavp_ccm_aes192_4_13_fail, "cavp_ccm_aes192_4_13_fail", Ccm<Aes192, U4, U13>);
aead::new_pass_test!(cavp_ccm_aes192_6_13_pass, "cavp_ccm_aes192_6_13_pass", Ccm<Aes192, U6, U13>);
aead::new_fail_test!(cavp_ccm_aes192_6_13_fail, "cavp_ccm_aes192_6_13_fail", Ccm<Aes192, U6, U13>);
aead::new_pass_test!(cavp_ccm_aes192_8_13_pass, "cavp_ccm_aes192_8_13_pass", Ccm<Aes192, U8, U13>);
aead::new_fail_test!(cavp_ccm_aes192_8_13_fail, "cavp_ccm_aes192_8_13_fail", Ccm<Aes192, U8, U13>);
aead::new_pass_test!(cavp_ccm_aes192_10_13_pass, "cavp_ccm_aes192_10_13_pass", Ccm<Aes192, U10, U13>);
aead::new_fail_test!(cavp_ccm_aes192_10_13_fail, "cavp_ccm_aes192_10_13_fail", Ccm<Aes192, U10, U13>);
aead::new_pass_test!(cavp_ccm_aes192_12_13_pass, "cavp_ccm_aes192_12_13_pass", Ccm<Aes192, U12, U13>);
aead::new_fail_test!(cavp_ccm_aes192_12_13_fail, "cavp_ccm_aes192_12_13_fail", Ccm<Aes192, U12, U13>);
aead::new_pass_test!(cavp_ccm_aes192_14_13_pass, "cavp_ccm_aes192_14_13_pass", Ccm<Aes192, U14, U13>);
aead::new_fail_test!(cavp_ccm_aes192_14_13_fail, "cavp_ccm_aes192_14_13_fail", Ccm<Aes192, U14, U13>);
aead::new_pass_test!(cavp_ccm_aes192_16_7_pass, "cavp_ccm_aes192_16_7_pass", Ccm<Aes192, U16, U7>);
aead::new_fail_test!(cavp_ccm_aes192_16_7_fail, "cavp_ccm_aes192_16_7_fail", Ccm<Aes192, U16, U7>);
aead::new_pass_test!(cavp_ccm_aes192_16_8_pass, "cavp_ccm_aes192_16_8_pass", Ccm<Aes192, U16, U8>);
aead::new_fail_test!(cavp_ccm_aes192_16_8_fail, "cavp_ccm_aes192_16_8_fail", Ccm<Aes192, U16, U8>);
aead::new_pass_test!(cavp_ccm_aes192_16_9_pass, "cavp_ccm_aes192_16_9_pass", Ccm<Aes192, U16, U9>);
aead::new_fail_test!(cavp_ccm_aes192_16_9_fail, "cavp_ccm_aes192_16_9_fail", Ccm<Aes192, U16, U9>);
aead::new_pass_test!(cavp_ccm_aes192_16_10_pass, "cavp_ccm_aes192_16_10_pass", Ccm<Aes192, U16, U10>);
aead::new_fail_test!(cavp_ccm_aes192_16_10_fail, "cavp_ccm_aes192_16_10_fail", Ccm<Aes192, U16, U10>);
aead::new_pass_test!(cavp_ccm_aes192_16_11_pass, "cavp_ccm_aes192_16_11_pass", Ccm<Aes192, U16, U11>);
aead::new_fail_test!(cavp_ccm_aes192_16_11_fail, "cavp_ccm_aes192_16_11_fail", Ccm<Aes192, U16, U11>);
aead::new_pass_test!(cavp_ccm_aes192_16_12_pass, "cavp_ccm_aes192_16_12_pass", Ccm<Aes192, U16, U12>);
aead::new_fail_test!(cavp_ccm_aes192_16_12_fail, "cavp_ccm_aes192_16_12_fail", Ccm<Aes192, U16, U12>);
aead::new_pass_test!(cavp_ccm_aes192_16_13_pass, "cavp_ccm_aes192_16_13_pass", Ccm<Aes192, U16, U13>);
aead::new_fail_test!(cavp_ccm_aes192_16_13_fail, "cavp_ccm_aes192_16_13_fail", Ccm<Aes192, U16, U13>);

aead::new_pass_test!(cavp_ccm_aes256_4_7_pass, "cavp_ccm_aes256_4_7_pass", Ccm<Aes256, U4, U7>);
aead::new_fail_test!(cavp_ccm_aes256_4_7_fail, "cavp_ccm_aes256_4_7_fail", Ccm<Aes256, U4, U7>);
aead::new_pass_test!(cavp_ccm_aes256_4_13_pass, "cavp_ccm_aes256_4_13_pass", Ccm<Aes256, U4, U13>);
aead::new_fail_test!(cavp_ccm_aes256_4_13_fail, "cavp_ccm_aes256_4_13_fail", Ccm<Aes256, U4, U13>);
aead::new_pass_test!(cavp_ccm_aes256_6_13_pass, "cavp_ccm_aes256_6_13_pass", Ccm<Aes256, U6, U13>);
aead::new_fail_test!(cavp_ccm_aes256_6_13_fail, "cavp_ccm_aes256_6_13_fail", Ccm<Aes256, U6, U13>);
aead::new_pass_test!(cavp_ccm_aes256_8_13_pass, "cavp_ccm_aes256_8_13_pass", Ccm<Aes256, U8, U13>);
aead::new_fail_test!(cavp_ccm_aes256_8_13_fail, "cavp_ccm_aes256_8_13_fail", Ccm<Aes256, U8, U13>);
aead::new_pass_test!(cavp_ccm_aes256_10_13_pass, "cavp_ccm_aes256_10_13_pass", Ccm<Aes256, U10, U13>);
aead::new_fail_test!(cavp_ccm_aes256_10_13_fail, "cavp_ccm_aes256_10_13_fail", Ccm<Aes256, U10, U13>);
aead::new_pass_test!(cavp_ccm_aes256_12_13_pass, "cavp_ccm_aes256_12_13_pass", Ccm<Aes256, U12, U13>);
aead::new_fail_test!(cavp_ccm_aes256_12_13_fail, "cavp_ccm_aes256_12_13_fail", Ccm<Aes256, U12, U13>);
aead::new_pass_test!(cavp_ccm_aes256_14_13_pass, "cavp_ccm_aes256_14_13_pass", Ccm<Aes256, U14, U13>);
aead::new_fail_test!(cavp_ccm_aes256_14_13_fail, "cavp_ccm_aes256_14_13_fail", Ccm<Aes256, U14, U13>);
aead::new_pass_test!(cavp_ccm_aes256_16_7_pass, "cavp_ccm_aes256_16_7_pass", Ccm<Aes256, U16, U7>);
aead::new_fail_test!(cavp_ccm_aes256_16_7_fail, "cavp_ccm_aes256_16_7_fail", Ccm<Aes256, U16, U7>);
aead::new_pass_test!(cavp_ccm_aes256_16_8_pass, "cavp_ccm_aes256_16_8_pass", Ccm<Aes256, U16, U8>);
aead::new_fail_test!(cavp_ccm_aes256_16_8_fail, "cavp_ccm_aes256_16_8_fail", Ccm<Aes256, U16, U8>);
aead::new_pass_test!(cavp_ccm_aes256_16_9_pass, "cavp_ccm_aes256_16_9_pass",Ccm<Aes256, U16, U9>);
aead::new_fail_test!(cavp_ccm_aes256_16_9_fail, "cavp_ccm_aes256_16_9_fail",Ccm<Aes256, U16, U9>);
aead::new_pass_test!(cavp_ccm_aes256_16_10_pass, "cavp_ccm_aes256_16_10_pass", Ccm<Aes256, U16, U10>);
aead::new_fail_test!(cavp_ccm_aes256_16_10_fail, "cavp_ccm_aes256_16_10_fail", Ccm<Aes256, U16, U10>);
aead::new_pass_test!(cavp_ccm_aes256_16_11_pass, "cavp_ccm_aes256_16_11_pass", Ccm<Aes256, U16, U11>);
aead::new_fail_test!(cavp_ccm_aes256_16_11_fail, "cavp_ccm_aes256_16_11_fail", Ccm<Aes256, U16, U11>);
aead::new_pass_test!(cavp_ccm_aes256_16_12_pass, "cavp_ccm_aes256_16_12_pass", Ccm<Aes256, U16, U12>);
aead::new_fail_test!(cavp_ccm_aes256_16_12_fail, "cavp_ccm_aes256_16_12_fail", Ccm<Aes256, U16, U12>);
aead::new_pass_test!(cavp_ccm_aes256_16_13_pass, "cavp_ccm_aes256_16_13_pass", Ccm<Aes256, U16, U13>);
aead::new_fail_test!(cavp_ccm_aes256_16_13_fail, "cavp_ccm_aes256_16_13_fail", Ccm<Aes256, U16, U13>);
