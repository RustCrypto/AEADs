//! bash-prg-ae tests.

use aead::{AeadInOut, KeyInit, array::Array};
use bash_prg_ae::{
    BashPrgAe, BashPrgAe2561, BashPrgAe2562,
    aead::consts::{U0, U8, U12, U16, U24, U32},
};
use hex_literal::hex;

/// 8.13.2: the output must be cleared if the tag is wrong.
#[test]
fn decrypt_failure_clears_output() {
    let key = hex!("5BE3D61217B96181FE6786AD716B890B5CB0C0FF33C356B835C405AED8E07F99");
    let nonce = hex!("B194BAC80A08F53B366D008E584A5DE4");
    let aad = hex!(
        "E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4F"
        "F33C657B637C306ADD4EA7799EB23D313E"
    );
    let mut buf = hex!(
        "690673766C3E848CAC7C05169FFB7B7751E52A011040E5602573FAF991044A00"
        "4329EEF7BED8E6875830A91854D1BD2EDC6FC2FF37851DBAC249DF400A0549EA"
        "2E0C811D499E1FF1E5E32FAE7F0532FA4051D0F9E300D9B1DBF119AC8CFFC48D"
        "D3CBF1CA0DBA5DD97481C88DF0BE412785E40988B31585537948B80F5A9C49E0"
        "8DD684A7DCA871C380DFDC4C4DFBE61F50D2D0FBD24D8B9D32974A347247D001"
        "BAD5B168440025693967E77394DC088B0ECCFA8D291BA13D44F60B06E2EDB351"
    );
    let mut tag = hex!("CDE5AF6EF9A14B7D0C191B869A6343ED6A4E9AAB4EE00A579E9E682D0EC051E3");
    tag[0] ^= 0xaa;

    let cipher = BashPrgAe2561::new(&Array(key));
    let res =
        cipher.decrypt_inout_detached(&Array(nonce), &aad, buf.as_mut_slice().into(), &Array(tag));
    assert!(res.is_err());
    assert!(buf.iter().all(|&b| b == 0));
}

// Test vectors from tests BASH.PRG.AE*.1-4 of the STB 34.101.77 test methodology.
// BASH.PRG.AE256.4 is also Table A.6 of STB 34.101.77-2020.
aead::new_pass_test!(bash_prg_ae128_1_pass, "bash_prg_ae128_1_pass", BashPrgAe<U16, 2, U0>);
aead::new_fail_test!(bash_prg_ae128_1_fail, "bash_prg_ae128_1_fail", BashPrgAe<U16, 2, U0>);
aead::new_pass_test!(bash_prg_ae128_2_pass, "bash_prg_ae128_2_pass", BashPrgAe<U16, 2, U8>);
aead::new_fail_test!(bash_prg_ae128_2_fail, "bash_prg_ae128_2_fail", BashPrgAe<U16, 2, U8>);
aead::new_pass_test!(bash_prg_ae128_3_pass, "bash_prg_ae128_3_pass", BashPrgAe<U16, 1, U0>);
aead::new_fail_test!(bash_prg_ae128_3_fail, "bash_prg_ae128_3_fail", BashPrgAe<U16, 1, U0>);
aead::new_pass_test!(bash_prg_ae128_4_pass, "bash_prg_ae128_4_pass", BashPrgAe<U16, 1, U8>);
aead::new_fail_test!(bash_prg_ae128_4_fail, "bash_prg_ae128_4_fail", BashPrgAe<U16, 1, U8>);
aead::new_pass_test!(bash_prg_ae192_1_pass, "bash_prg_ae192_1_pass", BashPrgAe<U24, 2, U0>);
aead::new_fail_test!(bash_prg_ae192_1_fail, "bash_prg_ae192_1_fail", BashPrgAe<U24, 2, U0>);
aead::new_pass_test!(bash_prg_ae192_2_pass, "bash_prg_ae192_2_pass", BashPrgAe<U24, 2, U12>);
aead::new_fail_test!(bash_prg_ae192_2_fail, "bash_prg_ae192_2_fail", BashPrgAe<U24, 2, U12>);
aead::new_pass_test!(bash_prg_ae192_3_pass, "bash_prg_ae192_3_pass", BashPrgAe<U24, 1, U0>);
aead::new_fail_test!(bash_prg_ae192_3_fail, "bash_prg_ae192_3_fail", BashPrgAe<U24, 1, U0>);
aead::new_pass_test!(bash_prg_ae192_4_pass, "bash_prg_ae192_4_pass", BashPrgAe<U24, 1, U12>);
aead::new_fail_test!(bash_prg_ae192_4_fail, "bash_prg_ae192_4_fail", BashPrgAe<U24, 1, U12>);
aead::new_pass_test!(bash_prg_ae256_1_pass, "bash_prg_ae256_1_pass", BashPrgAe<U32, 2, U0>);
aead::new_fail_test!(bash_prg_ae256_1_fail, "bash_prg_ae256_1_fail", BashPrgAe<U32, 2, U0>);
aead::new_pass_test!(
    bash_prg_ae256_2_pass,
    "bash_prg_ae256_2_pass",
    BashPrgAe2562
);
aead::new_fail_test!(
    bash_prg_ae256_2_fail,
    "bash_prg_ae256_2_fail",
    BashPrgAe2562
);
aead::new_pass_test!(bash_prg_ae256_3_pass, "bash_prg_ae256_3_pass", BashPrgAe<U32, 1, U0>);
aead::new_fail_test!(bash_prg_ae256_3_fail, "bash_prg_ae256_3_fail", BashPrgAe<U32, 1, U0>);
aead::new_pass_test!(
    bash_prg_ae256_4_pass,
    "bash_prg_ae256_4_pass",
    BashPrgAe2561
);
aead::new_fail_test!(
    bash_prg_ae256_4_fail,
    "bash_prg_ae256_4_fail",
    BashPrgAe2561
);
