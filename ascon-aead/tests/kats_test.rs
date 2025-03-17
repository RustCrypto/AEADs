// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use ascon_aead::{
    AsconAead128,
    aead::{Aead, AeadInOut, KeyInit, Payload, Tag},
};
use hex_literal::hex;

fn run_tv<A: KeyInit + Aead + AeadInOut>(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
    ciphertext: &[u8],
) {
    let core = A::new(key.try_into().unwrap());
    let nonce = nonce.try_into().unwrap();
    let ctxt = core
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("Successful encryption");
    assert_eq!(ctxt, ciphertext);

    let ptxt = core
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .expect("Successful decryption");
    assert_eq!(ptxt, plaintext);

    let bad_tag = Tag::<A>::default();
    let mut buf = ciphertext[..ciphertext.len() - bad_tag.len()].to_vec();
    let res =
        core.decrypt_inout_detached(nonce, associated_data, buf.as_mut_slice().into(), &bad_tag);
    assert!(res.is_err());
    assert!(buf.iter().all(|b| *b == 0));
}

#[test]
fn test_ascon128_1() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!(""),
        &hex!("4427D64B8E1E1451FC445960F0839BB0"),
    )
}

#[test]
fn test_ascon128_2() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00"),
        &hex!("103AB79D913A0321287715A979BB8585"),
    )
}

#[test]
fn test_ascon128_3() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("0001"),
        &hex!("A50E88E30F923B90A9C810181230DF10"),
    )
}

#[test]
fn test_ascon128_4() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102"),
        &hex!("AE214C9F66630658ED8DC7D31131174C"),
    )
}

#[test]
fn test_ascon128_5() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00010203"),
        &hex!("C6FF3CF70575B144B955820D9BC7685E"),
    )
}

#[test]
fn test_ascon128_6() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("0001020304"),
        &hex!("6279C4882F99DFB6D9EC3695C9F2A773"),
    )
}

#[test]
fn test_ascon128_7() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405"),
        &hex!("078A29237061C0D397B2A0E6EA5C876B"),
    )
}

#[test]
fn test_ascon128_8() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00010203040506"),
        &hex!("03571475150BCEE52386848E25B06509"),
    )
}

#[test]
fn test_ascon128_9() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("0001020304050607"),
        &hex!("B26DFF49B1D32299DDAF77393DA1BFB9"),
    )
}

#[test]
fn test_ascon128_10() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708"),
        &hex!("199B9F815BA37A386D283F504B8D2277"),
    )
}

#[test]
fn test_ascon128_11() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("00010203040506070809"),
        &hex!("72ADAF0FB14368FCAE684504B30AC101"),
    )
}

#[test]
fn test_ascon128_12() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A"),
        &hex!("7A743A79172DA75466F25F40457A6B73"),
    )
}

#[test]
fn test_ascon128_13() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B"),
        &hex!("3147BDC1FE566B1981841CCF2A6AE34F"),
    )
}

#[test]
fn test_ascon128_14() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C"),
        &hex!("020EBC69E08706864E71E3D1B58B357F"),
    )
}

#[test]
fn test_ascon128_15() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("A82E222AFF512CDBC3DE114D906F19EC"),
    )
}

#[test]
fn test_ascon128_16() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("6FC17A2738F9F525213E59384FB75037"),
    )
}

#[test]
fn test_ascon128_17() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("B747D3235E971C20D00DCF87406938FD"),
    )
}

#[test]
fn test_ascon128_18() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("D990A242654D0741C7525E6F903653ED"),
    )
}

#[test]
fn test_ascon128_19() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("578A86396447B8A041BAD515A601A34A"),
    )
}

#[test]
fn test_ascon128_20() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("8DB8ADA4D118B78363846DD3541E2189"),
    )
}

#[test]
fn test_ascon128_21() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("60ADBE0BFFAD8E8A261E6B8CA48C75DF"),
    )
}

#[test]
fn test_ascon128_22() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("C85D563277DB0C83A2B4E94CD6EA1AEE"),
    )
}

#[test]
fn test_ascon128_23() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("211A251C1766C2E5A3FFDD74B03B2529"),
    )
}

#[test]
fn test_ascon128_24() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("12004754BA17098AAD179E061E1749E7"),
    )
}

#[test]
fn test_ascon128_25() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("B0C8E78E5E9091F5005D79AABDA96DB2"),
    )
}

#[test]
fn test_ascon128_26() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("AAA1A35A588016DC63EE291946FC6154"),
    )
}

#[test]
fn test_ascon128_27() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("166C67CC262390C81596F8C463C87B00"),
    )
}

#[test]
fn test_ascon128_28() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("143DB82F41FE376CFD53D29675078EAC"),
    )
}

#[test]
fn test_ascon128_29() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("6BAF6585E8FFE8F552780C7EADC7DA28"),
    )
}

#[test]
fn test_ascon128_30() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("D1401CB996969FD5F721A422439DFD2E"),
    )
}

#[test]
fn test_ascon128_31() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("78362CB020E6CE64063595D856AB9173"),
    )
}

#[test]
fn test_ascon128_32() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("2C899FF0082B24C0E179399DE588F918"),
    )
}

#[test]
fn test_ascon128_33() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("22133A313FBF0B38029A45870AADC542"),
    )
}

#[test]
fn test_ascon128_34() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!(""),
        &hex!("E79F58F1F541FC51B5D438F8E1DD03F147"),
    )
}

#[test]
fn test_ascon128_35() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00"),
        &hex!("25EB4B700ED4AC8517DCBA20F673292230"),
    )
}

#[test]
fn test_ascon128_36() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("0001"),
        &hex!("49BE454D8C97E1EAB5119BF47D3654DDE2"),
    )
}

#[test]
fn test_ascon128_37() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102"),
        &hex!("D2FDDB3A70AD9A1F2BB342615B97AB191A"),
    )
}

#[test]
fn test_ascon128_38() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00010203"),
        &hex!("4AC40555DC0E91960643A438D4EB371137"),
    )
}

#[test]
fn test_ascon128_39() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("0001020304"),
        &hex!("1F3F5CE816E7C1BA5F7453AB9D526B82D0"),
    )
}

#[test]
fn test_ascon128_40() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405"),
        &hex!("7C56A3122EC3F0FBFC89C725171061705D"),
    )
}

#[test]
fn test_ascon128_41() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00010203040506"),
        &hex!("44ED28EA9A451BE731C7D5B4AAEBD97969"),
    )
}

#[test]
fn test_ascon128_42() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("0001020304050607"),
        &hex!("10AAC070D4736FAD110E011A42D813E453"),
    )
}

#[test]
fn test_ascon128_43() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708"),
        &hex!("6A3D03F3A5AAB12316DB48C0ACFF1B6D0F"),
    )
}

#[test]
fn test_ascon128_44() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("00010203040506070809"),
        &hex!("F2CEE4C21C5E8BE47C62801CF8F99C0F68"),
    )
}

#[test]
fn test_ascon128_45() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A"),
        &hex!("29046A1589F368954B3B520A1582BF3999"),
    )
}

#[test]
fn test_ascon128_46() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBA99810090A3340A198FF6B536BAFE22E"),
    )
}

#[test]
fn test_ascon128_47() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4B9B02EEEE46735A799825D48A5793E1C6"),
    )
}

#[test]
fn test_ascon128_48() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E1B69707A42C085AB15B212E545AD48C4"),
    )
}

#[test]
fn test_ascon128_49() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B0EA3438393984BFBEBB5642907A511568"),
    )
}

#[test]
fn test_ascon128_50() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6AF88FDEC9275574DDA9C51F390C301A4F"),
    )
}

#[test]
fn test_ascon128_51() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("98BD6CB9C387D71D275A5D50E5525C643C"),
    )
}

#[test]
fn test_ascon128_52() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("5012CDE984E442C183285468CF95509AAB"),
    )
}

#[test]
fn test_ascon128_53() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64E8A535661ECD9BD9986CEA0A46A8556B"),
    )
}

#[test]
fn test_ascon128_54() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C31E5D2C32CD3BA00B03595D1D80580E5D"),
    )
}

#[test]
fn test_ascon128_55() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("99B94D9B0FDC389333390F467DA793DA18"),
    )
}

#[test]
fn test_ascon128_56() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("36F8BC8ECBE5373E8CF98A6AF971F4FF82"),
    )
}

#[test]
fn test_ascon128_57() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C03D53C849AD1DBAFE0CA9084AB60E4967"),
    )
}

#[test]
fn test_ascon128_58() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BAAE9C333640BCBD5AFD22A6D086BCD48A"),
    )
}

#[test]
fn test_ascon128_59() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4CF2085BF59B1F8D21FF2690EEE3A54E45"),
    )
}

#[test]
fn test_ascon128_60() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("12647E22AC5BE3FDF70E9FEFC249AD38CD"),
    )
}

#[test]
fn test_ascon128_61() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8B1FAB3F10CAF5CDC2E84954AB7F4169D"),
    )
}

#[test]
fn test_ascon128_62() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("669A01C76EF9F95F4B1C77C362D3789B62"),
    )
}

#[test]
fn test_ascon128_63() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26C5395877E5027743965CF9CC5C8364C0"),
    )
}

#[test]
fn test_ascon128_64() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F9B7E3321C6F13FBC36CB520FF40E398E"),
    )
}

#[test]
fn test_ascon128_65() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("145D307EAA756D8BA5D06A0BBE704B37CA"),
    )
}

#[test]
fn test_ascon128_66() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C6977B26283789F81CA53EE0C984D3FFA"),
    )
}

#[test]
fn test_ascon128_67() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!(""),
        &hex!("E770024EF7895C325CBE02EB5FBE6F9D7E8D"),
    )
}

#[test]
fn test_ascon128_68() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00"),
        &hex!("25FB41D2732019820A0F8BAB4248B35E7B0B"),
    )
}

#[test]
fn test_ascon128_69() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("0001"),
        &hex!("49E57017A30E8073D1FA284AC8346110F89F"),
    )
}

#[test]
fn test_ascon128_70() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102"),
        &hex!("D2729AEF0954A0B62131B41B77BB07DD1BDF"),
    )
}

#[test]
fn test_ascon128_71() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00010203"),
        &hex!("4A53C3ABDE1911DBBAFCA250E82B32E6623B"),
    )
}

#[test]
fn test_ascon128_72() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("0001020304"),
        &hex!("1F82CA8DB431D4C88044A58AD984EBDB0767"),
    )
}

#[test]
fn test_ascon128_73() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405"),
        &hex!("7CC825226D46FFA5AB35DC4F3802BB252B5A"),
    )
}

#[test]
fn test_ascon128_74() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00010203040506"),
        &hex!("4486D2C8ED8489C9E0D04DFFB8F412149695"),
    )
}

#[test]
fn test_ascon128_75() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("0001020304050607"),
        &hex!("108639EF290EA2810D6A1C03649CB66F6D94"),
    )
}

#[test]
fn test_ascon128_76() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708"),
        &hex!("6A25B328B990BF7D77C15C621519779A7126"),
    )
}

#[test]
fn test_ascon128_77() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("00010203040506070809"),
        &hex!("F2F4C9EDE27986D157E41FBAD2D2C805D070"),
    )
}

#[test]
fn test_ascon128_78() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A"),
        &hex!("29FC67CBC9D0678F451F593E4C827661F84A"),
    )
}

#[test]
fn test_ascon128_79() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE3268C0D34744D396B233E7C9FCAF5DE6"),
    )
}

#[test]
fn test_ascon128_80() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE58B7A9081226609FCAB0FC439CA9BA4DF"),
    )
}

#[test]
fn test_ascon128_81() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E58968373B211EA0FC538D8AA77E338CEF6"),
    )
}

#[test]
fn test_ascon128_82() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03EA80E65729A8CA944EA44BBBDE99658C5"),
    )
}

#[test]
fn test_ascon128_83() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A2834C4A74578201C95C841BF174402B238"),
    )
}

#[test]
fn test_ascon128_84() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813A67DFADCF44B938B0DDBBF1C246F24BA"),
    )
}

#[test]
fn test_ascon128_85() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DBB47F895CDE177FAD82CB3C7341A4541"),
    )
}

#[test]
fn test_ascon128_86() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64ACD2BDDB3E2E206DF00A71418289215105"),
    )
}

#[test]
fn test_ascon128_87() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C3050C85A58C4967CD61BEFF2C6A5E6D1513"),
    )
}

#[test]
fn test_ascon128_88() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("99493C7D15D98F80584F6A2B6F19E7827DF5"),
    )
}

#[test]
fn test_ascon128_89() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D092115E687090CE11EDB6E83B4029D51"),
    )
}

#[test]
fn test_ascon128_90() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EBFBE6F932F2EECD51DA65D220FBA68D7"),
    )
}

#[test]
fn test_ascon128_91() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35F45A5FB21281E4701FAB3C9ADEEA1170"),
    )
}

#[test]
fn test_ascon128_92() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C8393FAA9930679187C22C63879D6A4A714"),
    )
}

#[test]
fn test_ascon128_93() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244C10C58F56790662D4E862E0D3595864A"),
    )
}

#[test]
fn test_ascon128_94() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C800EF8E732F5D80CF31022F0A48CA7F5594"),
    )
}

#[test]
fn test_ascon128_95() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662DF08B8B3404A00343D5D4E616F29AA76C"),
    )
}

#[test]
fn test_ascon128_96() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6577F6634FE09EB7B1B7EEB6D7DA61DF1"),
    )
}

#[test]
fn test_ascon128_97() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55AB1A2B6B649ED9885B1BA67E8ECA6780"),
    )
}

#[test]
fn test_ascon128_98() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B95CA9B935C15006A74174A16962CBB75"),
    )
}

#[test]
fn test_ascon128_99() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C0838C27A7741EF0D33DD0312E48657F5FB"),
    )
}

#[test]
fn test_ascon128_100() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!(""),
        &hex!("E770D29AB195F40EE49B127840263B2A7F1356"),
    )
}

#[test]
fn test_ascon128_101() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00"),
        &hex!("25FBE4381FA4B64A6C6A5C06030EA163AE8082"),
    )
}

#[test]
fn test_ascon128_102() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("0001"),
        &hex!("49E505D644B6A140B7305500088BBD30A5963B"),
    )
}

#[test]
fn test_ascon128_103() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102"),
        &hex!("D2721F2ED83F53550FCFE2188D4151162A3F9D"),
    )
}

#[test]
fn test_ascon128_104() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00010203"),
        &hex!("4A53D9F9BFC2F512F9E90288EF5E4728C4D4CC"),
    )
}

#[test]
fn test_ascon128_105() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("0001020304"),
        &hex!("1F8202100240F484078227FF47F85A47E8CB51"),
    )
}

#[test]
fn test_ascon128_106() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405"),
        &hex!("7CC88B34BECE08E696ED8F527D0C89F05101DC"),
    )
}

#[test]
fn test_ascon128_107() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00010203040506"),
        &hex!("44864F9D866CD8429604894B45AFA35053170F"),
    )
}

#[test]
fn test_ascon128_108() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("0001020304050607"),
        &hex!("10864087901895D83F4902B68968EA8433A7A1"),
    )
}

#[test]
fn test_ascon128_109() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708"),
        &hex!("6A256F60B6870387756DD121FEB63276B3BD99"),
    )
}

#[test]
fn test_ascon128_110() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B3D4DE1D4214960F7A2A312527B2086CD"),
    )
}

#[test]
fn test_ascon128_111() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD8FEDFE3A8C68B307ECFA86DBE97E5FF9"),
    )
}

#[test]
fn test_ascon128_112() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D722692214C612F12FEE54E7A3E5565AA"),
    )
}

#[test]
fn test_ascon128_113() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547D02164F9B18D92235BB8804454A4AE83"),
    )
}

#[test]
fn test_ascon128_114() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E5892E6A4BD2A1951254CF8FF9004606EBD18"),
    )
}

#[test]
fn test_ascon128_115() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607B87982471BC3CDA0F4066BF58758C5C"),
    )
}

#[test]
fn test_ascon128_116() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A2821C812A75544ECBADC70A26480FEC45461"),
    )
}

#[test]
fn test_ascon128_117() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B79BA0B8F4055963CCF3A8169D250A9E42"),
    )
}

#[test]
fn test_ascon128_118() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE33089D4192C97E31F939A3A5D6D7AA0C"),
    )
}

#[test]
fn test_ascon128_119() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC7287B8B140172FF8B70B692323AEA189AE"),
    )
}

#[test]
fn test_ascon128_120() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB4A7A86AF2ADD545D828ACC346C47485B"),
    )
}

#[test]
fn test_ascon128_121() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("9949846BD638424096EE64054A358F2ADED190"),
    )
}

#[test]
fn test_ascon128_122() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61B37E6666E07C7B973529587D2C1F9820"),
    )
}

#[test]
fn test_ascon128_123() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA797B6CE28687236364C82756322ACF3A1"),
    )
}

#[test]
fn test_ascon128_124() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FAC0B48D847EAF787D6310BD06E0155FD2"),
    )
}

#[test]
fn test_ascon128_125() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29C7591CCB1C4F0BF7EA01E881C7BD878"),
    )
}

#[test]
fn test_ascon128_126() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5EA6793A91968167CF94F833568FDD265"),
    )
}

#[test]
fn test_ascon128_127() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E29CEC49F148B8540BCFB863DD5AADECE"),
    )
}

#[test]
fn test_ascon128_128() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D52606D8469F7BCD07C8B4090BF5507BD04"),
    )
}

#[test]
fn test_ascon128_129() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E702A8F08E0F97B8782A248375B88D6794"),
    )
}

#[test]
fn test_ascon128_130() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7460C590C19464890AB2EE78C127254F9"),
    )
}

#[test]
fn test_ascon128_131() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8BD2AD5A687F079420012C341C58166C81"),
    )
}

#[test]
fn test_ascon128_132() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086DCD5125F2AAC592072AF93BA58F4C466E"),
    )
}

#[test]
fn test_ascon128_133() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!(""),
        &hex!("E770D289723DBD7401E58C36EB488D1520305D0F"),
    )
}

#[test]
fn test_ascon128_134() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00"),
        &hex!("25FBE48A550AFEF7CE25BA45A6F0418AB2D671FE"),
    )
}

#[test]
fn test_ascon128_135() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("0001"),
        &hex!("49E505472EF152646BFF0BF584748E6702CC14DA"),
    )
}

#[test]
fn test_ascon128_136() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102"),
        &hex!("D2721FCB763F015C201A7983C9D5D36B463D1E0B"),
    )
}

#[test]
fn test_ascon128_137() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00010203"),
        &hex!("4A53D996863A6CE3E220259BB1D9405103D52E73"),
    )
}

#[test]
fn test_ascon128_138() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("0001020304"),
        &hex!("1F820273AC12205DC254A4777C873A050DA7B6DD"),
    )
}

#[test]
fn test_ascon128_139() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405"),
        &hex!("7CC88BDB4AD0FAF4F1DD4F40F80141148AF93D2E"),
    )
}

#[test]
fn test_ascon128_140() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00010203040506"),
        &hex!("44864FD3DBEA4923D1C581EDDA1ACD0070C6D7DC"),
    )
}

#[test]
fn test_ascon128_141() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("0001020304050607"),
        &hex!("108640BDF5755D678B2C03A9D5F97DFBAB13EE71"),
    )
}

#[test]
fn test_ascon128_142() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708"),
        &hex!("6A256FBB24744AD22D95E3208D705E4FE91C95D5"),
    )
}

#[test]
fn test_ascon128_143() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B08E0460C35AF5C3CBF5F1D4E626FC8D558"),
    )
}

#[test]
fn test_ascon128_144() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75D7877CB464B49B5E93A0EA495F0319AB"),
    )
}

#[test]
fn test_ascon128_145() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88AF62A4D15B897B118A05F9385535B3C4"),
    )
}

#[test]
fn test_ascon128_146() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE54773774E373E54CC5D746C6CAE56D4A540B3"),
    )
}

#[test]
fn test_ascon128_147() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270F4188BD0B38DBF880024DA167E143173"),
    )
}

#[test]
fn test_ascon128_148() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E6073927D845ABC584B40206A1E4520DC28AE"),
    )
}

#[test]
fn test_ascon128_149() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215EE219C60F71D317B2CA232101CDA4DCE7"),
    )
}

#[test]
fn test_ascon128_150() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B701495B9FB1286FD97880A182818688150C"),
    )
}

#[test]
fn test_ascon128_151() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE331256A6B92A6389F9D8644125E716A52F"),
    )
}

#[test]
fn test_ascon128_152() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72124A2C2750525514AAA8720C1E73B156DA"),
    )
}

#[test]
fn test_ascon128_153() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E9A9A7833C5F6FB36BD82F1C78C322678"),
    )
}

#[test]
fn test_ascon128_154() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D4BADCDC5496A1358D2540B786B8B2F04C"),
    )
}

#[test]
fn test_ascon128_155() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A83931283B9A628C1A5E82BE2E81429813"),
    )
}

#[test]
fn test_ascon128_156() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA779641A28CF5D536DFAFBCC99681BD2DFE4"),
    )
}

#[test]
fn test_ascon128_157() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7EC6E681B74F8CF58575D50FD3DE1B03CE"),
    )
}

#[test]
fn test_ascon128_158() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A2969AB6BC3FAE40BB8EFD7109C7622D6AC9"),
    )
}

#[test]
fn test_ascon128_159() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1167196DCD6EDC088A6D1FD392B0522D0"),
    )
}

#[test]
fn test_ascon128_160() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D3B47F7AE734361A6C94058DDD037238D"),
    )
}

#[test]
fn test_ascon128_161() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D5219BF07F68001CA1A177A4F5011514E6BE5"),
    )
}

#[test]
fn test_ascon128_162() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E7657BBD31B35A10BD09C27381DA60542992"),
    )
}

#[test]
fn test_ascon128_163() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D705915580B4AF6C588D35809636A697B148"),
    )
}

#[test]
fn test_ascon128_164() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25A30CBD1204ECBB79619CC02A3E2ED020"),
    )
}

#[test]
fn test_ascon128_165() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27493689F2C080418ACF11125FDE5C2F91"),
    )
}

#[test]
fn test_ascon128_166() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!(""),
        &hex!("E770D289D2E5705A06B6C2FAA93CC7108B5B1502B4"),
    )
}

#[test]
fn test_ascon128_167() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00"),
        &hex!("25FBE48AC1C46C0CC9ECB8CEB25053FFEC2C4AC129"),
    )
}

#[test]
fn test_ascon128_168() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("0001"),
        &hex!("49E50547CA6CC8555CC75D28EAD641E90E631BE359"),
    )
}

#[test]
fn test_ascon128_169() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102"),
        &hex!("D2721FCB367493484DB51C8BBBC43E1A1D14029689"),
    )
}

#[test]
fn test_ascon128_170() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00010203"),
        &hex!("4A53D9966D2C7DBF3BEEBF01EF347B8C773A6C17DB"),
    )
}

#[test]
fn test_ascon128_171() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("0001020304"),
        &hex!("1F820273C61B8B77D367C0D86E0557A43039A0A506"),
    )
}

#[test]
fn test_ascon128_172() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D993149407C6FB863AFF9894C309931C"),
    )
}

#[test]
fn test_ascon128_173() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00010203040506"),
        &hex!("44864FD33743ED20D7695A424D3505E437B8501178"),
    )
}

#[test]
fn test_ascon128_174() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("0001020304050607"),
        &hex!("108640BD714CD79EEC957DBC9D194598C083C982C7"),
    )
}

#[test]
fn test_ascon128_175() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD30168BBA48AB95240EA22A53A13225882"),
    )
}

#[test]
fn test_ascon128_176() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B0813F97AA0A08CAB30E34A22B72D4F06F35B"),
    )
}

#[test]
fn test_ascon128_177() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A40EBAA64F602CAD77EAF94419624A64BD"),
    )
}

#[test]
fn test_ascon128_178() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D8862AB4D9A818CFE0A9772010B53878C93F7"),
    )
}

#[test]
fn test_ascon128_179() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736B01309C6DA7218E0A44213CF96D0D33E2"),
    )
}

#[test]
fn test_ascon128_180() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB4C2A2A5F6A3A1586722395B49C06057"),
    )
}

#[test]
fn test_ascon128_181() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317FE6FE606F09A10C9C0DCEA94B35B44A7"),
    )
}

#[test]
fn test_ascon128_182() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A7B7D538B7076F7061FF4854FD882D3F1"),
    )
}

#[test]
fn test_ascon128_183() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B70130B49A4D7FEC9305A57598B9B85602F87B"),
    )
}

#[test]
fn test_ascon128_184() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EDF7C2C3ED1EE637795B45161B588223A"),
    )
}

#[test]
fn test_ascon128_185() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E3413D5D1308671462856E8461DED4635"),
    )
}

#[test]
fn test_ascon128_186() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E85B924A8BE14FB58D6CB2515C3FD5FF59B"),
    )
}

#[test]
fn test_ascon128_187() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48BECCFF2A29F142D5AD83B87E1C41B3D76"),
    )
}

#[test]
fn test_ascon128_188() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D44E33E09D28285ABB4B34325BD3C4504F"),
    )
}

#[test]
fn test_ascon128_189() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792B355FEEB4EAC92C8DD02EB28DA256C2AF"),
    )
}

#[test]
fn test_ascon128_190() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE0B6F05413DFFEC1812B3C7BBCE709732"),
    )
}

#[test]
fn test_ascon128_191() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686DC383714EDE30D9E1038E254DD33F5E0"),
    )
}

#[test]
fn test_ascon128_192() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B44B314EE6524B54917F90897F9D09548C"),
    )
}

#[test]
fn test_ascon128_193() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D44D34441EA7867C4A6A4472C3431D17C4D"),
    )
}

#[test]
fn test_ascon128_194() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D52198071651F8AB4CF52CD8C51FD0007A843EB"),
    )
}

#[test]
fn test_ascon128_195() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6F4E62701284C7B0033F6D40F1E6C862F"),
    )
}

#[test]
fn test_ascon128_196() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051DB231505F18918C0EAD574C471BBF1939"),
    )
}

#[test]
fn test_ascon128_197() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E57DE5241D5B15F6259CDF96A9B177DC42"),
    )
}

#[test]
fn test_ascon128_198() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3EF7065D7335F3321905C61C08462E879"),
    )
}

#[test]
fn test_ascon128_199() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!(""),
        &hex!("E770D289D2A4A5D8FAFA197CC29BD868CA5322B1CEBE"),
    )
}

#[test]
fn test_ascon128_200() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00"),
        &hex!("25FBE48AC155289C7CA4B7561222452AF2417C8A4A21"),
    )
}

#[test]
fn test_ascon128_201() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("0001"),
        &hex!("49E50547CA0C741C71BFA1F2CFDCF8CB9F7E4504759E"),
    )
}

#[test]
fn test_ascon128_202() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5445CD7AF443EC7E6B305B93601A578"),
    )
}

#[test]
fn test_ascon128_203() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00010203"),
        &hex!("4A53D9966D879358A83E1F9B487EA884B4E9D9854EEF"),
    )
}

#[test]
fn test_ascon128_204() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("0001020304"),
        &hex!("1F820273C65287B01F7EB63572CF2E2A5160BE11356F"),
    )
}

#[test]
fn test_ascon128_205() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D7E5D53D8457FFB27516E44D6E8C126CA5"),
    )
}

#[test]
fn test_ascon128_206() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00010203040506"),
        &hex!("44864FD337BB9600E5823A16A22384F826CE85791ED6"),
    )
}

#[test]
fn test_ascon128_207() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("0001020304050607"),
        &hex!("108640BD71341DE5B02980F6F8E8E1F8C4D852E25DEE"),
    )
}

#[test]
fn test_ascon128_208() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3724F7272227A805D7CC4EA25F9F53D4DD5"),
    )
}

#[test]
fn test_ascon128_209() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B0813120C401EB1FEA272BFF28E4431A587A458"),
    )
}

#[test]
fn test_ascon128_210() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A416204DF88D4BEF5CBFF3DA03DF92F50422"),
    )
}

#[test]
fn test_ascon128_211() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D886219CE7737ABB8B52EC3ABC35921336AD3D9"),
    )
}

#[test]
fn test_ascon128_212() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE14CB26786CCE959BFE361E05F823DDA7D"),
    )
}

#[test]
fn test_ascon128_213() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB802D06896BF3932C4CF603791221D2402"),
    )
}

#[test]
fn test_ascon128_214() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A295B8B855240BA70D70DBB90C0260F3A8"),
    )
}

#[test]
fn test_ascon128_215() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A60D8D2B69BE469A05A58C36DB58BB6D962"),
    )
}

#[test]
fn test_ascon128_216() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089C4B588AE68FADC469AD3225FB3662F01"),
    )
}

#[test]
fn test_ascon128_217() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4292894D9167763AC2F49642BCF1C0E24"),
    )
}

#[test]
fn test_ascon128_218() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66DC69F8DF81A340F47A926C6C42994536"),
    )
}

#[test]
fn test_ascon128_219() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DA4BEA085B1C931A90B99BBECE8CAF07D"),
    )
}

#[test]
fn test_ascon128_220() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B445900E803B938F327E6E3288CC67803F3"),
    )
}

#[test]
fn test_ascon128_221() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D48872C1D6060F6B69678B41D2A59DD84405"),
    )
}

#[test]
fn test_ascon128_222() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5BAC971D7B4A4248A9B5CBC8530701E58"),
    )
}

#[test]
fn test_ascon128_223() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7CFC2F7AF7D89D0E032826E294B20EFBFC"),
    )
}

#[test]
fn test_ascon128_224() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE9274F8ADEBB2340320399A5EC0D6B202"),
    )
}

#[test]
fn test_ascon128_225() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B4351FF1DD8DB594F774870E89010D69B0AC"),
    )
}

#[test]
fn test_ascon128_226() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447F6973726765006319B0E81F3EB320C6DB"),
    )
}

#[test]
fn test_ascon128_227() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D5219804260C037C4E8481FE7029C95BED1C5050E"),
    )
}

#[test]
fn test_ascon128_228() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BF495D976762756C7FF4E315D76EA70B8A"),
    )
}

#[test]
fn test_ascon128_229() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D74EB7CC65835F3CDB97AA9F5289A28BC06"),
    )
}

#[test]
fn test_ascon128_230() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E40CCC85994F5B78A7D9B653BBFD144A4"),
    )
}

#[test]
fn test_ascon128_231() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A036B71D170118B82192E7EFB2FBF59"),
    )
}

#[test]
fn test_ascon128_232() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!(""),
        &hex!("E770D289D2A44A71B1ED9117B692EDDB148CBB6699A7F1"),
    )
}

#[test]
fn test_ascon128_233() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00"),
        &hex!("25FBE48AC155C100336794354DD81E8675EB922524452C"),
    )
}

#[test]
fn test_ascon128_234() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("0001"),
        &hex!("49E50547CA0C750523D92CE28F16BEE9E75B5034B8FF6F"),
    )
}

#[test]
fn test_ascon128_235() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102"),
        &hex!("D2721FCB362AB55BEB58E640B6BA8C4B08196C990FF1F7"),
    )
}

#[test]
fn test_ascon128_236() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BF82DD40FEAC052EA4192AB813105B30DB"),
    )
}

#[test]
fn test_ascon128_237() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("0001020304"),
        &hex!("1F820273C652463A0DF41AAED674E9857368BB6B30DF04"),
    )
}

#[test]
fn test_ascon128_238() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D706B12F30E2303D3EE71E6DD3F6951776D6"),
    )
}

#[test]
fn test_ascon128_239() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF29552F1B2C0D86C197FA779F20E97B75E"),
    )
}

#[test]
fn test_ascon128_240() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345CD3B1EA3C08BEA6AC30A74C48F7BC2E2A"),
    )
}

#[test]
fn test_ascon128_241() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C3A42F7FF53E518AD829BFB2FB5D19661"),
    )
}

#[test]
fn test_ascon128_242() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3CE46331B924130CE74A112F778AB5FDE"),
    )
}

#[test]
fn test_ascon128_243() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163D7DA036D478F46A21A46781D675C11D5C"),
    )
}

#[test]
fn test_ascon128_244() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912082CE6BE1330DB520598448155AA0324"),
    )
}

#[test]
fn test_ascon128_245() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D88662A0E9BCABB519E4A44A6107F823AC"),
    )
}

#[test]
fn test_ascon128_246() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89B5B5A7884AFF4E587F96533EAB43DF6B4"),
    )
}

#[test]
fn test_ascon128_247() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251CCF75D8ECB57BA7863E7596EB262A0FB"),
    )
}

#[test]
fn test_ascon128_248() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FB68CB1FB348DAA426A508A4F09F229D"),
    )
}

#[test]
fn test_ascon128_249() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB2A8E65EE59764BDB6AAB789882779EA8"),
    )
}

#[test]
fn test_ascon128_250() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528D5EC577018F9492C1EFBC6C7E330F4C"),
    )
}

#[test]
fn test_ascon128_251() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A27AEA1C013E631E57BF078868FC1ED894"),
    )
}

#[test]
fn test_ascon128_252() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF97219BE37E416B942BA4B1A4864B9BD2D"),
    )
}

#[test]
fn test_ascon128_253() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B4BCFE48FEFE0BEC3AFD95C7983A9A2F4E"),
    )
}

#[test]
fn test_ascon128_254() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E80C2E81C095D6F5C9A7C492B124475EA0"),
    )
}

#[test]
fn test_ascon128_255() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9CA2A7EFBC273D59BA25054E3F804A39F"),
    )
}

#[test]
fn test_ascon128_256() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C78D9A4A41EAB23FAC36B8C90458EF56538"),
    )
}

#[test]
fn test_ascon128_257() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFDE1CCF11C4994F35A1486E7650810D9"),
    )
}

#[test]
fn test_ascon128_258() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFC824FB3C14F170CCDF906C80674A20C6"),
    )
}

#[test]
fn test_ascon128_259() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA490C5F38FD825E6B97B266FCFD6F8C77E"),
    )
}

#[test]
fn test_ascon128_260() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423C1E08A4C2AA892BAABFF521A74DA0C43E"),
    )
}

#[test]
fn test_ascon128_261() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE78AE8E46C5A4321B9FAC9F0A917C020A5"),
    )
}

#[test]
fn test_ascon128_262() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D747844B4E03718503CA10850C78FDC6BB0F5"),
    )
}

#[test]
fn test_ascon128_263() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D494C20BA259DACD1C527859F4059302E"),
    )
}

#[test]
fn test_ascon128_264() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A616FEA454758AAD99D6EB53AC3975DE0"),
    )
}

#[test]
fn test_ascon128_265() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!(""),
        &hex!("E770D289D2A44AEEB076C632E98C61F69CD5DB919B58D204"),
    )
}

#[test]
fn test_ascon128_266() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00"),
        &hex!("25FBE48AC155C10386CF87FE743D9A2A627FC00DAE5B9B52"),
    )
}

#[test]
fn test_ascon128_267() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("0001"),
        &hex!("49E50547CA0C7547950D3B9804241712431C81D23C03D7D3"),
    )
}

#[test]
fn test_ascon128_268() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E1F8FD3F2BD9F0FF14E7F0B9EBC084D752"),
    )
}

#[test]
fn test_ascon128_269() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED09BE0A67072FD1F51FE5B1CE7E8BB84C"),
    )
}

#[test]
fn test_ascon128_270() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B7267A2CB1C513FE65991DA288CCBC8985"),
    )
}

#[test]
fn test_ascon128_271() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D706056C8B219F65945332DEDE9303DEF1D5DF"),
    )
}

#[test]
fn test_ascon128_272() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF2374302FC5DAC7C369371C7171FADBDFD47"),
    )
}

#[test]
fn test_ascon128_273() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6E37294FAC4BDDCAD22EE5E7178D20132C"),
    )
}

#[test]
fn test_ascon128_274() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C8215F807001FD7678E08FDCD6B37EE9F01"),
    )
}

#[test]
fn test_ascon128_275() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8941D7A98139835C2A973E67E6361008A"),
    )
}

#[test]
fn test_ascon128_276() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE384DDC15FF1ED2C4A0427C605CB4641EF"),
    )
}

#[test]
fn test_ascon128_277() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED8EBF251E9D01F44DA85C293FC268DF21"),
    )
}

#[test]
fn test_ascon128_278() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6861CCF3287D781E0377726F81AF65F08"),
    )
}

#[test]
fn test_ascon128_279() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB2779FB252BD1BD51D3C48C5505BE0673C"),
    )
}

#[test]
fn test_ascon128_280() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B0D199FBBA97AEFC56FDD43971B6A765C6"),
    )
}

#[test]
fn test_ascon128_281() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FA5E3DA35C3EDA411E8D18EA4A253DC57E"),
    )
}

#[test]
fn test_ascon128_282() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB86E59079F8C17FF9705EB3F7B599004E40"),
    )
}

#[test]
fn test_ascon128_283() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528EE3CEB4CBD39E65B1E4328E8300D8FCF2"),
    )
}

#[test]
fn test_ascon128_284() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202FCF75807DF1FB9524BE8CF4213EA5F4D"),
    )
}

#[test]
fn test_ascon128_285() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B3978F03A1502E04DCEA4B4B8DFF15680"),
    )
}

#[test]
fn test_ascon128_286() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B494882DC9077A2CF12F66D31A233129F015"),
    )
}

#[test]
fn test_ascon128_287() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB184219C4DBB58348FE5ED5B33032EA06"),
    )
}

#[test]
fn test_ascon128_288() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F96293FE69533B1263F98ABF16914DB90D27"),
    )
}

#[test]
fn test_ascon128_289() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FE8F7EEC9EBC53BB595BFA5239AC4E987"),
    )
}

#[test]
fn test_ascon128_290() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC501F0788B15A180D61326986793B9DE0"),
    )
}

#[test]
fn test_ascon128_291() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF432D08A17E45051EB02E6C023B1D66E41"),
    )
}

#[test]
fn test_ascon128_292() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA429B700555F01728766EC33ECBBAC1FC09F"),
    )
}

#[test]
fn test_ascon128_293() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF9BB914B8AB0E0F71FE89504E2509D42E"),
    )
}

#[test]
fn test_ascon128_294() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC2710F5E7FCFF32C81CBCB9C43289B2D3"),
    )
}

#[test]
fn test_ascon128_295() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D5205F1740139CFE40E45C30027C648D50"),
    )
}

#[test]
fn test_ascon128_296() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D0107E70967DBECB41D7BF40C2D312AAD29"),
    )
}

#[test]
fn test_ascon128_297() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A23D39116F51D76FE9DE67890FCCD7DC3DB"),
    )
}

#[test]
fn test_ascon128_298() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7C61B4623AC9931D92AC8AAE3F9F78C0CE"),
    )
}

#[test]
fn test_ascon128_299() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00"),
        &hex!("25FBE48AC155C103926FD82C34FE8EDE74F8B4BDA0CBE9C500"),
    )
}

#[test]
fn test_ascon128_300() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("0001"),
        &hex!("49E50547CA0C7547848EFD5E4DE60C2580C4B48AC4ACA27F3A"),
    )
}

#[test]
fn test_ascon128_301() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C360520512C49823ACBD6701966E57F77"),
    )
}

#[test]
fn test_ascon128_302() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED68CFABF4D3B0A4D69F1D04681BF6271659"),
    )
}

#[test]
fn test_ascon128_303() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76DE40951C91F2C8B18097127BB1C1B59D6"),
    )
}

#[test]
fn test_ascon128_304() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D706059738292F22EC49DDF614846D1712D03227"),
    )
}

#[test]
fn test_ascon128_305() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DBD36368EE6094699B36657AA033BECDBC"),
    )
}

#[test]
fn test_ascon128_306() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDCD66C67162F61A848D296C4BCB8CBFD46"),
    )
}

#[test]
fn test_ascon128_307() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F40E10B01156FA225437C2E518FF29C37"),
    )
}

#[test]
fn test_ascon128_308() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C1C3EB2EE4FA2B8FE58F0B457FD49A3BBE"),
    )
}

#[test]
fn test_ascon128_309() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE31931F35D13C116FE3DCAA7D4CBBE18DC5E"),
    )
}

#[test]
fn test_ascon128_310() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED7365FC752813430D5A45AE29C534620291"),
    )
}

#[test]
fn test_ascon128_311() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CD48C637890D9B34AD5A702E4A3BE8C1BB"),
    )
}

#[test]
fn test_ascon128_312() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB224589220FCB5A616AD33159ABD95E074AD"),
    )
}

#[test]
fn test_ascon128_313() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B9012988302FE50D9FF044809B0D94A41"),
    )
}

#[test]
fn test_ascon128_314() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE49D797FAC59DC5A9F1501B82DE55BF79B"),
    )
}

#[test]
fn test_ascon128_315() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A3FA3006697C92747D37905BD9D387ADB"),
    )
}

#[test]
fn test_ascon128_316() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D9181A99F3956898A8484B9B3749B9DCE"),
    )
}

#[test]
fn test_ascon128_317() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A20243012E69A8309583C1DD8C860816B1439F"),
    )
}

#[test]
fn test_ascon128_318() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F1B715DFEFECEE7A83F2D6AEA3CBA3F35"),
    )
}

#[test]
fn test_ascon128_319() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B494468486B6FAA8AE1DBC985AB8CB58033654"),
    )
}

#[test]
fn test_ascon128_320() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F68A302A04EEC3B9FE72DD06BC6367EE6"),
    )
}

#[test]
fn test_ascon128_321() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F421E34FD5ABEF1EC7F43B6621A6E20B3"),
    )
}

#[test]
fn test_ascon128_322() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF21138EA057F2307E7DABE42D6A1C823D"),
    )
}

#[test]
fn test_ascon128_323() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3F63030A9CBBB3085CFDF2CB8F30824E0A"),
    )
}

#[test]
fn test_ascon128_324() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF48979024ABA2E259C98E89EC0C7AE18ACBC"),
    )
}

#[test]
fn test_ascon128_325() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945D03C7AD8B0DCFB190F2E9A0AEAD01693"),
    )
}

#[test]
fn test_ascon128_326() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF5233A5E1D7348DC85F7462505CB7380BCB"),
    )
}

#[test]
fn test_ascon128_327() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0EA959D9DAC45EF5E108685791C08D4364"),
    )
}

#[test]
fn test_ascon128_328() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53FF23AD62D658D494C051EC5D937923F81"),
    )
}

#[test]
fn test_ascon128_329() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B17CDF0E9E7BA08769A9AAE211125F0E26"),
    )
}

#[test]
fn test_ascon128_330() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A23336690C8B42C0B811E74CE6CF0A5F563D9"),
    )
}

#[test]
fn test_ascon128_331() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0BA5DFDFE05DBAAE61E1DFF349BE58240"),
    )
}

#[test]
fn test_ascon128_332() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E1EB44A2A166AF15A0D997B8DA642C1C2"),
    )
}

#[test]
fn test_ascon128_333() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F225F85AC672152F920DFFD248610090CE"),
    )
}

#[test]
fn test_ascon128_334() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C68689CD8F01AEA3BE660AA60EB692DB61D"),
    )
}

#[test]
fn test_ascon128_335() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED6865927D89264E1BFF075CDB8A00F62CD434"),
    )
}

#[test]
fn test_ascon128_336() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4F38773704C9B4C59E40007517BC1E5182"),
    )
}

#[test]
fn test_ascon128_337() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B8FC22EB913A41CEE3F01069AFAE92001"),
    )
}

#[test]
fn test_ascon128_338() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB149250FB8864B8C59BCE4F417F4904C5BC"),
    )
}

#[test]
fn test_ascon128_339() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AE686279EA0C1723AF33EADB5D77EF381"),
    )
}

#[test]
fn test_ascon128_340() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99F8B1E7E8AFB03983E3B524C05CD53C6C"),
    )
}

#[test]
fn test_ascon128_341() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E1F2E1DE986408917271CC2891D55607B"),
    )
}

#[test]
fn test_ascon128_342() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4900103A5D1A1AA33ECBEF7CAF2BBA7B6"),
    )
}

#[test]
fn test_ascon128_343() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737E8F5A49E06C52CCEC4C58AE9CD82BB5D9"),
    )
}

#[test]
fn test_ascon128_344() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE16E3F167A11EC658130C12ABAC3BED8A6"),
    )
}

#[test]
fn test_ascon128_345() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB224085211094DF3959B58E71A4F01F5CAF39E"),
    )
}

#[test]
fn test_ascon128_346() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B307D04637B673770952AEEAD496D4BFA99"),
    )
}

#[test]
fn test_ascon128_347() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE4204CF4E4DEEA8A532A6A5ED5DEF5B3E900"),
    )
}

#[test]
fn test_ascon128_348() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742548E1054AF955E532F91979A03351D9"),
    )
}

#[test]
fn test_ascon128_349() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BAFD6B5ECC9AB43C252B5F0962CB530EE"),
    )
}

#[test]
fn test_ascon128_350() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433CF2A6BA2326DA11905798274116CB9E1F"),
    )
}

#[test]
fn test_ascon128_351() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8A5C2433C5F7100D27481CEF49FD9590F4"),
    )
}

#[test]
fn test_ascon128_352() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B4944609DCF78D702E4721439B6AA051D87E6E8A"),
    )
}

#[test]
fn test_ascon128_353() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9FB23B82932FC6DB68696A860BC26860EF"),
    )
}

#[test]
fn test_ascon128_354() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F075E48C7CB297F1ED7C963194FB3F18D03"),
    )
}

#[test]
fn test_ascon128_355() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8BE43287D0137B079F940A363371F35AD1"),
    )
}

#[test]
fn test_ascon128_356() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD44B88CAC3F60962B510675C7BFB9102A"),
    )
}

#[test]
fn test_ascon128_357() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8B5AB5B2897B7F18A9D3B284B13D9E440"),
    )
}

#[test]
fn test_ascon128_358() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF6560FE45093C9B630E9AFA02B410E568"),
    )
}

#[test]
fn test_ascon128_359() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E0CE321AF34D5A1A1B7C6F11436119ED1"),
    )
}

#[test]
fn test_ascon128_360() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E259544D5F21C04650FF36AD994E43C966F"),
    )
}

#[test]
fn test_ascon128_361() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BF5FC3DADAC814E396C1B6B339D1AD36C"),
    )
}

#[test]
fn test_ascon128_362() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B1143974536141A7084D3A4AFE730ADB0E2A"),
    )
}

#[test]
fn test_ascon128_363() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFF9D363D14DCC737C8FAA67ED066DCE62"),
    )
}

#[test]
fn test_ascon128_364() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A4E063D016DE47F98A7F0B1B344410A944"),
    )
}

#[test]
fn test_ascon128_365() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E5969931EC0AD6B9CB14904E9E9BB49A02B"),
    )
}

#[test]
fn test_ascon128_366() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A67F63DE77E7B898037AE971E9EB4DE8D6"),
    )
}

#[test]
fn test_ascon128_367() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872614B633DCE534A333E506D26086966C7"),
    )
}

#[test]
fn test_ascon128_368() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED6865858439827C1BB65B7DF6F235BA8D648A5B"),
    )
}

#[test]
fn test_ascon128_369() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8AAB99C2E9AB1E0C6F508FE31D857F862"),
    )
}

#[test]
fn test_ascon128_370() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCC9AF5943FDD02FE0070703DD45BC3AC"),
    )
}

#[test]
fn test_ascon128_371() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14137BF76BE1C0CDF453929039B6C70282D9"),
    )
}

#[test]
fn test_ascon128_372() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC6E3CE10C6733FED240C25B2A6E84D515"),
    )
}

#[test]
fn test_ascon128_373() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E57762B45EE4594348B19B8CDA7340B1A4"),
    )
}

#[test]
fn test_ascon128_374() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E8423F1450500AA811C8CF28D360E0308D3"),
    )
}

#[test]
fn test_ascon128_375() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3CBCF82C6EEA838AD617067B84CFB72D4"),
    )
}

#[test]
fn test_ascon128_376() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EAD74F20DC2AA0B95BE083FF167AF1545D3"),
    )
}

#[test]
fn test_ascon128_377() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18DD23F4612D23A2B27DE8E591246F186DE"),
    )
}

#[test]
fn test_ascon128_378() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408043B62031CB3A7AAC293EB4A2088BF68AE"),
    )
}

#[test]
fn test_ascon128_379() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F7B9743D878EDF9AD8BBDAACCF10778A47"),
    )
}

#[test]
fn test_ascon128_380() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095CA57296D9A38F281EC0758B893057FB6"),
    )
}

#[test]
fn test_ascon128_381() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4A403B2F87FE884C6B34977053543418"),
    )
}

#[test]
fn test_ascon128_382() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC4A249F078C51F6ADAFEA0BDD4D11683E2"),
    )
}

#[test]
fn test_ascon128_383() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C61935F7080C32B1CFE757146EE33720C24"),
    )
}

#[test]
fn test_ascon128_384() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA25CB842C09B8087DA823958D45441CFD"),
    )
}

#[test]
fn test_ascon128_385() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092E7AF0001B616272F6DD0FAB613454B020"),
    )
}

#[test]
fn test_ascon128_386() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57DE9FDF3153B4BE00C987A6C9CF869D2D"),
    )
}

#[test]
fn test_ascon128_387() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A27DE83E5306C4D7CA5E9A9883493C868C"),
    )
}

#[test]
fn test_ascon128_388() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7EE8F2F5B376291234338F5EFA24CBE3B9"),
    )
}

#[test]
fn test_ascon128_389() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84BDDF4C43F10930D31BA83B84E86DD104"),
    )
}

#[test]
fn test_ascon128_390() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD1E9017A1E8EE19988053A60809039AC8"),
    )
}

#[test]
fn test_ascon128_391() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF666CA598FF75070E3CF50D46A73CF41CA0"),
    )
}

#[test]
fn test_ascon128_392() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7ED135881EBD6EC718B52FA5CC8308DA35"),
    )
}

#[test]
fn test_ascon128_393() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E258877A2D836356067424D228A3A84DFC81B"),
    )
}

#[test]
fn test_ascon128_394() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA0A8C8E06FB60BF627305F287F7EFE50E6"),
    )
}

#[test]
fn test_ascon128_395() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422BED79619A10D8D2CE95A45E25D351D27"),
    )
}

#[test]
fn test_ascon128_396() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC76375353C06366198CA0BD8954829EF02"),
    )
}

#[test]
fn test_ascon128_397() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48E4E6A4FF286931434579C0BD704E3D915"),
    )
}

#[test]
fn test_ascon128_398() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C6EC1848559DA4A363E0D56C6136CA07EB"),
    )
}

#[test]
fn test_ascon128_399() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F9F8D75BF188E83D1FBC93582BF15A3C33"),
    )
}

#[test]
fn test_ascon128_400() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C687244E486708610E62934EFBDC6D40E90BDE1"),
    )
}

#[test]
fn test_ascon128_401() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE55CE0EA2422AA3F2790539A216B2AB8F"),
    )
}

#[test]
fn test_ascon128_402() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1AEE5F251B92BE69AE7BE8C89773CDB91"),
    )
}

#[test]
fn test_ascon128_403() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD1ADFFFB6527B90BB2C394274D17FE1A8"),
    )
}

#[test]
fn test_ascon128_404() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139B7C534D271A620CCE5E9BFCC1AF3570C0"),
    )
}

#[test]
fn test_ascon128_405() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC766E448981134131AAB8BA7BD2B4948AC1"),
    )
}

#[test]
fn test_ascon128_406() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C524303CE4F7C99AEEF2CAAFCBD508A4D9"),
    )
}

#[test]
fn test_ascon128_407() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F97741939E99018CEBD55AAC85DE1EB39"),
    )
}

#[test]
fn test_ascon128_408() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E47C3ACA1BE5DBE1F4C9A7B0E99092CA56"),
    )
}

#[test]
fn test_ascon128_409() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1A799EFD6EB3D1DAB69BB2C2B0BECB465"),
    )
}

#[test]
fn test_ascon128_410() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D14FBF208AF27A909A0AEF11E5C7A3B5612"),
    )
}

#[test]
fn test_ascon128_411() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041D52241FA8E32B128F5E340BE620359204"),
    )
}

#[test]
fn test_ascon128_412() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744D69E011E60E55A63369595A289AC97A7"),
    )
}

#[test]
fn test_ascon128_413() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE4209531D4FF11F1DDE01A82ED0B498E24715DBA"),
    )
}

#[test]
fn test_ascon128_414() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C178483B900A69B3A53241256131DCF25"),
    )
}

#[test]
fn test_ascon128_415() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467DA548BFFE42584E2DB089D51A61F0718"),
    )
}

#[test]
fn test_ascon128_416() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C6182716AEFB3022C5BF9E839A1CC8BF37D0A"),
    )
}

#[test]
fn test_ascon128_417() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA4495787DE780A1410B50BADD84AE0639F4"),
    )
}

#[test]
fn test_ascon128_418() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE2998CC94BE03B4FEB2225C6D186B45E72"),
    )
}

#[test]
fn test_ascon128_419() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D72494D4268983B582233D1A4CA96B9D06"),
    )
}

#[test]
fn test_ascon128_420() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A2669F55B4B955F999281B76702DCA2B2FD4"),
    )
}

#[test]
fn test_ascon128_421() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41D925132755BEB256513FD4D0700CB058"),
    )
}

#[test]
fn test_ascon128_422() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD848971F914441B4F89AB9349105D8CFEE382"),
    )
}

#[test]
fn test_ascon128_423() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04329783BC8F04053DDE5FDF957B79B219"),
    )
}

#[test]
fn test_ascon128_424() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF333842BEE2E89F4BA375B92319791924"),
    )
}

#[test]
fn test_ascon128_425() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4FF79E9AA6D09FEDC587AC9D44CEB64F85"),
    )
}

#[test]
fn test_ascon128_426() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E2588660EF98E139504F92E5E88FA0A89D22F75"),
    )
}

#[test]
fn test_ascon128_427() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03E5AB7A2238074E8D0D53DD40591C49594"),
    )
}

#[test]
fn test_ascon128_428() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D98F455B73B776EC563854B20000D888A5"),
    )
}

#[test]
fn test_ascon128_429() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F2A13574D9140D012B69B057657168818E"),
    )
}

#[test]
fn test_ascon128_430() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE38A71EC52FCE382042598A9F3225DFA3"),
    )
}

#[test]
fn test_ascon128_431() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C8EF98D2402A1EB6A3DAFB2A289181C79"),
    )
}

#[test]
fn test_ascon128_432() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F9364929F9146287F322C38010C1BBA75303"),
    )
}

#[test]
fn test_ascon128_433() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449BA0F342779F302DA386F7C15096E69C72"),
    )
}

#[test]
fn test_ascon128_434() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A27B9DBE171DF9A348075E9B55005E247"),
    )
}

#[test]
fn test_ascon128_435() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD3801FBA7E68B45285FE7FBDC92A2B57"),
    )
}

#[test]
fn test_ascon128_436() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35502854FBE4C7136EE5A7D1DC40E73AB8"),
    )
}

#[test]
fn test_ascon128_437() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6CCD2ADAF132C61D96566566095F0DE2"),
    )
}

#[test]
fn test_ascon128_438() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3D2F959324D042C62BB360F3B2C5B19C"),
    )
}

#[test]
fn test_ascon128_439() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C52502748AE50F4343902A0DCE8C350D6456"),
    )
}

#[test]
fn test_ascon128_440() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0AEAF8A7090E8D948AFEA26489B148EAB3"),
    )
}

#[test]
fn test_ascon128_441() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C90D5E2CAD1CC203682F18461D2E866D44"),
    )
}

#[test]
fn test_ascon128_442() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B1E9DDCD35A88D280627380D6EC8474F1E"),
    )
}

#[test]
fn test_ascon128_443() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430CA3A5C60A60EE2E114D4D9BDEFAA1FB8"),
    )
}

#[test]
fn test_ascon128_444() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF90E30886E64690DD108B34620EEA8DF8"),
    )
}

#[test]
fn test_ascon128_445() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B75621C217F4E7AF4E84B280D94C99C621"),
    )
}

#[test]
fn test_ascon128_446() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B82B3778B933598FBF3F4359D11261C31"),
    )
}

#[test]
fn test_ascon128_447() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C1312FDC6CB8554CC51551385A3601012C9"),
    )
}

#[test]
fn test_ascon128_448() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A0AFBE21674E55C72A620F62A5A1410403"),
    )
}

#[test]
fn test_ascon128_449() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208FFD894880B66C4D42FEC1596C1C97F79"),
    )
}

#[test]
fn test_ascon128_450() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F22B29F278C6A5BB2E2D39135B246A5BC7"),
    )
}

#[test]
fn test_ascon128_451() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25E7570242793792B517BB860A3722E2EA4"),
    )
}

#[test]
fn test_ascon128_452() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D793B5B4FB493189636C7647E4D8808321F6"),
    )
}

#[test]
fn test_ascon128_453() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6038CE2EDB4B683152454A4B55B811B54"),
    )
}

#[test]
fn test_ascon128_454() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC64BCEC36CB18E75163D37682B751D520"),
    )
}

#[test]
fn test_ascon128_455() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6B49D86DFF62950C9F6409973FF29008"),
    )
}

#[test]
fn test_ascon128_456() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B825AAF34585583E9797A3F7A329B5A600"),
    )
}

#[test]
fn test_ascon128_457() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF533699F68050362B334F1E277DBA824795"),
    )
}

#[test]
fn test_ascon128_458() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BA954D61B21523C507EDC8347ED5321B2"),
    )
}

#[test]
fn test_ascon128_459() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657B1D673F89B0B6077F7E2DEA7807A9456"),
    )
}

#[test]
fn test_ascon128_460() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF24EB02FC8C4B87890382A7A4DD085EC0B"),
    )
}

#[test]
fn test_ascon128_461() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D940315A23C1ABC358C74F53E749F2C4047B"),
    )
}

#[test]
fn test_ascon128_462() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F2218C78BD40D7174F8D158AD297EB11E029"),
    )
}

#[test]
fn test_ascon128_463() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5202E5BAE52DD5E452F7B6B843B163BAB8"),
    )
}

#[test]
fn test_ascon128_464() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C8814D937B0BC7D7A26EF5BC0E802F14006"),
    )
}

#[test]
fn test_ascon128_465() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED772921C0C30D6F85E660B37F1EB55EF0"),
    )
}

#[test]
fn test_ascon128_466() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B1132F55C1D299956030E69273287971557"),
    )
}

#[test]
fn test_ascon128_467() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A284CF180A87F8CA62B92F20C9BD5061475"),
    )
}

#[test]
fn test_ascon128_468() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD776A6935D3E1DCDF8377826D3368428C0"),
    )
}

#[test]
fn test_ascon128_469() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DA86B4B88395FBABC8E6A07A29567836E1"),
    )
}

#[test]
fn test_ascon128_470() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E67C2B2455146B3D1F3CDBD39C2B09CE3"),
    )
}

#[test]
fn test_ascon128_471() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3B0A3FA61CD4F30D9EAD0901AB5CAB877E"),
    )
}

#[test]
fn test_ascon128_472() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CB77DDF9FACC702DFC3CEFDBDC016B1A7"),
    )
}

#[test]
fn test_ascon128_473() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBC03813101144C22ADEA4FE5131EC103B"),
    )
}

#[test]
fn test_ascon128_474() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F1128694A9AB183C5D0B7FB7C13A27916"),
    )
}

#[test]
fn test_ascon128_475() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FABE811B4B12E9A3F07BE943CDCB5EB48"),
    )
}

#[test]
fn test_ascon128_476() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BAD091C881BBD3327261B2832E39609AA8"),
    )
}

#[test]
fn test_ascon128_477() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D5146B49BB9D27512811C20B7D049DBCB"),
    )
}

#[test]
fn test_ascon128_478() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71940A51E5C77B95B21AE9E5F0F164F63B1"),
    )
}

#[test]
fn test_ascon128_479() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B181B3D95D5B6158D2F9D65BF3A4B8D6FFA"),
    )
}

#[test]
fn test_ascon128_480() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F156CE91ADA5289EC9C29BCA4290D6289E"),
    )
}

#[test]
fn test_ascon128_481() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A023D237CDE3BA8DA27A628B15F0DA8FF623"),
    )
}

#[test]
fn test_ascon128_482() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B20F4C73EC1D1886C845CB9C9C2C48B634"),
    )
}

#[test]
fn test_ascon128_483() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BD41B2B9605BAF759111600266D7038C5"),
    )
}

#[test]
fn test_ascon128_484() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF588BD05CA9FB8C8C39EA1F0EC85043235"),
    )
}

#[test]
fn test_ascon128_485() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D793502A2BC48F545D62DDEEBA429E23503974"),
    )
}

#[test]
fn test_ascon128_486() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF9ECD0D84895061B602DEA18A93DA7855"),
    )
}

#[test]
fn test_ascon128_487() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97D9E06997E811FE95676447F495557561"),
    )
}

#[test]
fn test_ascon128_488() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F7ED81CA474F733D33A115BA1441765CE"),
    )
}

#[test]
fn test_ascon128_489() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87BDF9463A583CDB25B513124CF11CDD5ED"),
    )
}

#[test]
fn test_ascon128_490() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375C2DCE9FC6FE329FBF4EAAE5DA899631D"),
    )
}

#[test]
fn test_ascon128_491() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BAB00E72894846E6609319E7B6AB9B6BDE1"),
    )
}

#[test]
fn test_ascon128_492() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E2588665748B7EE3A213082694FF1C6890EA307667D"),
    )
}

#[test]
fn test_ascon128_493() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF29056651660C3375F3EC4266AE67C182B81"),
    )
}

#[test]
fn test_ascon128_494() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048B35BDA0F89F7D79A585662310A0012A1"),
    )
}

#[test]
fn test_ascon128_495() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172ACE6260894BB22E96C9F382ED552B5E1"),
    )
}

#[test]
fn test_ascon128_496() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE52749EC39B48260DF0B8692D1D5239800449"),
    )
}

#[test]
fn test_ascon128_497() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A51F1BCFFF90BD2D2D447D0D8A505CE2EC"),
    )
}

#[test]
fn test_ascon128_498() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED94FA56CAB84ED5A2F5072AB61073575470"),
    )
}

#[test]
fn test_ascon128_499() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117BB3FD1597C7D3982784650EF9AEF01335"),
    )
}

#[test]
fn test_ascon128_500() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7B64D3EDA09F51BA9F7D619E4C5E77EA0"),
    )
}

#[test]
fn test_ascon128_501() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D13DF95A28388A8DCC7E183097DA04EAB"),
    )
}

#[test]
fn test_ascon128_502() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABDA04070DF1B7072B6E293E6CD58886C1D"),
    )
}

#[test]
fn test_ascon128_503() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1DE26C03879885A624B66C9FE102B9168B"),
    )
}

#[test]
fn test_ascon128_504() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5BA16E25343D2B86A32C7D8D32C155108"),
    )
}

#[test]
fn test_ascon128_505() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC5B180260510D28819F1793CBBECAAED7"),
    )
}

#[test]
fn test_ascon128_506() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB879E776B6AAA1492138EA11CEFE343049"),
    )
}

#[test]
fn test_ascon128_507() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D9397FF85D0FF19F13891279A3C9EB5F7"),
    )
}

#[test]
fn test_ascon128_508() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB4375E0EA77576881C298A6FEF1F738A8"),
    )
}

#[test]
fn test_ascon128_509() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA863DD0B48829CD59A69657488076F36917"),
    )
}

#[test]
fn test_ascon128_510() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55086C4318F5C1FC91C1CD83352B6479B3"),
    )
}

#[test]
fn test_ascon128_511() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965E2CD4BEE393F2DE0D8CD8B8B4827E6E9"),
    )
}

#[test]
fn test_ascon128_512() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187FDC46412B80E88264FE2415762FC76486"),
    )
}

#[test]
fn test_ascon128_513() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F140C9E7558506B8277CD46BF4619EF4893C"),
    )
}

#[test]
fn test_ascon128_514() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391946E05C9402166B0CFB2E25844EA1277"),
    )
}

#[test]
fn test_ascon128_515() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281A88BAD044AD709F21728F3EF541F8F3A"),
    )
}

#[test]
fn test_ascon128_516() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADBD6C6675A7D44CCEBEAA89BE8618B89E"),
    )
}

#[test]
fn test_ascon128_517() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF52146ACC5F1907622DE105CB986B4056FDB"),
    )
}

#[test]
fn test_ascon128_518() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E39FBCDB02E055DEA555E497720860FF58"),
    )
}

#[test]
fn test_ascon128_519() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF87F91504FABD05FBE4C17359AE43611DD4"),
    )
}

#[test]
fn test_ascon128_520() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC978234B069A9291EDBF7C8C0E654AD4C23DD"),
    )
}

#[test]
fn test_ascon128_521() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F516BE676D69734DCD05D340E9CF67338BD"),
    )
}

#[test]
fn test_ascon128_522() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B076CE5F8ABE4451BF4E79D1294E06A4915"),
    )
}

#[test]
fn test_ascon128_523() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF18B585C0CD01FF9267F92F2BA52E8E43"),
    )
}

#[test]
fn test_ascon128_524() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0431043CBDE24862C77A3F62DDF4606D1"),
    )
}

#[test]
fn test_ascon128_525() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E67FF0F7CF362C2DFC7132A73A0AA8E7B"),
    )
}

#[test]
fn test_ascon128_526() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C4581F8A5E332162E0C8B1ECE623E53AD0"),
    )
}

#[test]
fn test_ascon128_527() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8A979F770ABAC8CA4052239588187EC23"),
    )
}

#[test]
fn test_ascon128_528() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A973FD31C0A3F03CEBB3DF3BB7BBCF6D7E"),
    )
}

#[test]
fn test_ascon128_529() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E3EA721F9A8FC4E556F2745972F5A78411"),
    )
}

#[test]
fn test_ascon128_530() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56BBCAE1D932EEE3D3463DC8CAA44F3EF5B"),
    )
}

#[test]
fn test_ascon128_531() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED94970ABB678CD2213561991F08F5A61A9F1A"),
    )
}

#[test]
fn test_ascon128_532() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B999D3ECB707C921EA87CC2FB6E4163AFC4"),
    )
}

#[test]
fn test_ascon128_533() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D330B31B5D83F19653ABB5C4362BA1B1BD"),
    )
}

#[test]
fn test_ascon128_534() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CCEBBCC91D4DBCBB67DC33806C9AB0D0D"),
    )
}

#[test]
fn test_ascon128_535() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B1ACC4F81FFE3ECF118BBBFAA730FFB50"),
    )
}

#[test]
fn test_ascon128_536() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25D7EC1D31C8994781052A46722890DD6A"),
    )
}

#[test]
fn test_ascon128_537() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4C6E6AB66848F59AA2CA36C7F4414824A"),
    )
}

#[test]
fn test_ascon128_538() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC36B7E80EE1C0A9285685A95D261CA0AE33"),
    )
}

#[test]
fn test_ascon128_539() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D1728363A74744BA0ED4CA66D2477BBB3"),
    )
}

#[test]
fn test_ascon128_540() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5F5B5928563EBBF0F4F5FDAE0C71E6B4E0"),
    )
}

#[test]
fn test_ascon128_541() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19F08D351F1C4085D9F6BE99E2C82055ED"),
    )
}

#[test]
fn test_ascon128_542() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6E5469037AC06D4206BE3D8ECFF3D704"),
    )
}

#[test]
fn test_ascon128_543() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB94013B2148896577C0F401C50298297E"),
    )
}

#[test]
fn test_ascon128_544() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0821238149850B113A2CAF70A9B65C3D1"),
    )
}

#[test]
fn test_ascon128_545() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99E0C479771A09B5D29AFD05825B013D0D"),
    )
}

#[test]
fn test_ascon128_546() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408EBE839B337BF8289BA39CFF353229E0DA"),
    )
}

#[test]
fn test_ascon128_547() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BFE9DF482A0251E9C355A725CD35B9B049"),
    )
}

#[test]
fn test_ascon128_548() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F91C0C6B55D6BCC1821CCE2CA6B8D5C7E0"),
    )
}

#[test]
fn test_ascon128_549() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF1E5973F77F1A47C15E4D4FF09D68DA8FB"),
    )
}

#[test]
fn test_ascon128_550() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4EF2C7B174A7C41FCAB40AB9DC0ADFAA7"),
    )
}

#[test]
fn test_ascon128_551() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E353C9B63AF867F1531E87D661795CCAC05C"),
    )
}

#[test]
fn test_ascon128_552() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E24658BD441183DB814917AD2B612AACF"),
    )
}

#[test]
fn test_ascon128_553() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F4AC0D6C4E70CACAEF751BBCD5092A0BC"),
    )
}

#[test]
fn test_ascon128_554() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F51762485698C69834A49F84E1C05F0B9880D"),
    )
}

#[test]
fn test_ascon128_555() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B07630AB4A4A21709CA187E6A3DA5959ED254"),
    )
}

#[test]
fn test_ascon128_556() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF61A5B5CC5CF5C74F4BE93E39504A8B6390"),
    )
}

#[test]
fn test_ascon128_557() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FFF494D975B4DE29012E58D75929721162"),
    )
}

#[test]
fn test_ascon128_558() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D096D1C38B4DF6875CC5CA8CE018D0CFB"),
    )
}

#[test]
fn test_ascon128_559() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48BC42BBB51366D28C27FF3C180373C8833"),
    )
}

#[test]
fn test_ascon128_560() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C804D829BDFB647DF809721ECEEE433520E1"),
    )
}

#[test]
fn test_ascon128_561() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BC6D0EACE132FB02D26512DEF99D3AA62E"),
    )
}

#[test]
fn test_ascon128_562() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381A6132E1D1B072B1F103817B2D454700D"),
    )
}

#[test]
fn test_ascon128_563() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B694C864CD71D1266539E23801DFE750835"),
    )
}

#[test]
fn test_ascon128_564() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C313DE7AE137C9FD8B0DAE6B53ADFFB6FD"),
    )
}

#[test]
fn test_ascon128_565() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926900D29C2F298AC9E209CFA8DF4F1178B"),
    )
}

#[test]
fn test_ascon128_566() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D30217BCFF911A3FFA48C7F39065B6092038"),
    )
}

#[test]
fn test_ascon128_567() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC119415E9C145DA8790A1E8F52A6B8F3FD"),
    )
}

#[test]
fn test_ascon128_568() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B377C3843C5858B3006224EF2939BFA901B"),
    )
}

#[test]
fn test_ascon128_569() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D2514C6289FAD15429D7346FDBD112D38798F"),
    )
}

#[test]
fn test_ascon128_570() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DFCAA4EE178055310EB8FA6E1CA6F4FDA2"),
    )
}

#[test]
fn test_ascon128_571() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D6EAB0E6D1C189D9B3A0A6268E9A737F0"),
    )
}

#[test]
fn test_ascon128_572() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D307D0D9561560FE476926D255B4D992F4E"),
    )
}

#[test]
fn test_ascon128_573() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC463529C5FD3B534C95F58AC5E6A3213E8"),
    )
}

#[test]
fn test_ascon128_574() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9C762CA518BE19EE0098BE301E6924260"),
    )
}

#[test]
fn test_ascon128_575() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6BCF8DE2BCBC8F71E658DC705D8DFE15BD"),
    )
}

#[test]
fn test_ascon128_576() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BCD159F7F92968B02A07FD3E139B59FCF"),
    )
}

#[test]
fn test_ascon128_577() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1D5E576F7118A4E67FD4246766E7E7428"),
    )
}

#[test]
fn test_ascon128_578() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C58C47A610AD1D15094A4F527D902BBD6B"),
    )
}

#[test]
fn test_ascon128_579() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E9781D46986CBC03B3E6A335581EB9DA954"),
    )
}

#[test]
fn test_ascon128_580() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF4DEAB958A3870690C5899B22D39FCAA"),
    )
}

#[test]
fn test_ascon128_581() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F92987643DD59BD26F57C017368D058F9FDF"),
    )
}

#[test]
fn test_ascon128_582() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13B9D0C7F9B80A45244BDEDED1A56BBF663"),
    )
}

#[test]
fn test_ascon128_583() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E4981A2943A2748D066E5CF51251ECE205"),
    )
}

#[test]
fn test_ascon128_584() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E353111FE7D30AFDD8AC215BC542FFA87E8B09"),
    )
}

#[test]
fn test_ascon128_585() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B921F6CEC26CE77E238759A29CA28D638"),
    )
}

#[test]
fn test_ascon128_586() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F98F2BB975E1438F5D9FAB40C66FA6CD49F"),
    )
}

#[test]
fn test_ascon128_587() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6CA6415C6802CD4511CC14278980AA6CC"),
    )
}

#[test]
fn test_ascon128_588() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4D64F5D4E146CAB4FBA71093AE8A83223"),
    )
}

#[test]
fn test_ascon128_589() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF61021925FE6C4C23A3BE904FC33AE79150F4"),
    )
}

#[test]
fn test_ascon128_590() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF905A71A8F4B7A39603E766E5CFA5FF91CE"),
    )
}

#[test]
fn test_ascon128_591() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4CA370491E5EA138AAD665CEC4EFB1422B"),
    )
}

#[test]
fn test_ascon128_592() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D55981A135974A5C281BD4D23E3CD7127"),
    )
}

#[test]
fn test_ascon128_593() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045E24C2BE3EE6DCE07FB187A1922DCF08A7"),
    )
}

#[test]
fn test_ascon128_594() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCADA92B2A1CDEA6B1B8DA77294080EAD708"),
    )
}

#[test]
fn test_ascon128_595() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BA01E0EA2595E8A1298ED9AB925C7A430B"),
    )
}

#[test]
fn test_ascon128_596() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5190D7AECAE313946B30AD835341C6E48"),
    )
}

#[test]
fn test_ascon128_597() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A5FDC8BF0150C7FFE8E13EA187764148C2"),
    )
}

#[test]
fn test_ascon128_598() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B992679F2DE01627C325FAC1342EEFA58A28EAF"),
    )
}

#[test]
fn test_ascon128_599() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F420375B043C3F372BD02A9F3858ADABB"),
    )
}

#[test]
fn test_ascon128_600() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC170974453EB43684ECB92BC8E6BEEECC694"),
    )
}

#[test]
fn test_ascon128_601() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B93CE5DE0570F6E4868FD7561DBD25B9B3"),
    )
}

#[test]
fn test_ascon128_602() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140DEAFAAADAEA87E93BE84F137AAB6039A0"),
    )
}

#[test]
fn test_ascon128_603() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44FFD658E6770535C0ABDA9F47E26BA11C"),
    )
}

#[test]
fn test_ascon128_604() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13D066301F046D43DAFECCAF9ED9C7077E"),
    )
}

#[test]
fn test_ascon128_605() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B76D66D84E7F757C30AC8CE399BB74BF43"),
    )
}

#[test]
fn test_ascon128_606() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC473A85C21F34A587C3B3B63DEBF580E4487"),
    )
}

#[test]
fn test_ascon128_607() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDE695868387BE01A1EA7ECABE67843676"),
    )
}

#[test]
fn test_ascon128_608() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39596B5BD4381CD78F40ABBD7FADF9C419"),
    )
}

#[test]
fn test_ascon128_609() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA1D3FCB0E2D4ED80A1DF5D9349C69BD7C6"),
    )
}

#[test]
fn test_ascon128_610() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE63B7C60537954C9BD8F4AFF0701BA78B"),
    )
}

#[test]
fn test_ascon128_611() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D03C271847A2A5BBF71EFCF84AB57CB1D"),
    )
}

#[test]
fn test_ascon128_612() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CF95944BD80DCE8D124F20C04207351DA5"),
    )
}

#[test]
fn test_ascon128_613() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF2F81515016BF469F19C5B7FB795F42566"),
    )
}

#[test]
fn test_ascon128_614() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7D76B6D8C8E9A31F974B9D60F2F069D31"),
    )
}

#[test]
fn test_ascon128_615() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEA3112FE09E093C702B56F5280CB73C6B"),
    )
}

#[test]
fn test_ascon128_616() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B3904EA1D5D497E00CA12D7B9B6D0B86D"),
    )
}

#[test]
fn test_ascon128_617() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E3531114C57B945AE1B8C8B25E499F7FF77F8E7B"),
    )
}

#[test]
fn test_ascon128_618() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B5489D20894A5F82035A3B587643D7FB285"),
    )
}

#[test]
fn test_ascon128_619() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E30D229194F8E8699AD9C127539267015"),
    )
}

#[test]
fn test_ascon128_620() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B40C0D1FDD9FC5EFDD092FD1E5331889E3"),
    )
}

#[test]
fn test_ascon128_621() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C37C8C3108673186DE37F8373ED0551394"),
    )
}

#[test]
fn test_ascon128_622() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FCA29DADBA4B5C8C20149581F4173261B3"),
    )
}

#[test]
fn test_ascon128_623() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90076E9343E5EA3ED67E7FF9C6A7B5644EF9"),
    )
}

#[test]
fn test_ascon128_624() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B30EA817D3F150AF2A9D710FCE7F55584"),
    )
}

#[test]
fn test_ascon128_625() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D0077D6AF4A4CF430EFDCEBF8E41872764B"),
    )
}

#[test]
fn test_ascon128_626() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE79D4FC6CDB0BC7AA84420C8F1341CBE00"),
    )
}

#[test]
fn test_ascon128_627() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD880B5A1D83C4F24F355A61AE1578E1E550"),
    )
}

#[test]
fn test_ascon128_628() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BAD76042A7E82EA5439B942A5EF1584D3B8E"),
    )
}

#[test]
fn test_ascon128_629() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5F1E66589392B2E9969352609A0A62C917F"),
    )
}

#[test]
fn test_ascon128_630() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A55650829E182B5573CDA45BA5A0CED54A99"),
    )
}

#[test]
fn test_ascon128_631() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926791F6B928D29D4B7E2E1E1F6A945F1B466D4"),
    )
}

#[test]
fn test_ascon128_632() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F066C578B3974A9F987818181ACA2E708C9"),
    )
}

#[test]
fn test_ascon128_633() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC17033DADC9AE39DAE3F35977F2D88898F30D3"),
    )
}

#[test]
fn test_ascon128_634() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B998B431D6513C278DB361CB8C1242E68180"),
    )
}

#[test]
fn test_ascon128_635() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140D312DB060FE4DC661688340B57DB2E14FF8"),
    )
}

#[test]
fn test_ascon128_636() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44BE15A1F8ED39E6FA8F684DCC1BE746B536"),
    )
}

#[test]
fn test_ascon128_637() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13B730D9F3331F776C4DECB87FCC5EB09EBD"),
    )
}

#[test]
fn test_ascon128_638() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B7A2CFD84B5C030740DC4F117DC37A1D9468"),
    )
}

#[test]
fn test_ascon128_639() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC47326D6628F171C865049B95ACB10094FB748"),
    )
}

#[test]
fn test_ascon128_640() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDB39A9AFE53D9F5A8ED207F6AA3DE38F9AA"),
    )
}

#[test]
fn test_ascon128_641() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39F6E954231275446EB3D63070ECAF431B0D"),
    )
}

#[test]
fn test_ascon128_642() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA12550A23EFFC860BA935FAF8AF3FB1E0A9B"),
    )
}

#[test]
fn test_ascon128_643() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE7A13A6BD607EE4CB834B36D96335EF8C03"),
    )
}

#[test]
fn test_ascon128_644() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D2309F41D31EB4E2DE7C519A735193FB63C"),
    )
}

#[test]
fn test_ascon128_645() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CFED58366EFA92B7E0AD2DBF91C21F4390B5"),
    )
}

#[test]
fn test_ascon128_646() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF28DC8385063628D8DA0684EE01713098545"),
    )
}

#[test]
fn test_ascon128_647() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7AE24CF768720AE6A9CE48D6B365E83E81A"),
    )
}

#[test]
fn test_ascon128_648() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEC529F8CFE269D320A4F234B34443D563BA"),
    )
}

#[test]
fn test_ascon128_649() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B5C811766A550593539CFD337C5AAAC6D5A"),
    )
}

#[test]
fn test_ascon128_650() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E35311140467EC0054430055D00E0CDE9521D09A61"),
    )
}

#[test]
fn test_ascon128_651() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B541F3E1481572A2BFFD7F364F4D724FD7A9E"),
    )
}

#[test]
fn test_ascon128_652() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E197D6CDD419BCA138D20DC715EDCAE5758"),
    )
}

#[test]
fn test_ascon128_653() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B4ABE31BE9A7A51853156DFDBA71A38993B2"),
    )
}

#[test]
fn test_ascon128_654() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C3853B9F472BA9BFBA037011C9A500DBC6A2"),
    )
}

#[test]
fn test_ascon128_655() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FC33288C2CDFC11E2F406AAD754CD1E2FC8A"),
    )
}

#[test]
fn test_ascon128_656() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90072CC05E3E73B580EDBF13044A72C2DA550D"),
    )
}

#[test]
fn test_ascon128_657() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B7EC2DF39DC68AD83868CBACB0F3B74DCFA"),
    )
}

#[test]
fn test_ascon128_658() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D00B9E74E3F8DCC2E2E37BF1E22ABE4D2DF19"),
    )
}

#[test]
fn test_ascon128_659() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE7741AFEAD7B1D8ADADF1D961DC31887D6D0"),
    )
}

#[test]
fn test_ascon128_660() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD88B8066BEF43C66F5E186A788FE1DA56810F"),
    )
}

#[test]
fn test_ascon128_661() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BAD7E1EB410DB6608A9387396A64D0B6FD88A6"),
    )
}

#[test]
fn test_ascon128_662() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5F1C2DC871BB26DC7575ED897042381ABE90F"),
    )
}

#[test]
fn test_ascon128_663() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A556D3ED93FBB666DF0DB63E2633487525C0FE"),
    )
}

#[test]
fn test_ascon128_664() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926791FD7FACE4487FEA998C8D88E8A5A70C8BF3D"),
    )
}

#[test]
fn test_ascon128_665() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F06EB8D35B16F784706DDA743676C02294C27"),
    )
}

#[test]
fn test_ascon128_666() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC1703338EBA14D6B95D20687D1585A6AC5B48509"),
    )
}

#[test]
fn test_ascon128_667() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B998207B14C9F2F446D0F71192AFFE70C98364"),
    )
}

#[test]
fn test_ascon128_668() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140D311F800FEA58531C94CBBF5B41626C91197E"),
    )
}

#[test]
fn test_ascon128_669() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF99F9B9F52CE178E112F53947F02D2ED2E"),
    )
}

#[test]
fn test_ascon128_670() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13B714938DFBF751165B44414486395A8F2A96"),
    )
}

#[test]
fn test_ascon128_671() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B7A253F504E5FBE1BCC508289F663E00EB2ED1"),
    )
}

#[test]
fn test_ascon128_672() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC473269A68963E1BFC5244F9A64497D69BCF61EA"),
    )
}

#[test]
fn test_ascon128_673() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDB36783BF33792EEBDB555653F1A0E5386106"),
    )
}

#[test]
fn test_ascon128_674() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39F6A46E068ED8479EBB94E4117D70C3FF558A"),
    )
}

#[test]
fn test_ascon128_675() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA125D4D25A21C1C52F102A4348D1EE7BE13F64"),
    )
}

#[test]
fn test_ascon128_676() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE7A35E0517DE679D7DAEBB250FE17BCEDA001"),
    )
}

#[test]
fn test_ascon128_677() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D23069628AF741BE40A933DE5D40395C687E5"),
    )
}

#[test]
fn test_ascon128_678() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CFEDCA3C671D399FBE05D9D28DF3E961CB3C2B"),
    )
}

#[test]
fn test_ascon128_679() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF28D939B604252A81A6325E2732DB9C88020DA"),
    )
}

#[test]
fn test_ascon128_680() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7AE66517CFC08FF1DAD724E80BD6E531F4929"),
    )
}

#[test]
fn test_ascon128_681() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEC54DF097509F683EAB735088E9F72D091489"),
    )
}

#[test]
fn test_ascon128_682() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B5CC0E3B0F7AB1A4B30E37AC791886750C5C4"),
    )
}

#[test]
fn test_ascon128_683() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E35311140403D638904947DF0A880016384E5E30AC83"),
    )
}

#[test]
fn test_ascon128_684() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B541FA7B7092858CE21D5DF3A6CEAB9C3070FC6"),
    )
}

#[test]
fn test_ascon128_685() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E196EE175660528C6B0079177FDEC8BAF1C1E"),
    )
}

#[test]
fn test_ascon128_686() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF105024B76299B1F8EDE03DFC9E6AF4FF3"),
    )
}

#[test]
fn test_ascon128_687() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C385F1B420A794A857C30FD0BF0BADDAE41D93"),
    )
}

#[test]
fn test_ascon128_688() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FC33E1A4D0BFFDEE1B2D355CCDCC8F338C064A"),
    )
}

#[test]
fn test_ascon128_689() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90072C740F8635B4DBF4D1934573C9C7661E7480"),
    )
}

#[test]
fn test_ascon128_690() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B7E0361660EAAFC3E361193F908545AE87196"),
    )
}

#[test]
fn test_ascon128_691() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D00B9AFD96F9C4525B106E95F4FBAEB00D5EB3D"),
    )
}

#[test]
fn test_ascon128_692() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE7744D76ED368CAE6A9B45C3276B7805712717"),
    )
}

#[test]
fn test_ascon128_693() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4427B136D2C172762AAACD306A569FD3F"),
    )
}

#[test]
fn test_ascon128_694() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BAD7E1637C3B51865920FB3F01F36CE63C8AD387"),
    )
}

#[test]
fn test_ascon128_695() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5F1C2255A402CE1981198154D1B1079C777067B"),
    )
}

#[test]
fn test_ascon128_696() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A556D34D8A767A9C904D517B0EA320B6526A40F5"),
    )
}

#[test]
fn test_ascon128_697() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926791FD749F00914C927167B8407247374C7804696"),
    )
}

#[test]
fn test_ascon128_698() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F06EBA8DCECF0F5A787C22CD604631AC4605721"),
    )
}

#[test]
fn test_ascon128_699() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC1703338B9F64CA097DB3709A6BD11D0C6285B023D"),
    )
}

#[test]
fn test_ascon128_700() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B998207A75F3FE9B2955DA60A3D488CBCD623B5B"),
    )
}

#[test]
fn test_ascon128_701() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140D311F19F37B2D7311FDFA5368EEA8D45D531B4F"),
    )
}

#[test]
fn test_ascon128_702() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE528F1FF9AA57E1E25695644B8F3120A6"),
    )
}

#[test]
fn test_ascon128_703() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13B7143020F5C954755C63E73ABA3E9BA5B6513A"),
    )
}

#[test]
fn test_ascon128_704() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A371B9BEF5C4D98ABFDFEFADD2503B96F"),
    )
}

#[test]
fn test_ascon128_705() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E141DB836F92F53414251FA32C0431D61"),
    )
}

#[test]
fn test_ascon128_706() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDB367E4F22888E43D09B7057CDF8DD62B539532"),
    )
}

#[test]
fn test_ascon128_707() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE40A399A5DF9BF10ECA510EAF3E56D47E"),
    )
}

#[test]
fn test_ascon128_708() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA125D4D1FAFCC4C197E011C0A969AB3C016B7445"),
    )
}

#[test]
fn test_ascon128_709() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE7A356F1F52C0F4C6DC83BC51D502344451D11B"),
    )
}

#[test]
fn test_ascon128_710() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D2306BED4CCEACCA3A5148A5C34D6D2D135AF11"),
    )
}

#[test]
fn test_ascon128_711() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CFEDCAAA645A3A63E10C34F8914B1E89C721389B"),
    )
}

#[test]
fn test_ascon128_712() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF28D935090BB06D2127B068B5DCBE0F1195B7615"),
    )
}

#[test]
fn test_ascon128_713() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7AE66B793B92B88581786C19CD234407B51359D"),
    )
}

#[test]
fn test_ascon128_714() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8B2847F1BD79D70F802068FC7E0593CEDB"),
    )
}

#[test]
fn test_ascon128_715() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B5CC07FD25BFC5AA9B9F3BD5C1FDB9FF261C5D5"),
    )
}

#[test]
fn test_ascon128_716() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E35311140403545C733D52B97665F3E62C2144FB016E4B"),
    )
}

#[test]
fn test_ascon128_717() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B541FA73E093A842817725C631F9E9E6F5BE22684"),
    )
}

#[test]
fn test_ascon128_718() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED31855EBCD46CB34D3910B9DC87D0DEA73"),
    )
}

#[test]
fn test_ascon128_719() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143256D7C294658694857EF8B6F18A10E63"),
    )
}

#[test]
fn test_ascon128_720() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C385F184478326E9F1AEAE51C3CA305B87C7E255"),
    )
}

#[test]
fn test_ascon128_721() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FC33E1A00C127A280F0D4F7C2A369090E68AD325"),
    )
}

#[test]
fn test_ascon128_722() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90072C743E0C5468A71BD0A700158D740234906F2C"),
    )
}

#[test]
fn test_ascon128_723() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB659C541BA7282DDBE249231EE73FEECD"),
    )
}

#[test]
fn test_ascon128_724() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59FED36BC074E552EBEE246D665A234483"),
    )
}

#[test]
fn test_ascon128_725() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE7744DD07E7FB401D9131A2695D23D3CD96BA591"),
    )
}

#[test]
fn test_ascon128_726() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D7EE52AFC8415C2D767A5BDC06FCCAA99C"),
    )
}

#[test]
fn test_ascon128_727() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DC6E54D095ECBCDB59DF8B4779CC28AFE0"),
    )
}

#[test]
fn test_ascon128_728() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5F1C225BF368B5C971C27A1E531ED15E26FA228A5"),
    )
}

#[test]
fn test_ascon128_729() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A556D34DE416BD153619E57621A7F55C856EA3EFC4"),
    )
}

#[test]
fn test_ascon128_730() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926791FD749259C4BC8D681AA8E06C6E2C0F2394B502A"),
    )
}

#[test]
fn test_ascon128_731() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35196BBE2DB2B9988217AF821BD50EF5"),
    )
}

#[test]
fn test_ascon128_732() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC1703338B98C36C3BC0ADD13225E014A9778772228A3"),
    )
}

#[test]
fn test_ascon128_733() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55A34DD6F028BA5A0799134D91F7F8BAA4"),
    )
}

#[test]
fn test_ascon128_734() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140D311F19C05C664B32273234D589E4E2BB094C77B9"),
    )
}

#[test]
fn test_ascon128_735() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7BB3FD3FD5E71A774C6894F4AA9D20A8BE"),
    )
}

#[test]
fn test_ascon128_736() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13B714309A184FF8E4EC3619D716F4D2C0FD374FAD"),
    )
}

#[test]
fn test_ascon128_737() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A357CD783A1945D02B44F6F2BE17EB4833D"),
    )
}

#[test]
fn test_ascon128_738() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FD2E4CB864BE3C3668C54DDCD6EF1A0B1"),
    )
}

#[test]
fn test_ascon128_739() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F449D8FAFD23D81CFB04BC80E7AC87F30"),
    )
}

#[test]
fn test_ascon128_740() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4EC54A634FD5C690D0A55DA54E89D0E8F9"),
    )
}

#[test]
fn test_ascon128_741() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E539AE8E2B99546CE7E0D4BB9CBD8A91FC"),
    )
}

#[test]
fn test_ascon128_742() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE7A356FFF03EA938CDAB114B57470851C77986666"),
    )
}

#[test]
fn test_ascon128_743() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D2306BE156BA606E90EEA62412AA3BFE35639234F"),
    )
}

#[test]
fn test_ascon128_744() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CFEDCAAA2252140B25B1111ADDE61BF9A8A63CD1A6"),
    )
}

#[test]
fn test_ascon128_745() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9A90B0B6183BA2E518126112D005440CE"),
    )
}

#[test]
fn test_ascon128_746() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7AE66B779CC861AEFA2BEC2167558845C75D69340"),
    )
}

#[test]
fn test_ascon128_747() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA3BA8223BF064CCB5E6F9DBBAEB951151"),
    )
}

#[test]
fn test_ascon128_748() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B5CC07FA6C1051D6B2C56B34BE2EA7874C3ECDC56"),
    )
}

#[test]
fn test_ascon128_749() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E353111404035451F7A9B3458FDE3C4E42FA2CF1D1BCA6B8"),
    )
}

#[test]
fn test_ascon128_750() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D47DC99B3F631ECB8E3A6160891B7CF90"),
    )
}

#[test]
fn test_ascon128_751() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384B12A4643C0113B978DB1EE21F3020F3C"),
    )
}

#[test]
fn test_ascon128_752() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DD9497FD9A2D52B61CAD3BFF32A3DC428A"),
    )
}

#[test]
fn test_ascon128_753() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C385F1840457F9387CF2EC2A000871A670292DF5EC"),
    )
}

#[test]
fn test_ascon128_754() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8AC6AF12AD62DB45D4CC9D29E67A56367"),
    )
}

#[test]
fn test_ascon128_755() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90072C743E4FC00EAE19115C6404EEF519AB689F4CCE"),
    )
}

#[test]
fn test_ascon128_756() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93FC6D58387955D80E44830908AC635414"),
    )
}

#[test]
fn test_ascon128_757() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D37CCFB9DC62CDD9E1DE7B35CC4518E892"),
    )
}

#[test]
fn test_ascon128_758() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE7744DD004F1EED0816EC94F283717DFF43E8179D5"),
    )
}

#[test]
fn test_ascon128_759() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E0DE21FF41C5FE116F1F5B2EBF202CAF7"),
    )
}

#[test]
fn test_ascon128_760() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC43D37BF733634D15FE76FACD13605CB8E"),
    )
}

#[test]
fn test_ascon128_761() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3AE3AC4472F25E74FCF65877F1C0B40D9D"),
    )
}

#[test]
fn test_ascon128_762() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CCE819F4692D8D7EBC79AD4FD673497E6A"),
    )
}

#[test]
fn test_ascon128_763() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926791FD74925F013D70AFC00B61DE6478F7E514466A1AB"),
    )
}

#[test]
fn test_ascon128_764() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD357FFE25AE1540062A50D5A35BD7FFD6AD"),
    )
}

#[test]
fn test_ascon128_765() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4E484D5A98B5F9561286C821B07A8C151"),
    )
}

#[test]
fn test_ascon128_766() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC46EE96F90CF6BCA7BC4604F16873F86D"),
    )
}

#[test]
fn test_ascon128_767() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140D311F19C059BD465B47858744894F0A48D2395CC33E"),
    )
}

#[test]
fn test_ascon128_768() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69F3A40596C7AD15BD9171E82F67D4A0F6"),
    )
}

#[test]
fn test_ascon128_769() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA917BD015B2FEBB876B8DC12C7A421779"),
    )
}

#[test]
fn test_ascon128_770() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A357200816AF9D65FF10149196A97621471FD"),
    )
}

#[test]
fn test_ascon128_771() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA7BB2CFA2F6D9FCEA68CE44C1256D08097"),
    )
}

#[test]
fn test_ascon128_772() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0B223B1CDF0FFEAE96E05F308B2FBFC97F"),
    )
}

#[test]
fn test_ascon128_773() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E43365B6E90147867FE50B2872E77BE95AD"),
    )
}

#[test]
fn test_ascon128_774() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F83292D524D664A0FC04FA8BE2CC6BCFA"),
    )
}

#[test]
fn test_ascon128_775() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE7A356FFF03AEE6806FA02008A5736199F6E8404238"),
    )
}

#[test]
fn test_ascon128_776() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D2306BE1573DB4BE1D5F4C7AB0C2532C807C080C756"),
    )
}

#[test]
fn test_ascon128_777() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7B21749273A178107A9020F00C2A14030"),
    )
}

#[test]
fn test_ascon128_778() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CA302A7A1DC2C8F7A07B845CF7485A8BAA"),
    )
}

#[test]
fn test_ascon128_779() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7AE66B779C1D3E920637DC7D304D2CCAD8C5BFAA973"),
    )
}

#[test]
fn test_ascon128_780() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10933F0837AB3D76D93DD435DA34D61900"),
    )
}

#[test]
fn test_ascon128_781() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7C96072286570056F5FF008717AB93497"),
    )
}

#[test]
fn test_ascon128_782() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E3531114040354519513CC80F0AAF5FD0F9C98FAABCFC93CE9"),
    )
}

#[test]
fn test_ascon128_783() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A9F158190A2470F912DD0D0FCD8B7664B"),
    )
}

#[test]
fn test_ascon128_784() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E70A60E87A982748DEE006E35C40F27E01"),
    )
}

#[test]
fn test_ascon128_785() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD9781455E019E8E757C5006A28EB364D64"),
    )
}

#[test]
fn test_ascon128_786() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C385F18404430F2DA7A4C292A930E7925C54B21B3779"),
    )
}

#[test]
fn test_ascon128_787() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5C1DDF5245DC462F44CCB7AEE1E14ED1"),
    )
}

#[test]
fn test_ascon128_788() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90072C743E4FE874D8F0EAE1C02A10E5EFCC2B796AC572"),
    )
}

#[test]
fn test_ascon128_789() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3470DE000F51AB291B3571CDB13E162D4"),
    )
}

#[test]
fn test_ascon128_790() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EF9A24C6095137DC2F5117E0EB7C6AB3FC"),
    )
}

#[test]
fn test_ascon128_791() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF13008BBDF90F0C4CB9CFAB2F902A9CF"),
    )
}

#[test]
fn test_ascon128_792() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50465FD50333149A24F1942FFA2FBD0909"),
    )
}

#[test]
fn test_ascon128_793() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC497C421CAD7E3A4DF2BE9EACCD8117C717A"),
    )
}

#[test]
fn test_ascon128_794() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D1C37FA000CF7F14D1292240519DA162A"),
    )
}

#[test]
fn test_ascon128_795() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC230774C0524B0D93519802603DFD1294C8"),
    )
}

#[test]
fn test_ascon128_796() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9E1D8D700203C201DC092524957D7253A"),
    )
}

#[test]
fn test_ascon128_797() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C7C3A13A4DFF475AE828D73D0EAE922441"),
    )
}

#[test]
fn test_ascon128_798() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B3644C77AC426E3C930EC8748FAC43E360"),
    )
}

#[test]
fn test_ascon128_799() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC995A3B40EF5CFFA2E66753FB1AE9940D69"),
    )
}

#[test]
fn test_ascon128_800() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FFB480724FD5977A225C9ED8ABC7E4710"),
    )
}

#[test]
fn test_ascon128_801() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C868BAB4D2BC58FECF3B186070234B6A38"),
    )
}

#[test]
fn test_ascon128_802() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44FF83CA90C0AF633654E6BF1466F4B3AD"),
    )
}

#[test]
fn test_ascon128_803() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E241C1D4AF53026F3C1F1E39055789F23"),
    )
}

#[test]
fn test_ascon128_804() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795DED3E085A303C110AD095C91C6D2E3A9"),
    )
}

#[test]
fn test_ascon128_805() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4511B5873E39E1EC8D3677BCE6CA1BD0A"),
    )
}

#[test]
fn test_ascon128_806() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436E2CDF9C41BA76C2DA79780E3C728A1CC0"),
    )
}

#[test]
fn test_ascon128_807() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75F2F4D7AA062DADA76E065C8324FB909C"),
    )
}

#[test]
fn test_ascon128_808() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C420436A4179A327AD848A729F2201E3D"),
    )
}

#[test]
fn test_ascon128_809() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6BD4B3D1465019DC6EF9BEA0FEDD640B4"),
    )
}

#[test]
fn test_ascon128_810() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA0C3523DA5B9FFC3E6CC8DC3D4FD36367"),
    )
}

#[test]
fn test_ascon128_811() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9DAFBE59DA765099A78EB0BFBB934C51B"),
    )
}

#[test]
fn test_ascon128_812() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7AE66B779C14DF81A0085840580FE2FBCA0AF5002907A"),
    )
}

#[test]
fn test_ascon128_813() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8363B3B123E5CE1916C194243E70D41BD"),
    )
}

#[test]
fn test_ascon128_814() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7491C9EC0EDEF3F0873E9365C84F1316107"),
    )
}

#[test]
fn test_ascon128_815() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E35311140403545195428D6217730F6DBA712A153ADF7C563BD2"),
    )
}

#[test]
fn test_ascon128_816() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A6F96EEE1C5AE4DFBE81154CF9CEED5AA"),
    )
}

#[test]
fn test_ascon128_817() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DD2B386F44B2BEBDD5831EAAECADF9E41E"),
    )
}

#[test]
fn test_ascon128_818() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92D56C0B24679ADB36B174F78F624C60C48"),
    )
}

#[test]
fn test_ascon128_819() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DFB4D6E7CC26F65FCA9EFF8DCB34D2B76"),
    )
}

#[test]
fn test_ascon128_820() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5FB78C6872C53021857E4298A48AFF37DD"),
    )
}

#[test]
fn test_ascon128_821() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C2C63783AACB33B9B8822B633AB996C42D"),
    )
}

#[test]
fn test_ascon128_822() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC5A31966531B2FBAC82CCE165CAE57077"),
    )
}

#[test]
fn test_ascon128_823() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCCD8878D87010E49267C8F6C8D3E691785"),
    )
}

#[test]
fn test_ascon128_824() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF048282B68E02F547F7C35483EBFBC73B3"),
    )
}

#[test]
fn test_ascon128_825() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622408C3012880E1A58D9FA4F3D615552F"),
    )
}

#[test]
fn test_ascon128_826() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(""),
        &hex!("E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970FEE464255B60E9CC0E29009675FDFC0A7"),
    )
}

#[test]
fn test_ascon128_827() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00"),
        &hex!("25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C190891EC8318193A373229C2546BBA9D"),
    )
}

#[test]
fn test_ascon128_828() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("0001"),
        &hex!("49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F35C92DBE4380DEC34E332D81B38876F53"),
    )
}

#[test]
fn test_ascon128_829() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102"),
        &hex!("D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9450575789E98D824EA496A80F58C9EF7D7"),
    )
}

#[test]
fn test_ascon128_830() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00010203"),
        &hex!("4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C768D4D24DA4A38BB07C2558F5D0385E55E7"),
    )
}

#[test]
fn test_ascon128_831() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("0001020304"),
        &hex!("1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B2B4250A85106D4C0FCCD668BB068B429"),
    )
}

#[test]
fn test_ascon128_832() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405"),
        &hex!("7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A9ECB0B9F69E994A6DA9E6E154BE1DC15"),
    )
}

#[test]
fn test_ascon128_833() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00010203040506"),
        &hex!("44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB06EFDA11A466E170BEC185E15D44D4095"),
    )
}

#[test]
fn test_ascon128_834() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("0001020304050607"),
        &hex!("108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85AF3B96E2806F85EF467964E61C33799A3"),
    )
}

#[test]
fn test_ascon128_835() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708"),
        &hex!("6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD471C4E15858085DE8B0170FA94A451D1"),
    )
}

#[test]
fn test_ascon128_836() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("00010203040506070809"),
        &hex!("F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E570E884CA46E06A8F920851044A4E1A176"),
    )
}

#[test]
fn test_ascon128_837() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A"),
        &hex!("29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B0FF8BBE180F887AC099F83A91FDE022C3"),
    )
}

#[test]
fn test_ascon128_838() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B"),
        &hex!("BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4ACF682BF9828617E0DC846D3C961CDF6A2"),
    )
}

#[test]
fn test_ascon128_839() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C"),
        &hex!("4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EABC40AA73DACAA54FE7C0E669DA40D2F16"),
    )
}

#[test]
fn test_ascon128_840() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!("4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD18248AAFAE15970F226DB09EE7E91CBF"),
    )
}

#[test]
fn test_ascon128_841() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!("B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9EE7DFB458B1E697D8F05FB493E88E8585"),
    )
}

#[test]
fn test_ascon128_842() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E382A72A447DDA92CA81C4915AA9F5CCA1"),
    )
}

#[test]
fn test_ascon128_843() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!("9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA812C547DA33141797A957581D17D6838DC"),
    )
}

#[test]
fn test_ascon128_844() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!("501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B219F385E889843E9F713697C8B8661892"),
    )
}

#[test]
fn test_ascon128_845() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!("64AC72120E66A202433C618208B281F929D7AE66B779C14D18FF31FCF531CF6D0807819E73005B4954"),
    )
}

#[test]
fn test_ascon128_846() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!("C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA3E92F97A10A6F24AB2776F0EBFD299B4"),
    )
}

#[test]
fn test_ascon128_847() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!("994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492BBCA07C2D3DDFBC4D17F59B6EDFD66214"),
    )
}

#[test]
fn test_ascon128_848() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!("368D61A8D488E8FB0F9F57D79350E353111404035451954226EA27EF2E6EDE634FCC87A482AC9FB661"),
    )
}

#[test]
fn test_ascon128_849() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!("C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62E967A0D31DA54CD7CEC94635182C2CD5"),
    )
}

#[test]
fn test_ascon128_850() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!("BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEBDC85A7823C106488B253F11ADC6C0960"),
    )
}

#[test]
fn test_ascon128_851() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF82C7B4AF6883D72572FC8C04A794A2B0D"),
    )
}

#[test]
fn test_ascon128_852() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE4591B3FC911902805A8F1B449703CAC0C"),
    )
}

#[test]
fn test_ascon128_853() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F13BA0902646A17E74A4FB3167A72237DD3"),
    )
}

#[test]
fn test_ascon128_854() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A9F1A13413E966429A5415CD5978D124F"),
    )
}

#[test]
fn test_ascon128_855() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC227883A81C03223A4D809F03ECC6F2B5FA"),
    )
}

#[test]
fn test_ascon128_856() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D52FD0F6DA838CABEBFFA00ED6E1DAE16"),
    )
}

#[test]
fn test_ascon128_857() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B0CDD133CEBACB318749343241B73005D"),
    )
}

#[test]
fn test_ascon128_858() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622DDEF004D51115487FA8D2A8813EA18657"),
    )
}

#[test]
fn test_ascon128_859() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(""),
        &hex!(
            "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F786005D5FF17BCE157263989199E84DC15"
        ),
    )
}

#[test]
fn test_ascon128_860() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00"),
        &hex!(
            "25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C73CE46F92D48534DD5CA3D1E19C64B7140"
        ),
    )
}

#[test]
fn test_ascon128_861() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("0001"),
        &hex!(
            "49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F3C29022F78F0DA130522C3098E2255E5649"
        ),
    )
}

#[test]
fn test_ascon128_862() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102"),
        &hex!(
            "D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9459C1E7E94EC141145D78D952428C9A06D19"
        ),
    )
}

#[test]
fn test_ascon128_863() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00010203"),
        &hex!(
            "4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C76806DF75F1A321E30CECF7E2FCD30F9D0924"
        ),
    )
}

#[test]
fn test_ascon128_864() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("0001020304"),
        &hex!(
            "1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B5AD170303C8FA30A9669BB249ACA5AA4EB"
        ),
    )
}

#[test]
fn test_ascon128_865() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405"),
        &hex!(
            "7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A71DEB3C0D8C9B357A0D5ADD56B2BE93854"
        ),
    )
}

#[test]
fn test_ascon128_866() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00010203040506"),
        &hex!(
            "44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB031D093181BB3818DDED8BC78E7A59B05ED"
        ),
    )
}

#[test]
fn test_ascon128_867() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("0001020304050607"),
        &hex!(
            "108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85A958FC051CE45717655F0D929CF7641E1BB"
        ),
    )
}

#[test]
fn test_ascon128_868() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708"),
        &hex!(
            "6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD906F890C0EFBBE835D48D2D61F540EBB3F"
        ),
    )
}

#[test]
fn test_ascon128_869() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("00010203040506070809"),
        &hex!(
            "F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E5754EEB221110C19D7865832E0DCEDD6DD7B"
        ),
    )
}

#[test]
fn test_ascon128_870() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A"),
        &hex!(
            "29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B067EA1AE225C0C142812AA3382FF6ABE64E"
        ),
    )
}

#[test]
fn test_ascon128_871() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4AC9F3C36A75E4693628AA6B530B7BF999C0C"
        ),
    )
}

#[test]
fn test_ascon128_872() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EAB592D19CE76A99F60E2143A1F470A9FE0A4"
        ),
    )
}

#[test]
fn test_ascon128_873() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD9BB80BE753B0D6F9C548891496A48DC3AB"
        ),
    )
}

#[test]
fn test_ascon128_874() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9E948B096FCA2C76332BB3EAB79C39758D13"
        ),
    )
}

#[test]
fn test_ascon128_875() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E3EC0200D93E1F7F68AC44870330A47828F1"
        ),
    )
}

#[test]
fn test_ascon128_876() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA8104F4A441EF3B0BADFA31BB1946A6755FB9"
        ),
    )
}

#[test]
fn test_ascon128_877() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B2B73CFEF4CFACAA6499487404BF232D449A"
        ),
    )
}

#[test]
fn test_ascon128_878() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "64AC72120E66A202433C618208B281F929D7AE66B779C14D18DDD3FC89A696B86B569537969056AFEC73"
        ),
    )
}

#[test]
fn test_ascon128_879() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA91960C5F2359839920BDB1AB46D615418B"
        ),
    )
}

#[test]
fn test_ascon128_880() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492B55D01FAA6EDF34944AF393396AABA744A4"
        ),
    )
}

#[test]
fn test_ascon128_881() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "368D61A8D488E8FB0F9F57D79350E353111404035451954226DDEB75CA0F57DAC7F74603A0D4B0D7BF2D"
        ),
    )
}

#[test]
fn test_ascon128_882() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62DA067FF116A44684402C709E102E504389"
        ),
    )
}

#[test]
fn test_ascon128_883() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEB24BFAA34FC345FA13B71B5D7C68669066C"
        ),
    )
}

#[test]
fn test_ascon128_884() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF81E5F57FE4173AD4966C29CFB3686157228"
        ),
    )
}

#[test]
fn test_ascon128_885() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE417E79D7B256D52BE5AFB7CB4EFC9DE14A1"
        ),
    )
}

#[test]
fn test_ascon128_886() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F13349A85F26FC9AF40E66CABE820045F6EDB"
        ),
    )
}

#[test]
fn test_ascon128_887() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A85B629F622A3EDB42E5B8CB7D49A379306"
        ),
    )
}

#[test]
fn test_ascon128_888() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC223FF7F44A6ADD47D6C3C2074136AD7CA3ED"
        ),
    )
}

#[test]
fn test_ascon128_889() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D347F9C6392F2F0B7D9C6C6AB44D5094085"
        ),
    )
}

#[test]
fn test_ascon128_890() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B6C643855105B0BA973BD4AEC3BC0ECDE1F"
        ),
    )
}

#[test]
fn test_ascon128_891() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622D789BFE76CE0A2130453F7A05B0B5364BD6"
        ),
    )
}

#[test]
fn test_ascon128_892() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(""),
        &hex!(
            "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F78734DDB9CE0523B99779E4497AD5964E6C5"
        ),
    )
}

#[test]
fn test_ascon128_893() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("00"),
        &hex!(
            "25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C7379935C053F229C92D664368876B2011791"
        ),
    )
}

#[test]
fn test_ascon128_894() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("0001"),
        &hex!(
            "49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F3C21CEB9882BB795889D4AEE31E9EA04405FB"
        ),
    )
}

#[test]
fn test_ascon128_895() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102"),
        &hex!(
            "D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9459CFA79715549452A9F918CAE4D52ACBA51C6"
        ),
    )
}

#[test]
fn test_ascon128_896() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("00010203"),
        &hex!(
            "4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C768069356836DE14D328579C63AD95BA95DF96A"
        ),
    )
}

#[test]
fn test_ascon128_897() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("0001020304"),
        &hex!(
            "1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B5AF98A2B0B5271981599FF69C203245B6C50"
        ),
    )
}

#[test]
fn test_ascon128_898() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405"),
        &hex!(
            "7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A717F732BFC622DD69894029AEBF2C35DB916"
        ),
    )
}

#[test]
fn test_ascon128_899() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("00010203040506"),
        &hex!(
            "44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB031CB29DC6847FC70FD80EC17C8AA8C5BAF6C"
        ),
    )
}

#[test]
fn test_ascon128_900() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("0001020304050607"),
        &hex!(
            "108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85A95787A5A9FF1968324C0702913253B832393"
        ),
    )
}

#[test]
fn test_ascon128_901() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708"),
        &hex!(
            "6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD909FFE14A59BBF3F300E9FB78D441FB13F3D"
        ),
    )
}

#[test]
fn test_ascon128_902() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("00010203040506070809"),
        &hex!(
            "F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E57540B37FB439E9C5CB4CEA08F3A47D71A96C2"
        ),
    )
}

#[test]
fn test_ascon128_903() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A"),
        &hex!(
            "29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B0677008D6DC5CE5E8761AF221E745C627C657"
        ),
    )
}

#[test]
fn test_ascon128_904() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4AC9F9FA167C566FA70846600FAA8457823EDE0"
        ),
    )
}

#[test]
fn test_ascon128_905() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EAB5920017C8BE261B3527DAAD2E162D1DB1120"
        ),
    )
}

#[test]
fn test_ascon128_906() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD9BDEBCFB6DB67C43EA35032BC886EFD1647D"
        ),
    )
}

#[test]
fn test_ascon128_907() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9E94013EE1C1217DAA7B9B24CE353B970257C4"
        ),
    )
}

#[test]
fn test_ascon128_908() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E3ECFE0225B1C8C72F7BE7EDA082DB418C4FD1"
        ),
    )
}

#[test]
fn test_ascon128_909() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA81042CF85A9C35E464D5129663C60B2D8B2928"
        ),
    )
}

#[test]
fn test_ascon128_910() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B2B7769C9B3CA234D5AD37A7FF0D0E51396A86"
        ),
    )
}

#[test]
fn test_ascon128_911() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "64AC72120E66A202433C618208B281F929D7AE66B779C14D18DDBFA32274938424DD5547FD8247960A8BB7"
        ),
    )
}

#[test]
fn test_ascon128_912() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA913DE17A3D510380A8280002CCE30C18B375"
        ),
    )
}

#[test]
fn test_ascon128_913() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492B55C67854A378E62C2E1D7860330C9338C437"
        ),
    )
}

#[test]
fn test_ascon128_914() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "368D61A8D488E8FB0F9F57D79350E353111404035451954226DDA2E7FEF6411D78766708AF9E771FA9926B"
        ),
    )
}

#[test]
fn test_ascon128_915() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62DACFA5550C592C73E531D84F1B4B1198EC58"
        ),
    )
}

#[test]
fn test_ascon128_916() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEB247AE6F7EAC22E33990B1F339CD292F02122"
        ),
    )
}

#[test]
fn test_ascon128_917() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF81E5DE52943526766B92E9EDB0E7BF8B30B67"
        ),
    )
}

#[test]
fn test_ascon128_918() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE41790D7E9874DF9F1E50C3ACF75B27C40E760"
        ),
    )
}

#[test]
fn test_ascon128_919() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F1334D8425B8D00EF29C46500F749304729E591"
        ),
    )
}

#[test]
fn test_ascon128_920() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A85A2164E68ED7A1BD67999EB77E5FF73424A"
        ),
    )
}

#[test]
fn test_ascon128_921() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC223FF6C6849E90348530D6AE2A625971B3950A"
        ),
    )
}

#[test]
fn test_ascon128_922() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D344E47832ADEBCB69AFDE570DF1D2C186425"
        ),
    )
}

#[test]
fn test_ascon128_923() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B6CED2D32A4013CED6406F39489C10DDC7CF9"
        ),
    )
}

#[test]
fn test_ascon128_924() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622D788334FB2AD867472BD640796447077D4998"
        ),
    )
}

#[test]
fn test_ascon128_925() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(""),
        &hex!(
            "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F7873615B1BF7E07D0DFD0303366291F0C13421"
        ),
    )
}

#[test]
fn test_ascon128_926() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("00"),
        &hex!(
            "25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C7379FAAAC5D1351FAE1727CE0BA9CC4B82092D"
        ),
    )
}

#[test]
fn test_ascon128_927() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("0001"),
        &hex!(
            "49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F3C21CDBBE1F3D9C6D9E2AC0B43A92029D91A2BE"
        ),
    )
}

#[test]
fn test_ascon128_928() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102"),
        &hex!(
            "D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9459CFA792C3849B85749785E8A1B29242FBA2A88"
        ),
    )
}

#[test]
fn test_ascon128_929() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("00010203"),
        &hex!(
            "4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C768069349410982EE12CC87BE081648520EECFB66"
        ),
    )
}

#[test]
fn test_ascon128_930() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("0001020304"),
        &hex!(
            "1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B5AF9CE9CC04B87820146D6D4A86A6DBDECB2E3"
        ),
    )
}

#[test]
fn test_ascon128_931() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405"),
        &hex!(
            "7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A717FF8DFF86953AB81BC6CB91BDD12C652C71A"
        ),
    )
}

#[test]
fn test_ascon128_932() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("00010203040506"),
        &hex!(
            "44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB031CB9C901226DC60B5DC8993FA2227331DC5DB"
        ),
    )
}

#[test]
fn test_ascon128_933() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("0001020304050607"),
        &hex!(
            "108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85A9578C707599F7664AD6F3C871A49B6EF2FC0DD"
        ),
    )
}

#[test]
fn test_ascon128_934() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708"),
        &hex!(
            "6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD909F3207CE2218F0CE99E5878061A010A8EEC9"
        ),
    )
}

#[test]
fn test_ascon128_935() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("00010203040506070809"),
        &hex!(
            "F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E57540B5D7BE52443B10F3200DBBC17CC81465BEF"
        ),
    )
}

#[test]
fn test_ascon128_936() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A"),
        &hex!(
            "29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B067700C3273091B5764C4AB027956C000B33C6B"
        ),
    )
}

#[test]
fn test_ascon128_937() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4AC9F9F77F1A8000686EB011F1AEBB6926BE3E822"
        ),
    )
}

#[test]
fn test_ascon128_938() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EAB5920DB50E17E7552090E4C904AA7FEF1BAD896"
        ),
    )
}

#[test]
fn test_ascon128_939() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD9BDE4B735B92725281AA24D69DDBA2FCEC9F44"
        ),
    )
}

#[test]
fn test_ascon128_940() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9E9401932DA440B79B125551BC821418D1BE4A25"
        ),
    )
}

#[test]
fn test_ascon128_941() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E3ECFE0D046BF0FBFFB62C298F093881764EF462"
        ),
    )
}

#[test]
fn test_ascon128_942() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA81042C2D570AD452403CB99E83788E79C676E7E1"
        ),
    )
}

#[test]
fn test_ascon128_943() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B2B7762C62FC5E4A3679CCC3C44C0D0407BEC3EC"
        ),
    )
}

#[test]
fn test_ascon128_944() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "64AC72120E66A202433C618208B281F929D7AE66B779C14D18DDBFA2FDC44D03A640D612E3C5D2589B81A12A"
        ),
    )
}

#[test]
fn test_ascon128_945() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA913D4A8FAD0BA3F4809D1621E8CB88F5664BAF"
        ),
    )
}

#[test]
fn test_ascon128_946() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492B55C6602560193EAF9FFA99FE9CA775F813F1A9"
        ),
    )
}

#[test]
fn test_ascon128_947() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "368D61A8D488E8FB0F9F57D79350E353111404035451954226DDA2C9F65B20E8A4C237EB98CBBA80B96E7C67"
        ),
    )
}

#[test]
fn test_ascon128_948() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62DACFA022033F750B5C5C2B04423F4AFD526723"
        ),
    )
}

#[test]
fn test_ascon128_949() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEB247A7285C58D114687832855FADD754794347D"
        ),
    )
}

#[test]
fn test_ascon128_950() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF81E5D8CBC22B0233BF9527E78D9A38F022253A5"
        ),
    )
}

#[test]
fn test_ascon128_951() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE417905F7CEE504FE9065E580BC3D89BDB6B4EC1"
        ),
    )
}

#[test]
fn test_ascon128_952() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F1334D88DD8344D168CA1EE1955E71DF515158CC2"
        ),
    )
}

#[test]
fn test_ascon128_953() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A85A28D17DB899AFA425A5F24C8731CDA6C17F0"
        ),
    )
}

#[test]
fn test_ascon128_954() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC223FF6FD3892ABE1218D8566FFF6C56969FBD34B"
        ),
    )
}

#[test]
fn test_ascon128_955() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D344E6A233F14FA3CEBE88FBC844075D5EF10E1"
        ),
    )
}

#[test]
fn test_ascon128_956() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B6CED0ED22951AF4016B148D6CACDFA78303BEC"
        ),
    )
}

#[test]
fn test_ascon128_957() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622D7883455AAF5E8ADE16FBB36FD476A76B5F5988"
        ),
    )
}

#[test]
fn test_ascon128_958() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(""),
        &hex!(
            "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F7873610D634EBDD09456E5DC2ED6CD5A5FF86793"
        ),
    )
}

#[test]
fn test_ascon128_959() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("00"),
        &hex!(
            "25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C7379FA53C0F55E525E1023B8E6E9513B4EE51E68"
        ),
    )
}

#[test]
fn test_ascon128_960() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("0001"),
        &hex!(
            "49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F3C21CDB6DFE71F0328D900C490648E46AAC9D4082"
        ),
    )
}

#[test]
fn test_ascon128_961() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102"),
        &hex!(
            "D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9459CFA7940D7E3F79349BDB969183E1A48EDC72F52"
        ),
    )
}

#[test]
fn test_ascon128_962() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("00010203"),
        &hex!(
            "4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C7680693493074BEA0E944FC217A77F54877728BF91F"
        ),
    )
}

#[test]
fn test_ascon128_963() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("0001020304"),
        &hex!(
            "1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B5AF9CE4690D0E25CA0307C11D11193E9B6A2D1EC"
        ),
    )
}

#[test]
fn test_ascon128_964() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405"),
        &hex!(
            "7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A717FF870CFCD6A10B058644D4E1280909098E44B"
        ),
    )
}

#[test]
fn test_ascon128_965() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("00010203040506"),
        &hex!(
            "44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB031CB9C2D69B0131D48D0DC05B096642FFE827F45"
        ),
    )
}

#[test]
fn test_ascon128_966() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("0001020304050607"),
        &hex!(
            "108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85A9578C77024FCD71415E9DE2E21FB1655F0BC3039"
        ),
    )
}

#[test]
fn test_ascon128_967() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708"),
        &hex!(
            "6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD909F327B6BD5F25F7E7E04A778494BD666ECC9A4"
        ),
    )
}

#[test]
fn test_ascon128_968() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("00010203040506070809"),
        &hex!(
            "F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E57540B5D9B352103AC233F21002072E0A7DC3E4739"
        ),
    )
}

#[test]
fn test_ascon128_969() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A"),
        &hex!(
            "29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B067700C51F0B3353B31AE123D0B649F6349C37124"
        ),
    )
}

#[test]
fn test_ascon128_970() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4AC9F9F771E0BB4D73C507DF3596E6C654BA6D31CCF"
        ),
    )
}

#[test]
fn test_ascon128_971() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EAB5920DB12870C2B41369AAB1C7D2E78B09C7D74A7"
        ),
    )
}

#[test]
fn test_ascon128_972() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD9BDE4BDAC028AD0195B3CB95E3EA9D256901F249"
        ),
    )
}

#[test]
fn test_ascon128_973() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9E940193629BB55AA5F905DC5DC35CAC1391580489"
        ),
    )
}

#[test]
fn test_ascon128_974() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E3ECFE0DF8D707751412AB9F5819AAE3FBBD6AB682"
        ),
    )
}

#[test]
fn test_ascon128_975() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA81042C2D4E2E663D6EAC31A5377FFF65B3F5D8BCAF"
        ),
    )
}

#[test]
fn test_ascon128_976() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B2B7762C6D187730437F6996206799A7ED5E2298B4"
        ),
    )
}

#[test]
fn test_ascon128_977() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "64AC72120E66A202433C618208B281F929D7AE66B779C14D18DDBFA2EFE717C6C901C73EE6A3FC6ABB0B74A375"
        ),
    )
}

#[test]
fn test_ascon128_978() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA913D4A943587C6DBB56716BC8F09C50B118C6C45"
        ),
    )
}

#[test]
fn test_ascon128_979() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492B55C6607DD458067A071F27E94CDFD080478E5351"
        ),
    )
}

#[test]
fn test_ascon128_980() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "368D61A8D488E8FB0F9F57D79350E353111404035451954226DDA2C9F9671748BAAE80280A25E9935CC6EB9A92"
        ),
    )
}

#[test]
fn test_ascon128_981() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62DACFA0F73A8234C5B06CD0A47F2DEBA68F290558"
        ),
    )
}

#[test]
fn test_ascon128_982() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEB247A728E287F016B12CB4E4320E4C93A1BEF2161"
        ),
    )
}

#[test]
fn test_ascon128_983() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF81E5D8CD3EAF8436A80449E750590176EA1C70C04"
        ),
    )
}

#[test]
fn test_ascon128_984() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE417905FA64AC13E572557AAFE3B9C869FE347C1F3"
        ),
    )
}

#[test]
fn test_ascon128_985() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F1334D88D73AA18D10D1504CB9F41260505FBF70BD4"
        ),
    )
}

#[test]
fn test_ascon128_986() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A85A28D43A846FEABE6F85FE9A0D1DBA6E18C5166"
        ),
    )
}

#[test]
fn test_ascon128_987() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC223FF6FD6E6803AE420D1A57792899CF43ED6C3823"
        ),
    )
}

#[test]
fn test_ascon128_988() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D344E6AE82601F4B891685C1D025C914994E43338"
        ),
    )
}

#[test]
fn test_ascon128_989() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B6CED0E4FC0B4604271FEF50FA50611B77254BAEB"
        ),
    )
}

#[test]
fn test_ascon128_990() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622D788345FAF0DDEF49C8963D18488CA6F992383336"
        ),
    )
}

#[test]
fn test_ascon128_991() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(""),
        &hex!(
            "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F7873610DEB7075EFBF71C194850DE9DA2A50236A60"
        ),
    )
}

#[test]
fn test_ascon128_992() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("00"),
        &hex!(
            "25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C7379FA53BA874D9E05ECA3464427A2896943063027"
        ),
    )
}

#[test]
fn test_ascon128_993() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0001"),
        &hex!(
            "49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F3C21CDB6D4458468F2AC3D82ADB2D25AA5B2F56CDBA"
        ),
    )
}

#[test]
fn test_ascon128_994() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102"),
        &hex!(
            "D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9459CFA7940BD5A8E37679BB8ED3219BF985CFD74C278"
        ),
    )
}

#[test]
fn test_ascon128_995() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("00010203"),
        &hex!(
            "4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C76806934930918654B7DA2A75AF4090204A5EDABB559B"
        ),
    )
}

#[test]
fn test_ascon128_996() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0001020304"),
        &hex!(
            "1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B5AF9CE4612B77C2C4550E87B333BBB434C3AD78012"
        ),
    )
}

#[test]
fn test_ascon128_997() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405"),
        &hex!(
            "7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A717FF8702FF4097F81119F1E4932A06A72C5474F89"
        ),
    )
}

#[test]
fn test_ascon128_998() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("00010203040506"),
        &hex!(
            "44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB031CB9C2DBE006DA16A75677F9A181AF9CEBBB0ACC2"
        ),
    )
}

#[test]
fn test_ascon128_999() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("0001020304050607"),
        &hex!(
            "108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85A9578C7705A3C8F60FBA293114A22E92E16B10EA2FC"
        ),
    )
}

#[test]
fn test_ascon128_1000() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708"),
        &hex!(
            "6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD909F327B30500E02A8E8089A98BF778113746075D5"
        ),
    )
}

#[test]
fn test_ascon128_1001() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("00010203040506070809"),
        &hex!(
            "F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E57540B5D9BBA277A5993BFE34637D241A9374EAD046C"
        ),
    )
}

#[test]
fn test_ascon128_1002() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A"),
        &hex!(
            "29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B067700C518D010539B10558995926316D58ABF2DC29"
        ),
    )
}

#[test]
fn test_ascon128_1003() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4AC9F9F771E2CD2CD2586CE37BCE0BF9054EA011366C6"
        ),
    )
}

#[test]
fn test_ascon128_1004() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EAB5920DB12B419D6921FD73CF05E06A2339A2F5CB138"
        ),
    )
}

#[test]
fn test_ascon128_1005() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD9BDE4BDA18344AF6C7AA31C4FE4EABD7BBFABABFC9"
        ),
    )
}

#[test]
fn test_ascon128_1006() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9E94019362C555926E326980EAF271CBE6C2432D1077"
        ),
    )
}

#[test]
fn test_ascon128_1007() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E3ECFE0DF819C47B6A78FAD2BE485D4D523E3ADA1EAE"
        ),
    )
}

#[test]
fn test_ascon128_1008() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA81042C2D4E30120A1ACC6753BE432F717776533AFB02"
        ),
    )
}

#[test]
fn test_ascon128_1009() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B2B7762C6DA840C162E0F19111066B112B0734AF5B19"
        ),
    )
}

#[test]
fn test_ascon128_1010() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "64AC72120E66A202433C618208B281F929D7AE66B779C14D18DDBFA2EF50AA94E47E5D6F9F0924E384BD76ADF883"
        ),
    )
}

#[test]
fn test_ascon128_1011() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA913D4A94AD6BE35E586291754D0A06D917ED2166A3"
        ),
    )
}

#[test]
fn test_ascon128_1012() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492B55C6607D5216E01C84A49097436451869E44C124A2"
        ),
    )
}

#[test]
fn test_ascon128_1013() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "368D61A8D488E8FB0F9F57D79350E353111404035451954226DDA2C9F9B632B26220FB0BC970DA69B1AE523C02F7"
        ),
    )
}

#[test]
fn test_ascon128_1014() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62DACFA0F769AE8CA4EEAA704D6127F4D78F91A31E8F"
        ),
    )
}

#[test]
fn test_ascon128_1015() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEB247A728ED9C04DF7AD6634225D49480D085585D969"
        ),
    )
}

#[test]
fn test_ascon128_1016() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF81E5D8CD31395024DCB4FD3ED5F6C9886B4E85FDEAE"
        ),
    )
}

#[test]
fn test_ascon128_1017() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE417905FA6B5D8CFF8C9C321E2A1379EF317E589DA16"
        ),
    )
}

#[test]
fn test_ascon128_1018() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F1334D88D73E274F44792336787A210718DC48899155C"
        ),
    )
}

#[test]
fn test_ascon128_1019() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A85A28D43F772A794F27D5ACC2063B77FBD6D79BE5B"
        ),
    )
}

#[test]
fn test_ascon128_1020() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC223FF6FD6EBA220D6AF228B692AE090DD47A2F95F3E8"
        ),
    )
}

#[test]
fn test_ascon128_1021() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D344E6AE8D86066282C5512C7D7F7BF835ABACBD337"
        ),
    )
}

#[test]
fn test_ascon128_1022() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B6CED0E4F256DADE434F55ADB4DABA13ACA40B781D2"
        ),
    )
}

#[test]
fn test_ascon128_1023() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622D788345FA7B202C9DB99A6CD7AAB352BFC0E9FA180A"
        ),
    )
}

#[test]
fn test_ascon128_1024() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(""),
        &hex!(
            "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F7873610DEBBED2E8B3025BB7767D5A9B992787BFA711"
        ),
    )
}

#[test]
fn test_ascon128_1025() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("00"),
        &hex!(
            "25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C7379FA53BAD5D7AC8DDFCDB071577ABBC85A3F3EBDF3"
        ),
    )
}

#[test]
fn test_ascon128_1026() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("0001"),
        &hex!(
            "49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F3C21CDB6D447C7A7A81140204835F9B0F5FCFD8C063A7"
        ),
    )
}

#[test]
fn test_ascon128_1027() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102"),
        &hex!(
            "D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9459CFA7940BD1BD3321ADE3CD62DA279301477D96BD55D"
        ),
    )
}

#[test]
fn test_ascon128_1028() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("00010203"),
        &hex!(
            "4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C7680693493091067F98DDB903C5D684F30F3CD4BDC114FD"
        ),
    )
}

#[test]
fn test_ascon128_1029() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("0001020304"),
        &hex!(
            "1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B5AF9CE461202D4668B6D9E0B5AFEE5400BCA3E605B19"
        ),
    )
}

#[test]
fn test_ascon128_1030() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405"),
        &hex!(
            "7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A717FF8702F10256B0DC55184F0EACB8E8809CAE80E6D"
        ),
    )
}

#[test]
fn test_ascon128_1031() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("00010203040506"),
        &hex!(
            "44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB031CB9C2DBE3B9E31EF3E5C9D02C7BE72ABFA1DA1B252"
        ),
    )
}

#[test]
fn test_ascon128_1032() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("0001020304050607"),
        &hex!(
            "108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85A9578C7705ACA84E85A556A93D4F83BC2572A3F803056"
        ),
    )
}

#[test]
fn test_ascon128_1033() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708"),
        &hex!(
            "6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD909F327B301D3E4AB074CDAFC883FE363DA28C5F107D"
        ),
    )
}

#[test]
fn test_ascon128_1034() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("00010203040506070809"),
        &hex!(
            "F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E57540B5D9BBA996D011D99913FF27F37961B26258BF4A0"
        ),
    )
}

#[test]
fn test_ascon128_1035() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A"),
        &hex!(
            "29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B067700C518DE8BDCCEAAE3606D1E6E6E79FECE071288D"
        ),
    )
}

#[test]
fn test_ascon128_1036() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4AC9F9F771E2C2158128743E9227CE49039593DF72B6CAE"
        ),
    )
}

#[test]
fn test_ascon128_1037() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EAB5920DB12B43AC9DC073324C3CC82F899DEF41CF81C9D"
        ),
    )
}

#[test]
fn test_ascon128_1038() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD9BDE4BDA18C0CA35235DE9B4FF8BF4C4E3095936A977"
        ),
    )
}

#[test]
fn test_ascon128_1039() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9E94019362C559DBD916D6373BB469C267589A911F725A"
        ),
    )
}

#[test]
fn test_ascon128_1040() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E3ECFE0DF819DB8E887F35C143068B14A963D71E9EFA7E"
        ),
    )
}

#[test]
fn test_ascon128_1041() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA81042C2D4E301DF46E8A30DB901442D9259F26980BE630"
        ),
    )
}

#[test]
fn test_ascon128_1042() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B2B7762C6DA888AB27D593E0BC110DD9718DA52208EAC7"
        ),
    )
}

#[test]
fn test_ascon128_1043() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "64AC72120E66A202433C618208B281F929D7AE66B779C14D18DDBFA2EF50E591CE9EF909554131E2DB1DF5ED8AF8D1"
        ),
    )
}

#[test]
fn test_ascon128_1044() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA913D4A94AD72148DE364DEF49DC5144A813F7EC9F93E"
        ),
    )
}

#[test]
fn test_ascon128_1045() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492B55C6607D52E83D3A452794913709BD7690C11B04FBDF"
        ),
    )
}

#[test]
fn test_ascon128_1046() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "368D61A8D488E8FB0F9F57D79350E353111404035451954226DDA2C9F9B695FF9F39E52C178A7791F995DF8D5CE251"
        ),
    )
}

#[test]
fn test_ascon128_1047() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62DACFA0F769609BE56EC62AB5043D092DA9929ED7A21E"
        ),
    )
}

#[test]
fn test_ascon128_1048() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEB247A728ED97D33BC915A466AE53524DCC2F89499AE3C"
        ),
    )
}

#[test]
fn test_ascon128_1049() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF81E5D8CD313181F2BE9D90172C9A88B9649B9F150FCAC"
        ),
    )
}

#[test]
fn test_ascon128_1050() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE417905FA6B524DC62CF611C80D167A79C32FE260F54D0"
        ),
    )
}

#[test]
fn test_ascon128_1051() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F1334D88D73E2D9150E7D73DFD6E6CAFF5A53A7EBF5EB0D"
        ),
    )
}

#[test]
fn test_ascon128_1052() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A85A28D43F7804CC64A7A66ADFADBDDAF6CE57D79762C"
        ),
    )
}

#[test]
fn test_ascon128_1053() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC223FF6FD6EBA0BA324E89FF4631ACFED599ACB499EC391"
        ),
    )
}

#[test]
fn test_ascon128_1054() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D344E6AE8D8DF9EA64F7AE36235FC9A84FBD6CE49C390"
        ),
    )
}

#[test]
fn test_ascon128_1055() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B6CED0E4F255B196B883137E0D1CAF33AFEBB4B9E72C4"
        ),
    )
}

#[test]
fn test_ascon128_1056() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622D788345FA7BEE2FA78AED259CE07FB15CD65585E407B5"
        ),
    )
}

#[test]
fn test_ascon128_1057() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(""),
        &hex!(
            "E770D289D2A44AEE7CD0A48ECE5274E381BAD7E163DCC4970F7873610DEBBEB1A28657F6E82FE53D08B09EFF9330BD2B"
        ),
    )
}

#[test]
fn test_ascon128_1058() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("00"),
        &hex!(
            "25FBE48AC155C103927E59C60C88A56B69F5F1C225BF3A1D5C7379FA53BAD550B72100ED30B362AD4E54DA95D5FE81BE"
        ),
    )
}

#[test]
fn test_ascon128_1059() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("0001"),
        &hex!(
            "49E50547CA0C754784F2A6F936ED9497C3A556D34DE4CC23F3C21CDB6D447CDB0F7324DEC1D9F0B3C2125EA5AAD85A12"
        ),
    )
}

#[test]
fn test_ascon128_1060() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102"),
        &hex!(
            "D2721FCB362AB5E15C6872449B117B9926791FD74925F0D9459CFA7940BD1BC1E2A1C710B0814E44188B2207828C7206"
        ),
    )
}

#[test]
fn test_ascon128_1061() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("00010203"),
        &hex!(
            "4A53D9966D87BFED686585FE7A28C7D3027F06EBA8BD35C7680693493091068DB6219EB3BDEFCA3655D4BD834136383B"
        ),
    )
}

#[test]
fn test_ascon128_1062() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("0001020304"),
        &hex!(
            "1F820273C65246B76D4FF8D1ADD72D5CC1703338B98CE4B34B5AF9CE46120201F53D87E6764E4008CBE3FBE87A08ADF9"
        ),
    )
}

#[test]
fn test_ascon128_1063() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405"),
        &hex!(
            "7CC88BDBF6D70605975B2FCD35DABD5B37B998207A55DC996A717FF8702F107074247F782093AD907E7040B22CA7BD7C"
        ),
    )
}

#[test]
fn test_ascon128_1064() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("00010203040506"),
        &hex!(
            "44864FD337BBF237DB14139BDC6E1D25140D311F19C0590FB031CB9C2DBE3BA0DFC1D241CC18E6228544BD816283C38E"
        ),
    )
}

#[test]
fn test_ascon128_1065() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("0001020304050607"),
        &hex!(
            "108640BD71345C6EDC4AEC76EA3BE5D4DF44BEF9CE7B69C85A9578C7705ACA2E5CAF789E99F9F566DE4EB813B600FE74"
        ),
    )
}

#[test]
fn test_ascon128_1066() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708"),
        &hex!(
            "6A256FBBD3726C823F99E5C5252CFC367D13B714309AEA44AD909F327B301DC475C5CD33E913B0B198EFF30508CB9B54"
        ),
    )
}

#[test]
fn test_ascon128_1067() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("00010203040506070809"),
        &hex!(
            "F2F44B081312F3F8C13E843F0ADBB84D30B7A2535A35720E57540B5D9BBA99531A32EAA78CB4A105912623AF2C895F95"
        ),
    )
}

#[test]
fn test_ascon128_1068() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A"),
        &hex!(
            "29FCAD75A4163DE319D4E3E4C98F5D5FC473269A6E6FA795B067700C518DE89A9D3D6FB75EA34A68A5B0A003771EF16D"
        ),
    )
}

#[test]
fn test_ascon128_1069() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B"),
        &hex!(
            "BBAE1D88621912ED737EADA1B19FCB19A9DDB367E42F0BF4AC9F9F771E2C2195D4C4A1412D57DA00D67B8F561DC04B06"
        ),
    )
}

#[test]
fn test_ascon128_1070() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C"),
        &hex!(
            "4BE547736BE1D8A6CDE18D1430BA869E6B39F6A4AE4E436EAB5920DB12B43A64D24740A17013ED20E655CDD25E3396EE"
        ),
    )
}

#[test]
fn test_ascon128_1071() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D"),
        &hex!(
            "4E589270FEB89BB22408041DAF7D55DB9BA125D4D1E58F75BD9BDE4BDA18C0793384BDE51781CFEC7EC9CE6961827063"
        ),
    )
}

#[test]
fn test_ascon128_1072() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E"),
        &hex!(
            "B03E607317A251B08B30F744B71965B0F1BE7A356FFF037C9E94019362C559A217552DA84151A370BB25D4F78B6F1168"
        ),
    )
}

#[test]
fn test_ascon128_1073() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!(
            "6A28215E4A6023FAE42095318B187F99C56D2306BE1573F6E3ECFE0DF819DB87363A60D9CDA76645D7CBED45B7C56470"
        ),
    )
}

#[test]
fn test_ascon128_1074() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F10"),
        &hex!(
            "9813B7013089DB863A742A4C13F1408E97CFEDCAAA22A7DA81042C2D4E301DACD14E8CB31E60870699542BE0D16800B0"
        ),
    )
}

#[test]
fn test_ascon128_1075() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011"),
        &hex!(
            "501DFE330EC4528E8D3BC467A02391BF2CF28D9350A9CAF9B2B7762C6DA88818F2F5E3B3A0AF95ED6BCDAD67E50DD6A3"
        ),
    )
}

#[test]
fn test_ascon128_1076() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112"),
        &hex!(
            "64AC72120E66A202433C618208B281F929D7AE66B779C14D18DDBFA2EF50E5A50DD77DDD74446DDDA76EB8E599E16084"
        ),
    )
}

#[test]
fn test_ascon128_1077() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213"),
        &hex!(
            "C305EB0E851DF92B6F8ACA44F24BADF13BEEC54D8BAA10B8CA913D4A94AD72F626D2ED4344DCDDB709823A4AFF345F4A"
        ),
    )
}

#[test]
fn test_ascon128_1078() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314"),
        &hex!(
            "994984D48B44B49446092EE25EF521A4E44B5CC07FA6E7492B55C6607D52E89F7ADC60EDA79A4CE5CB822A4A371805D6"
        ),
    )
}

#[test]
fn test_ascon128_1079() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415"),
        &hex!(
            "368D61A8D488E8FB0F9F57D79350E353111404035451954226DDA2C9F9B695388820AEC504402E011B974B6B0CEC2A26"
        ),
    )
}

#[test]
fn test_ascon128_1080() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516"),
        &hex!(
            "C01EA7792BF5F9621F07A266E6DF876E7B541FA73E8D8A2A62DACFA0F769601B137B92B496041A8A1B2C7E06000D619D"
        ),
    )
}

#[test]
fn test_ascon128_1081() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F1011121314151617"),
        &hex!(
            "BA35FA7ECE7C780FFF8B7E41BC97822F982E196ED384E7DDEB247A728ED97D2EF7AB5FC950E9B24177F4FD14557CC12C"
        ),
    )
}

#[test]
fn test_ascon128_1082() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718"),
        &hex!(
            "4C83A29686FE1AFC3FAD84899E6F5176B6B4ABF143DDD92DF81E5D8CD31318E605E2A08F457910F05BE0553A2971BF88"
        ),
    )
}

#[test]
fn test_ascon128_1083() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F10111213141516171819"),
        &hex!(
            "1244D5C1B435AFF489A8FD04B87B0763E4C385F18404435DE417905FA6B5247AE8F61A273B6D9357FA8E9869D54DD342"
        ),
    )
}

#[test]
fn test_ascon128_1084() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A"),
        &hex!(
            "C8002E9D447FA42945BF66AF5375BF6102FC33E1A0A8ED5F1334D88D73E2D95B50459F83BBBBCFC34715D41A58D58610"
        ),
    )
}

#[test]
fn test_ascon128_1085() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B"),
        &hex!(
            "662D521980423CBF521E7E4F9BABD0FF90072C743E4FE8C27A85A28D43F7807334B38C59FE294D019FC599C562790E93"
        ),
    )
}

#[test]
fn test_ascon128_1086() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C"),
        &hex!(
            "26A6E765E6BFE7EC0E25886657486E8D4C0B7E03EB93A3BC223FF6FD6EBA0B1C7A7122C0D077AE4E76A310EDB67F79F1"
        ),
    )
}

#[test]
fn test_ascon128_1087() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D"),
        &hex!(
            "0F55D7051D7478D53F2BA03EF290C48B2D00B9AF59D3EFCC0D344E6AE8D8DF02AABF416D29B6E558DFE1B1E5561DCED7"
        ),
    )
}

#[test]
fn test_ascon128_1088() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
        &hex!(
            "141B8B25E59E0D01B11422D94048C8045EE7744DD0040BF08B6CED0E4F255BBD4D4A994B5F271A0A659530252583A4C4"
        ),
    )
}

#[test]
fn test_ascon128_1089() {
    run_tv::<AsconAead128>(
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        &hex!(
            "4C086D27A3B51A2333CFC7F22172A9BCAD88B8D4D77E50622D788345FA7BEE4468915D3F9422289F2349D6A3B4160397"
        ),
    )
}
