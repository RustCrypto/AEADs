use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use ccm::{
    consts::{U10, U13, U8},
    Ccm,
};
use hex_literal::hex;

// Test vectors from https://tools.ietf.org/html/rfc3610
macro_rules! new_test {
    (
        $name:ident, $tag_n:ty, $nonce_n:ty,
        key: $key:expr, nonce: $nonce:expr, ad: $ad:expr,
        pt: $pt:expr, ct: $ct:expr, tag: $tag:expr,
    ) => {
        #[test]
        fn $name() {
            type Cipher = Ccm<aes::Aes128, $tag_n, $nonce_n>;
            let key = GenericArray::from_slice(&$key);
            let c = Cipher::new(key);
            let mut buf1 = $pt.clone();
            let nonce = GenericArray::from_slice(&$nonce);
            let mut res = c.encrypt_in_place_detached(nonce, &$ad, &mut buf1).unwrap();
            assert_eq!(buf1, $ct);
            assert_eq!(res.as_slice(), &$tag);

            let mut buf2 = $ct.clone();
            c.decrypt_in_place_detached(nonce, &$ad, &mut buf2, &res)
                .unwrap();
            assert_eq!(buf2, $pt);

            let mut buf3 = $ct.clone();
            res[0] = res[0].wrapping_add(1);
            let r = c.decrypt_in_place_detached(nonce, &$ad, &mut buf3, &res);
            assert!(r.is_err());
        }
    };
}

new_test!(
    vector1,
    U8,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("00000003020100A0A1A2A3A4A5"),
    ad: hex!("0001020304050607"),
    pt: hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
    ct: hex!("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384"),
    tag: hex!("17E8D12CFDF926E0"),
);

new_test!(
    vector2,
    U8,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("00000004030201A0A1A2A3A4A5"),
    ad: hex!("0001020304050607"),
    pt: hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
    ct: hex!("72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3B"),
    tag: hex!("A091D56E10400916"),
);

new_test!(
    vector3,
    U8,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("00000005040302A0A1A2A3A4A5"),
    ad: hex!("0001020304050607"),
    pt: hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
    ct: hex!("51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA859657"),
    tag: hex!("4ADAA76FBD9FB0C5"),
);

new_test!(
    vector4,
    U8,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("00000006050403A0A1A2A3A4A5"),
    ad: hex!("000102030405060708090A0B"),
    pt: hex!("0C0D0E0F101112131415161718191A1B1C1D1E"),
    ct: hex!("A28C6865939A9A79FAAA5C4C2A9D4A91CDAC8C"),
    tag: hex!("96C861B9C9E61EF1"),
);

new_test!(
    vector5,
    U8,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("00000007060504A0A1A2A3A4A5"),
    ad: hex!("000102030405060708090A0B"),
    pt: hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F"),
    ct: hex!("DCF1FB7B5D9E23FB9D4E131253658AD86EBDCA3E"),
    tag: hex!("51E83F077D9C2D93"),
);

new_test!(
    vector6,
    U8,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("00000008070605A0A1A2A3A4A5"),
    ad: hex!("000102030405060708090A0B"),
    pt: hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
    ct: hex!("6FC1B011F006568B5171A42D953D469B2570A4BD87"),
    tag: hex!("405A0443AC91CB94"),
);

new_test!(
    vector7,
    U10,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("00000009080706A0A1A2A3A4A5"),
    ad: hex!("0001020304050607"),
    pt: hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"),
    ct: hex!("0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C"),
    tag: hex!("048C56602C97ACBB7490"),
);

new_test!(
    vector8,
    U10,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("0000000A090807A0A1A2A3A4A5"),
    ad: hex!("0001020304050607"),
    pt: hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
    ct: hex!("7B75399AC0831DD2F0BBD75879A2FD8F6CAE6B6CD9B7DB24"),
    tag: hex!("C17B4433F434963F34B4"),
);

new_test!(
    vector9,
    U10,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("0000000B0A0908A0A1A2A3A4A5"),
    ad: hex!("0001020304050607"),
    pt: hex!("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
    ct: hex!("82531A60CC24945A4B8279181AB5C84DF21CE7F9B73F42E197"),
    tag: hex!("EA9C07E56B5EB17E5F4E"),
);

new_test!(
    vector10,
    U10,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("0000000C0B0A09A0A1A2A3A4A5"),
    ad: hex!("000102030405060708090A0B"),
    pt: hex!("0C0D0E0F101112131415161718191A1B1C1D1E"),
    ct: hex!("07342594157785152B074098330ABB141B947B"),
    tag: hex!("566AA9406B4D999988DD"),
);

new_test!(
    vector11,
    U10,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("0000000D0C0B0AA0A1A2A3A4A5"),
    ad: hex!("000102030405060708090A0B"),
    pt: hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F"),
    ct: hex!("676BB20380B0E301E8AB79590A396DA78B834934"),
    tag: hex!("F53AA2E9107A8B6C022C"),
);

new_test!(
    vector12,
    U10,
    U13,
    key: hex!("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"),
    nonce: hex!("0000000E0D0C0BA0A1A2A3A4A5"),
    ad: hex!("000102030405060708090A0B"),
    pt: hex!("0C0D0E0F101112131415161718191A1B1C1D1E1F20"),
    ct: hex!("C0FFA0D6F05BDB67F24D43A4338D2AA4BED7B20E43"),
    tag: hex!("CD1AA31662E7AD65D6DB"),
);

new_test!(
    vector13,
    U8,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("00412B4EA9CDBE3C9696766CFA"),
    ad: hex!("0BE1A88BACE018B1"),
    pt: hex!("08E8CF97D820EA258460E96AD9CF5289054D895CEAC47C"),
    ct: hex!("4CB97F86A2A4689A877947AB8091EF5386A6FFBDD080F8"),
    tag: hex!("E78CF7CB0CDDD7B3"),
);

new_test!(
    vector14,
    U8,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("00412B4EA9CDBE3C9696766CFA"),
    ad: hex!("0BE1A88BACE018B1"),
    pt: hex!("08E8CF97D820EA258460E96AD9CF5289054D895CEAC47C"),
    ct: hex!("4CB97F86A2A4689A877947AB8091EF5386A6FFBDD080F8"),
    tag: hex!("E78CF7CB0CDDD7B3"),
);

new_test!(
    vector15,
    U8,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("00103FE41336713C9696766CFA"),
    ad: hex!("AA6CFA36CAE86B40"),
    pt: hex!("B916E0EACC1C00D7DCEC68EC0B3BBB1A02DE8A2D1AA346132E"),
    ct: hex!("B1D23A2220DDC0AC900D9AA03C61FCF4A559A4417767089708"),
    tag: hex!("A776796EDB723506"),
);

new_test!(
    vector16,
    U8,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("00764C63B8058E3C9696766CFA"),
    ad: hex!("D0D0735C531E1BECF049C244"),
    pt: hex!("12DAAC5630EFA5396F770CE1A66B21F7B2101C"),
    ct: hex!("14D253C3967B70609B7CBB7C49916028324526"),
    tag: hex!("9A6F49975BCADEAF"),
);

new_test!(
    vector17,
    U8,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("00F8B678094E3B3C9696766CFA"),
    ad: hex!("77B60F011C03E1525899BCAE"),
    pt: hex!("E88B6A46C78D63E52EB8C546EFB5DE6F75E9CC0D"),
    ct: hex!("5545FF1A085EE2EFBF52B2E04BEE1E2336C73E3F"),
    tag: hex!("762C0C7744FE7E3C"),
);

new_test!(
    vector18,
    U8,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("00D560912D3F703C9696766CFA"),
    ad: hex!("CD9044D2B71FDB8120EA60C0"),
    pt: hex!("6435ACBAFB11A82E2F071D7CA4A5EBD93A803BA87F"),
    ct: hex!("009769ECABDF48625594C59251E6035722675E04C8"),
    tag: hex!("47099E5AE0704551"),
);

new_test!(
    vector19,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("0042FFF8F1951C3C9696766CFA"),
    ad: hex!("D85BC7E69F944FB8"),
    pt: hex!("8A19B950BCF71A018E5E6701C91787659809D67DBEDD18"),
    ct: hex!("BC218DAA947427B6DB386A99AC1AEF23ADE0B52939CB6A"),
    tag: hex!("637CF9BEC2408897C6BA"),
);

new_test!(
    vector20,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("00920F40E56CDC3C9696766CFA"),
    ad: hex!("74A0EBC9069F5B37"),
    pt: hex!("1761433C37C5A35FC1F39F406302EB907C6163BE38C98437"),
    ct: hex!("5810E6FD25874022E80361A478E3E9CF484AB04F447EFFF6"),
    tag: hex!("F0A477CC2FC9BF548944"),
);

new_test!(
    vector21,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("0027CA0C7120BC3C9696766CFA"),
    ad: hex!("44A3AA3AAE6475CA"),
    pt: hex!("A434A8E58500C6E41530538862D686EA9E81301B5AE4226BFA"),
    ct: hex!("F2BEED7BC5098E83FEB5B31608F8E29C38819A89C8E776F154"),
    tag: hex!("4D4151A4ED3A8B87B9CE"),
);

new_test!(
    vector22,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("005B8CCBCD9AF83C9696766CFA"),
    ad: hex!("EC46BB63B02520C33C49FD70"),
    pt: hex!("B96B49E21D621741632875DB7F6C9243D2D7C2"),
    ct: hex!("31D750A09DA3ED7FDDD49A2032AABF17EC8EBF"),
    tag: hex!("7D22C8088C666BE5C197"),
);

new_test!(
    vector23,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("003EBE94044B9A3C9696766CFA"),
    ad: hex!("47A65AC78B3D594227E85E71"),
    pt: hex!("E2FCFBB880442C731BF95167C8FFD7895E337076"),
    ct: hex!("E882F1DBD38CE3EDA7C23F04DD65071EB41342AC"),
    tag: hex!("DF7E00DCCEC7AE52987D"),
);

new_test!(
    vector24,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("008D493B30AE8B3C9696766CFA"),
    ad: hex!("6E37A6EF546D955D34AB6059"),
    pt: hex!("ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4"),
    ct: hex!("F32905B88A641B04B9C9FFB58CC390900F3DA12AB1"),
    tag: hex!("6DCE9E82EFA16DA62059"),
);

// Here and below test vectors are generated by this library
new_test!(
    no_ad,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("905B88A641B04B9C9FFB58CC39"),
    ad: hex!(""),
    pt: hex!("ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4"),
    ct: hex!("8286E356FD1499832BCDDC71AA8366CD3CE9F070AF"),
    tag: hex!("42F12BC694BF4D700DA1"),
);

new_test!(
    no_data,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("2F1DBD38CE3EDA7C23F04DD650"),
    ad: hex!("6E37A6EF546D955D34AB6059"),
    pt: hex!(""),
    ct: hex!(""),
    tag: hex!("A2CCE6AA700FF162CF39"),
);

new_test!(
    big_ad,
    U10,
    U13,
    key: hex!("D7828D13B2B0BDC325A76236DF93CC6B"),
    nonce: hex!("AAC5630EFA5396F770CE1A66B1"),
    ad: [0x80; core::u16::MAX as usize],
    pt: hex!("009769ECABDF48625594C59251E6035722675E04C8"),
    ct: hex!("880DA7DA27DC28F531C3B2CA2BDF23B118A0637E8A"),
    tag: hex!("05F53D01E8CB88021B86"),
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
