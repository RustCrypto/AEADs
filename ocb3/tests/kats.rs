#![allow(non_snake_case)]

use aead::{
    consts::{U12, U8},
    AeadInPlace, KeyInit,
};
use aes::{Aes128, Aes192, Aes256, Block};
use hex_literal::hex;
use ocb3::{AesOcb3, GenericArray};

/// Test vectors from https://www.rfc-editor.org/rfc/rfc7253.html#appendix-A
#[test]
fn rfc7253_sample_results() {
    let key = GenericArray::from(hex!("000102030405060708090A0B0C0D0E0F"));
    struct Kat {
        nonce: Vec<u8>,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
    }
    let kats = [
            Kat {
                nonce: hex!("BBAA99887766554433221100").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("785407BFFFC8AD9EDCC5520AC9111EE6").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221101").to_vec(),
                associated_data: hex!("0001020304050607").to_vec(),
                plaintext: hex!("0001020304050607").to_vec(),
                ciphertext: hex!("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221102").to_vec(),
                associated_data: hex!("0001020304050607").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("81017F8203F081277152FADE694A0A00").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221103").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("0001020304050607").to_vec(),
                ciphertext: hex!("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221104").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                ciphertext: hex!(
                    "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"
                )
                .to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221105").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("8CF761B6902EF764462AD86498CA6B97").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221106").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                ciphertext: hex!(
                    "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D"
                )
                .to_vec(),
            },
            Kat {
                 nonce: hex!("BBAA99887766554433221107").to_vec(),
                 associated_data: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                 plaintext: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                 ciphertext: hex!("1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221108").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("6DC225A071FC1B9F7C69F93B0F1E10DE").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221109").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                ciphertext: hex!("221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110A").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                ciphertext: hex!("BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110B").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("FE80690BEE8A485D11F32965BC9D2A32").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110C").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                ciphertext: hex!("2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110D").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                ciphertext: hex!("D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110E").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("C5CD9D1850C141E358649994EE701B68").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110F").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                ciphertext: hex!("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479").to_vec(),
            },
        ];

    for kat in kats {
        let ocb3 = Aes128Ocb3::new(&key);

        let buffer = &mut kat.plaintext.clone();
        let tag = ocb3
            .encrypt_in_place_detached(
                kat.nonce.as_slice().into(),
                kat.associated_data.as_slice(),
                buffer,
            )
            .unwrap();

        assert_eq!(
            &tag,
            Block::from_slice(&kat.ciphertext.as_slice()[kat.ciphertext.len() - 16..])
        );
        assert_eq!(
            buffer.as_slice(),
            &kat.ciphertext.as_slice()[..kat.ciphertext.len() - 16]
        );

        let res = ocb3.decrypt_in_place_detached(
            kat.nonce.as_slice().into(),
            kat.associated_data.as_slice(),
            buffer,
            &tag,
        );
        assert!(res.is_ok());
        assert_eq!(buffer.as_slice(), kat.plaintext.as_slice());
    }
}

fn num2str96(num: usize) -> [u8; 12] {
    let num: u32 = num.try_into().unwrap();
    let mut out = [0u8; 12];
    out[8..12].copy_from_slice(&num.to_be_bytes());
    out
}

/// Test vectors from Page 18 of https://www.rfc-editor.org/rfc/rfc7253.html#appendix-A
macro_rules! rfc7253_wider_variety {
    ($ocb:tt, $keylen:tt, $taglen:expr, $expected:expr) => {
        let mut key_bytes = vec![0u8; $keylen];
        key_bytes[$keylen - 1] = 8 * $taglen; // taglen in bytes

        let key = GenericArray::from_slice(key_bytes.as_slice());
        let ocb = $ocb::new(key);

        let mut ciphertext = Vec::new();

        for i in 0..128 {
            // S = zeros(8i)
            let S = vec![0u8; i];

            // N = num2str(3i+1,96)
            // C = C || OCB-ENCRYPT(K,N,S,S)
            let N = num2str96(3 * i + 1);
            let mut buffer = S.clone();
            let tag = ocb
                .encrypt_in_place_detached(N.as_slice().into(), &S, &mut buffer)
                .unwrap();
            ciphertext.append(&mut buffer);
            ciphertext.append(&mut tag.as_slice().to_vec());

            // N = num2str(3i+2,96)
            // C = C || OCB-ENCRYPT(K,N,<empty string>,S)
            let N = num2str96(3 * i + 2);
            let mut buffer = S.clone();
            let tag = ocb
                .encrypt_in_place_detached(N.as_slice().into(), &[], &mut buffer)
                .unwrap();
            ciphertext.append(&mut buffer);
            ciphertext.append(&mut tag.as_slice().to_vec());

            // N = num2str(3i+3,96)
            // C = C || OCB-ENCRYPT(K,N,S,<empty string>)
            let N = num2str96(3 * i + 3);
            let tag = ocb
                .encrypt_in_place_detached(N.as_slice().into(), &S, &mut [])
                .unwrap();
            ciphertext.append(&mut tag.as_slice().to_vec());
        }
        if $taglen == 16 {
            assert_eq!(ciphertext.len(), 22_400);
        } else if $taglen == 12 {
            assert_eq!(ciphertext.len(), 20_864);
        } else if $taglen == 8 {
            assert_eq!(ciphertext.len(), 19_328);
        } else {
            unreachable!();
        }

        // N = num2str(385,96)
        // Output : OCB-ENCRYPT(K,N,C,<empty string>)
        let N = num2str96(385);
        let tag = ocb
            .encrypt_in_place_detached(N.as_slice().into(), &ciphertext, &mut [])
            .unwrap();

        assert_eq!(tag.as_slice(), hex!($expected))
    };
}

// More types for testing
type Aes192Ocb3 = AesOcb3<Aes192, U12>;
type Aes128Ocb3Tag96 = AesOcb3<Aes128, U12, U12>;
type Aes192Ocb3Tag96 = AesOcb3<Aes192, U12, U12>;
type Aes256Ocb3Tag96 = AesOcb3<Aes256, U12, U12>;
type Aes128Ocb3Tag64 = AesOcb3<Aes128, U12, U8>;
type Aes192Ocb3Tag64 = AesOcb3<Aes192, U12, U8>;
type Aes256Ocb3Tag64 = AesOcb3<Aes256, U12, U8>;
type Aes128Ocb3 = AesOcb3<aes::Aes128, U12>;
type Aes256Ocb3 = AesOcb3<aes::Aes256, U12>;

/// Test vectors from Page 18 of https://www.rfc-editor.org/rfc/rfc7253.html#appendix-A
#[test]
fn rfc7253_more_sample_results() {
    rfc7253_wider_variety!(Aes128Ocb3, 16, 16, "67E944D23256C5E0B6C61FA22FDF1EA2");
    rfc7253_wider_variety!(Aes192Ocb3, 24, 16, "F673F2C3E7174AAE7BAE986CA9F29E17");
    rfc7253_wider_variety!(Aes256Ocb3, 32, 16, "D90EB8E9C977C88B79DD793D7FFA161C");
    rfc7253_wider_variety!(Aes128Ocb3Tag96, 16, 12, "77A3D8E73589158D25D01209");
    rfc7253_wider_variety!(Aes192Ocb3Tag96, 24, 12, "05D56EAD2752C86BE6932C5E");
    rfc7253_wider_variety!(Aes256Ocb3Tag96, 32, 12, "5458359AC23B0CBA9E6330DD");
    rfc7253_wider_variety!(Aes128Ocb3Tag64, 16, 8, "192C9B7BD90BA06A");
    rfc7253_wider_variety!(Aes192Ocb3Tag64, 24, 8, "0066BC6E0EF34E24");
    rfc7253_wider_variety!(Aes256Ocb3Tag64, 32, 8, "7D4EA5D445501CBE");
}
