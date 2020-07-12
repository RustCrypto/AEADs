//! AES-128-GCM tests

#[macro_use]
extern crate hex_literal;

#[macro_use]
mod common;

use self::common::TestVector;
use eax::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use eax::Aes128Eax;

/// EAX test vectors
///
/// <https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf>
const TEST_VECTORS: &[TestVector<[u8; 16]>] = &[
    TestVector {
        key: &hex!("233952DEE4D5ED5F9B9C6D6FF80FF478"),
        nonce: &hex!("62EC67F9C3A4A407FCB2A8C49031A8B3"),
        plaintext: &hex!(""),
        aad: &hex!("6BFB914FD07EAE6B"),
        ciphertext: &hex!("E037830E8389F27B025A2D6527E79D01"),
    },
    TestVector {
        key: &hex!("91945D3F4DCBEE0BF45EF52255F095A4"),
        nonce: &hex!("BECAF043B0A23D843194BA972C66DEBD"),
        plaintext: &hex!("F7FB"),
        aad: &hex!("FA3BFD4806EB53FA"),
        ciphertext: &hex!("19DD5C4C9331049D0BDAB0277408F67967E5"),
    },
    TestVector {
        key: &hex!("01F74AD64077F2E704C0F60ADA3DD523"),
        nonce: &hex!("70C3DB4F0D26368400A10ED05D2BFF5E"),
        plaintext: &hex!("1A47CB4933"),
        aad: &hex!("234A3463C1264AC6"),
        ciphertext: &hex!("D851D5BAE03A59F238A23E39199DC9266626C40F80"),
    },
    TestVector {
        key: &hex!("D07CF6CBB7F313BDDE66B727AFD3C5E8"),
        nonce: &hex!("8408DFFF3C1A2B1292DC199E46B7D617"),
        plaintext: &hex!("481C9E39B1"),
        aad: &hex!("33CCE2EABFF5A79D"),
        ciphertext: &hex!("632A9D131AD4C168A4225D8E1FF755939974A7BEDE"),
    },
    TestVector {
        key: &hex!("35B6D0580005BBC12B0587124557D2C2"),
        nonce: &hex!("FDB6B06676EEDC5C61D74276E1F8E816"),
        plaintext: &hex!("40D0C07DA5E4"),
        aad: &hex!("AEB96EAEBE2970E9"),
        ciphertext: &hex!("071DFE16C675CB0677E536F73AFE6A14B74EE49844DD"),
    },
    TestVector {
        key: &hex!("BD8E6E11475E60B268784C38C62FEB22"),
        nonce: &hex!("6EAC5C93072D8E8513F750935E46DA1B"),
        plaintext: &hex!("4DE3B35C3FC039245BD1FB7D"),
        aad: &hex!("D4482D1CA78DCE0F"),
        ciphertext: &hex!("835BB4F15D743E350E728414ABB8644FD6CCB86947C5E10590210A4F"),
    },
    TestVector {
        key: &hex!("7C77D6E813BED5AC98BAA417477A2E7D"),
        nonce: &hex!("1A8C98DCD73D38393B2BF1569DEEFC19"),
        plaintext: &hex!("8B0A79306C9CE7ED99DAE4F87F8DD61636"),
        aad: &hex!("65D2017990D62528"),
        ciphertext: &hex!("02083E3979DA014812F59F11D52630DA30137327D10649B0AA6E1C181DB617D7F2"),
    },
    TestVector {
        key: &hex!("5FFF20CAFAB119CA2FC73549E20F5B0D"),
        nonce: &hex!("DDE59B97D722156D4D9AFF2BC7559826"),
        plaintext: &hex!("1BDA122BCE8A8DBAF1877D962B8592DD2D56"),
        aad: &hex!("54B9F04E6A09189A"),
        ciphertext: &hex!("2EC47B2C4954A489AFC7BA4897EDCDAE8CC33B60450599BD02C96382902AEF7F832A"),
    },
    TestVector {
        key: &hex!("A4A4782BCFFD3EC5E7EF6D8C34A56123"),
        nonce: &hex!("B781FCF2F75FA5A8DE97A9CA48E522EC"),
        plaintext: &hex!("6CF36720872B8513F6EAB1A8A44438D5EF11"),
        aad: &hex!("899A175897561D7E"),
        ciphertext: &hex!("0DE18FD0FDD91E7AF19F1D8EE8733938B1E8E7F6D2231618102FDB7FE55FF1991700"),
    },
    TestVector {
        key: &hex!("8395FCF1E95BEBD697BD010BC766AAC3"),
        nonce: &hex!("22E7ADD93CFC6393C57EC0B3C17D6B44"),
        plaintext: &hex!("CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7"),
        aad: &hex!("126735FCC320D25A"),
        ciphertext: &hex!(
            "CB8920F87A6C75CFF39627B56E3ED197C552D295A7CFC46AFC253B4652B1AF3795B124AB6E"
        ),
    },
];

tests!(Aes128Eax, TEST_VECTORS);
