#[macro_use]
mod helpers;

use self::helpers::TestVector;

use aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use committing_aead::PaddedAead;
use generic_array::{typenum::Unsigned, GenericArray};

use hex_literal::hex;

const KEY: &[u8; 32] = &[
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];

const AAD: &[u8; 12] = &[
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];

const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
    If I could offer you only one tip for the future, sunscreen would be it.";

/// Copied non-Wycheproof ChaCha20Poly1305 test vector and updated the ctxt and tags
const PAD_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        key: KEY,
        nonce: &[
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ],
        plaintext: PLAINTEXT,
        aad: AAD,
        ciphertext: &hex!("9F7BE95D01FD40BA15E28FFB36810AAEC1C0883F09016EDEDD8AD087558203A54E9ECB38AC8E5E2BB8DAB20FFADB52E87504B26EBE696D4F60A485CF11B81B59FCB1C45F4219EEACEC6ADEC34E6669788EDB41C49CA301E127E0ACAB3B44B9CF10E7DFFC85182D93FE7E960281C5924E7055696DEE5A0AF7D21E06DBBE839E1706D4103059B9F4FA654C6F39710A5040AFFC78223BB7863C9065F5D756D3DADBE9210BD0B6D45CEB0B3114DB9DB40B5822C93B3B5B66BD7F18CF4AA3A47CE8C5E000AF7697335503FBFB5F43BA21B67AF13F"),
        tag: &hex!("CCEC51BFFC65E60810F678FB4F73FA3B"),
    },
];

tests_no_inplace!(PaddedAead<ChaCha20Poly1305>, PAD_TEST_VECTORS);
