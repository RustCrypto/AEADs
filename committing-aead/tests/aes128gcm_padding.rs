#[macro_use]
mod helpers;

use self::helpers::TestVector;

use aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use committing_aead::PaddedAead;
use generic_array::{typenum::Unsigned, GenericArray};

use hex_literal::hex;

/// Copied a handful of AES-256-GCM test vectors and updated the tags via Python
const PAD_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        key: &hex!("11754cd72aec309bf52f7687212e8957"),
        nonce: &hex!("3c819d9a9bed087615030b65"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!("9238D4C2EA6CC96FF204063074E345B7DE28A65EB55E6F0C98C7513A14E4F303CDB2A91A2E93125F2CFBDEDCF00BFF8D"),
        tag: &hex!("80FF70A9B8804988D46EA234B3618518"),
    },
    TestVector {
        key: &hex!("89c949e9c804af014d5604b39459f2c8"),
        nonce: &hex!("d1b104c815bf1e94e28c8f16"),
        plaintext: &hex!(""),
        aad: &hex!("82adcd638d3fa9d9f3e84100d61e0777"),
        ciphertext: &hex!("936B6E47964ED8376F9F9988B53520CFC4BF3E4842E75618C9EC82AFA53D67EC482A2FFB50825DD323675C931C84E811"),
        tag: &hex!("7AA91F2C56204AD8ECADA9A19BC31685"),
    },
    TestVector {
        key: &hex!("9b2ddd1af666b91e052d624b04e6b042"),
        nonce: &hex!("4ee12e62899c61f9520a13c1"),
        plaintext: &hex!("01e5dc87a242782ca3156a27446f386bd9a060ffef1f63c3bc11a93ce305175d"),
        aad: &hex!("e591e6ee094981b0e383429a31cceaaa"),
        ciphertext: &hex!("865CAACF28820F7C0947F431464635D8B6ED582A2AD3D7D12EA7C50DDA6469E3C93CCB7A22AD9A068634B8E5DB34CBD12E57448BAA46E6DC9A1616D1BB4D3D89525EDDEAA2CB2F953B8D275E6ECAA157"),
        tag: &hex!("25304F1836620DBFF689E213033AA17B"),
    }
];

tests_no_inplace!(PaddedAead<Aes128Gcm>, PAD_TEST_VECTORS);
