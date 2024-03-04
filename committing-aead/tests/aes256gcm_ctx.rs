mod helpers;

use self::helpers::TestVector;

use aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use committing_aead::CtxAead;
use generic_array::{typenum::Unsigned, GenericArray};
use hex_literal::hex;
use sha2::Sha256;

/// Copied a handful of AES-256-GCM test vectors and updated the tags via Python
const CTX_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        key: &hex!("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4"),
        nonce: &hex!("516c33929df5a3284ff463d7"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("dd63e6e6c77d5f29975803882becd40b16326b278832b72123d03ea023ad42af"),
    },
    TestVector {
        key: &hex!("26dc5ce74b4d64d1dc2221cdd6a63d7a9226134708299cd719a68f636b6b5ebd"),
        nonce: &hex!("0294c54ff4ed30782222c834"),
        plaintext: &hex!("ae4c7f040d3a5ff108e29381e7a0830221d5378b13b87ef0703c327686d30af004902d4ddb59d5787fecea4731eaa8042443d5"),
        aad: &hex!("2a9fb326f98bbe2d2cf57bae9ecbeff7"),
        ciphertext: &hex!("9601aec6bc6e8a09d054a01e500a4e4cdcc7c2cf83122656be7c26fc7dc1a773a40be7e8a049a6cdf059e93a23ca441ef1ca96"),
        tag: &hex!("f6f0e3bcf9b603d9b434bad0cfbee9a4ea90b3e3731e466d4a0d6a3b21bc6641"),
    },
    TestVector {
        key: &hex!("54c31fb2fb4aab6a82ce188e6afa71a3354811099d1203fe1f991746f7342f90"),
        nonce: &hex!("f0fe974bdbe1694dc3b06cc6"),
        plaintext: &hex!("fbb7b3730f0cd7b1052a5298ee"),
        aad: &hex!("2879e05e0f8dd4402425eabb0dc184dcd07d46d54d775d7c2b76b0f76b3eed5f7ca93c6ae71bf509c270490269ea869ed6603fdf7113aa625648ab8ed88210f8b30ec9c94bca5757ca3d77491f64109101165636b068e3095cb4"),
        ciphertext: &hex!("3a5a2a8aa93c462cfb80f1f728"),
        tag: &hex!("42a344ebdaa63ff7cb8cf37405cb0efae3b8a2c12113b4cb9647157220565829"),
    }
];

#[test]
fn ctx_encryptonly() {
    for vector in CTX_TEST_VECTORS {
        let key = GenericArray::from_slice(vector.key);
        let nonce = GenericArray::from_slice(vector.nonce);
        let payload = Payload {
            msg: vector.plaintext,
            aad: vector.aad,
        };

        let cipher = CtxAead::<Aes256Gcm, Sha256>::new(key);
        let ciphertext = cipher.encrypt(nonce, payload).unwrap();
        let (ct, tag) = ciphertext.split_at(
            ciphertext.len() - <CtxAead<Aes256Gcm, Sha256> as AeadCore>::TagSize::to_usize(),
        );
        assert_eq!(vector.ciphertext, ct, "ctxt mismatch");
        assert_eq!(vector.tag, tag, "tag mismatch");
    }
}
