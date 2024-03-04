#[macro_use]
mod helpers;

use self::helpers::TestVector;

use aead::{Aead, AeadCore, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use committing_aead::CtxishHmacAead;
use generic_array::{typenum::Unsigned, GenericArray};
use hex_literal::hex;
use sha2::Sha256;

/// Copied a handful of AES-256-GCM test vectors and updated the tags via Python
const CTXISH_TEST_VECTORS: &[TestVector] = &[
    TestVector {
        key: &hex!("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4"),
        nonce: &hex!("516c33929df5a3284ff463d7"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("bdc1ac884d332457a1d2664f168c76f0DD2305070280150ED89E7ED6B1282479FA3A42166153B6BBCFAF0E796843B1A4"),
    },
    TestVector {
        key: &hex!("26dc5ce74b4d64d1dc2221cdd6a63d7a9226134708299cd719a68f636b6b5ebd"),
        nonce: &hex!("0294c54ff4ed30782222c834"),
        plaintext: &hex!("ae4c7f040d3a5ff108e29381e7a0830221d5378b13b87ef0703c327686d30af004902d4ddb59d5787fecea4731eaa8042443d5"),
        aad: &hex!("2a9fb326f98bbe2d2cf57bae9ecbeff7"),
        ciphertext: &hex!("9601aec6bc6e8a09d054a01e500a4e4cdcc7c2cf83122656be7c26fc7dc1a773a40be7e8a049a6cdf059e93a23ca441ef1ca96"),
        tag: &hex!("b620a8a0c8fe6117f22735c0ca29434c186379AA20DB53D6A0CD8375FA95665F7CD9677FF690BA437E6D0092A4AF8344"),
    },
    TestVector {
        key: &hex!("54c31fb2fb4aab6a82ce188e6afa71a3354811099d1203fe1f991746f7342f90"),
        nonce: &hex!("f0fe974bdbe1694dc3b06cc6"),
        plaintext: &hex!("fbb7b3730f0cd7b1052a5298ee"),
        aad: &hex!("2879e05e0f8dd4402425eabb0dc184dcd07d46d54d775d7c2b76b0f76b3eed5f7ca93c6ae71bf509c270490269ea869ed6603fdf7113aa625648ab8ed88210f8b30ec9c94bca5757ca3d77491f64109101165636b068e3095cb4"),
        ciphertext: &hex!("3a5a2a8aa93c462cfb80f1f728"),
        tag: &hex!("59ef9d54ee01fb6cd54bd0e08f74096fE292175F750A80FD39F7E0F8EAA075DF471481ED2B780DE8BC2EAB0DA3032288"),
    }
];

tests_with_inplace!(CtxishHmacAead<Aes256Gcm, Sha256>, CTXISH_TEST_VECTORS);
