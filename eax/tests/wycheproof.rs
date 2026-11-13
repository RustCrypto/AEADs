//! Test vectors from Wycheproof (`aes_eax_test.json`) with a 128-bit tag, for
//! AES-128, AES-192 and AES-256.
#![cfg(feature = "alloc")]

use aead::{
    array::ArraySize,
    consts::{U0, U4, U8, U12, U16, U20, U32, U64, U128, U257},
    dev::{TestVector, blobby, pass_test},
};
use aes::{Aes128, Aes192, Aes256};
use eax::{
    Eax, KeyInit, Tag,
    cipher::{BlockCipherEncrypt, BlockSizeUser},
    online::{Decrypt, Eax as EaxOnline, Encrypt},
};

// The groups with a 128-bit nonce.
aead::new_pass_test!(aes128_pass, "wycheproof-128_pass", Eax<Aes128>);
aead::new_fail_test!(aes128_fail, "wycheproof-128_fail", Eax<Aes128>);
aead::new_pass_test!(aes192_pass, "wycheproof-192_pass", Eax<Aes192>);
aead::new_fail_test!(aes192_fail, "wycheproof-192_fail", Eax<Aes192>);
aead::new_pass_test!(aes256_pass, "wycheproof-256_pass", Eax<Aes256>);
aead::new_fail_test!(aes256_fail, "wycheproof-256_fail", Eax<Aes256>);

/// Checks a vector with both `Eax` and `online::Eax` using an `N`-byte nonce.
fn nonce_len_test<C, N>(i: usize, tv: &TestVector)
where
    C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + Clone + KeyInit,
    N: ArraySize,
{
    if let Err(reason) = pass_test::<Eax<C, U16, N>>(tv) {
        panic!("\nFailed test #{i}\nreason:\t{reason:?}\ntest vector:\t{tv:?}\n");
    }

    let key = tv.key.try_into().expect("wrong key size");
    let nonce = tv.nonce.try_into().expect("wrong nonce size");
    let (ct, tag) = tv.ciphertext.split_at(tv.plaintext.len());
    let tag: &Tag<U16> = tag.try_into().expect("wrong tag size");

    let mut buf = tv.plaintext.to_vec();
    let mut cipher = EaxOnline::<C, Encrypt, U16, N>::with_key_and_nonce(key, nonce);
    cipher.update_assoc(tv.aad);
    cipher.encrypt(&mut buf);
    assert_eq!(buf, ct, "online encryption, test #{i}");
    assert_eq!(&cipher.finish(), tag, "online tag, test #{i}");

    let mut cipher = EaxOnline::<C, Decrypt, U16, N>::with_key_and_nonce(key, nonce);
    cipher.update_assoc(tv.aad);
    cipher.decrypt_unauthenticated_hazmat(&mut buf);
    assert_eq!(buf, tv.plaintext, "online decryption, test #{i}");
    assert!(cipher.finish(tag).is_ok(), "online tag check, test #{i}");
}

/// The groups with a nonce that is not 128 bits long (0 to 257 bytes).
macro_rules! new_nonce_len_test {
    ($name:ident, $test_name:expr, $cipher:ty) => {
        #[test]
        fn $name() {
            blobby::parse_into_structs!(
                include_bytes!(concat!("data/", $test_name, ".blb"));
                static TEST_VECTORS: &[
                    TestVector { key, nonce, aad, plaintext, ciphertext }
                ];
            );

            for (i, tv) in TEST_VECTORS.iter().enumerate() {
                match tv.nonce.len() {
                    0 => nonce_len_test::<$cipher, U0>(i, tv),
                    4 => nonce_len_test::<$cipher, U4>(i, tv),
                    8 => nonce_len_test::<$cipher, U8>(i, tv),
                    12 => nonce_len_test::<$cipher, U12>(i, tv),
                    20 => nonce_len_test::<$cipher, U20>(i, tv),
                    32 => nonce_len_test::<$cipher, U32>(i, tv),
                    64 => nonce_len_test::<$cipher, U64>(i, tv),
                    128 => nonce_len_test::<$cipher, U128>(i, tv),
                    257 => nonce_len_test::<$cipher, U257>(i, tv),
                    n => panic!("no test for a {n}-byte nonce"),
                }
            }
        }
    };
}

new_nonce_len_test!(aes128_nonce_len, "wycheproof-128_nonce-len", Aes128);
new_nonce_len_test!(aes192_nonce_len, "wycheproof-192_nonce-len", Aes192);
new_nonce_len_test!(aes256_nonce_len, "wycheproof-256_nonce-len", Aes256);
