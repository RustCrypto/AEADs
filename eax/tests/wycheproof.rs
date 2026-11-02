//! Test vectors from Wycheproof (`aes_eax_test.json`): the groups with a
//! 128-bit nonce and a 128-bit tag, for AES-128, AES-192 and AES-256.
#![cfg(feature = "alloc")]

use aes::{Aes128, Aes192, Aes256};
use eax::Eax;

aead::new_pass_test!(aes128_pass, "wycheproof-128_pass", Eax<Aes128>);
aead::new_fail_test!(aes128_fail, "wycheproof-128_fail", Eax<Aes128>);
aead::new_pass_test!(aes192_pass, "wycheproof-192_pass", Eax<Aes192>);
aead::new_fail_test!(aes192_fail, "wycheproof-192_fail", Eax<Aes192>);
aead::new_pass_test!(aes256_pass, "wycheproof-256_pass", Eax<Aes256>);
aead::new_fail_test!(aes256_fail, "wycheproof-256_fail", Eax<Aes256>);
