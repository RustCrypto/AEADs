//! Regression tests for clearing unauthenticated plaintext.

use deoxys::aead::{AeadInOut, Key, KeyInit, Nonce, inout::InOutBuf};
use deoxys::{DeoxysI128, DeoxysI256, DeoxysII128, DeoxysII256};

fn assert_failed_decrypt_clears<C>()
where
    C: AeadInOut + KeyInit,
{
    let key = Key::<C>::default();
    let cipher = C::new(&key);
    for len in [0, 1, 15, 16, 17, 31, 32, 33, 64, 65] {
        let mut nonce = Nonce::<C>::default();
        nonce[0] = len;
        let mut ciphertext = [0x42; 65];
        let ciphertext = &mut ciphertext[..usize::from(len)];
        let tag = cipher
            .encrypt_inout_detached(&nonce, b"associated data", ciphertext.into())
            .expect("encryption failed");

        for tamper in 0..4 {
            if tamper == 3 && ciphertext.is_empty() {
                continue;
            }
            let mut bad_tag = tag.clone();
            let mut bad_nonce = nonce.clone();
            let mut input = ciphertext.to_vec();
            let aad: &[u8] = match tamper {
                0 => {
                    bad_tag[0] ^= 1;
                    b"associated data"
                }
                1 => b"different data",
                2 => {
                    bad_nonce[0] ^= 1;
                    b"associated data"
                }
                _ => {
                    input[0] ^= 1;
                    b"associated data"
                }
            };

            let mut output = vec![0xa5; input.len()];
            let buffer = InOutBuf::new(&input, &mut output).expect("equal buffer lengths");
            cipher
                .decrypt_inout_detached(&bad_nonce, aad, buffer, &bad_tag)
                .expect_err("tampered message was accepted");
            assert!(
                output.iter().all(|&byte| byte == 0),
                "len={len}, tamper={tamper}"
            );

            cipher
                .decrypt_inout_detached(&bad_nonce, aad, input.as_mut_slice().into(), &bad_tag)
                .expect_err("tampered message was accepted");
            assert!(
                input.iter().all(|&byte| byte == 0),
                "len={len}, tamper={tamper}"
            );
        }
    }
}

#[test]
fn deoxys_i_128_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysI128>();
}

#[test]
fn deoxys_i_256_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysI256>();
}

#[test]
fn deoxys_ii_128_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysII128>();
}

#[test]
fn deoxys_ii_256_failed_decrypt_clears_output() {
    assert_failed_decrypt_clears::<DeoxysII256>();
}
