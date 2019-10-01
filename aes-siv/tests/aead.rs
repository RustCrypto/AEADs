pub mod vectors;

use self::vectors::aead::AesSivAeadExample;
use aes_siv::{
    aead::{generic_array::GenericArray, AeadMut, NewAead, Payload},
    Aes128SivAead, Aes256SivAead,
};
#[cfg(feature = "pmac")]
use aes_siv::{Aes128PmacSivAead, Aes256PmacSivAead};

#[test]
fn aes_siv_aead_examples_encrypt() {
    let examples = AesSivAeadExample::load_all();

    for example in examples {
        let nonce = GenericArray::clone_from_slice(&example.nonce);
        let payload = Payload {
            aad: &example.ad,
            msg: &example.plaintext,
        };

        let ciphertext = match example.alg.as_ref() {
            "AES-SIV" => match example.key.len() {
                32 => Aes128SivAead::new(GenericArray::clone_from_slice(&example.key))
                    .encrypt(&nonce, payload),
                64 => Aes256SivAead::new(GenericArray::clone_from_slice(&example.key))
                    .encrypt(&nonce, payload),
                _ => panic!("unexpected key size: {}", example.key.len()),
            },
            #[cfg(feature = "pmac")]
            "AES-PMAC-SIV" => match example.key.len() {
                32 => Aes128PmacSivAead::new(GenericArray::clone_from_slice(&example.key))
                    .encrypt(&nonce, payload),
                64 => Aes256PmacSivAead::new(GenericArray::clone_from_slice(&example.key))
                    .encrypt(&nonce, payload),
                _ => panic!("unexpected key size: {}", example.key.len()),
            },
            _ => {
                if example.alg == "AES-PMAC-SIV" {
                    continue;
                } else {
                    panic!("unexpected algorithm: {}", example.alg)
                }
            }
        };

        assert_eq!(ciphertext.expect("encryption failure"), example.ciphertext);
    }
}

#[test]
fn aes_siv_aead_examples_decrypt() {
    let examples = AesSivAeadExample::load_all();

    for example in examples {
        let nonce = GenericArray::clone_from_slice(&example.nonce);
        let payload = Payload {
            aad: &example.ad,
            msg: &example.ciphertext,
        };

        let plaintext = match example.alg.as_ref() {
            "AES-SIV" => match example.key.len() {
                32 => Aes128SivAead::new(GenericArray::clone_from_slice(&example.key))
                    .decrypt(&nonce, payload),
                64 => Aes256SivAead::new(GenericArray::clone_from_slice(&example.key))
                    .decrypt(&nonce, payload),
                _ => panic!("unexpected key size: {}", example.key.len()),
            },
            #[cfg(feature = "pmac")]
            "AES-PMAC-SIV" => match example.key.len() {
                32 => Aes128PmacSivAead::new(GenericArray::clone_from_slice(&example.key))
                    .decrypt(&nonce, payload),
                64 => Aes256PmacSivAead::new(GenericArray::clone_from_slice(&example.key))
                    .decrypt(&nonce, payload),
                _ => panic!("unexpected key size: {}", example.key.len()),
            },
            _ => {
                if example.alg == "AES-PMAC-SIV" {
                    continue;
                } else {
                    panic!("unexpected algorithm: {}", example.alg)
                }
            }
        }
        .expect("decrypt failure");

        assert_eq!(plaintext, example.plaintext);
    }
}
