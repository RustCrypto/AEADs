#![cfg(feature = "alloc")] // TODO: remove after migration to the new `aead` crate
use ascon_aead::{
    AsconAead128,
    aead::{Aead, KeyInit, Nonce, Payload, dev::blobby},
};

fn run_pass_test<C: Aead>(
    cipher: &C,
    nonce: &Nonce<C>,
    aad: &[u8],
    pt: &[u8],
    ct: &[u8],
) -> Result<(), &'static str> {
    let res = cipher
        .encrypt(nonce, Payload { aad, msg: pt })
        .map_err(|_| "encryption failure")?;
    if res != ct {
        return Err("encrypted data is different from target ciphertext");
    }

    let res = cipher
        .decrypt(nonce, Payload { aad, msg: ct })
        .map_err(|_| "decryption failure")?;
    if res != pt {
        return Err("decrypted data is different from target plaintext");
    }

    Ok(())
}

#[macro_export]
macro_rules! new_pass_test {
    ($name:ident, $test_name:expr, $cipher:ty $(,)?) => {
        #[test]
        fn $name() {
            use blobby::Blob5Iterator;
            use $crate::KeyInit;

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob5Iterator::new(data).unwrap().enumerate() {
                let [key, nonce, aad, pt, ct] = row.unwrap();
                let key = key.try_into().expect("wrong key size");
                let nonce = nonce.try_into().expect("wrong nonce size");
                let cipher = <$cipher as KeyInit>::new(key);
                let res = run_pass_test(&cipher, nonce, aad, pt, ct);
                if let Err(reason) = res {
                    panic!(
                        "\n\
                        Failed (pass) test #{i}\n\
                        reason:\t{reason:?}\n\
                        key:\t{key:?}\n\
                        nonce:\t{nonce:?}\n\
                        aad:\t{aad:?}\n\
                        plaintext:\t{pt:?}\n\
                        ciphertext:\t{ct:?}\n"
                    );
                }
            }
        }
    };
}

// Test vectors are taken from the reference Ascon implementation:
// https://github.com/ascon/ascon-c/blob/fdfca408/crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
new_pass_test!(ascon_aead_reference_kats, "reference_kats", AsconAead128);
