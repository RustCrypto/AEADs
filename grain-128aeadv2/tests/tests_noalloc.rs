#![no_std]

#[cfg(not(feature = "vec"))]
#[test]
fn test_assert_no_alloc() {
    use assert_no_alloc::{AllocDisabler, assert_no_alloc};
    use grain_128aeadv2::aead::{AeadInOut, arrayvec::ArrayVec};
    use grain_128aeadv2::{Grain128, KeyInit};

    #[global_allocator]
    static A: AllocDisabler = AllocDisabler;

    assert_no_alloc(|| {
        // Init and load keys into the cipher
        let key = [0u8; 16];
        let nonce = [0u8; 12];

        let mut buffer = ArrayVec::<u8, 16>::new();
        for i in 0..7 {
            buffer.push(i);
        }

        let cipher = Grain128::new(&key.into());

        cipher
            .encrypt_in_place(&nonce.into(), b"this is authenticated data", &mut buffer)
            .expect("Unable to encrypt");
        cipher
            .decrypt_in_place(&nonce.into(), b"this is authenticated data", &mut buffer)
            .expect("Unable to decrypt");
    });
}
