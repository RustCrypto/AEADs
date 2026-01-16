use aead::{
    AeadInOut, KeyInit,
    consts::{U12, U16},
};
use aes::Aes128;
use hex_literal::hex;
use ocb3::Ocb3;

const L_SIZE: usize = 16;
const MAX_SIZE: usize = 1 << (L_SIZE + 4);

#[test]
fn ocb3_len_check() {
    let key = hex!("000102030405060708090A0B0C0D0E0F").into();
    let nonce = hex!("BBAA9988776655443322110F").into();
    let cipher = Ocb3::<Aes128, U12, U16, L_SIZE>::new(&key);
    let mut buf = vec![0u8; MAX_SIZE];
    cipher
        .encrypt_inout_detached(&nonce, &[], (&mut buf[..]).into())
        .unwrap_err();
    cipher
        .encrypt_inout_detached(&nonce, &[], (&mut buf[..MAX_SIZE - 1]).into())
        .unwrap();
}
