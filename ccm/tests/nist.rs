use aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use ccm::{Ccm, consts};
use hex_literal::hex;

/// Example test vectors from NIST SP 800-38C
#[test]
fn sp800_38c_examples() {
    let key = hex!("40414243 44454647 48494a4b 4c4d4e4f");
    let nonce = hex!("10111213 141516");
    let adata = hex!("00010203 04050607");
    let pt = hex!("20212223");
    let ct = hex!("7162015b 4dac255d");

    let key = GenericArray::from_slice(&key);

    let c = Ccm::<aes::Aes128, consts::U4, consts::U7>::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    let res = c.encrypt(nonce, Payload { aad: &adata, msg: &pt }).unwrap();
    assert_eq!(res, ct);
    let res = c.decrypt(nonce, Payload { aad: &adata, msg: &ct }).unwrap();
    assert_eq!(res, pt);

    let nonce = hex!("10111213 14151617");
    let adata = hex!("00010203 04050607 08090a0b 0c0d0e0f");
    let pt = hex!("20212223 24252627 28292a2b 2c2d2e2f");
    let ct = hex!("d2a1f0e0 51ea5f62 081a7792 073d593d 1fc64fbf accd");

    let c = Ccm::<aes::Aes128, consts::U6, consts::U8>::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    let res = c.encrypt(nonce, Payload { aad: &adata, msg: &pt }).unwrap();
    assert_eq!(res, ct);
    let res = c.decrypt(nonce, Payload { aad: &adata, msg: &ct }).unwrap();
    assert_eq!(res, pt);

    let nonce = hex!("10111213 14151617 18191a1b");
    let adata = hex!("00010203 04050607 08090a0b 0c0d0e0f 10111213");
    let pt = hex!("
        20212223 24252627 28292a2b 2c2d2e2f
        30313233 34353637
    ");
    let ct = hex!("
        e3b201a9 f5b71a7a 9b1ceaec cd97e70b
        6176aad9 a4428aa5 484392fb c1b09951
    ");

    let c = Ccm::<aes::Aes128, consts::U8, consts::U12>::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    let res = c.encrypt(nonce, Payload { aad: &adata, msg: &pt }).unwrap();
    assert_eq!(res, ct);
    let res = c.decrypt(nonce, Payload { aad: &adata, msg: &ct }).unwrap();
    assert_eq!(res, pt);

    let nonce = hex!("10111213 14151617 18191a1b 1c");
    let adata = (0..524288/8).map(|i| i as u8).collect::<Vec<u8>>();
    let pt = hex!("
        20212223 24252627 28292a2b 2c2d2e2f
        30313233 34353637 38393a3b 3c3d3e3f
    ");
    let ct = hex!("
        69915dad 1e84c637 6a68c296 7e4dab61
        5ae0fd1f aec44cc4 84828529 463ccf72
        b4ac6bec 93e8598e 7f0dadbc ea5b
    ");

    let c = Ccm::<aes::Aes128, consts::U14, consts::U13>::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    let res = c.encrypt(nonce, Payload { aad: &adata, msg: &pt }).unwrap();
    assert_eq!(res, ct.as_ref());
    let res = c.decrypt(nonce, Payload { aad: &adata, msg: &ct }).unwrap();
    assert_eq!(res, pt);
}

#[test]
fn vpt128() {
    let key = hex!("2ebf60f0969013a54a3dedb19d20f6c8");
    let nonce = hex!("1de8c5e21f9db33123ff870add");
    let adata = hex!("e1de6c6119d7db471136285d10b47a450221b16978569190ef6a22b055295603");
    let pt = hex!("");
    let ct = hex!("0ead29ef205fbb86d11abe5ed704b880");

    let key = GenericArray::from_slice(&key);

    let c = Ccm::<aes::Aes128, consts::U16, consts::U13>::new(key);
    let nonce = GenericArray::from_slice(&nonce);
    let res = c.encrypt(nonce, Payload { aad: &adata, msg: &pt }).unwrap();
    assert_eq!(res, ct);
    let res = c.decrypt(nonce, Payload { aad: &adata, msg: &ct }).unwrap();
    assert_eq!(res, pt);
}
