// Uses the official test vectors.
use deoxys::aead::generic_array::GenericArray;
use deoxys::aead::{Aead, KeyInit, Payload};
use deoxys::DeoxysII256;

use hex_literal::hex;

#[test]
fn test_deoxys_ii_256_1() {
    let plaintext = Vec::new();

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("2b97bd77712f0cde975309959dfe1d7c");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_ii_256_2() {
    let plaintext = Vec::new();

    let aad = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("54708ae5565a71f147bdb94d7ba3aed7");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_ii_256_3() {
    let plaintext = Vec::new();

    let aad = hex!("f495c9c03d29989695d98ff5d430650125805c1e0576d06f26cbda42b1f82238b8");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("3277689dc4208cc1ff59d15434a1baf1");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_ii_256_4() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext = hex!("9da20db1c2781f6669257d87e2a4d9be1970f7581bef2c995e1149331e5e8cc1");

    let tag: [u8; 16] = hex!("92ce3aec3a4b72ff9eab71c2a93492fa");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_256_5() {
    let plaintext = hex!("15cd77732f9d0c4c6e581ef400876ad9188c5b8850ebd38224da95d7cdc99f7acc");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext = hex!("e5ffd2abc5b459a73667756eda6443ede86c0883fc51dd75d22bb14992c684618c");

    let tag: [u8; 16] = hex!("5fa78d57308f19d0252072ee39df5ecc");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_256_6() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = hex!("000102030405060708090a0b0c0d0e0f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: [u8; 32] =
        hex!("109f8a168b36dfade02628a9e129d5257f03cc7912aefa79729b67b186a2b08f");

    let tag: [u8; 16] = hex!("6549f9bf10acba0a451dbb2484a60d90");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_256_7() {
    let plaintext = hex!("422857fb165af0a35c03199fb895604dca9cea6d788954962c419e0d5c225c0327");

    let aad = hex!("000102030405060708090a0b0c0d0e0f10");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: [u8; 33] =
        hex!("7d772203fa38be296d8d20d805163130c69aba8cb16ed845c2296c61a8f34b394e");

    let tag: [u8; 16] = hex!("0b3f10e3933c78190b24b33008bf80e9");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_256_8() {
    let plaintext =
        hex!("83dab23b1379e090755c99079cfe918cb737e989f2d720ccaff493a744927644fec3653211fa75306a83486e5c34ecfe63870c97251a73e4b9033ae374809711b211ed5d293a592e466a81170f1d85750b5ca025ccd4579947edbae9ec132bfb1a7233ad79fae30006a6699f143893861b975226ed9d3cfb8a240be232fbf4e83755d59d20bc2faa2ea5e5b0428427485cca5e76a89fe32bdd59ab4177ad7cb1899c101e3c4f7535129591390ebdf30140846078b13867bbb2efd6cf434afe356eb18d716b21fd664c26c908496534bf2cde6d6b897799016594fb6d9f830ae5f44ccec26d42ff0d1a21b80cdbe8c8c170a5f766fad884abcc781b5b8ebc0f559bfeaa4557b04d977d51411a7f47bf437d0280cf9f92bc4f9cd6226337a492320851955adae2cafea22a89c3132dd252e4728328eda05555dff3241404341b8aa502d45c456113af42a8e91a85e4b4e9555028982ec3d144722af0eb04a6d3b8127c3040629de53f5fd187048198e8f8e8cc857afcbae45c693fec12fc2149d5e7587d0121b1717d0147f6979f75e8f085293f705c3399a6cc8df7057bf481e6c374edf0a0af7479f858045357b7fe21021c3fabdaf012652bf2e5db257bd9490ce637a81477bd3f9814a2198fdb9afa9344321f2393798670e588c47a1924d592cda3eb5a96754dfd92d87ee1ffa9d4ee586c85d7518c5d2db57d0451c33de0");

    let aad = hex!("3290bb8441279dc6083a43e9048c3dc08966ab30d7a6b35759e7a13339f124918f3b5ab1affa65e6c0e3680eb33a6ec82424ab1ce5a40b8654e13d845c29b13896a1466a75fc875acba4527ded37ed00c600a357c9a6e586c74cf3d85cd3258c813218f319d12b82480e5124ff19ec00bda1fbb8bd25eeb3de9fcbf3296deba250caf7e9f4ef0be1918e24221dd0be888c59c166ad761d7b58462a1b1d44b04265b45827172c133dd5b6c870b9af7b21368d12a88f4efa1751047543d584382d9ec22e7550d50ecddba27d1f65453f1f3398de54ee8c1f4ac8e16f5523d89641e99a632380af0f0b1e6b0e192ec29bf1d8714978ff9fbfb93604142393e9a82c3aaebbbe15e3b4e5cfd18bdfe309315c9f9f830deebe2edcdc24f8eca90fda49f6646e789c5041fb5be933fa843278e95f3a54f8eb41f14777ea949d5ea442b01249e64816151a325769e264ed4acd5c3f21700ca755d5bc0c2c5f9453419510bc74f2d71621dcecb9efc9c24791b4bb560fb70a8231521d6560af89d8d50144d9c080863f043781153bcd59030e60bd17a6d7aa083211b67b581fa4f74cce4d030d1e8f9429fd725c110040d41eb6989ffb1595c72cbe3c9b78a8ab80d71a6a5283da77b89cae295bb13c14fbe466b617f4da8ad60b085e2ea153f6713ae0046aa31e0ba44e43ef36a111bf05c073a4e3624cd35f63a546f9142b35aa81b8826d");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext =
        hex!("88294fcef65a1bdfd7baaa472816c64ef5bef2622b88c1ec5a739396157ef4935f3aa76449e391c32da28ee2857f399ac3dd95aed30cfb26cc0063cd4cd8f7431108176fbf370123856662b000a8348e5925fbb97c9ec0c737758330a7983f06b51590c1d2f5e5faaf0eb58e34e19e5fc85cec03d3926dd46a79ba7026e83dec24e07484c9103dd0cdb0edb505500caca5e1d5dbc71348cf00648821488ebaab7f9d84bbbf91b3c521dbef30110e7bd94f8dad5ab8e0cc5411ca9682d210d5d80c0c4bdbba8181789a4273d6deb80899fdcd976ca6f3a9770b54305f586a04256cfbeb4c11254e88559f294db3b9a94b80ab9f9a02cb4c0748de0af7818685521691dba5738be546dba13a56016fb8635af9dff50f25d1b17ad21707db2640a76a741e65e559b2afaaec0f37e18436bf02008f84dbd7b2698687a22376b65dc7524fca8a28709eee3f3caee3b28ed1173d1e08ee849e2ca63d2c90d555755c8fbafd5d2f4b37f06a1dbd6852ee2ffcfe79d510152e98fc4f3094f740a4aede9ee378b606d34576776bf5f1269f5385a84b3928433bfca177550ccfcd22cd0331bbc595e38c2758b2662476fa66354c4e84c7b360405aa3f5b2a48621bdca1a90c69b21789c91b5b8c568e3c741d99e22f6d7e26f2abed045f1d578b782ab4a5cf2af636d842b3012e180e4b045d8d15b057b69c92398a517053daf9be7c2935e");

    let tag: [u8; 16] = hex!("a616f0c218e18b526cf2a3f8c115e262");

    let encrypted = DeoxysII256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}
