// Uses the official test vectors.
use deoxys::aead::generic_array::GenericArray;
use deoxys::aead::{Aead, KeyInit, Payload};
use deoxys::DeoxysI128;

use hex_literal::hex;

#[test]
fn test_deoxys_i_128_1() {
    let plaintext = Vec::new();

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("eec87dce98d29d4078598abd16d550ff");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_i_128_2() {
    let plaintext = Vec::new();

    let aad = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("b507e4aee5f9d7cb9eaebd8370f25a98");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_i_128_3() {
    let plaintext = Vec::new();

    let aad = hex!("0429974cda6665fb9bb4b67d50859258dd69883d50c1eff4bd5962bf4038ad0497");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("fbb9c589e3a54df11e8573d94e6b1000");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_i_128_4() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext = hex!("4bf8c5ecec375b25acabd687aa605f1a8bb296face74f82527d4944dbb11b757");

    let tag: [u8; 16] = hex!("f32754de1727da4909413815a64e6a69");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_128_5() {
    let plaintext = hex!("5a4c652cb880808707230679224b11799b5883431292973215e9bd03cf3bc32fe4");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext = hex!("cded5a43d3c76e942277c2a1517530ad66037897c985305ede345903ed7585a626");

    let tag: [u8; 16] = hex!("cbf5faa6b8398c47f4278d2019161776");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_128_6() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = hex!("000102030405060708090a0b0c0d0e0f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: [u8; 32] =
        hex!("4bf8c5ecec375b25acabd687aa605f1a8bb296face74f82527d4944dbb11b757");

    let tag: [u8; 16] = hex!("a1b897f1901e5d98e17936ec1b4d85b3");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_128_7() {
    let plaintext = hex!("ee8f487e01f5a101dee6cfd5915d6b5b2c5b6305c782bc7e727bd08096e4208216");

    let aad = hex!("000102030405060708090a0b0c0d0e0f10");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: [u8; 33] =
        hex!("09af865850abc0bce7d35f664a63e41b1475d0385e31a6551edf69ea9f2f8b8ed4");

    let tag: [u8; 16] = hex!("9326c6c2a0b7f065e591eb9050169603");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_128_8() {
    let plaintext = hex!("1857d4edf080e8e2c83aa9e794ebf90d1ea0ccb977287a019aca3daa7af2ad5709d63f05b5b00f4b004b56e802d298ea78afd5d21fd2619248a0897b8e141dc6e1f8b49056d570571a294152a7d7387dbac1ab9ff799dbe0e6c3ae23a14908a3e48eb224824eee8ea4ee3b4ab1bd12a81e3a393ca1344fd9ca5309b116ab2e49e12020f1d6d3bbf608c4e33472c33c6a8d088124c0de4161d94833d75a9bfde908d57d182675c992ad8545198ad2565bac43ce1786e92ec01961c424c1b4c23bc97959ed185193c08e49c6741061e300c94216e505569bcc528f4ced786d1939b4568be157a4b9231b1baf19fc90ee35e97dbfb2965468c2882f1706c6ccec31be7759640c4a2a8a22ecac433eba2223d9685215a8e12bf262f4a72a8bb85ef4181b1d513218a657a24f2903da166f06abd27fbd757ad87473deb844c24e7f7a9295299580bdb1a99acf53a2cc3b1234fb9b0976b6b0ae42605536f46239d1ebd1283adf41f250761d54280e65d79e16200b16d899702530314c6eb5bcb0f1de6d61eaa7ea4c097075ac691754cb1eebbe7ff8cfc39000d9eca154ea37a9d635385b1e132ac3a0d3ffdc362b4333db6b56960cd0d86d02f08ea6e6e1e20a12b7d0b0fe897ab2fcb43f44afb2d42326b2d8d0531e6c9c64aae896caa74299c6d8e10a45360d67373aae7326a1b0484aa42e970510ecb02ca739c38183a43881e6");

    let aad = hex!("d4e7fc007c9f462d3c2f3ee1c2b92597a838be68930fcc770d3f4a6e8d3f245567c28772c7891c8a605e3f64dd584c264685794c23458c0faf8bbfc5925fe8278eaa1f35322b78c27fcfad42da7f1e9c4ab3aea98c236846690eeb63a26eb60f4cdaef83c3941b57b81529704e404444ed541269428baecd17f4e7f3bde62566b65b578eba069990e8fb10696d94e925ec41b9142de25cd30750cabd41d0a100bebe5eeada44caabff9ede3c251bb57bb48dfb90f7bb9f7d82f131ee20788ff3d9435f8c4f1590cd3cf2dbda143d8a6bcec5e95834578d46561ea209b4d29b1bb74c2c5d1f1bb765cd1d3a1e95984e7f257f4a8a91b3d3d587b43a4023593948d0a58fb1be920f493e5615abd2ecd38f45ed8c440c427a0d2eb76f91adee4c119ac980f28d87585a68039761dbea738a006ec0d9a7dde2ea873c4cf27c8b3565d776473f247b30198e62d4bc722b84d6260bb9e4b8c36dbf1ce6a2b91211bc25d1c0797c5b992920810e78ea6e474f69c9f14550eac375e896a2e5facebcf97bbf5bfdb547ef202222693b4c3120fe8a9559bee514e0b6d9a711a632a7d55398ddd8de66ef3b6f8dd8fa468d27ca455a5fcda20dd12aa426053e9f8454d9598e2d6a528aa4ffe272a4f1341e695dbb1b43bd720ab87ba62290e2d3f78a497a20d1bb0ed72430698b857774d6414ca856019660aba783ff9794d395c82de41a031a");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext=
        hex!("f86ecad0d69d2c573cdeee96c90f37ac3c861bd5f4d82ac7396dda102adfa7a94f1daab1e537f03b2a6665eaa8ee057eee403db7ced61adbd77b5c286b7afc5ec23f3f9333773f02d533b0c49ecfc6bcd359bc8a3db6ab16b423efc93e2591e5485a5b21a8cf9312a10d76c840bd1a7e9f5a9954cb636b01ebc8e91a550a0123a50883627d5535f0f6a7960f005d5f340e054ea145dd756e37efd91bc774f93d385da7135372bc51d0401e6499784618da55c31e0b7ad1aa09a3e002f3021ce02926c79741992d9d0252761a7ca6667a56f78e81eaf08cf36d4117d9b2349262d411bef955d7408562ed040e1ea85e3aa3dcf942ea5205edec164dbd6304f90da59b9fb4f8fdeb2c2df473f90494cf09c6af69d191abd7baf97058a3694872d01f63afc225e3796251375a7520a5f755b24b8fd153f362ff09c7e85f02e789ed8cf8adabfcde4c764ebdd703dee39b4e90a91ab0377e0bebc61b2ec9b3c4e3ac7fd893e13c5d0e303e7e625281c988a48dcfd9ee4b698a1c2a82927168e754c99338ea24d24b9bba11cdb4472badc038ab01f250d359c4ade703329062c6260d8fcfda3a6b50b641f9e1e5f2107fd6ca77140dba9048919cab4ea21e4178fde08e7213bf0b730c0415331775039e99f11146b0ebb99a8f5f2d2c4e1767b6fed9c7140dfcf01c793e88889cf34b4ecb044fc740f3d4a2cad1f93455cc36b9a0c6");

    let tag: [u8; 16] = hex!("5c89d78dbef3d727013b59af859f17da");

    let encrypted = DeoxysI128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}
