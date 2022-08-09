// Uses the official test vectors.
use deoxys::aead::generic_array::GenericArray;
use deoxys::aead::{Aead, KeyInit, Payload};
use deoxys::DeoxysI256;

use hex_literal::hex;

#[test]
fn test_deoxys_i_256_1() {
    let plaintext = Vec::new();

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("50b0deaa3c3129d1ea1ef96b7c8db67f");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_i_256_2() {
    let plaintext = Vec::new();

    let aad = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("0e641b45bcffb3c07fa7f7d31edc37d2");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_i_256_3() {
    let plaintext = Vec::new();

    let aad = hex!("52d15808134c3c2e8acbc154299df5c6f86f48ec5dafa5363989b33ba7e0299565");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("f343b91c303180ae2ae4f379022087fa");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_i_256_4() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext = hex!("2c36c041fa3b1436c5153214131d493be9d014689a6a1e93e4a50989f0342941");

    let tag: [u8; 16] = hex!("ae66f78a3abf1bb7608c6fe949effb57");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_256_5() {
    let plaintext = hex!("9d63bc34aceebe70b21768e4f1cfd87bacbcae1e2577b6018de1d72707a42b2569");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext = hex!("fd1ea6745fb5b435751d92be58f5973b84c7589501fcfaff6ce07e2a0e9a72c23e");

    let tag: [u8; 16] = hex!("e957add57b7c5924d9a22db6fe03cce7");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_256_6() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = hex!("000102030405060708090a0b0c0d0e0f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: [u8; 32] =
        hex!("2c36c041fa3b1436c5153214131d493be9d014689a6a1e93e4a50989f0342941");

    let tag: [u8; 16] = hex!("6da67607bad9cdd34d702325d52abcdd");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_256_7() {
    let plaintext = hex!("8a968861ccb4aa1b7744ffff4812e001d1a749df3f66497c1c717681c43987b4eb");

    let aad = hex!("000102030405060708090a0b0c0d0e0f10");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext: [u8; 33] =
        hex!("705f9db5d50ec6ff0ae28557a5640d32b19504833d5fc6de3baf638cef4cda50bc");

    let tag: [u8; 16] = hex!("88f06bac360362824401c8f1385073a8");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_i_256_8() {
    let plaintext = hex!("d18db1b44ad16fe5623ccd73c250c27240daf512e97de1ca770983f262d36e1c9eafdf925c9786aeb556c1d058e1d3d0d92b8a5fed45bff46204f7cc1db8b23e69f271593f4c8427ee5660fad6edf209f903921c1eba5c884777be45ca7875c72e5b44b550dc30ee875798a19a0d61965bf9ec6a17bdebb91b9e503dbf70e5ec314e67d199296cd6375c510b04dbe30ac3b6a083f655627ab3859c168263babfbd5ca2f9c33df7deefd46f37693ba4350b69e3ddbde6b0d5711c4a0a7c8dcadf8b2340ed7a0748c3e9ef6ae72022fd3799b0561f00b255cdde1199b1c2def3b6324508f28b1f1935aeb1083072598d8cea7e420ad8ce090922fca2be67b68e0b8fe5db2f06faca945480f4831a6fd9bbeb40084403a8a2617184f8c9d3340c2720b19f838d64a82eff4b2020ee92a72291102487788d8f774a32d5b1a6752cd80118f400806fe613d312d8d65cc21f4af83b50407fedec7ed4972a54b8d2260cb652f3d9f3868d3081b20a719a1ff8611fe19ec41dc92570b74688506746cf96c7f5db878446b0fdcc554a1c3e7fa62b611077a65e29bb460699a6187fa4c52b91f58cc103a7dce86d3feefd9dcbc86fa5bf67b13fc0157c6da22d5dda3f0443a05b2d7b286b5da2372013f18a361cab696219d84f8677588d8500b7ebb34b29b1520258bcaa19f77229ddab6fcba75faaf4e09ecaa590e77e027477f5399b47");

    let aad = hex!("bbc9aa3017a7ee71293eb2ea451f2efa6794e41c55b7505df1f2073f5babe332a479619f855a39e45ef469b0c6329a786dbfc2b05b27983683d5edf26949cf964d75d7110bd4dba14a76f88353e3c652b46aca2f661d37dc7ffcf8da13c7aa48f25095ce16c8834c3d2c9c813197926d47c9f73895fdf70f2574d7f8539a9ef2aba78e80ec138ef1f702daf007ba337e1e0dfc49e6bd3f3eb4ff5a5c4e0ca2bdcf3e5b6fea5401dfaa40e66db6fc63a6e306755492684bbc6021e2a1bbf1245422377664475b22cdd83960e47852b474da196e67db018b87839966ffe52c665cabe0c021df68d0c1454505b0458fe3dc3acc6b8400ec04a3129266ae9368c15bbf13aabd05f859e2e9ea7cc937e899cc5c5bd72d2b72bd16d9024db4706fcf5195bbe25eb807fea01840f4b572f0fadb8a4246d6895547a37cd8a9b756425b31872a1d51c0ef2d53ca000711388228b76490780e3a10389c72ccc0deded32a5d9e723aa31dddd3344b068bcde9d483c9249375a88dce482a819361993fde555603cea01cede77fe64190906157ded418c3c21bc5274034b8d9edf09daf2aa90fb3b5f7d3b7da5c018144e54af9737227d2c13210c861fd5b4246d1a290fd054fd15d59d2e08894239d000b1076055771f7a7da54b2fcd7cd1f5a9e1da5a25a0ddbaa8d4397d74828a2b75a8da4730b87ac6c2fc5ef4985b9915320ea4942690df6");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("0001020304050607");
    let nonce = GenericArray::from_slice(&nonce[..8]);

    let ciphertext =
        hex!("e94c5c6df7c19474bbdd292baa2555fdbd5e90a35fb94627cdd7dd3b424ca47d6779f3e6997809204263bdbd4825b7d6510995b1c371e582942bd7f6ab909f993cd5b7db5f95e8b8b56e4cdf016f5cab37f662329b32801fda4403f731fa61f7aa16b9a23f2637b1f75fa0b36ced90ce6a1f73aafbb5adca756e0d59b8ae6661f2d3fc409c88d8baf3836fac55df78b9ba522221345f42bd794c26d5d1a83fed0114d1d1b04d3c3b77ff0083647710b316e17896b2081d9375fde1f2fe063e66423a0d413919ffa6b5754d10de8de64d32ede0d02ebe8f8791d8e9f59462b615f4122dd8c3b97671a8c156eb32ebebb3fb91832fd01f6afee9d4ab045fea83ec87743823ea3bd18f7826229c312ad8a4bc9e2f6d1ad520e6d850bd189b4538d10005abf5a7c50f4f8ded6a62b18cd2a7e6bd3159edc3e9b553cbddd419af540da10576e9ea7d49e2fd0dc1c5ee7693504b63b928e4e23b1753147a3d0ad00cc2e6390fba10e925dc536db4eb30cf152ddb0420f8e8eaa8460feb9a7f0be589ccb877732d8d606085536c405c2ba6c03cb68e12f7d14609587a6c478e2a32794290ba35ce6dba21784d8f6faf401920bfc2aa172c3b4d9bea2eae8542b18410d3a40414247a406379855cb78c28e82ab67b62433a4016b15c4abf4f01c372ba4f1562596531cb0337117ad769eaa666b497b7822eba924e358693bc48cf555f70");

    let tag: [u8; 16] = hex!("e404257c9cf7eb9774fc288a9ef1592e");

    let encrypted = DeoxysI256::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysI256::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}
