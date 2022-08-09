// Uses the official test vectors.
use deoxys::aead::generic_array::GenericArray;
use deoxys::aead::{Aead, KeyInit, Payload};
use deoxys::DeoxysII128;

use hex_literal::hex;

#[test]
fn test_deoxys_ii_128_1() {
    let plaintext = Vec::new();

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("97d951f2fd129001483e831f2a6821e9");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_ii_128_2() {
    let plaintext = Vec::new();

    let aad = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("3c197ca5317af5a2b95b178a60553132");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_ii_128_3() {
    let plaintext = Vec::new();

    let aad = hex!("a754f3387be992ffee5bee80e18b151900c6d69ec59786fb12d2eadb0750f82cf5");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: Vec<u8> = Vec::new();

    let tag: [u8; 16] = hex!("0a989ed78fa16776cd6c691ea734d874");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_deoxys_ii_128_4() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext = hex!("fa22f8eb84ee6d2388bdb16150232e856cd5fa3508bc589dad16d284208048c9");

    let tag: [u8; 16] = hex!("a381b06ef16db99df089e738c3b4064a");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_128_5() {
    let plaintext = hex!("06ac1756eccece62bd743fa80c299f7baa3872b556130f52265919494bdc136db3");

    let aad = Vec::new();

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext = hex!("82bf241958b324ed053555d23315d3cc20935527fc970ff34a9f521a95e302136d");

    let tag: [u8; 16] = hex!("0eadc8612d5208c491e93005195e9769");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_128_6() {
    let plaintext = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    let aad = hex!("000102030405060708090a0b0c0d0e0f");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: [u8; 32] =
        hex!("9cdb554dfc03bff4feeb94df7736038361a76532b6b5a9c0bdb64a74dee983ff");

    let tag: [u8; 16] = hex!("bc1a7b5b8e961e65ceff6877ef9e4a98");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_128_7() {
    let plaintext = hex!("039ca0907aa315a0d5ba020c84378840023d4ad3ba639787d3f6f46cb446bd63dc");

    let aad = hex!("000102030405060708090a0b0c0d0e0f10");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext: [u8; 33] =
        hex!("801f1b81878faca562c8c6c0859b166c2669fbc54b1784be637827b4905729bdf9");

    let tag: [u8; 16] = hex!("fe4e9bcd26b96647350eda1e550cc994");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}

#[test]
fn test_deoxys_ii_128_8() {
    let plaintext =
        hex!("95330042c3d48419798f9285fbd8d24968d7cee311f637463f8c0a1778f79d758a84e35b7d4a9fde2ed56fa796ad5a0f7004490ed32664ad69069678f53dfd7ee92e00a8ee34776b4d758536dc725ec4d48e2c11d0c5a16e4a2ce6c0e91604adb33a11127f50a46ea3cf5353d88a7a244c0f4337f449e68bf7c31feab02346d3c84c2335b8a06dc7df89dab05b6496fe428133c210c3bac68e18f026daa56662a41c36f9b55787fc1c5382d70b86e33be8555fd924606d2572c30a6ab6da71eccd4744ceb4e729519eef42ef4260db0e015832bfb0e742201fac36c711969a61243b08a77c372e44f76646fd1e9c9c06570447aa30527339baceb1d002e24e6ee3114f5a5daf0062bd372f824a60eebd74afc4fecffe74541933411b575295e27891abc71fc0e9597f65fc51be21962eea0aec96214b40a1a8ef32329df02a8b0ef038c48a1d5b2529ed01a820a6f262488de7791b07c5f941126be7893f7dadfb9639892264bc01af40402aa87a44df1754ce4e17226c41a8e3f05e4883d6ef4511e96378067f455f3a7275215622bfc71bb4db398b03b08e4bf6c54b2b6396c5b501fa26782fc36ad22044f5eb6a8f83efc8850d70ae4525d4e798f2aa1894621803394415f34cd4d002a2b3d393efa7d57f687b753830ff04798c240f05f581ce706f7d151417f09f17174cb87eff0e042c1860342b4ace069e1691e092e3");

    let aad = hex!("5b187979e145d7b5beebbc0e689e759a027b5588059419b06b1afe4224f8f56ecccb2bfe2cef9ecf103eb382172320a17c19dce14a3e38030d3443697845b992ff1e871c02e788d7b40264f52ef0733791dc82dacdfa987685b33423bed0c05e0a65bce48ce1006d16628ea21b4390e75be72e043f299d6290289f90007474bf4e9ffb6c774d762afec8f3a01b2db545611772c32386fe6c7332125f0750c4987988d1e0e727c3c295bc743a34d3196d5e2d14f11bf2c884265ba901e77144a4b5a77864ad082e945727786f376bfcae99048ee7a994a2ea87584cd2e7e83ffd0310cf9cdb2cff5cf8c9cc09c94becb3f37fb9b071a76ee7ae115a49f0d95b1a9ec97e5b62bcae2c3cf47a3d2cb1b3d3dcd1729c33266ad7b0899654949a6f09086b74297cb48227e566e1f401109495ea05d636a5025104cd04c2a3c59f396b858f7f025825baf667b29b4f7f692f3a6c0c8956575a8dd183d1d03bd372c214e005d6e1090d89f2d950b8ac856465943568bc320602f52bf67d30f0d8ec7a9550dcdef99a43404a6d32d8f6b537b3eed568e32ab7ee63e16be63009702995d4d9300114638ba4c874f02039f3f67e2df64946030edef1930f30d4e6b9ca95887539d1af2036c8f5cf129c54d5734224e09b3daab5fb0e74c848af70a49c1499a5e56bc5eea90395df5bfd3e84a1c0a5be02dd3f2e2353e5522aeadaafdbf44444");

    let payload = Payload {
        msg: &plaintext,
        aad: &aad,
    };

    let key = hex!("101112131415161718191a1b1c1d1e1f");
    let key = GenericArray::from_slice(&key);

    let nonce = hex!("202122232425262728292a2b2c2d2e2f");
    let nonce = GenericArray::from_slice(&nonce[..15]);

    let ciphertext=
        hex!("b8eddddb8d0042bb42fdf675bae285e504b90e4d73e02f99f790b2ffe7815dba40fe4c7bc886ce44505f6ac53d3bba5d3c73efd98daf4b7a5af250a5d100ff5558c211cb03a28d9519502d7d0fc85a6d73e618feb6b503af12cb0330bb9c5743b19996174a84dbf5bac38d10d207067e4ab211a62ad0f85dd8245dfb077443017b7847996fe7ed547b9e02051f1cbe39128e21486b4f73399d0a50d9a1111bed11ebb0547454d0a922633c83f0bba784571f63f55dc33f92e09862471945312d99e40b4ed739556f102afd43055497739a4b22d107e867cc652a5d96974ff785976c82bc1ff89731c780e84a257bb885cd23e00a7bdc7a68e0a1668516fb972721a777429c76cfd4adb45afa554d44a8932d133af8c9254fd3fef2bd0bb65801f2ffbf752f14eaa783e53c2342f021863598e88b20232a0c44e963dd8943e9a54213ffbb174b90e38b55aa9b223e9596acb1517ff21b7458b7694488047797c521883c00762e7227f1e8a5e3f11a43962bdccde8dc4009aef7628a96efa8793d6080982f9b00a7b97d93fd5928702e78427f34eb434e2286de00216b405c36105dc2e8dae68c3342a23274b32a6d2d8ac85239a8fa2947126f505a517fb18847104b21b0326b7fd67efb54f5d0b12b311ef998ebaf14939b7cdb44b35435eedf1ba5b07eea99533f1857b8cc1538290a8dbd44ca696c6bc2f1105451032a650c");

    let tag: [u8; 16] = hex!("e68a5de27beaeb6472611dfa9783602a");

    let encrypted = DeoxysII128::new(key).encrypt(nonce, payload).unwrap();

    let tag_begins = encrypted.len() - 16;
    assert_eq!(ciphertext, encrypted[..tag_begins]);
    assert_eq!(tag, encrypted[tag_begins..]);

    let payload = Payload {
        msg: &encrypted,
        aad: &aad,
    };

    let decrypted = DeoxysII128::new(key).decrypt(nonce, payload).unwrap();

    assert_eq!(&plaintext[..], &decrypted[..]);
}
