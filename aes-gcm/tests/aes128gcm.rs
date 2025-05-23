//! AES-128-auth tag tests

#![cfg(all(feature = "aes", feature = "alloc"))]

#[macro_use]
mod common;

use self::common::TestVector;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, AeadInOut, KeyInit, Payload, array::Array};
use hex_literal::hex;

/// NIST CAVS vectors
///
/// <https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES>
///
/// From: `gcmEncryptExtIV128.rsp`
const TEST_VECTORS: &[TestVector<[u8; 16], [u8; 12]>] = &[
    TestVector {
        key: &hex!("11754cd72aec309bf52f7687212e8957"),
        nonce: &hex!("3c819d9a9bed087615030b65"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("250327c674aaf477aef2675748cf6971"),
    },
    TestVector {
        key: &hex!("ca47248ac0b6f8372a97ac43508308ed"),
        nonce: &hex!("ffd2b598feabc9019262d2be"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("60d20404af527d248d893ae495707d1a"),
    },
    TestVector {
        key: &hex!("db1ad0bd1cf6db0b5d86efdd8914b218"),
        nonce: &hex!("36fad6acb3c98e0138aeb9b1"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("5ee2ba737d3f2a944b335a81f6653cce"),
    },
    TestVector {
        key: &hex!("1c7135af627c04c32957f33f9ac08590"),
        nonce: &hex!("355c094fa09c8e9281178d34"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("b6ab2c7d906c9d9ec4c1498d2cbb5029"),
    },
    TestVector {
        key: &hex!("6ca2c11205a6e55ab504dbf3491f8bdc"),
        nonce: &hex!("b1008b650a2fee642175c60d"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("7a9a225d5f9a0ebfe0e69f371871a672"),
    },
    TestVector {
        key: &hex!("69f2ca78bb5690acc6587302628828d5"),
        nonce: &hex!("701da282cb6b6018dabd00d3"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("ab1d40dda1798d56687892e2159decfd"),
    },
    TestVector {
        key: &hex!("dcf4e339c487b6797aaca931725f7bbd"),
        nonce: &hex!("2c1d955e35366760ead8817c"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("32b542c5f344cceceb460a02938d6b0c"),
    },
    TestVector {
        key: &hex!("7658cdbb81572a23a78ee4596f844ee9"),
        nonce: &hex!("1c3baae9b9065961842cbe52"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("70c7123fc819aa060ed2d3c159b6ea41"),
    },
    TestVector {
        key: &hex!("281a570b1e8f265ee09303ecae0cc46d"),
        nonce: &hex!("8c2941f73cf8713ad5bc13df"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("a42e5e5f6fb00a9f1206b302edbfd87c"),
    },
    TestVector {
        key: &hex!("cd332a986f82d98c215278131ad387b7"),
        nonce: &hex!("1d12b259f44b873d3942bc11"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("34238023648185d7ef0cfcf5836e93cc"),
    },
    TestVector {
        key: &hex!("80e1d98d10b27237386f029189ec0448"),
        nonce: &hex!("239ebab2f524fd62c554a190"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("4c0f29d963f0ed68dccf34496cf43d00"),
    },
    TestVector {
        key: &hex!("40650cdb61e3e19a1a98fb4e05377d35"),
        nonce: &hex!("69f0a81aaf6bb8486282f1b9"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("2657e12dec21c3ecf071af6179529fb4"),
    },
    TestVector {
        key: &hex!("1e89a6cd7528cce1e2b2b5f7fd2b6b52"),
        nonce: &hex!("e11fd427a782d543f78efc60"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("eeedff874c8edeea53e8be2a13afd81b"),
    },
    TestVector {
        key: &hex!("2a7ad6146676057db777dea4683d0d45"),
        nonce: &hex!("ed721ea67456d4594aafbd51"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("ee3cab5778888439d90fa718b75738ad"),
    },
    TestVector {
        key: &hex!("a364f494a4cd0147c34731074dc1a85b"),
        nonce: &hex!("4aa8470dd404e4054b30093a"),
        plaintext: &hex!(""),
        aad: &hex!(""),
        ciphertext: &hex!(""),
        tag: &hex!("d8a7bba3a451902e3adc01060c3c91a7"),
    },
    TestVector {
        key: &hex!("77be63708971c4e240d1cb79e8d77feb"),
        nonce: &hex!("e0e00f19fed7ba0136a797f3"),
        plaintext: &hex!(""),
        aad: &hex!("7a43ec1d9c0a5a78a0b16533a6213cab"),
        ciphertext: &hex!(""),
        tag: &hex!("209fcc8d3675ed938e9c7166709dd946"),
    },
    TestVector {
        key: &hex!("7680c5d3ca6154758e510f4d25b98820"),
        nonce: &hex!("f8f105f9c3df4965780321f8"),
        plaintext: &hex!(""),
        aad: &hex!("c94c410194c765e3dcc7964379758ed3"),
        ciphertext: &hex!(""),
        tag: &hex!("94dca8edfcf90bb74b153c8d48a17930"),
    },
    TestVector {
        key: &hex!("a82bb1edc7c01a3689006f34bfed783e"),
        nonce: &hex!("963836b67b188becf9ba1411"),
        plaintext: &hex!(""),
        aad: &hex!("9d115bb9bbd119fb777b6316065a9ac8"),
        ciphertext: &hex!(""),
        tag: &hex!("c491889fa3eca4544ba0d51b8e0f3837"),
    },
    TestVector {
        key: &hex!("b9782d0a5986c63f352d3bc4c7ecc96d"),
        nonce: &hex!("4541e15b92edea44eceb1f2a"),
        plaintext: &hex!(""),
        aad: &hex!("f1a9f0723429c5b26185ac3ea7e13d7a"),
        ciphertext: &hex!(""),
        tag: &hex!("74d0d36949f0276670f9ddc579e94f3a"),
    },
    TestVector {
        key: &hex!("59b95785b30f205679fc4f3f9a90102f"),
        nonce: &hex!("1908787cc1e1880a6ef5dd17"),
        plaintext: &hex!(""),
        aad: &hex!("39852d3182944a5177db277b63910702"),
        ciphertext: &hex!(""),
        tag: &hex!("8f9a96c013992485b43e2b62745ad173"),
    },
    TestVector {
        key: &hex!("34dd7926ab13d4078160d87de2e3c724"),
        nonce: &hex!("c11ccdaf798ab03af2d97ef9"),
        plaintext: &hex!(""),
        aad: &hex!("af698717a6d790b3bfc39195857bb5ff"),
        ciphertext: &hex!(""),
        tag: &hex!("48116050bbd9118270d0be252d29d5d4"),
    },
    TestVector {
        key: &hex!("8ec86fab55aaab0e77455e9cd3dbc78e"),
        nonce: &hex!("15fd90a9867e14f0d63b53b9"),
        plaintext: &hex!(""),
        aad: &hex!("e7509e276209a6d3ecfabb53ccdcd236"),
        ciphertext: &hex!(""),
        tag: &hex!("d96d6ac0d309cebedeba2af9f262132f"),
    },
    TestVector {
        key: &hex!("66b2473d9e0121666d47633f7008eb1c"),
        nonce: &hex!("c1716c68a24d57770b867e51"),
        plaintext: &hex!(""),
        aad: &hex!("c20f686317d67e53dd79bae5c46dc111"),
        ciphertext: &hex!(""),
        tag: &hex!("9a08616809cf15247dfeb9756ba4f609"),
    },
    TestVector {
        key: &hex!("5b262a9d00904d30a2587caade091381"),
        nonce: &hex!("f7bc154ca562e8f2c1845598"),
        plaintext: &hex!(""),
        aad: &hex!("23112d078c9914fa3dfe5218cd191016"),
        ciphertext: &hex!(""),
        tag: &hex!("98854d193a06dbe32ce4497eec5c9a8b"),
    },
    TestVector {
        key: &hex!("2e4fb9cc320188a6f1fa89a7a252273a"),
        nonce: &hex!("7a6d4ee69c7256c14fba8f5e"),
        plaintext: &hex!(""),
        aad: &hex!("80ba4a202a68c3590d6557912c6f878e"),
        ciphertext: &hex!(""),
        tag: &hex!("9280313273befb8afa0bceca5a966d85"),
    },
    TestVector {
        key: &hex!("5ea94973d8616dafa7f31db0716d1729"),
        nonce: &hex!("a05b62669d250e61b077d28a"),
        plaintext: &hex!(""),
        aad: &hex!("9620baf2f58d013f8a4c4871989c1b17"),
        ciphertext: &hex!(""),
        tag: &hex!("7e550398dee728256d6928cdaac43b73"),
    },
    TestVector {
        key: &hex!("910385f6f07f9e57e483c47dd5206bcc"),
        nonce: &hex!("518f56e33658df311d42d9fe"),
        plaintext: &hex!(""),
        aad: &hex!("5d157909a2a4607117e77da0e4493b88"),
        ciphertext: &hex!(""),
        tag: &hex!("a7041ea4a1d74d9e66b9571b59b6a1d8"),
    },
    TestVector {
        key: &hex!("cab3af7a15b430e034e793bb30db8ab2"),
        nonce: &hex!("963a56e2e12f387062e18498"),
        plaintext: &hex!(""),
        aad: &hex!("a094a1dd1121d3aa52c81e8f10bf9f0c"),
        ciphertext: &hex!(""),
        tag: &hex!("1a31d295601eb3c82a54b234984ffdf5"),
    },
    TestVector {
        key: &hex!("89c949e9c804af014d5604b39459f2c8"),
        nonce: &hex!("d1b104c815bf1e94e28c8f16"),
        plaintext: &hex!(""),
        aad: &hex!("82adcd638d3fa9d9f3e84100d61e0777"),
        ciphertext: &hex!(""),
        tag: &hex!("88db9d62172ed043aa10f16d227dc41b"),
    },
    TestVector {
        key: &hex!("a4d994c4ac5ac0f02913245714fbe235"),
        nonce: &hex!("a9472dadcca8d7e0e3b8084d"),
        plaintext: &hex!(""),
        aad: &hex!("eb318b9e17575203dd29ebed20ec82f9"),
        ciphertext: &hex!(""),
        tag: &hex!("323df7f33694106f56739de0973216a3"),
    },
    TestVector {
        key: &hex!("2fb45e5b8f993a2bfebc4b15b533e0b4"),
        nonce: &hex!("5b05755f984d2b90f94b8027"),
        plaintext: &hex!(""),
        aad: &hex!("e85491b2202caf1d7dce03b97e09331c32473941"),
        ciphertext: &hex!(""),
        tag: &hex!("c75b7832b2a2d9bd827412b6ef5769db"),
    },
    TestVector {
        key: &hex!("952117048f77e276c2ef6580537c1403"),
        nonce: &hex!("070b8fb46a7ad52885be1b26"),
        plaintext: &hex!(""),
        aad: &hex!("34b088f982818b5f07dabe2b62f9547f4ed09912"),
        ciphertext: &hex!(""),
        tag: &hex!("bedd4cf30fd7a4abc49bdcc3f3b248b1"),
    },
    TestVector {
        key: &hex!("7f6453b39bde018560a16a2704217543"),
        nonce: &hex!("0f3eecf48d68353226a77fe4"),
        plaintext: &hex!(""),
        aad: &hex!("11e4ecb256ebff56453fa2e75e43eb9d641049e6"),
        ciphertext: &hex!(""),
        tag: &hex!("b512623a12d5492b7d76d39be0df5777"),
    },
    TestVector {
        key: &hex!("9332e433bf6100c6cc23b08710627c40"),
        nonce: &hex!("aab3db3015b29d24f329beb4"),
        plaintext: &hex!(""),
        aad: &hex!("bd843a08f0a822f8f4f76c3648380aab7622e719"),
        ciphertext: &hex!(""),
        tag: &hex!("e54f1d18c61d8be15484727605b5a5dc"),
    },
    TestVector {
        key: &hex!("5773750a493096a99d84c0563fc293e9"),
        nonce: &hex!("c390ed70dc9497234413ad52"),
        plaintext: &hex!(""),
        aad: &hex!("6012517258716c1f0035efa60a0f36b5c65e7379"),
        ciphertext: &hex!(""),
        tag: &hex!("b011b264610e58082705476f040b8c86"),
    },
    TestVector {
        key: &hex!("41b0d0fce5d31359cfd5db4064e2d46b"),
        nonce: &hex!("b903e9d0cea25795a82e73e3"),
        plaintext: &hex!(""),
        aad: &hex!("4cba501876f33e1fda9cd456e3180683e3863bd9"),
        ciphertext: &hex!(""),
        tag: &hex!("18bc39d0b95cf059cd8c25004f5e507c"),
    },
    TestVector {
        key: &hex!("4748b782e3fe5e4effeb7c67232d2b07"),
        nonce: &hex!("c5e4dcf18f86076b88a5d5e9"),
        plaintext: &hex!(""),
        aad: &hex!("3b2fcad8739ed87e1d02e80845f120e249ea92b1"),
        ciphertext: &hex!(""),
        tag: &hex!("b8ae718e2879c9cb658d5d1122e69bb7"),
    },
    TestVector {
        key: &hex!("e30cc22077d5951216d07f37c51b58f9"),
        nonce: &hex!("fc583ad159b52e0b6378157e"),
        plaintext: &hex!(""),
        aad: &hex!("c3cb7be8888ef44ca5aa93dde26d2751288e1f5a"),
        ciphertext: &hex!(""),
        tag: &hex!("a8ce25b5dc8f84e2f5dae5f085aaccd4"),
    },
    TestVector {
        key: &hex!("7c8b10ba75ee6ab4a997d3f598b79d40"),
        nonce: &hex!("6fb55188ddf00dde09596587"),
        plaintext: &hex!(""),
        aad: &hex!("2ddc0acf9705f8d18f905b8f9d472e7dbf6b91e3"),
        ciphertext: &hex!(""),
        tag: &hex!("5791d3805109c5e18adff4e80906a018"),
    },
    TestVector {
        key: &hex!("72c7db6ca29f83641c3fff5b71c4bc30"),
        nonce: &hex!("f2000742e249ac56d5b2f65f"),
        plaintext: &hex!(""),
        aad: &hex!("cd994d2d08232770927d854ef2b6ca2f087370cf"),
        ciphertext: &hex!(""),
        tag: &hex!("a5966df39feeba0336f0b9a3f4ffe6c3"),
    },
    TestVector {
        key: &hex!("2833cc10195030e4a1155532666cb049"),
        nonce: &hex!("ad802b9a5c9409fa3e7dcfcc"),
        plaintext: &hex!(""),
        aad: &hex!("b3ecbea2797d006c07b8ce621be3b0eccd37c3ec"),
        ciphertext: &hex!(""),
        tag: &hex!("81deab8bdee0d391495eed4029a6d205"),
    },
    TestVector {
        key: &hex!("d8985bb5ac0258adad86660ebbc6d19f"),
        nonce: &hex!("b5ee26f8c463bbfc27115b0a"),
        plaintext: &hex!(""),
        aad: &hex!("613f51f832fbf434b8e3fe9454ae46a862d831f0"),
        ciphertext: &hex!(""),
        tag: &hex!("fe9f0b1bdc68dee6e8dc2ce12665d336"),
    },
    TestVector {
        key: &hex!("9b8f6924dc22f1073c1a38448a2f0447"),
        nonce: &hex!("09cdabf87d82828eca1c0c7f"),
        plaintext: &hex!(""),
        aad: &hex!("69210e4e0a1cfd5038756652790b9a8cfbbd943d"),
        ciphertext: &hex!(""),
        tag: &hex!("a60c104a6fb4638427a88a86c04923bd"),
    },
    TestVector {
        key: &hex!("72132213d5d95309bf7e10f8318d7c20"),
        nonce: &hex!("fb90bf283c5411230355d7a1"),
        plaintext: &hex!(""),
        aad: &hex!("a30bb17c8089c6f5f61b250a94cbbbfdf5f2a3e6"),
        ciphertext: &hex!(""),
        tag: &hex!("09191af418949fe6be8dbf13e006527a"),
    },
    TestVector {
        key: &hex!("652ffbad4e1fcbe75564395e6c1c3924"),
        nonce: &hex!("111349636d106fd5f6a1e088"),
        plaintext: &hex!(""),
        aad: &hex!("5f52aa85dc3ac042647e32ada050d67e59b519aa"),
        ciphertext: &hex!(""),
        tag: &hex!("28d980d7bfd878c227c140de3482765b"),
    },
    TestVector {
        key: &hex!("99e3e8793e686e571d8285c564f75e2b"),
        nonce: &hex!("c2dd0ab868da6aa8ad9c0d23"),
        plaintext: &hex!(""),
        aad: &hex!(
            "b668e42d4e444ca8b23cfdd95a9fedd5178aa521144890b093733cf5cf22526c5917ee476541809ac6867a8c399309fc"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("3f4fba100eaf1f34b0baadaae9995d85"),
    },
    TestVector {
        key: &hex!("f8e29efd00a423c4ea9456863f83c54f"),
        nonce: &hex!("2d3cf67cbce69d639bd1c092"),
        plaintext: &hex!(""),
        aad: &hex!(
            "02c70fc8a2544619c1c3e9fce6b3c6c3bc24643e0f140e6b48ac505ea666cd9a2010c3a8e2f5f10437887fe803b54db3"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("963cb50aca3e09dd0d9a013c8734155f"),
    },
    TestVector {
        key: &hex!("00e3491dfcf3bec39c89ccfd80a5a896"),
        nonce: &hex!("29f6ff4edc4ac3e97ffb1680"),
        plaintext: &hex!(""),
        aad: &hex!(
            "73813351b39f5e4000a9ee8d2b85f131634acaede0dd25d691a2b829ad4fe9ea699f12242519847cb083b0b4d3d8b3bc"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("01b2e9ba719ad77c753b364ecc5aabeb"),
    },
    TestVector {
        key: &hex!("0ad06f4c19af1d5f602b38f86e56291c"),
        nonce: &hex!("0b235c6a75cecdfcba9001ce"),
        plaintext: &hex!(""),
        aad: &hex!(
            "7d4f26f7895b2ef3da2e4f93e411cdb74025c7759c038d872344a45ce56d92a581862c3bace039090a2ccfa43b623dcb"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("b4bc9ce1475d0c93dfd5a5d8d45bd8e5"),
    },
    TestVector {
        key: &hex!("eeeb33e0c8a406ea236a075cdbe9d6f9"),
        nonce: &hex!("b935e8eed66227836ede189a"),
        plaintext: &hex!(""),
        aad: &hex!(
            "9a4291acb9924bba4241b0c9c3c2e1262b25a7c7f02c92adeadf92254d618ab59388aa30b47eafa58899c357cf281e31"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("143d6954eb6fe70aff70da978ccd4509"),
    },
    TestVector {
        key: &hex!("600b5442a0b550a38f85d2fb0acc9c96"),
        nonce: &hex!("5e65dd6e8b20d6b2931fe6c2"),
        plaintext: &hex!(""),
        aad: &hex!(
            "461e54a092f8392466849fb0370ae30c14c1bf3987ab2ebbe98e18d13f041d09d043f7aea78bfcc42f864a9fb40f0031"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("2cd626f9a0686300cf23c0bc597c63b4"),
    },
    TestVector {
        key: &hex!("ce8d1103100fa290f953fbb439efdee4"),
        nonce: &hex!("4874c6f8082366fc7e49b933"),
        plaintext: &hex!(""),
        aad: &hex!(
            "d69d033c32029789263c689e11ff7e9e8eefc48ddbc4e10eeae1c9edbb44f04e7cc6471501eadda3940ab433d0a8c210"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("a5964b77af0b8aecd844d6adec8b7b1c"),
    },
    TestVector {
        key: &hex!("ae7114c09ffa04298834412f6a8de453"),
        nonce: &hex!("f380c2d860be2af41e1be5c6"),
        plaintext: &hex!(""),
        aad: &hex!(
            "7e16082f689c63e8adddd5cb2da610bbfb88d073cf8b204384a937aab0376523a50d3d5f1392978f79609f12df8fc288"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("40d3a36358a6f6caaa6af92cfd874a22"),
    },
    TestVector {
        key: &hex!("d8f520b6f3cf6b835ce4cce48f4cb033"),
        nonce: &hex!("019a55c98615c022afff9644"),
        plaintext: &hex!(""),
        aad: &hex!(
            "c3fb518ddb2d73417e243359a0ed8c126750eb163e7bd845637159397075e3db1db72fe2f0e13b599c333c473feb2245"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("467cfad5af11852d6eca289c86f967ad"),
    },
    TestVector {
        key: &hex!("13ba95606b01af035bf961e39852e34b"),
        nonce: &hex!("9ec9cf3b002cfed9e761934f"),
        plaintext: &hex!(""),
        aad: &hex!(
            "bb9de563836d1f1b1de964514ecebb8ad10501db562280b7bd98804814735817908b2856cafadecd40b04832fbde2bfb"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("172a3bcbc5001dfd3815175a88f7056c"),
    },
    TestVector {
        key: &hex!("1c97da5fc5a9640f289622842408cba2"),
        nonce: &hex!("6d765a988e934588163e29b7"),
        plaintext: &hex!(""),
        aad: &hex!(
            "1026a590816d2e1aa67aa0d13d50a8413af4d8ee9b1fa5ceb8deacc9f41e8e764b3ac15f98295e8800adf6a7175448cd"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("4945a79d5edbb934c5cf94395c359deb"),
    },
    TestVector {
        key: &hex!("8dd46f271a201cc21ca0823248157e6b"),
        nonce: &hex!("1821b310ce2dba999cdf7576"),
        plaintext: &hex!(""),
        aad: &hex!(
            "34ba409997ceba065f4a5457078a9e232a84f594011aecfdbfbd24a802ca129e01cb1327e265b4a9004fb4c5003fffd3"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("304cc2cd2fcdd4abc844bc9c1cbe0241"),
    },
    TestVector {
        key: &hex!("0c545d95333b6acf8b2928f3efd083de"),
        nonce: &hex!("31de89d07e7577956fa95ef3"),
        plaintext: &hex!(""),
        aad: &hex!(
            "5574d65f5afffb2d31cca8f58cf5945b83553cd45d2dba0e05fa54e42aa3f5a051e1624de16d4b93cbab7988c6d95f8c"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("4ed91cfe90a49900e0565697bc82b659"),
    },
    TestVector {
        key: &hex!("790b39f301383a82b377f585d3bf0f26"),
        nonce: &hex!("2fd9c142b5fc62e87efff1fd"),
        plaintext: &hex!(""),
        aad: &hex!(
            "45634e0afc59ae9f6e30f7f5fe43cf5a4e1f78d0aebb9e5a7ad9d86f25278e521f4845d49d6cb533cac6439839647fd0"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("69637c3f9233da23f8df7b09e8cfb252"),
    },
    TestVector {
        key: &hex!("8f63652632d07b2a4a83c26dedd32657"),
        nonce: &hex!("747bee0e1d462a9016f1468d"),
        plaintext: &hex!(""),
        aad: &hex!(
            "9c00ff969b55a497dc523fa0cedaa339dc3c6ce18e61c7bf800c361201351bc49728c3bb15067e906162ee791b8d333a"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("bd5a0cbf859a6133a7f2d504d97cae05"),
    },
    TestVector {
        key: &hex!("20b5b6b854e187b058a84d57bc1538b6"),
        nonce: &hex!("94c1935afc061cbf254b936f"),
        plaintext: &hex!(""),
        aad: &hex!(
            "ca418e71dbf810038174eaa3719b3fcb80531c7110ad9192d105eeaafa15b819ac005668752b344ed1b22faf77048baf03dbddb3b47d6b00e95c4f005e0cc9b7627ccafd3f21b3312aa8d91d3fa0893fe5bff7d44ca46f23afe0"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("b37286ebaf4a54e0ffc2a1deafc9f6db"),
    },
    TestVector {
        key: &hex!("7aa53188a9c597126a10d248603ebb62"),
        nonce: &hex!("aa45ca5dac41a825c45d36bf"),
        plaintext: &hex!(""),
        aad: &hex!(
            "417fd5147d56de0c74329597824ec2788a344fb60b403edf0187afa12e72a05009bb70f83ccad11efa487c1965cf84feac067c1ffdbf531fca97c554f875c4a1a1d3ab3c53c8a74ef3ee9415a87e231699c82d764debeda18132"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("997bf84654bb9616c0cc9b45f82c7673"),
    },
    TestVector {
        key: &hex!("72b5848ed1d2badbd427e16fc3b3e44d"),
        nonce: &hex!("a84c7e928dc6e6379a513a20"),
        plaintext: &hex!(""),
        aad: &hex!(
            "1c0dfcecbd7bb0e680ce042d08b2d9a741267bd1da768df2ba08379233a9973f14928e9da6353768b9b2601c033fd964b16a16daaa3ea35ad7cef7e31eb1f7340aa34e8bfc08b0a6e6205292570ced43316876d0d499d9192e6b"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("270cd786b95e6820cdb65a231b7530ed"),
    },
    TestVector {
        key: &hex!("6d0512ebf2e73d63f42849c57f073fd0"),
        nonce: &hex!("c1c46927c74c03f19342c33a"),
        plaintext: &hex!(""),
        aad: &hex!(
            "28bf8903b2dfb7e69f1a735121c7efe9a4c42b6a295327bceb0246c85d782ce62bf075dbdf6e8ec6589c26d30696ccceef03870bd0abfd26d30600eafc65613740b54d777d379e8aacf241ecfba11b060186ac065db171aab099"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("a686f5941ceb510e126a6316e3404dc0"),
    },
    TestVector {
        key: &hex!("6438bc79520def5db58e49639774687a"),
        nonce: &hex!("d682b47418ceb5bc09c713c2"),
        plaintext: &hex!(""),
        aad: &hex!(
            "d252b164ae559ed155c8417b96652529df151f24ccf1ce98d0c7ddf293f4f1236630a19b24dc23978d3377a099065d0ba71d4bb8a7dc0cb76760ca7c4a0e12c8cb56c6102646323c08c4f4f56226fd5b71a84590913ad20da287"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("04e78796dbf42e9ffa6bb9e346581f13"),
    },
    TestVector {
        key: &hex!("117a0aa592fff17ae36c94917db16c65"),
        nonce: &hex!("c3537be6029d54ffefab2730"),
        plaintext: &hex!(""),
        aad: &hex!(
            "29e959b96817547ae06bf85fe164e82a2693f82a7aeb66d535f0d2c3bffd1ba18e94ef457939f0c0733eda4738d136380fc876075c4943220237a5929b01b32da2bc2a6afd6ae1d89fd470093835962ff6708bb39ba365202f56"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("b87fcc4d5c484e68ea52c01b55ffa438"),
    },
    TestVector {
        key: &hex!("5d995a338ed60f8ab0b59da6c9a40c52"),
        nonce: &hex!("2723c54e31c5c57f0236e816"),
        plaintext: &hex!(""),
        aad: &hex!(
            "239c80683feb6afd38f8759a27cb5f350fbc2f757838c40858c9d08f699cc56c4236f4a77bd80df0e8e41d5f9ba732db2e0a3a5e952ede7bfdd5fcbebd23d07271134db5b82461537c47e2ca51b348b0830f5ee575ad4b4414dc"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("94356a3bfaf07f2ef0ebe3a507076b16"),
    },
    TestVector {
        key: &hex!("c8a863a1ebaf10c0fc0e80df12444e6e"),
        nonce: &hex!("c3e8cdf086827fee7095d0ea"),
        plaintext: &hex!(""),
        aad: &hex!(
            "9927da88c5d336256699c76845e946dc53c87bf0e11e4bec9450981602b32010d2b52bfc91283a6329d455598998ede2e61e352e553110154b4da5ce668d664b83f671c010bf220b7d32b34f4ca69b66cc87233d792337cb2bff"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("098837de27707ea3593e31ceb8276732"),
    },
    TestVector {
        key: &hex!("69cc28b161f214a580e6ba4bc2e3de9d"),
        nonce: &hex!("f2a566f9cf83fd280c8fe08e"),
        plaintext: &hex!(""),
        aad: &hex!(
            "f8c5263a4e06b49e184589a1e071978643c353aa27b4817fe39e45abc442e22ab5d683bcee5dbbd589fa583f171bb59536addd2b6cefd49823413005efb2a665e26a6029c927d3891cb0d4f23e8ccc60cfd02ce8978c451ddc11"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("c9c806cb8b1a889809695c2ec5a7a86e"),
    },
    TestVector {
        key: &hex!("bbf35920fcab2cedaafdf3f00321f544"),
        nonce: &hex!("2c7ee3ff1df84f3650bc9298"),
        plaintext: &hex!(""),
        aad: &hex!(
            "a75f50ba9a50f48799594b6195b3125ed92df73144bfcb624ce67323d834ba1afaf0df4c6c022c11d48bd75c86675a5927ac1250030f720f97498d4fe0787bae655dc5537ac1bcac198a893f9af7c2ef9b971dd64f7e7b62603e"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("c7cd3f938f4ab18642d86234edfc17ed"),
    },
    TestVector {
        key: &hex!("9690de669702ba72aeb934f5ac50e03c"),
        nonce: &hex!("da8713fe2b2058c438aff260"),
        plaintext: &hex!(""),
        aad: &hex!(
            "f30ee950da37c7224b5c93e9a29cafdbf8e2070f65c226244b1a683459e0c5c11c9b77c8fc286d4298a5b9cd1fee3e13d4690a88780d35b558b5d9e52b1a67fc8857076691dca7f5fe8ef22065cc5d9c003ffd25ebe23e61440e"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("7f92914518ddbe842b06771f64c40f59"),
    },
    TestVector {
        key: &hex!("e5d8c6e2ac6935c85e81ee0ef723eacf"),
        nonce: &hex!("c73140ee90cc1dcf88457da2"),
        plaintext: &hex!(""),
        aad: &hex!(
            "f6c267a6ae5ce3cf4bcdf59cfd1f777c66133e0ec4772785f33e5fa800d310b24b5773bc603a76b30fc32328a8e40f02f823a813a9e4b4fac726e992c183bd0815111c1d3a35884a4eff32027ba60dba679b469af31bc50c0591"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("f938fd0d8c148d81765109df66dac9aa"),
    },
    TestVector {
        key: &hex!("e23458f6b304c2d8feb3dedd3741bc24"),
        nonce: &hex!("4619036b50ba012fe50be1d7"),
        plaintext: &hex!(""),
        aad: &hex!(
            "74bfdc6bc4bfc38d666b985cfe043c67798b2db98f149268dba24436cab83e9a91f244ffc5748c93f8df339ae24ba4318c50da011ab368d3167c16e503309b01351a11f14d067cc6769b9989c7d952e3315011ee2ea034db8cb8"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("6053ab80c746821ec50c97e5a1424a85"),
    },
    TestVector {
        key: &hex!("5372ac5d3b08d860919110bdeb7f31df"),
        nonce: &hex!("06ca979d8c250d9b7be45573"),
        plaintext: &hex!(""),
        aad: &hex!(
            "e1f958834e63c75c8c758bafaa2f257ea5689d0d55b877b4d67b8b73c25ce24e9b094b976db920a159968da9d33c511aa8999aba42b8bb886e6545dd108693150af357496bb5898b4e8f725d50ef474afb836a3358da2217bb93"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("9338e14fe0b08a969a104c828528a6a4"),
    },
    TestVector {
        key: &hex!("bf1cb49e980cec0b153fe3573875ac6c"),
        nonce: &hex!("5426669d25524036fbe81e89"),
        plaintext: &hex!(""),
        aad: &hex!(
            "b336949766e9948a7e6f36a2d377b84a25c4b4988794f3deab7af4b14a12dac641e25fe2ae9ff53450ace1513acd0b284a490b455f04f40af94418c8792ec1a0983fb1d9a31d93dc3ed2c75e6a6ce092111eabad039bac2a49f6"
        ),
        ciphertext: &hex!(""),
        tag: &hex!("e2996a2b3b6bf52217cfc4d0f5bb351b"),
    },
    TestVector {
        key: &hex!("7fddb57453c241d03efbed3ac44e371c"),
        nonce: &hex!("ee283a3fc75575e33efd4887"),
        plaintext: &hex!("d5de42b461646c255c87bd2962d3b9a2"),
        aad: &hex!(""),
        ciphertext: &hex!("2ccda4a5415cb91e135c2a0f78c9b2fd"),
        tag: &hex!("b36d1df9b9d5e596f83e8b7f52971cb3"),
    },
    TestVector {
        key: &hex!("ab72c77b97cb5fe9a382d9fe81ffdbed"),
        nonce: &hex!("54cc7dc2c37ec006bcc6d1da"),
        plaintext: &hex!("007c5e5b3e59df24a7c355584fc1518d"),
        aad: &hex!(""),
        ciphertext: &hex!("0e1bde206a07a9c2c1b65300f8c64997"),
        tag: &hex!("2b4401346697138c7a4891ee59867d0c"),
    },
    TestVector {
        key: &hex!("77b0a58a1e60541e5ea3d4d42007940e"),
        nonce: &hex!("ae7a27904d95fe800e83b345"),
        plaintext: &hex!("6931a3ea07a9e95207334f0274a454dd"),
        aad: &hex!(""),
        ciphertext: &hex!("76e39fad4000a07d35d879b785bd7fca"),
        tag: &hex!("5cb3724712f129f86b7927f13b45c835"),
    },
    TestVector {
        key: &hex!("caaa3f6fd31822ed2d2125f225b0169f"),
        nonce: &hex!("7f6d9041483e8c1412fa552a"),
        plaintext: &hex!("84c907b11ae3b79fc4451d1bf17f4a99"),
        aad: &hex!(""),
        ciphertext: &hex!("fdb4aafa3519d3c055be8b347764ea33"),
        tag: &hex!("89e43bfead01692c4ebe656586e3fbe3"),
    },
    TestVector {
        key: &hex!("02c8e81debc563e99cd262bfc64b0e11"),
        nonce: &hex!("b49057c9778d8c02fe00d029"),
        plaintext: &hex!("ca2a51e9d05e96e6f1d14ced36811c5c"),
        aad: &hex!(""),
        ciphertext: &hex!("5db602fb31bb9268d233bee0dd6b87ae"),
        tag: &hex!("789d2be2cc70b7c389b31912e1c0a041"),
    },
    TestVector {
        key: &hex!("4e625a3edc61f0cb2f002da8f8a70245"),
        nonce: &hex!("66d632dd5ca10b08d4d8f97b"),
        plaintext: &hex!("0b76d498add6e09c96d7694e5d620bd5"),
        aad: &hex!(""),
        ciphertext: &hex!("17bdc7ef5649bec9cf6c565ce33cf889"),
        tag: &hex!("3f7944bad062605f937ff6d6598a7651"),
    },
    TestVector {
        key: &hex!("41ab3fc488f8d4a820e65b9d41a87de3"),
        nonce: &hex!("9b5d27d75a0571e93f581885"),
        plaintext: &hex!("5ed0836e0a52777599800d4fe754ccbe"),
        aad: &hex!(""),
        ciphertext: &hex!("88c0eb8c33a10a22e7561866566b191f"),
        tag: &hex!("83e885802a594a8b008a94aa7ef06907"),
    },
    TestVector {
        key: &hex!("0047184240a5948ed55701eac2c4c26c"),
        nonce: &hex!("a3ab8da22648c2453cdef55b"),
        plaintext: &hex!("89ee9502871be15ee4a8c47ab123bfc9"),
        aad: &hex!(""),
        ciphertext: &hex!("8b5cb59e7ad2e15c40d5fbcde28a0d17"),
        tag: &hex!("538e79f880e2f65c72148f5ade4080a1"),
    },
    TestVector {
        key: &hex!("735c5a4ff2438852df3530c23590ac28"),
        nonce: &hex!("7bee7c6938f1ae59671e2ddb"),
        plaintext: &hex!("479e8d3bf0de4ce7cd4377d2ed3925cd"),
        aad: &hex!(""),
        ciphertext: &hex!("2ca09b58178fbbfb82556599b92329a3"),
        tag: &hex!("2e3cf2895f111ec2a86508c36a24e45d"),
    },
    TestVector {
        key: &hex!("016dbb38daa76dfe7da384ebf1240364"),
        nonce: &hex!("0793ef3ada782f78c98affe3"),
        plaintext: &hex!("4b34a9ec5763524b191d5616c547f6b7"),
        aad: &hex!(""),
        ciphertext: &hex!("609aa3f4541bc0fe9931daad2ee15d0c"),
        tag: &hex!("33afec59c45baf689a5e1b13ae423619"),
    },
    TestVector {
        key: &hex!("2d176607883aface75011d14818f1be6"),
        nonce: &hex!("02162c3635bf6d543e1cc148"),
        plaintext: &hex!("71905ad5df601d056effd80dd7333662"),
        aad: &hex!(""),
        ciphertext: &hex!("1b68598e1676d2cfd37aa00396fa9676"),
        tag: &hex!("5d060aa8a729774da001aa9fdef2b3d2"),
    },
    TestVector {
        key: &hex!("94fd0269a0ce813133626f93c4af7e6f"),
        nonce: &hex!("11fc3928028dfa34db06a1bc"),
        plaintext: &hex!("a1aefec976cd87cf8a4c21bbe902f7b4"),
        aad: &hex!(""),
        ciphertext: &hex!("b1baf8c58cdec88238b1b0ab0b40337d"),
        tag: &hex!("882f865df7da529f768d4944e8387f69"),
    },
    TestVector {
        key: &hex!("a7bec5e24f0db2629a257d02fdfaea02"),
        nonce: &hex!("9d2ec94b927327793583b818"),
        plaintext: &hex!("a17bc5d428700f94c641e74aaacf2c5d"),
        aad: &hex!(""),
        ciphertext: &hex!("d460fda5b24425b5caa8176c8c67b3a9"),
        tag: &hex!("0df724340b8ca56e8dea6bbeb4b55c35"),
    },
    TestVector {
        key: &hex!("39d945a00e05d70a16e61334d2010209"),
        nonce: &hex!("1f931448e9013ec4ec61af0c"),
        plaintext: &hex!("9dd90ebfc054da214cbb30db7f75c692"),
        aad: &hex!(""),
        ciphertext: &hex!("e4cb765408697cf85917a7a9264086e4"),
        tag: &hex!("fe9a1fe7a58d66e3b922693a163c1ff4"),
    },
    TestVector {
        key: &hex!("6620ca65f72de7b865de731928a4723e"),
        nonce: &hex!("e6428b6b77e9b6993b809aef"),
        plaintext: &hex!("7044f7c27d776f6a7d43abea35908de4"),
        aad: &hex!(""),
        ciphertext: &hex!("a1c5634a07d05ca909dba87bf02228e4"),
        tag: &hex!("d8b40a60a65237337db05b045de8074c"),
    },
    TestVector {
        key: &hex!("c939cc13397c1d37de6ae0e1cb7c423c"),
        nonce: &hex!("b3d8cc017cbb89b39e0f67e2"),
        plaintext: &hex!("c3b3c41f113a31b73d9a5cd432103069"),
        aad: &hex!("24825602bd12a984e0092d3e448eda5f"),
        ciphertext: &hex!("93fe7d9e9bfd10348a5606e5cafa7354"),
        tag: &hex!("0032a1dc85f1c9786925a2e71d8272dd"),
    },
    TestVector {
        key: &hex!("599eb65e6b2a2a7fcc40e51c4f6e3257"),
        nonce: &hex!("d407301cfa29af8525981c17"),
        plaintext: &hex!("a6c9e0f248f07a3046ece12125666921"),
        aad: &hex!("10e72efe048648d40139477a2016f8ce"),
        ciphertext: &hex!("1be9359a543fd7ec3c4bc6f3c9395e89"),
        tag: &hex!("e2e9c07d4c3c10a6137ca433da42f9a8"),
    },
    TestVector {
        key: &hex!("2d265491712fe6d7087a5545852f4f44"),
        nonce: &hex!("c59868b8701fbf88e6343262"),
        plaintext: &hex!("301873be69f05a84f22408aa0862d19a"),
        aad: &hex!("67105634ac9fbf849970dc416de7ad30"),
        ciphertext: &hex!("98b03c77a67831bcf16b1dd96c324e1c"),
        tag: &hex!("39152e26bdc4d17e8c00493fa0be92f2"),
    },
    TestVector {
        key: &hex!("1fd1e536a1c39c75fd583bc8e3372029"),
        nonce: &hex!("281f2552f8c34fb9b3ec85aa"),
        plaintext: &hex!("f801e0839619d2c1465f0245869360da"),
        aad: &hex!("bf12a140d86727f67b860bcf6f34e55f"),
        ciphertext: &hex!("35371f2779f4140dfdb1afe79d563ed9"),
        tag: &hex!("cc2b0b0f1f8b3db5dc1b41ce73f5c221"),
    },
    TestVector {
        key: &hex!("7b0345f6dcf469ecf9b17efa39de5359"),
        nonce: &hex!("b15d6fcde5e6cf1fa99ba145"),
        plaintext: &hex!("822ae01a0372b6aa46c2e5bf19db92f2"),
        aad: &hex!("72e9cb26885154d4629e7bc91279bb19"),
        ciphertext: &hex!("382e440694b0c93be8dd438e37635194"),
        tag: &hex!("2fa042bff9a9cd35e343b520017841bb"),
    },
    TestVector {
        key: &hex!("9db91a40020cdb07f88769309a6ac40b"),
        nonce: &hex!("f89e1b7e598cc2535a5c8659"),
        plaintext: &hex!("f4a5003db4a4ebbc2fdb8c6756830391"),
        aad: &hex!("70910598e7abd4f0503ecd9e21bdafb5"),
        ciphertext: &hex!("40d7fc4ccc8147581f40655a07f23ee9"),
        tag: &hex!("243331b48404859c66af4d7b2ee44109"),
    },
    TestVector {
        key: &hex!("e2f483989b349efb59ae0a7cadc74b7a"),
        nonce: &hex!("3338343f9b97ebb784e75027"),
        plaintext: &hex!("14d80ad66e8f5f2e6c43c3109e023a93"),
        aad: &hex!("8b12987e600ff58df54f1f5e62e59e61"),
        ciphertext: &hex!("43c2d68384d486e9788950bbb8cd8fd1"),
        tag: &hex!("47d7e9144ff0ed4aa3300a944a007882"),
    },
    TestVector {
        key: &hex!("5c1155084cc0ede76b3bc22e9f7574ef"),
        nonce: &hex!("9549e4ba69a61cad7856efc1"),
        plaintext: &hex!("d1448fa852b84408e2dad8381f363de7"),
        aad: &hex!("e98e9d9c618e46fef32660976f854ee3"),
        ciphertext: &hex!("f78b60ca125218493bea1c50a2e12ef4"),
        tag: &hex!("d72da7f5c6cf0bca7242c71835809449"),
    },
    TestVector {
        key: &hex!("2352503740a4e1b22dcc9c002f53bd11"),
        nonce: &hex!("474ecccc3182e03c80a7be74"),
        plaintext: &hex!("dc1c35bc78b985f2d2b1a13ce635dd69"),
        aad: &hex!("a1bc98dacec4b6aa7fee6dfa0802f21a"),
        ciphertext: &hex!("3f6f4daf6d07743b9bd2a069d3710834"),
        tag: &hex!("b9c2b319adbd743f5e4ffd44304a1b5f"),
    },
    TestVector {
        key: &hex!("fc1f971b514a167865341b828a4295d6"),
        nonce: &hex!("8851ea68d20ce0beff1e3a98"),
        plaintext: &hex!("2fec17b1a9570f6651bbe9a657d82bce"),
        aad: &hex!("ece8d5f63aebda80ebde4b750637f654"),
        ciphertext: &hex!("2d27e5fa08e218f02b2e36dfad87a50e"),
        tag: &hex!("eb9966774c588a31b71c4d8daa495e9e"),
    },
    TestVector {
        key: &hex!("00ef3c6762be3fbab38154d902ff43b5"),
        nonce: &hex!("c3c1c3079cda49a75a53b3cc"),
        plaintext: &hex!("be425e008e9b0c083b19a2d945c2ede9"),
        aad: &hex!("714fa1d6904187b3c5c08a30dffc86e8"),
        ciphertext: &hex!("c961a1758dcf91e539658372db18968e"),
        tag: &hex!("eaf9bda9b3322f501f7329cb61c1c428"),
    },
    TestVector {
        key: &hex!("2d70b9569943cc49cdef8495bdb6f0e6"),
        nonce: &hex!("b401d0f50880a6211fde9d9c"),
        plaintext: &hex!("47a87a387944f739bd3cb03e0e8be499"),
        aad: &hex!("592e7276bda066327f2b3cd8cc39f571"),
        ciphertext: &hex!("c1b2af4d273231e71e7e066c206bf567"),
        tag: &hex!("c68d8d3cf8b89e6b15f623d60fef60bd"),
    },
    TestVector {
        key: &hex!("775cb7f8dc73f04fe4f9d22126bb7b57"),
        nonce: &hex!("81ceb17deee19b8153ff927c"),
        plaintext: &hex!("8242c6c0eed6d5d1ab69cd11dbe361d0"),
        aad: &hex!("97e07cd65065d1edc863192de98bc62c"),
        ciphertext: &hex!("580f063ab1a4801d279e4ee773200abe"),
        tag: &hex!("29e4d7e054a6b0a4e01133573fbe632b"),
    },
    TestVector {
        key: &hex!("58ba3cb7c0a0cf5775002bf3b112d051"),
        nonce: &hex!("bb923c93ddca303ab131238d"),
        plaintext: &hex!("6b93d2d92de05b53769ec398ab8097dc"),
        aad: &hex!("0898ea55c0ca0594806e2dc78be15c27"),
        ciphertext: &hex!("d0564006b1897bf21922fef4f6386fd4"),
        tag: &hex!("3a92f3c9e3ae6b0c69dcb8868d4de27c"),
    },
    TestVector {
        key: &hex!("955b761de8e98f37acb41259fa308442"),
        nonce: &hex!("a103db8a0825e606b70427fc"),
        plaintext: &hex!("d18344c86caffc4237d2daae47817b13"),
        aad: &hex!("c2d0d8b77a6fd03ced080e0f89de8a4b"),
        ciphertext: &hex!("065d228c1289007a682aa847a36b6f30"),
        tag: &hex!("fb367f47922d67c84bf47aabb2b98421"),
    },
    TestVector {
        key: &hex!("d4a22488f8dd1d5c6c19a7d6ca17964c"),
        nonce: &hex!("f3d5837f22ac1a0425e0d1d5"),
        plaintext: &hex!("7b43016a16896497fb457be6d2a54122"),
        aad: &hex!("f1c5d424b83f96c6ad8cb28ca0d20e475e023b5a"),
        ciphertext: &hex!("c2bd67eef5e95cac27e3b06e3031d0a8"),
        tag: &hex!("f23eacf9d1cdf8737726c58648826e9c"),
    },
    TestVector {
        key: &hex!("e8899345e4d89b76f7695ddf2a24bb3c"),
        nonce: &hex!("9dfaeb5d73372ceb06ca7bbe"),
        plaintext: &hex!("c2807e403e9babf645268c92bc9d1de6"),
        aad: &hex!("fed0b45a9a7b07c6da5474907f5890e317e74a42"),
        ciphertext: &hex!("8e44bf07454255aa9e36eb34cdfd0036"),
        tag: &hex!("2f501e5249aa595a53e1985e90346a22"),
    },
    TestVector {
        key: &hex!("c1629d6320b9da80a23c81be53f0ef57"),
        nonce: &hex!("b8615f6ffa30668947556cd8"),
        plaintext: &hex!("65771ab52532c9cdfcb3a9eb7b8193df"),
        aad: &hex!("5f2955e4301852a70684f978f89e7a61531f0861"),
        ciphertext: &hex!("c2a72d693181c819f69b42b52088d3a2"),
        tag: &hex!("cadaee305d8bb6d70259a6503280d99a"),
    },
    TestVector {
        key: &hex!("196ed78281bb7543d60e68cca2aaa941"),
        nonce: &hex!("6e7d2c8f135715532a075c50"),
        plaintext: &hex!("15b42e7ea21a8ad5dcd7a9bba0253d44"),
        aad: &hex!("d6fc98c632d2e2641041ff7384d92a8358ae9abe"),
        ciphertext: &hex!("06e5cc81c2d022cb2b5de5a881c62d09"),
        tag: &hex!("28e8cad3346ce583d5eebaa796e50974"),
    },
    TestVector {
        key: &hex!("55fe8a1bdc6806ed2f4a84891db943a0"),
        nonce: &hex!("af4d0ba0a90f1e713d71ae94"),
        plaintext: &hex!("81315972f0b1aeaa005363e9eca09d7a"),
        aad: &hex!("677cd4e6c0a67913085dba4cc2a778b894e174ad"),
        ciphertext: &hex!("c47bcb27c5a8d9beb19fee38b90861b7"),
        tag: &hex!("e061ee4868edf2d969e875b8685ca8a9"),
    },
    TestVector {
        key: &hex!("6d86a855508657f804091be2290a17e0"),
        nonce: &hex!("65dce18a4461afd83f1480f5"),
        plaintext: &hex!("0423bd1c8aea943637c7c3b0ca61d54b"),
        aad: &hex!("e0ef8f0e1f442a2c090568d2af336ec59f57c896"),
        ciphertext: &hex!("53505d449369c9bcd8a138740ea6602e"),
        tag: &hex!("86f928b4532825af9cac3820234afe73"),
    },
    TestVector {
        key: &hex!("66bd7b5dfd0aaaed8bb8890eee9b9c9a"),
        nonce: &hex!("6e92bf7e8fd0fb932451fdf2"),
        plaintext: &hex!("8005865c8794b79612447f5ef33397d0"),
        aad: &hex!("60459c681bda631ece1aacca4a7b1b369c56d2bb"),
        ciphertext: &hex!("83b99253de05625aa8e68490bb368bb9"),
        tag: &hex!("65d444b02a23e854a85423217562d07f"),
    },
    TestVector {
        key: &hex!("e7e825707c5b7ccf6cfc009dd134f166"),
        nonce: &hex!("dd0c7a9c68d14e073f16a7a0"),
        plaintext: &hex!("88b1b11e47dfe2f81096c360cf1e30e7"),
        aad: &hex!("11c69ed187f165160683e7f0103038b77512460b"),
        ciphertext: &hex!("550fa499a7cb4783c1957288a5cc557f"),
        tag: &hex!("5d2c2f71a2e6ad9b3001bdbf04690093"),
    },
    TestVector {
        key: &hex!("92591b15e28ce471316c575f3963103a"),
        nonce: &hex!("2c30d215e5c950f1fe9184f6"),
        plaintext: &hex!("dc8842b3c146678627600742126ea714"),
        aad: &hex!("46e1bd5fa646e4605e2fbec700fa592a714bc7ef"),
        ciphertext: &hex!("a541d3d8f079bfe053ba8835e02b349d"),
        tag: &hex!("d322a924bf44809cb8cfe8c4b972a307"),
    },
    TestVector {
        key: &hex!("74f08353d4139ddad46691da888ee897"),
        nonce: &hex!("e2619217dc8b093e2c7c5b78"),
        plaintext: &hex!("1690d6c8f95ef5ac35c56e3129717b44"),
        aad: &hex!("92277cf78abe24720ce219bba3a7a339a2e011b2"),
        ciphertext: &hex!("b413557c0df29e3072bb1b326e2002dc"),
        tag: &hex!("3bb6273687ec6a3f4a0366f1b54bd318"),
    },
    TestVector {
        key: &hex!("5c951cd038a3c65cd65325bfdde86964"),
        nonce: &hex!("3bf5623fd1155f1036ea893f"),
        plaintext: &hex!("b609ec6673e394176dd982b981a5436b"),
        aad: &hex!("dc34014513fd0eede8e9ca44a16e400a5f89cdd0"),
        ciphertext: &hex!("009cf623e57a3129626a30489b730607"),
        tag: &hex!("1d202825db813c0fc521c284dd543fff"),
    },
    TestVector {
        key: &hex!("72301c093ba804671c44a6bf52839d9c"),
        nonce: &hex!("87cc7e6579cc92822f5744f6"),
        plaintext: &hex!("d59bbae4ff3e3755c0a61a9b6d3e234c"),
        aad: &hex!("f461946c4feba79c18366555d85311248d269c87"),
        ciphertext: &hex!("ee743d29dcbaa084fda91eb48b3be961"),
        tag: &hex!("07934a5372d41928f2ee7d4bb8c18982"),
    },
    TestVector {
        key: &hex!("39b4f826b520830941b3b1bcd57e41d5"),
        nonce: &hex!("ca32ac523fe7dfefe415cba1"),
        plaintext: &hex!("aa2b7a6c918ed6715441d046858b525f"),
        aad: &hex!("c586cd939b27821695b4ee4dd799fb0e3449a80e"),
        ciphertext: &hex!("8b64f5ea9a8cb521c66df9c74d4b7ecd"),
        tag: &hex!("3db56a792b67ac6d0c4001e17f446111"),
    },
    TestVector {
        key: &hex!("79449e5f670d55ee2d91ca994a267a8c"),
        nonce: &hex!("c779da00d672811d8a5124f1"),
        plaintext: &hex!("767e120debd8a1dc8d2db8b7f4750741"),
        aad: &hex!("54780846dc3df77c8d90c9f2decb0738da36fbda"),
        ciphertext: &hex!("eb864412add08abb4f89d72d412d0085"),
        tag: &hex!("494a547f617840267d3fed5280e3eb30"),
    },
    TestVector {
        key: &hex!("cc90c2f37f970f97ac97e3e3b88e8ae3"),
        nonce: &hex!("67bcc08f223f12107e4d9122"),
        plaintext: &hex!("b0fe0dcdcd526017f551da1f73ef9fe1"),
        aad: &hex!("065acdc19233af4be7c067744aabab024c677c5e"),
        ciphertext: &hex!("501cda2c954f830e8922c3d7405b5ee1"),
        tag: &hex!("9deee5d0e4778a9f770367f19c74daef"),
    },
    TestVector {
        key: &hex!("89850dd398e1f1e28443a33d40162664"),
        nonce: &hex!("e462c58482fe8264aeeb7231"),
        plaintext: &hex!("2805cdefb3ef6cc35cd1f169f98da81a"),
        aad: &hex!(
            "d74e99d1bdaa712864eec422ac507bddbe2b0d4633cd3dff29ce5059b49fe868526c59a2a3a604457bc2afea866e7606"
        ),
        ciphertext: &hex!("ba80e244b7fc9025cd031d0f63677e06"),
        tag: &hex!("d84a8c3eac57d1bb0e890a8f461d1065"),
    },
    TestVector {
        key: &hex!("cdb850da94d3b56563897c5961ef3ad8"),
        nonce: &hex!("841587b7174fb38fb7b3626e"),
        plaintext: &hex!("c16837cb486c04bd30dcae4bcd0bc098"),
        aad: &hex!(
            "de33e6d20c14796484293dff48caffc784367f4bd7b957512ec026c0abc4a39217af0db35be154c45833b97a0b6454df"
        ),
        ciphertext: &hex!("f41a9ba9ff296ebdbe3fdd8b1c27dcdb"),
        tag: &hex!("506cc2136c15238b0f24f61b520fb5e6"),
    },
    TestVector {
        key: &hex!("45551710464a9ea105a30e056167cfb0"),
        nonce: &hex!("5727688c9e74bcd23c14a345"),
        plaintext: &hex!("6adeaaa151b58c337471653c99affbdc"),
        aad: &hex!(
            "3eebcdc5c5e9970b3fca94bd0d28ead70d1f36a94f27780472bc3cc9ff39dd7b7e3a76ebce967d6ae5724ad904dc5548"
        ),
        ciphertext: &hex!("ec18f1d675dd056baeb374829ce45a33"),
        tag: &hex!("378bdc4c34753a1284b654af049b853a"),
    },
    TestVector {
        key: &hex!("c8650e8695396b84a3fdeea8f95c8215"),
        nonce: &hex!("5a1c26d3848910137df9f76c"),
        plaintext: &hex!("88aecd97435d97e2dff8763f640a5640"),
        aad: &hex!(
            "3dace39b7284ea2786a6bc670ced1c7cc0c28c4ae4e7494a6d834eb09260b68898b914d5a6b0b5334eff9669f233aeb8"
        ),
        ciphertext: &hex!("49a9398c70a89c0e43ce7a7bd7a90c58"),
        tag: &hex!("8509ef5fa8046a48a5f081e5215db2eb"),
    },
    TestVector {
        key: &hex!("76470ff92aaeeeb24172b823fce630b1"),
        nonce: &hex!("c70088e92633688bebe3265b"),
        plaintext: &hex!("ff4f74af151c292a0b35ba7049c9a5ad"),
        aad: &hex!(
            "a262fc02a3d0db113493d4179cc9ec806825f20f5864bb105c6116ea72f0284950ecc8a05dc548023853a657b67ce01e"
        ),
        ciphertext: &hex!("2404868e6bfee5ffe6ec851785618aab"),
        tag: &hex!("b338a9ccf10d45dfd4e0ccb8a87b3c1a"),
    },
    TestVector {
        key: &hex!("247b0330aa35a8a855142f933d182581"),
        nonce: &hex!("6df7990b60e41f1fac5f283f"),
        plaintext: &hex!("fa979c20be9f7f7e802fd5ca55c14618"),
        aad: &hex!(
            "0cec69d6f6532bf781f5b0fe70e33e1cd68f8b2019aa73951baf978bc1141b51083a8e5c785c994b12ffeca01b6c94f4"
        ),
        ciphertext: &hex!("ca4b66a09606caae8a100ce994da9452"),
        tag: &hex!("534188f439b929183d21109d962145ea"),
    },
    TestVector {
        key: &hex!("1ea5cdfe206130596b655bc6fb935fad"),
        nonce: &hex!("0ec93072e726ec58352d5a90"),
        plaintext: &hex!("1ac044b5f8b693fa236986ad1621edd8"),
        aad: &hex!(
            "d9da4741fda4821eb391a23f7f6b377bed923260b6f8c8ac9bbca4edef1bc2a48a45c8676cb598a668e28fe1103efa23"
        ),
        ciphertext: &hex!("33d387a3b73a590bfd78320ddad8c169"),
        tag: &hex!("ef36d6c01b5a54bf06ba218aa237fa54"),
    },
    TestVector {
        key: &hex!("d5a707d2e3163fbd9fba2f12e8dd980c"),
        nonce: &hex!("4a4ed3d33e5a1dd6befdb382"),
        plaintext: &hex!("639331ff4efaadc93e92e58de9e886ee"),
        aad: &hex!(
            "f5392e014cbe2d33cd0a0497cf0398883338748491a8543991990f9958e4a827e190e6f5ce89baac5f3bef91dcb5858b"
        ),
        ciphertext: &hex!("c986c4c805092a51103176b56507dd95"),
        tag: &hex!("5da4fe4e281e995d0c75587b4945ca85"),
    },
    TestVector {
        key: &hex!("3d2c604398c247e3ae7d90cc1e11f6cf"),
        nonce: &hex!("5dfafa52cbb52f57ac304381"),
        plaintext: &hex!("9c12cb73902608e7b2ea30da7397b66a"),
        aad: &hex!(
            "53e050b559308705376a23ee2b22b7642f06ab77a00259bf7bf28cf6665912af4b8901f8af76e982a8bcbafe5ea1aaf6"
        ),
        ciphertext: &hex!("7fe6b5a881c8a6b8e3e29f1a3819383b"),
        tag: &hex!("c528fddf8166a5c0ec3f0295b2c3d7a6"),
    },
    TestVector {
        key: &hex!("a335f0577c876e61d94522d526159f57"),
        nonce: &hex!("6ea85a74513f664a907fef80"),
        plaintext: &hex!("db38cf3bb14825a6c11ac978fb516647"),
        aad: &hex!(
            "038af270aece9687e34c55ec30494e9f72b6a90ac43280a9b8e958353d8c02a83ed163c6924b7201759615779cd5661e"
        ),
        ciphertext: &hex!("7e81df8bf0b671e89a639d6432d44952"),
        tag: &hex!("2180e6c8fe8fbb3394f9dfdc1c439d80"),
    },
    TestVector {
        key: &hex!("afb3ab51cf05e0cfa2ccc2c3c8f4b67f"),
        nonce: &hex!("26a5d1667feae062c14663bc"),
        plaintext: &hex!("26821b2fe21c26d20843af266fce1f16"),
        aad: &hex!(
            "130b15bde79749d0577bff6c98ab50f035abae041b0d5f666db27c262c0ed2a801c24feffcfe248cf3af5afcb6b0dd1a"
        ),
        ciphertext: &hex!("c5317ad695606124662453dbfb96a26d"),
        tag: &hex!("2ace2fa75daa31fe4f2020cea9e71ec6"),
    },
    TestVector {
        key: &hex!("0b4d033bf0182bb06f8b9714d525ee74"),
        nonce: &hex!("f0807dcca355aa339febada2"),
        plaintext: &hex!("7c90709d6ea3e586bbf11913bb2b5261"),
        aad: &hex!(
            "9cb373a8b7cc61eb382dfe1ea17d78877e9366207c3a5161a1f34b75ac503dc20e4af9d9962b7d4fb0f39ac9666c660c"
        ),
        ciphertext: &hex!("bfdde06e311240348f04277504fd75fb"),
        tag: &hex!("1dc5898c49e2dab4ae1a599547a76ab1"),
    },
    TestVector {
        key: &hex!("d32b7c3cb327780d1422116c40470ab0"),
        nonce: &hex!("fcc79573051011685ee0d9e1"),
        plaintext: &hex!("f015f4ab3bc159db9cf6b4bb6750db46"),
        aad: &hex!(
            "cdaae988d8bf01e24a4baf489893ee329b7d0dcfdef684fe3e382b200cbd5a7ea3e46be281b0c6cc00417d67f4d3db02"
        ),
        ciphertext: &hex!("48bec210f66942f877993e9486a678e7"),
        tag: &hex!("e4a3821709626cc3006c805a75f067cc"),
    },
    TestVector {
        key: &hex!("086a0cdd8d520a8a695d17e869e03efc"),
        nonce: &hex!("f0a463c0d1e28633da98b1e2"),
        plaintext: &hex!("ad6fbcf714ab893455eddb3c5fb406dc"),
        aad: &hex!(
            "aa7ebac61f7e0b9da0d941e801730a393b2728476dfd065e2f6ef4b343bc2ba6e17c59a2e5381597948a73ff25493f8e"
        ),
        ciphertext: &hex!("f0b1a368b832ed35d54c80067a06a2ae"),
        tag: &hex!("e3c80910db9ce1f3ad2519fe1ee2dfd7"),
    },
    TestVector {
        key: &hex!("e47e1e3a95627418ed659452a3c92d45"),
        nonce: &hex!("78adcf3f732dd3787cb5490b"),
        plaintext: &hex!("801efcab1e329a536a7b506c4a7509ec"),
        aad: &hex!(
            "41913a6c5c4dddae06f3c0f68e8ece139ca902fe340a820e7c40d895b35e8f4cba7809c7eed0b2b7ad45c6d152ec3053"
        ),
        ciphertext: &hex!("6751a4a5e0cc3c0f46cb5540937efde8"),
        tag: &hex!("7b07d21a4cbadeedcadce817d9ab81be"),
    },
    TestVector {
        key: &hex!("bd7c5c63b7542b56a00ebe71336a1588"),
        nonce: &hex!("87721f23ba9c3c8ea5571abc"),
        plaintext: &hex!("de15ddbb1e202161e8a79af6a55ac6f3"),
        aad: &hex!(
            "a6ec8075a0d3370eb7598918f3b93e48444751624997b899a87fa6a9939f844e008aa8b70e9f4c3b1a19d3286bf543e7127bfecba1ad17a5ec53fccc26faecacc4c75369498eaa7d706aef634d0009279b11e4ba6c993e5e9ed9"
        ),
        ciphertext: &hex!("41eb28c0fee4d762de972361c863bc80"),
        tag: &hex!("9cb567220d0b252eb97bff46e4b00ff8"),
    },
    TestVector {
        key: &hex!("11f47551416154006bf89e7594ea2082"),
        nonce: &hex!("d546fcd3ff2a6a17461e9e94"),
        plaintext: &hex!("d3783a3d7a1e091f9cb647bf45604457"),
        aad: &hex!(
            "49efdce48e821eb14eca5f1dd661f8b6b9a5a6917b08ec9486c29124ef1e7a9af2217494eecad3d8eef9fc22d29ce18d92006de1588c3b06f8db9fe809bede40908cef4f46d2c4b6f92ff5a8304362749143dab266de45bf5b4a"
        ),
        ciphertext: &hex!("e97988a6645b93a32e8296bb1dbcb8f9"),
        tag: &hex!("399345f974a82a2a75007c84aa08dc1a"),
    },
    TestVector {
        key: &hex!("0736a1f074919dfe23bf2a828eac2b26"),
        nonce: &hex!("5b2105166bcb15efc07f1c03"),
        plaintext: &hex!("402b5b45dbbef7f1d955423e95cda404"),
        aad: &hex!(
            "f331a6f6d31de69f116b27fcd7f914aa0b2c3a09490360e7863417a2346030cc99b6ba389e65e0f10fe0815d383e6f98dd8bb97d29908560ce98e4bf177e42e14a7137cfd30b7dcb4d8655b3c03514e95adf698645584475865a"
        ),
        ciphertext: &hex!("6e9e79e29f3085183e0a7ac7f6ba1d67"),
        tag: &hex!("84434e0c82b858ec27e61c54ecf6cd94"),
    },
    TestVector {
        key: &hex!("a3929d753fe45a6f326a85bb9f1e777f"),
        nonce: &hex!("aed85f89844f061113004d2c"),
        plaintext: &hex!("f024e796f449712b70d5c7fe5be5fe14"),
        aad: &hex!(
            "ecef72a7ae9e6bd15e63c8e9fb2a3a7c53eb9a88bc05296ff6f25544f681fff5289a099d38abb68316eed8215ead9ca0462065bee79fdb63b4405384053fdc68fe4124a883f50a2b4bc4df6e29383c2ceea424e4ac539b26c9ce"
        ),
        ciphertext: &hex!("349e770a7f7dc2fb41fa089bf723f6b6"),
        tag: &hex!("26f12bc8777d724fe59ad4fe2b9757f4"),
    },
    TestVector {
        key: &hex!("85abd6c7b90314b29bbd293ff113637e"),
        nonce: &hex!("f48f4ed2eb7b7aaeb017ee72"),
        plaintext: &hex!("542c6fa7e7cdaf21e6f6b34517f26ab5"),
        aad: &hex!(
            "2b825d477eb96e0d8d787ee4f284eca567fb5214b47e26705389cf9fce4b8dbc49a152df5e4accb0adaa19b37c90fe7d6eb456a067f1c2b63b61f6d596209f7ee96c85aa48f1870e9338743edff1d8ffb61dbdab88b6755fa135"
        ),
        ciphertext: &hex!("8374f96f03780724a8e8d1f11768d44f"),
        tag: &hex!("b41b53c46ae76eff505cfee47a8daaa3"),
    },
    TestVector {
        key: &hex!("0a2f29710feb7c86175a37c41e32fadd"),
        nonce: &hex!("b190fdb91061a08ef82100b8"),
        plaintext: &hex!("dfb6284ffd6cc195ed75db0c9faf5559"),
        aad: &hex!(
            "0af4d5c1ec517a1fc104aea7d513b591b603634fc558007e06d6cd22997407eb8281a742aef6e88ba08f10c64b423121d898bcd04c1f1d6c7c12d673aa1abb004a8525f1d7abc23c8724885179e292c0565a39d9f5c6d2369e37"
        ),
        ciphertext: &hex!("fb6cb6527b92dc2ef6a227e8067879aa"),
        tag: &hex!("e01037f6e9d62c18b163a714f85a92cc"),
    },
    TestVector {
        key: &hex!("470d577137c5014b78137dc6b24efa6d"),
        nonce: &hex!("4afa7f5766f8345a1b12042b"),
        plaintext: &hex!("4745cb9a3ee3a76ae166dad5a1b62b1c"),
        aad: &hex!(
            "cfdd5d42e0d0127a1c0d3c4bad302ef23ab63d879fad71109f4792e5b21156dafdcec022fc323028a9fbcafe0c3606ed61b582bfa00ba6e5c9a1b13b976d67c14c79905a769399d967b0dd45f0e74967b67d7bb67d9466618fa1"
        ),
        ciphertext: &hex!("ca58ced863696bf80ae0191de1252333"),
        tag: &hex!("246d451faab88511467e38b60c5b46c7"),
    },
    TestVector {
        key: &hex!("5cf9cfa4d367752f1354037e132bc948"),
        nonce: &hex!("13e6a286a6c7b189974d7ea3"),
        plaintext: &hex!("c7ef33e7abc8f298b2f224cf5218661d"),
        aad: &hex!(
            "65da4dbd6cef7fc8a09a766a6f5b474e9711a2d40faf841c467a8838e5c8cada3f1cca74ed3b4cdda6d5d334c91763e798b9c7891b291dbf46d89ddc728d72f93c95e081bc340448519aeccc6d105bf1696b7ff9c0b7c006444c"
        ),
        ciphertext: &hex!("ad88f4e7b980be05b3df0fc05a49d1eb"),
        tag: &hex!("0ad15378f18f4338966e8e17951d8dad"),
    },
    TestVector {
        key: &hex!("d1dafd9e07ab0f903a9b00d6e353d67f"),
        nonce: &hex!("8a96a0fe88f0c7e3077c38f4"),
        plaintext: &hex!("bbe4ccbd26522d35ca0d483341385e2b"),
        aad: &hex!(
            "d3e1ecd06f79e6839767d957c4d715b4228f4cbca7afa429d860c5db2a6bf4a3ade2d00b91875fedbf9b09e9ee5e69182f326fb36fcc35475efb32e5eada3a6fa6046c8d0c0ee933b0e7f37c87b3eb8b9c0c2b457f8695d25875"
        ),
        ciphertext: &hex!("9d016cd94933c07c10b92af40eafac7d"),
        tag: &hex!("022e2dd58ac862962e7fa0536bad87cb"),
    },
    TestVector {
        key: &hex!("da5236b254ee2ff5d7e73d7a09574177"),
        nonce: &hex!("d2d91f5c302212557fd62bce"),
        plaintext: &hex!("3aaa2a7b2605686c3444bb16df8c57a5"),
        aad: &hex!(
            "9ddfa05290e228e5eceb7e96de3a097afaa96d8d3e0d5ffc0e0116f43814f5b0947919267c2dbf0e5f52a97296e7826f2891dd4a043c845046c9ab9ae8327346c7695a72875b9062dd5578be8985edf9faa4917981aacc6f112f"
        ),
        ciphertext: &hex!("202a8e67d7f22ff83757fc9ef9b20a0f"),
        tag: &hex!("a55bab242a4ebe73b52cc7202f5cdd57"),
    },
    TestVector {
        key: &hex!("c3e577da2a2b7fdd05c99dc6fc81ccdd"),
        nonce: &hex!("dfa747b08f536915345766f0"),
        plaintext: &hex!("b863120426d4cbd5c73124c7b0342fa7"),
        aad: &hex!(
            "872a6d0e3a0a3b32f4c92a4e5baf7efb7270a9ab9cfcd3c1173a2fcb2c155a923f9d8b8e35a965b11d15e2e0cc591e953da81c172b8882344cff7b40eeaa30d4793900dd85cb65fbeae9d1d3b2a62c66cb932dac1e6806ab6150"
        ),
        ciphertext: &hex!("43da888047cb1cfc7dd42329310c8234"),
        tag: &hex!("f8267635aa7b51b89c80fa979861eb3f"),
    },
    TestVector {
        key: &hex!("69e1c0917ca8d49aa69f38cf9c66eb4d"),
        nonce: &hex!("0c55672336d219e64c60e15d"),
        plaintext: &hex!("7dac3e31269dd79399c94798f4bbc640"),
        aad: &hex!(
            "c1b423f27d794e947bc56aace3995065279221f5b8bef6568b5b2882209bf0dd7776e9ae6eb1a1eda0b768aeaaed9e3884cc3968b6d179e9e5abf08df8261c3ee54f8b0eaf2646cb221288a879c5ea4e9183805dc1da8a636a58"
        ),
        ciphertext: &hex!("37d215a13362bf087bcba8f95901eb05"),
        tag: &hex!("1b3eecb7ae9386dbc1409e70f5827f58"),
    },
    TestVector {
        key: &hex!("08818d516558631161e49eebd621f78d"),
        nonce: &hex!("f1f855eb8aeccc9ddf7aa80e"),
        plaintext: &hex!("1a89c9c9623a26b7c8062c5f6a5f7f98"),
        aad: &hex!(
            "68fedf6a42b780eeb011aa0b242636668e5c8941d6045b05c948f82c5db3977831435ab4049895b607e854f710e3d8b7a26afaa2e7913093313e93c3e106a8356d6c44579398ce4341aacb3b726e7f42fab75934920df230cb4b"
        ),
        ciphertext: &hex!("9e12e3842ff7f5c25a171cc4c5a3dfa8"),
        tag: &hex!("01cd4980d92df6739bedf22201a2cc12"),
    },
    TestVector {
        key: &hex!("bfa4a12b357605b11e65fa92b90d22fc"),
        nonce: &hex!("9aeb721b698db40dc9080e23"),
        plaintext: &hex!("9383358a4065f3e365924f7fa664012b"),
        aad: &hex!(
            "53bc66164811866e12ebcd64447c999777378119a257fe00d45b5c9392d5618f2c2c784696f5a9fea85d0f8c9cb5438b15b3f5661d49e0b0980ff61aeee0cdf650ab4fa82bcb0d0390f99daf02d8561bf5bca5627e3b194951ae"
        ),
        ciphertext: &hex!("df469d986744c33244682184912cdd68"),
        tag: &hex!("8c12f8338ffb7840e085fdedaa6ab3cc"),
    },
    TestVector {
        key: &hex!("e16a57c83f230c368a0f599a7ebf3f5e"),
        nonce: &hex!("2631b811ea57cb7d58fa232a"),
        plaintext: &hex!("2a37e380f575e4365116fe89a58ee8dc"),
        aad: &hex!(
            "d5bc101ad26f7d03999eac122f4e060f20a402ff8a2a0324a77754e1eb8b7a65f78743ac2ee34b5429ec9fd6120fe6d17e71f738cebf0ae39a5be5a4dde85384d98cd90d218785b08daa662f24187156118fba981b9691cf12f8"
        ),
        ciphertext: &hex!("9278d1eab07dc7fa68742059d9fdbe60"),
        tag: &hex!("27a474294ff811db4f6e0c88b1a86b0c"),
    },
    TestVector {
        key: &hex!("fe9bb47deb3a61e423c2231841cfd1fb"),
        nonce: &hex!("4d328eb776f500a2f7fb47aa"),
        plaintext: &hex!("f1cc3818e421876bb6b8bbd6c9"),
        aad: &hex!(""),
        ciphertext: &hex!("b88c5c1977b35b517b0aeae967"),
        tag: &hex!("43fd4727fe5cdb4b5b42818dea7ef8c9"),
    },
    TestVector {
        key: &hex!("6703df3701a7f54911ca72e24dca046a"),
        nonce: &hex!("12823ab601c350ea4bc2488c"),
        plaintext: &hex!("793cd125b0b84a043e3ac67717"),
        aad: &hex!(""),
        ciphertext: &hex!("b2051c80014f42f08735a7b0cd"),
        tag: &hex!("38e6bcd29962e5f2c13626b85a877101"),
    },
    TestVector {
        key: &hex!("5bd7362f38bafd33ff4068860eb35c27"),
        nonce: &hex!("6064368166c48633b090cb9a"),
        plaintext: &hex!("634852a6b68543ead889aa19ef"),
        aad: &hex!(""),
        ciphertext: &hex!("3a44f911376c371e6d597539d3"),
        tag: &hex!("452b67e9d36a9ec5a893272b4d2f2103"),
    },
    TestVector {
        key: &hex!("2591360228dd945aae8fba95dc2725c5"),
        nonce: &hex!("2adabc15c16e5c5954c8ab01"),
        plaintext: &hex!("c580b051600dd902b273e26677"),
        aad: &hex!(""),
        ciphertext: &hex!("9ac66aa93d7547bc0a45baf5ac"),
        tag: &hex!("a609413c9c13817287f39cfcf4da2e6e"),
    },
    TestVector {
        key: &hex!("3c85f64e35953f2caded63f987592611"),
        nonce: &hex!("7ad13cb40e21ee633251968f"),
        plaintext: &hex!("7bddb4037c2be00f4ef6f85ccd"),
        aad: &hex!(""),
        ciphertext: &hex!("9c2030e3e19e490c309610d889"),
        tag: &hex!("b0e4080a8dae54a6770f4e21d5324e90"),
    },
    TestVector {
        key: &hex!("7b8d32382d29c00198f1d41fc6b52b8c"),
        nonce: &hex!("bd65d7281a9a6aa9fc268f61"),
        plaintext: &hex!("10f27dabb9c9e9facbd21b13cd"),
        aad: &hex!(""),
        ciphertext: &hex!("707efbd54aabbecc22ee6b5304"),
        tag: &hex!("ca35f5dea869508653ce556c9c05d32e"),
    },
    TestVector {
        key: &hex!("dd95a8ca25883353aff5c414ad9ac5c0"),
        nonce: &hex!("be2ed3a4d38fa65cf341e5ee"),
        plaintext: &hex!("5b0c29c8bef219d52932b33041"),
        aad: &hex!(""),
        ciphertext: &hex!("4918ace25961fae06dbd891d16"),
        tag: &hex!("ae6f069accfacba61a38323dd65f4c02"),
    },
    TestVector {
        key: &hex!("4db01983f6ad9e39385070b810c26c80"),
        nonce: &hex!("2342dc3fb660e3925509b6ed"),
        plaintext: &hex!("5cef6c4f05073ae39e05356dc5"),
        aad: &hex!(""),
        ciphertext: &hex!("12e41f4373f1e5dcfcf758e2c8"),
        tag: &hex!("36fe1b8981946fd16cf12ad80f04d59e"),
    },
    TestVector {
        key: &hex!("8d59f931d4cf8a2683e269008ee86062"),
        nonce: &hex!("7ac862a09c3408b667e8cd38"),
        plaintext: &hex!("2c47413a8256f25677b1de8ef1"),
        aad: &hex!(""),
        ciphertext: &hex!("284ff4dfe4255f56b4a56585a7"),
        tag: &hex!("16c0a4a5826e291d4b3f7ead6892c392"),
    },
    TestVector {
        key: &hex!("01c681e2cf1d7c8484c3811201376187"),
        nonce: &hex!("56a8f48a3198b977f5064d02"),
        plaintext: &hex!("37dc0f572c9e51c6fc18642d7f"),
        aad: &hex!(""),
        ciphertext: &hex!("54922c65023605c1eba146d448"),
        tag: &hex!("dddbf654030e73be0dd6d26b67efd0e6"),
    },
    TestVector {
        key: &hex!("dae6cfda8979801d9399006797a2366b"),
        nonce: &hex!("1cb41dac13ffa72e72a405d0"),
        plaintext: &hex!("9f43ac53d4cec80dd29a902d86"),
        aad: &hex!(""),
        ciphertext: &hex!("e156a5f0711096cadd489937a7"),
        tag: &hex!("dfa2d2a342b78ac6e7276365f2fa6dc0"),
    },
    TestVector {
        key: &hex!("5146ebe3d1fdf166ffa4099b638c5b64"),
        nonce: &hex!("10014449817d881328c2b882"),
        plaintext: &hex!("700af6989527eb16ffab6634d2"),
        aad: &hex!(""),
        ciphertext: &hex!("8ab35c288f09084da3c0cbd240"),
        tag: &hex!("eec8232f2907b2e1cb2c940622530d25"),
    },
    TestVector {
        key: &hex!("cd70f86fc0a1780740fefef5742e4398"),
        nonce: &hex!("c2abd119f22d310b34f41c5c"),
        plaintext: &hex!("39fb497a2691264f02fcba4887"),
        aad: &hex!(""),
        ciphertext: &hex!("01339a3a9119836f6b038a1a50"),
        tag: &hex!("e45a0a12c84ebaaf1885f457507b9a5e"),
    },
    TestVector {
        key: &hex!("8828454ceefd9004e30ae8a03d71f9d1"),
        nonce: &hex!("8d9e3c61aa687a8f2b9ee30a"),
        plaintext: &hex!("a94b020f4724178a3f4f9137c5"),
        aad: &hex!(""),
        ciphertext: &hex!("c4a94f89e03305aa415c7b350c"),
        tag: &hex!("1acc1c75b9fc826af2e950cc7be6cf64"),
    },
    TestVector {
        key: &hex!("47982f133cb72342dd642f3475bde634"),
        nonce: &hex!("8304304acea2def778f2bf9e"),
        plaintext: &hex!("2c97a5fb6df85153a5c3bf414c"),
        aad: &hex!(""),
        ciphertext: &hex!("37e0962960edcf0a09a8538cac"),
        tag: &hex!("07459fa438e1f159a6649a8ed6f934b8"),
    },
    TestVector {
        key: &hex!("dfefde23c6122bf0370ab5890e804b73"),
        nonce: &hex!("92d6a8029990670f16de79e2"),
        plaintext: &hex!("64260a8c287de978e96c7521d0"),
        aad: &hex!("a2b16d78251de6c191ce350e5c5ef242"),
        ciphertext: &hex!("bf78de948a847c173649d4b4d0"),
        tag: &hex!("9da3829968cdc50794d1c30d41cd4515"),
    },
    TestVector {
        key: &hex!("3016620015db1d85eef09bbce50ae294"),
        nonce: &hex!("eb481db3a52201173e2d4ad7"),
        plaintext: &hex!("38b57c0d4151d7ee57e032829f"),
        aad: &hex!("fa3d95b81a619638cea3f68dfbc02133"),
        ciphertext: &hex!("7738601ab14748223164d1f69d"),
        tag: &hex!("63ca9e8c27d9fa837ca4a0bb7039e390"),
    },
    TestVector {
        key: &hex!("b3ba382909e94ef5d318ee32cb54a33e"),
        nonce: &hex!("3cf10b1700711486119cfd9e"),
        plaintext: &hex!("4a90ad3f97c9c7e82efcbb318b"),
        aad: &hex!("d1e17c0189b04561699bd2f791d69491"),
        ciphertext: &hex!("bdf6a8a11288e83126932cd946"),
        tag: &hex!("ca7ff7458c3adf388eef7e0e32d6b2c4"),
    },
    TestVector {
        key: &hex!("0a8fc9e07eb50b092cd9fccb3db2373e"),
        nonce: &hex!("371d0af80bb20f2ead09dc22"),
        plaintext: &hex!("7826bf01e962a201f5c8e7f742"),
        aad: &hex!("9f42976847531ddfe428694f61260b2a"),
        ciphertext: &hex!("665cdb3e2568ee1157d877dd25"),
        tag: &hex!("c66fc129ecb30ea0d54b6d6932d9d7a8"),
    },
    TestVector {
        key: &hex!("3d1fc93233e86cb882e4cd754df63754"),
        nonce: &hex!("1ede8cadc78bb4733c341bac"),
        plaintext: &hex!("74232bfedc377efd5a63ab77cc"),
        aad: &hex!("5807c856944fee1e6c2e70ad9a08de00"),
        ciphertext: &hex!("ff3e09311d59bf1f3dff474fd4"),
        tag: &hex!("7dbaf75ab6084504e080460ebfd255af"),
    },
    TestVector {
        key: &hex!("936ba9fc715c6e2d70a7986b14b82ce6"),
        nonce: &hex!("45b3239d045bd56ea5a0e77f"),
        plaintext: &hex!("941255369704ec192bab1cf039"),
        aad: &hex!("a2570d9548bd6c05f824577871784ee4"),
        ciphertext: &hex!("b3ead079446053a8206f4a37a6"),
        tag: &hex!("fa5d98f053e8520f45e1597ee38b3751"),
    },
    TestVector {
        key: &hex!("96a05889a7591c1918472fd26977451a"),
        nonce: &hex!("7d80492afefce80da6689ffc"),
        plaintext: &hex!("b09b2dc5c5463a03dd5c9b0ecf"),
        aad: &hex!("f4ffa36a478c795e0d28d37fa9e6fcc2"),
        ciphertext: &hex!("f7cb053d447dddcb6e3a2d891f"),
        tag: &hex!("2a38f63a1b7cdccec426683b34a44ff5"),
    },
    TestVector {
        key: &hex!("7c98567fb5ae9601fca412e72dc9fe2f"),
        nonce: &hex!("1218ce69073eefd25a7944e6"),
        plaintext: &hex!("0df75d39d8facc3accbdefc87c"),
        aad: &hex!("df4203c3402d2b328bcb44e7683e08ab"),
        ciphertext: &hex!("7e5ca0d1c1ff83bc3633f2301c"),
        tag: &hex!("7ea717458ca93d8844da5df7ef74005a"),
    },
    TestVector {
        key: &hex!("4e1b199c12f12b591c051c7edc608d11"),
        nonce: &hex!("a4bd3af7f35d0fa21f73641e"),
        plaintext: &hex!("051ed5d700a7e59990f0358928"),
        aad: &hex!("dae2cd749195bcfb67a663789e85995e"),
        ciphertext: &hex!("ae50359f104ba2089ae98eb45a"),
        tag: &hex!("c08a7cce7c38626604032d2be9bd519c"),
    },
    TestVector {
        key: &hex!("9491cb5d4f2b94cc5a50dc67bfedd074"),
        nonce: &hex!("8377399607418e8d51dac5ea"),
        plaintext: &hex!("2a1e50ccb5a52be3d338e8f0a6"),
        aad: &hex!("972d9c486961334afc104765c2863253"),
        ciphertext: &hex!("afe759b51318f67d872a1dfdae"),
        tag: &hex!("77a4493aed7e3a6e014d0a1a314c3f86"),
    },
    TestVector {
        key: &hex!("0993571183089c4a7bd8e8789854c265"),
        nonce: &hex!("d72ce6db33b33e2a2d430d2e"),
        plaintext: &hex!("daf7f3ec2e2592c65847734f40"),
        aad: &hex!("e47252d2a8ef5190faf328176588609b"),
        ciphertext: &hex!("c6fadec0c7520f717144f0104a"),
        tag: &hex!("6670c8cbf7e9eb431e899f61acccf456"),
    },
    TestVector {
        key: &hex!("d45b6c85293d609310eb3179cfbac4fb"),
        nonce: &hex!("b02328302cc469cda1c7eb48"),
        plaintext: &hex!("70f5af8c1da987f6ab5dea31de"),
        aad: &hex!("74ca5b46ab31a11b4b4c253666844b32"),
        ciphertext: &hex!("da6b359072accf5f036c85600d"),
        tag: &hex!("d8e496c53797b124e356967ee525c0ca"),
    },
    TestVector {
        key: &hex!("9326155a9b81013c1edb143f9f5ae9d2"),
        nonce: &hex!("c95383eb3050ebea4deb80e9"),
        plaintext: &hex!("aa80cbebfb01b035a4e1e50e35"),
        aad: &hex!("64a73f0497746436ac94c3c18e1ef6e1"),
        ciphertext: &hex!("45ec8de633c7bb585c0a7fea1f"),
        tag: &hex!("537b6103b0f7c5dce82bfa37c2734877"),
    },
    TestVector {
        key: &hex!("9192ce4d383752e9d9c66b93ef7f05ab"),
        nonce: &hex!("adabd3baa4374697c53b4289"),
        plaintext: &hex!("c55b5d16e3cee22bad1f5420ba"),
        aad: &hex!("14cad0cb1736ccde73f86897ea017570"),
        ciphertext: &hex!("3aa22a57646229fd33bbfae6ce"),
        tag: &hex!("5ce7cd439823538fbc194886348ff029"),
    },
    TestVector {
        key: &hex!("3dd104297e803dc22b8f11f1951c8508"),
        nonce: &hex!("8abd1fd8cd88ef848e8ce082"),
        plaintext: &hex!("e1eb53704ccd5d7992f1c91097"),
        aad: &hex!("96f6c82aa93ccca47056efc3ac971613"),
        ciphertext: &hex!("8e4125514870003f0b0e8044a8"),
        tag: &hex!("d951047cd8d50ca5f7ffdebf78725c56"),
    },
    TestVector {
        key: &hex!("fe0121f42e599f88ff02a985403e19bb"),
        nonce: &hex!("3bb9eb7724cbe1943d43de21"),
        plaintext: &hex!("fd331ca8646091c29f21e5f0a1"),
        aad: &hex!("2662d895035b6519f3510eae0faa3900ad23cfdf"),
        ciphertext: &hex!("59fe29b07b0de8d869efbbd9b4"),
        tag: &hex!("d24c3e9c1c73c0af1097e26061c857de"),
    },
    TestVector {
        key: &hex!("544ec82f837fbe561f371b266cc52ed5"),
        nonce: &hex!("b756952a0e98cf4cb024a499"),
        plaintext: &hex!("a2e81f78b8e3e39e6cdf2f2982"),
        aad: &hex!("cd0a24fd0f6a693a1578b9dfd2a212e990aa662b"),
        ciphertext: &hex!("a4f08997e2d93c3c622137f9a8"),
        tag: &hex!("059cf266240236fd3f41a3f4fabb36bf"),
    },
    TestVector {
        key: &hex!("91b73e2061b02b1e5e4c150ce1df4d27"),
        nonce: &hex!("8b15597c84db62e2d8b03857"),
        plaintext: &hex!("21e1b4b405050408b08e5e2a97"),
        aad: &hex!("eba7f1a060e81f4ae7a77346d74dae9263ec284c"),
        ciphertext: &hex!("0f819b25fc683c182533503ad8"),
        tag: &hex!("5a1da6290fef801f2131614f7cd2d0bf"),
    },
    TestVector {
        key: &hex!("e6a1e4260efb2bb3073a1ab475e901b9"),
        nonce: &hex!("be445fbabc3866d702965b08"),
        plaintext: &hex!("2897d77c7f20679cbf27181aca"),
        aad: &hex!("9452137225de644f94556b382ac13915e8261913"),
        ciphertext: &hex!("d56e2d6d52923205291fffa50a"),
        tag: &hex!("a6acf19c5434f95e333827ed9c7b88ec"),
    },
    TestVector {
        key: &hex!("49c18bed9412346a8ef02351cd4680d6"),
        nonce: &hex!("7b5a7e9beec5b627f78bfd1d"),
        plaintext: &hex!("bafe851c800f6df67e941fb496"),
        aad: &hex!("251b9e935d72c1ed05795c74c88b6d4a03bd729b"),
        ciphertext: &hex!("6f0c2eeb0a37d51d78314c3414"),
        tag: &hex!("1a75d962d34205d60f79e4de87381046"),
    },
    TestVector {
        key: &hex!("ed0334239eb6f1ee1d686df163d219b7"),
        nonce: &hex!("6146338e40fcd8bf264bc83b"),
        plaintext: &hex!("954ddf553bf66473657110a028"),
        aad: &hex!("cdba8eb5713075497eb5abf1434045a010f81832"),
        ciphertext: &hex!("3eb76dfd40c5ebc840951d1b28"),
        tag: &hex!("5d5aa1dc4a663eeb847e540f9a468155"),
    },
    TestVector {
        key: &hex!("14ab4d3a91e8f8320edba5b045b9474a"),
        nonce: &hex!("83c6ac97704afdd24fbe3eba"),
        plaintext: &hex!("de5f1521ce9423526932917863"),
        aad: &hex!("e3981ea2e7468973a6a998deb7676d06630bad47"),
        ciphertext: &hex!("19936ae7d6620899649a5c7887"),
        tag: &hex!("66a805353bde0b1315f772d49eeaf8f2"),
    },
    TestVector {
        key: &hex!("f822c39eaba3ebb3d8b58cff3845ac59"),
        nonce: &hex!("1f5d11c469e9fb74f19d8581"),
        plaintext: &hex!("c0fac87ca518ab22853c8fa02b"),
        aad: &hex!("b33871f65233bb2ba773cd8fedb517179a2a24a5"),
        ciphertext: &hex!("a072381956210925148e3bc55d"),
        tag: &hex!("f716ec012f7f9be988a9e450da7aa2fe"),
    },
    TestVector {
        key: &hex!("c566e9995c03a777f9999446382ef2fc"),
        nonce: &hex!("4f343477387f48b9c6d15e69"),
        plaintext: &hex!("a9eafd8903c71862c7c99cf068"),
        aad: &hex!("c2b73bf0d1abd6d484df725a760f184bc315e0ba"),
        ciphertext: &hex!("9f9551a3ad017c3fa518964704"),
        tag: &hex!("15383fb8ace2e001c194474031c14e87"),
    },
    TestVector {
        key: &hex!("fa2fe01b7cb4ca24aba5880da268398a"),
        nonce: &hex!("93f19d0a8edf1f29364743f2"),
        plaintext: &hex!("006c3b0681f21ad705cf94d070"),
        aad: &hex!("e80f337eb56c336d1e928db3b7eeee968e2f75bd"),
        ciphertext: &hex!("a73b314c7f0bbd79ee56bd77bb"),
        tag: &hex!("d2f9ecc80a5ae2e1d2735b9fbf01be25"),
    },
    TestVector {
        key: &hex!("77b34970d4300069e0092cd64ad17305"),
        nonce: &hex!("d88e76814f3cf7a2f887e371"),
        plaintext: &hex!("4e65a46a4579f08130272e5c83"),
        aad: &hex!("7c772010e83befec22f6aebe8e18a0437f50a573"),
        ciphertext: &hex!("d2d8ffd3f841e6039f1d551905"),
        tag: &hex!("ee2c73c455081d84a631b18a7fe5f789"),
    },
    TestVector {
        key: &hex!("3c1c2aae3954d6f645ce2a697a4f3af8"),
        nonce: &hex!("04b54f6447ebbcfbda57445a"),
        plaintext: &hex!("f73e226b50a75558a389ccd738"),
        aad: &hex!("e7a9d5c8328278311dca3e84da2bf0f573198d4f"),
        ciphertext: &hex!("770e4b798b91850ec4e90136ca"),
        tag: &hex!("8cb9ce2c90417f1c49a235de9b2ada2d"),
    },
    TestVector {
        key: &hex!("15ca2910df4e43c44a7c01d485b99157"),
        nonce: &hex!("4a65ca77dde14bbf131dd597"),
        plaintext: &hex!("786744b394e40bfe5db938c0ad"),
        aad: &hex!("f9011e2cfb9c82d37f6b3f2af730a2e28c036f2c"),
        ciphertext: &hex!("43c00fac7c11c3273078f09fe2"),
        tag: &hex!("955beaa87737d3094bacc42a15986d83"),
    },
    TestVector {
        key: &hex!("998990fe4a9a6c56efdf1deac41a1ef5"),
        nonce: &hex!("1b7a766436f4a674b5ed86ab"),
        plaintext: &hex!("e53a9954c3943691dee5b17991"),
        aad: &hex!("2eba6f2c61704917434507f4a2db16c4906bb4e5"),
        ciphertext: &hex!("e5682045f438f4a96ac870690b"),
        tag: &hex!("1afddc03809e565321ea66d8c83a324a"),
    },
    TestVector {
        key: &hex!("268ba76816d00e20997da268bd8faa18"),
        nonce: &hex!("21cd5d21ed193612fd6db854"),
        plaintext: &hex!("16339986d092027e7cbece0fb6"),
        aad: &hex!("1971b90da0554ee7b6b0a5e9a782f05d511c1b99"),
        ciphertext: &hex!("7cfd53b8c3c834c213d9860499"),
        tag: &hex!("1f8522bfab97bec436d768332ae37c20"),
    },
    TestVector {
        key: &hex!("cbd3b8dbfcfb11ce345706e6cd73881a"),
        nonce: &hex!("dc62bb68d0ec9a5d759d6741"),
        plaintext: &hex!("85f83bf598dfd55bc8bfde2a64"),
        aad: &hex!(
            "0944b661fe6294f3c92abb087ec1b259b032dc4e0c5f28681cbe6e63c2178f474326f35ad3ca80c28e3485e7e5b252c8"
        ),
        ciphertext: &hex!("206f6b3bb032dfecd39f8340b1"),
        tag: &hex!("425a21b2ea90580c889134032b914bb5"),
    },
    TestVector {
        key: &hex!("a78f34cd0cac70aab64acae18e3cbeee"),
        nonce: &hex!("3c88570498da96e7b52c7929"),
        plaintext: &hex!("bf61b1fb3b24506cc8c730d399"),
        aad: &hex!(
            "36b66ff81ec23a28944c98d2834cc764bb70703f0b26e079b6eb008ec11ccfb54a189ad393878f0824436ae69e7e2d8c"
        ),
        ciphertext: &hex!("f72057f873ad12b5e19ce433e0"),
        tag: &hex!("1fea5b4176464b1f5dce11558a75ec21"),
    },
    TestVector {
        key: &hex!("0e038a1368999e2e70b6e350e01684bd"),
        nonce: &hex!("a58952b8135420cd0f61be18"),
        plaintext: &hex!("801bbabf908ff04d5856cadc2b"),
        aad: &hex!(
            "765203b3d61537be2883fba9899c3f3eff60cb9714e54de3a78a96dbf29cf53d82112e19b10141f13b11627a8fa55026"
        ),
        ciphertext: &hex!("7f0f35cb15fb4e7e3820d9ab1f"),
        tag: &hex!("8dce643720d9d6f90f13a155e0be5936"),
    },
    TestVector {
        key: &hex!("b69d82e78b22a473af6234066b891778"),
        nonce: &hex!("0415ab2f32d2a15006c3bdd5"),
        plaintext: &hex!("d4ab346edaca5c84d45b45c6fe"),
        aad: &hex!(
            "f0be65105e1cd4fd1a272f7f6db958040b44edd0608b2225789cf34217cfcd6a5879b8e79dfa7d24345ad20f0c4f9a1c"
        ),
        ciphertext: &hex!("ad77c91c6ba6cb29eb5e4f6071"),
        tag: &hex!("f67061dbded1a8df55fe9fcd68f61168"),
    },
    TestVector {
        key: &hex!("78faf937758f34b6d314e2fa30f60c2e"),
        nonce: &hex!("85c9ef0e17ebcbb7227ba4c1"),
        plaintext: &hex!("0ad91a8be4ccd6ee0ce75413a3"),
        aad: &hex!(
            "70fec6e608b6264228b822e7490e5e76398494c6489de5e839fb80513442cd0dfcf883000995185213e283f49234280b"
        ),
        ciphertext: &hex!("4298d0a1ea4c54950021d91921"),
        tag: &hex!("19893b83fd24a8c21bb4ff14612cdb27"),
    },
    TestVector {
        key: &hex!("f812627cb6dc5921d3567dd17f1f3b9a"),
        nonce: &hex!("37beb9c060f240d9ff78c844"),
        plaintext: &hex!("dbce5235bccd0bc6249b30e9b1"),
        aad: &hex!(
            "a27fd811330efa672bbfa1cb2a221fa45bab88c5183eed6383e34c7e7450fd577f6c783c75d9ecaf74bb2ad2b2e8c143"
        ),
        ciphertext: &hex!("100ab04960a762db73174666b4"),
        tag: &hex!("122172ee3093b8cb238a7c991da3b94f"),
    },
    TestVector {
        key: &hex!("a495f82751bf7781fee36d265607aa6b"),
        nonce: &hex!("729a513baf1ccd1c97311700"),
        plaintext: &hex!("0ac413fa533b01be459e95d784"),
        aad: &hex!(
            "3a44a7ea6d3ed13005d46c19f5ec7d2f7e50e8a268fc49e3c6fe15b41b6f6ea7245d88cb358e53cdba82cf297ea0ea97"
        ),
        ciphertext: &hex!("d05f52a875f56d3a6971495b7b"),
        tag: &hex!("14ae378a5f75b386202194c677377803"),
    },
    TestVector {
        key: &hex!("63eed2623c80ea1c5d06a0003c4b3065"),
        nonce: &hex!("3a276f4361cc6d7bdb340986"),
        plaintext: &hex!("65067b281d5aafc0146d206fe2"),
        aad: &hex!(
            "d484646fdca9f5d3d4fa2c85ed145f99e3c73f4d81f6c08eadf318694bd7cc94382cc73a5610f9cbfd9987dc167d670c"
        ),
        ciphertext: &hex!("4cf2ff71e44a39eb6a9611e150"),
        tag: &hex!("113e7d239946d784c331bccd5e098194"),
    },
    TestVector {
        key: &hex!("3ad85304b4267dd603070c1a999eb658"),
        nonce: &hex!("2a02a6220d395dc91fa0d220"),
        plaintext: &hex!("e0620a9e28ad8dba32b601c662"),
        aad: &hex!(
            "7a1511cab8aa9f7277f7b26cdee602e4a608b5565a20eedd66d70507a90e79da6521cae1e2ca810771392567af51d883"
        ),
        ciphertext: &hex!("cf38f7abaf4f92414ecb7021a8"),
        tag: &hex!("8bebb0b62c81a4a3ae765dbc7c8747a8"),
    },
    TestVector {
        key: &hex!("63010b75ada3ccd0c1338613d57e3f53"),
        nonce: &hex!("9898b912da0a2f169c3bf907"),
        plaintext: &hex!("fc10d85cb5485be263374aaadf"),
        aad: &hex!(
            "565e1e581089098451ccaf1d594d1b4edbdcd5cb00ba4b2e08e4db780ce8258df41d01dbdd50521b75a72a8259f70321"
        ),
        ciphertext: &hex!("8f2390e88bc6f18ecdc1a1b9d2"),
        tag: &hex!("15c40e98b6bd5b07d4757727ad6b7b71"),
    },
    TestVector {
        key: &hex!("d2a18188bb88312ec18916431b6dd880"),
        nonce: &hex!("aedf2efb80b633d7afbe5a51"),
        plaintext: &hex!("343f8363662077fb0ab50ba284"),
        aad: &hex!(
            "52492921f6b76e888baa5a4cb391af04faeb31bf00e8ed4363482fa95148f573b9adbebabf48d3ad33cb5ed3c0d6df61"
        ),
        ciphertext: &hex!("97a6f44a04055850779bc70842"),
        tag: &hex!("5ffb75b58b4572366fb006455f692f93"),
    },
    TestVector {
        key: &hex!("7b3b81fa87f6fc20795e5fe33fe0d1e8"),
        nonce: &hex!("b858127e11ea0d5ba523f7ce"),
        plaintext: &hex!("e574920cdba3524bac8c2294bf"),
        aad: &hex!(
            "c23d4cf74bd76adee0973e4b3ac31a96fdeb0f2455e044d2d1b82ebd1937e09623921c81b6a1b9698b5b097b7c5c483d"
        ),
        ciphertext: &hex!("016a7b57db778fd019628016f6"),
        tag: &hex!("e8035022b05e4c10792321d195b75854"),
    },
    TestVector {
        key: &hex!("852c34591e7ffef09259a9edf25020e1"),
        nonce: &hex!("9e4243f5356d48f853cc3acb"),
        plaintext: &hex!("c991389c242c48e31a9ae00d59"),
        aad: &hex!(
            "8a4514a5e7d4e2e036490b541206bfe6471c14bb50af6fc869048bae954b5dd813429359ee5eef23ee42ea35e0c36bb8"
        ),
        ciphertext: &hex!("5c319983e5e276658f10a58edb"),
        tag: &hex!("5343086d4ac0e45e4adc6dc27d566296"),
    },
    TestVector {
        key: &hex!("b9840f1c04f7c9e9b2c9bec0c6176738"),
        nonce: &hex!("7af462cc891270fe78566890"),
        plaintext: &hex!("c9171685284b205bf4fd9d3f45"),
        aad: &hex!(
            "493ef83c18389c1e52050d2569f0d6f955cf8e76cf0a1697ffcb1665e285fe6e3595f456cff7f32feb7bde4cc82d4ebb"
        ),
        ciphertext: &hex!("988c2c3df37c68fc8bc7a29b11"),
        tag: &hex!("d81b0bc3543fef4a929867bff63a1c17"),
    },
    TestVector {
        key: &hex!("9449043071de904f5e6e7922b263f122"),
        nonce: &hex!("39f0713e60cbc8e41e4d7328"),
        plaintext: &hex!("869a917e056f4460d6c2076d10"),
        aad: &hex!(
            "0b7a25e3e3027095772f3f8b8336813b607031eddd6f354a171e4b585504952cb51326c3edf4c48e41498da441cc090f"
        ),
        ciphertext: &hex!("cc878c8f760961e4ad08ad09a5"),
        tag: &hex!("c303c9680b673c049e9b7bec8c28428b"),
    },
    TestVector {
        key: &hex!("e5b1e7a94e9e1fda0873571eec713429"),
        nonce: &hex!("5ddde829a81713346af8e5b7"),
        plaintext: &hex!("850069e5ed768b5dc9ed7ad485"),
        aad: &hex!(
            "b0ce75da427fba93da6d3455b2b440a877599a6d8d6d2d66ee90b5cf9a33baaa8329a9ffaac290e8e33f2af2548c2a8a181b3d4d9f8fac860cc26b0d26b9cc53bc9f405afa73605ebeb376f2d1d7fcb065bab92f20f295556ade"
        ),
        ciphertext: &hex!("c211d9079d5562659db01e17d1"),
        tag: &hex!("884893fb035d3d7237d47c363de62bb3"),
    },
    TestVector {
        key: &hex!("1b96a8699f84058591f28590a5e63c0e"),
        nonce: &hex!("d437b28673240ddc63d22d2b"),
        plaintext: &hex!("802192b9c2d78e1df9ac223598"),
        aad: &hex!(
            "0f985a66d350c153a4882d0a4fc6e1b8b8450cd0825182358521b1be5fc734338af72a48170fde7512a8a92ac81d12e3a7fdcf7d98933732a9893d92d9435fcaee6033b726d28f73c5f76fd6b93d13bc8904d11cd4a713cd353f"
        ),
        ciphertext: &hex!("8c13cded61d08c1f2db878378e"),
        tag: &hex!("43ee877c121d4a329e81e51d68a9d845"),
    },
    TestVector {
        key: &hex!("94874b6f3738d963577553a19155f4fa"),
        nonce: &hex!("8e9f61edc853db24fb162062"),
        plaintext: &hex!("ab5fa8933bf8b4b6eb8fd4a0f6"),
        aad: &hex!(
            "d30b11456b68d89dfecc00930c5102cabdb207abadfc7e26286e822a14c6e723ea5492ef53cc2206dbe9860583e2fd2a8ed26fcf5dba8914cae4829ff83745bcf203c2c9729ec5f635d368f8697139b18f1c39ea4e3e849f4b3f"
        ),
        ciphertext: &hex!("e359459af9418493dd8af46d27"),
        tag: &hex!("4dd94f3b128f34ddd4036886fa084506"),
    },
    TestVector {
        key: &hex!("7434e4ec0aa26aa89f7a025b7cabee6b"),
        nonce: &hex!("ed9fa99d2a22cb4fcb2d25ee"),
        plaintext: &hex!("fd53183688a51d4bcbe52f6d37"),
        aad: &hex!(
            "ec9bad331852febf4ee1928c65d57df5eea95caf852fbb821c022978d33d07fec1ced606caed13624bb6d08a22da7e23e39298e10395b29d91a46220f64ca4d7d333d93ddec412322b67d5e101784e0a65088779b8c44f7cd05d"
        ),
        ciphertext: &hex!("97f74cd6ff2ea7d43262fe6f19"),
        tag: &hex!("7ed5bcf0ce0448fa661d0c0fbcd36578"),
    },
    TestVector {
        key: &hex!("72a565d3b3b6814bea37db7f659ba1d2"),
        nonce: &hex!("6f975cfb8f0973eba7cff602"),
        plaintext: &hex!("46a9956585a9c06507ec073e2c"),
        aad: &hex!(
            "bac017084cdd4c035a1917de4abc453e875d1ec9f7d603683cccdd64e6273eaf11619acbef407fed03ff3e76373132c5bd680f7645e4fcdb09ccc60ce65584f607a090426f660df5bf4daba95e7cfb3f30e4197218f8decf0dca"
        ),
        ciphertext: &hex!("a657482d12377846ebe3ca6f66"),
        tag: &hex!("0f10964e776b25ae079b357e199c8cd0"),
    },
    TestVector {
        key: &hex!("a85a8e0f16c7af9e7f32c817611a0249"),
        nonce: &hex!("12b4a1c1bed206c426c1d977"),
        plaintext: &hex!("4544079578dc90631c616a89cb"),
        aad: &hex!(
            "40741eac93ba6f3b60fdf1ac1b17fa3dd70d1ad4755f5a6bbd59c9c5aa99bb65bf7e077e5863b1d0b93104dea7b8e455d7bc149668822dc788b46980b2b439c33e10cc7c17415529c942e9eaf33eaeb627bc4cffc35cae4d37c9"
        ),
        ciphertext: &hex!("b0be95166bf557bae6152b360b"),
        tag: &hex!("46391f35d73901732a7b9c7eb976aed9"),
    },
    TestVector {
        key: &hex!("96c837ca5294446d389a6f06cb42e737"),
        nonce: &hex!("b37ce0928e17982ef783b2b8"),
        plaintext: &hex!("8b77fe7aac6a70fcae1ee74157"),
        aad: &hex!(
            "8f67abbb7a9394821c7196349262c589d5e1c156d6126fb3da0562bf403e733508f1f1926d6c9045350cad3d1243504dc70aa17a4de748e4a1fd804ae262c8ad557adaf799466434266b91d2c083f96218473adfc9dd2e8c3700"
        ),
        ciphertext: &hex!("d950ab8631a66c313d6801977d"),
        tag: &hex!("31e109753cbb651ed194369f00840323"),
    },
    TestVector {
        key: &hex!("fad699fe2dfb8a2b955708ff97b15892"),
        nonce: &hex!("61d9979bb5dd655e826abf68"),
        plaintext: &hex!("ca88d99b2c88b078a9878fcfde"),
        aad: &hex!(
            "7c02b7f2e7be357843a86596d7ba3a87e922bb0a982c32a20e809491c6343cfee2ee92fa2b6f898ee5b77a9ec5719de356c5e7507b1cac49b06e6fd5311eb9cf7a0c42b5252ca90632296d12ff5316a56253cc6666fb4d0a38f2"
        ),
        ciphertext: &hex!("bfa286323d4904de8cd21389c0"),
        tag: &hex!("cf3af80df6bde595d6b5a28d6b7112f1"),
    },
    TestVector {
        key: &hex!("ca83a1109cf5bfb7d24d6ba72c6c1a74"),
        nonce: &hex!("ee40762d9a5fcdb41438ce05"),
        plaintext: &hex!("53c7fa9eba69541113c1998c46"),
        aad: &hex!(
            "f54c4418df498c782ed61ccba4e657c8de9032231fd6a98c718063600d96f0e5f17fa73b9492faa264b5b9706e0d096386983694fb41b904c109b32b67c4e472e2a416fdd8f2a41fbfb1c5ecdf5be97fcd347c2541c1e50cfe18"
        ),
        ciphertext: &hex!("8cedd6149a203beb47d78489ff"),
        tag: &hex!("00906817785539306d07775e215bfb4b"),
    },
    TestVector {
        key: &hex!("65a467d5e8d503a0916e5ccaaf240b20"),
        nonce: &hex!("0cc6f2f2a5cf96ce6adc2c5e"),
        plaintext: &hex!("b619af43215d41b1b0650bbe0d"),
        aad: &hex!(
            "ae98d8e675bca2cd4bf8f0860d46bd2c18f2d15dd431c51fe63c878cc9b1cf47a3b84cf1e9a02a4f0a8940008b72f4f1ed9cb5aae670899705573a8045008cad1284cddd1532791d38c8067694669d8b7d06a46969c413e6e35c"
        ),
        ciphertext: &hex!("6c24bd0ecc97873f0f7c8802c5"),
        tag: &hex!("03168a06b495f3f31d46f0de87d5471a"),
    },
    TestVector {
        key: &hex!("4cf328e1f2f180c2dd9e6d703cae188f"),
        nonce: &hex!("35b7cfe65331e520265d6657"),
        plaintext: &hex!("9c1a195735a84e6491a8ac07ff"),
        aad: &hex!(
            "72a6a4f43598b91169a834d906cbe4cb40da1a41502a7f4bc80265a239330a9102de94a7fe8d57d28dc125aa5e6d061e7d2a90cdad8406ee899687d02f780f0c1ae8e944b300b61cd3489852d61eb2349a447be85d25d3cdde0e"
        ),
        ciphertext: &hex!("eb4d38c23be97445c25e8bf2f4"),
        tag: &hex!("b005f424f77a81f4a965aa7a1bf8cfe5"),
    },
    TestVector {
        key: &hex!("7d62b16a551c12ac2102472492a4d3af"),
        nonce: &hex!("d464c988013cfee4bafd7a9b"),
        plaintext: &hex!("6de52d4b0878c26b0d8a6ff127"),
        aad: &hex!(
            "12a9155e72f6c19a9f00a651fe52d6dac331cac06b3ba594e24021900cdaa7d73a75a0968dd5d7d2f16ebab2197c620a1768bbc0839e21c8a37203af4c2ba146fdcac2b48701cc4bb5863f514c6562e01e807cd5308c9274ad9e"
        ),
        ciphertext: &hex!("a6dd42b752cacb47f1de9adaa1"),
        tag: &hex!("c6472e722a39ae44be5e4242cc58e046"),
    },
    TestVector {
        key: &hex!("ef6c85fa490919d342734357fe3656bd"),
        nonce: &hex!("7790d3a8deb8712c68ddae80"),
        plaintext: &hex!("bf45d58e3cf0cd47bfe90814ea"),
        aad: &hex!(
            "fb04ccc1d78523c9aef6e8285fa991026c5aa4cbc8c37f9e0969d74c571e2409775d116c4a55b03f029842d7e3a53df8f7ceb9469b4461649dfb4183e57ebea8971bd967ee95d5f656873368a83313fa31cf6ab11d7b2c77d20d"
        ),
        ciphertext: &hex!("7cf1afa60d3428c8fd25d9479b"),
        tag: &hex!("63e3a5eebcd72468e8ffab55e3caefe7"),
    },
    TestVector {
        key: &hex!("ac5b4ad09c73ed0b80931b920ceb0fad"),
        nonce: &hex!("1c0ab2941025ce7f084b8509"),
        plaintext: &hex!("bf64de420133b29d1d50f4757d"),
        aad: &hex!(
            "e8cb8547ac67dccb3cb88e0443f9566944a79adaed7680b9e174080751d91e4d83357f28802a576e0fb53fb32e8d4d879d55aa9e79e201be363f4ddb16dad35e058a7d69e262c359c036f0d72151aa0bf04fbef5c4c3f7e91d05"
        ),
        ciphertext: &hex!("3761f611ec3ff853c915e61ef6"),
        tag: &hex!("bf906c3dabd785968ba5c7abd4a1eceb"),
    },
    TestVector {
        key: &hex!("35818c93c54a321f2ccc28e967d22ce1"),
        nonce: &hex!("18dfcc73829a3c13287a6112"),
        plaintext: &hex!("6f32f25bfc511e8a7c60854944"),
        aad: &hex!(
            "09be731cd52fe4f7c6dd9aef978f8f117c358997842ffbb2df96727625669b58513e2bc97ef9c7119afa6b088a4f9312bebebfa6e71080a6e7f369207f3396f9c240a13143d7bfc5cad5049cb067ce4f57876d883bc8283fed87"
        ),
        ciphertext: &hex!("9553eb0378229fdb213fd46002"),
        tag: &hex!("ec228ec0fc273b67d922c2ba3dde5bdf"),
    },
    TestVector {
        key: &hex!("9971071059abc009e4f2bd69869db338"),
        nonce: &hex!("07a9a95ea3821e9c13c63251"),
        plaintext: &hex!("f54bc3501fed4f6f6dfb5ea80106df0bd836e6826225b75c0222f6e859b35983"),
        aad: &hex!(""),
        ciphertext: &hex!("0556c159f84ef36cb1602b4526b12009c775611bffb64dc0d9ca9297cd2c6a01"),
        tag: &hex!("7870d9117f54811a346970f1de090c41"),
    },
    TestVector {
        key: &hex!("f0a551c56973e1cfdfe2d353aad66c2a"),
        nonce: &hex!("94e95e0544ab0b0b9997aee3"),
        plaintext: &hex!("734c0907ef49a1d86bc665bb9da9cedeeecd2abfed7f591c201ac360ca42f941"),
        aad: &hex!(""),
        ciphertext: &hex!("f2c2f0c35e0bf6c5f5c24d8aadba19ed35848959b9c586604c396428493418d0"),
        tag: &hex!("8855aecbe9604a839fa5d481f8760ffc"),
    },
    TestVector {
        key: &hex!("c635775fa1416abe375c792ea7a486ac"),
        nonce: &hex!("5b9f038596f55115986a3109"),
        plaintext: &hex!("54172156fcb2c40392009807bd3ec4a11c2c1b6d69ad20c773df3d9e7cf35e3d"),
        aad: &hex!(""),
        ciphertext: &hex!("73a9d9de0a3dcdc52dd9745fdf12353f4d63d0c7646443f5206883f6b7da2b94"),
        tag: &hex!("11970a60855b0fe890d4f5988f6cafae"),
    },
    TestVector {
        key: &hex!("43d0651aa5d06f2846fed833fbb72241"),
        nonce: &hex!("2ae626772b73c7cd25dab014"),
        plaintext: &hex!("cec1607ccdc6332e5371766190cc7b03a09fb814b3d2afc52edc747d70b7fff4"),
        aad: &hex!(""),
        ciphertext: &hex!("ea742cc41afac5ffbfa81e89bad82f1f8a07eca281fc253b533cc157eceec4e0"),
        tag: &hex!("db1e19fb545ae218f4ad3c9a6da64997"),
    },
    TestVector {
        key: &hex!("defa2f0eba651799c6041e6f28a0db3b"),
        nonce: &hex!("102158d6ed54ecc7efdeba7a"),
        plaintext: &hex!("67844577a198b456fa410afcede8fc24fb970459096ebae03bfe1dd32a6b9665"),
        aad: &hex!(""),
        ciphertext: &hex!("4d87782c99ea2b18c58393eef975007b9019f42667b98098404137dc085d631b"),
        tag: &hex!("fbdf857c1bff89bd725b8ca90d643e5b"),
    },
    TestVector {
        key: &hex!("f098deb1e8149b3c88320efbfea087e2"),
        nonce: &hex!("8146393ed0dd09d89d1ae7e5"),
        plaintext: &hex!("8ee6f4c01e98b501a9914f57239bda7d5831ac147c320651863e06db60c1a02d"),
        aad: &hex!(""),
        ciphertext: &hex!("122309ab94c98901104bda0488efb563959da64979653ee4f8e658a3ea8a3c9c"),
        tag: &hex!("93e3d93d0580c5567ecfac274da211e2"),
    },
    TestVector {
        key: &hex!("63b28aec8f7dd44af269e48e35294a34"),
        nonce: &hex!("4c3d88500f6a483b63ba1139"),
        plaintext: &hex!("5b86eb718b3917537d4ef51b6c74a85cc9a90002410d8f346cbe56c86ac72d4d"),
        aad: &hex!(""),
        ciphertext: &hex!("d0281117e29fbf9676f7887811b010a19a34475ad9e4516cd8424d0b9e5a2c3c"),
        tag: &hex!("904ba928205fdda9e2674805be07e93e"),
    },
    TestVector {
        key: &hex!("765ed884a7554c792cc671e93c02433f"),
        nonce: &hex!("667467b168db56adf48a26e2"),
        plaintext: &hex!("b941bb1f73980b0d76324a49a6c33623d4a1063b05c82cb43e4b0cdd4f913860"),
        aad: &hex!(""),
        ciphertext: &hex!("84906e78ac79df67a0fb4ccf4c8da439094339adc92d98abbe032cdf4f5d92ec"),
        tag: &hex!("750a89a842a6dd7d1317f561b9038402"),
    },
    TestVector {
        key: &hex!("816ed7edadca9e8fa2b2b9f9ebd14d51"),
        nonce: &hex!("7da514e274b5b812722b5c3f"),
        plaintext: &hex!("c76908234954ff939ba2293fa1ac654a4bee41a574f2694d090980481a08083f"),
        aad: &hex!(""),
        ciphertext: &hex!("b59a50e4414b4903c195ff47e8f9028d77b7e73a9a54e1ced9ebb1636b123864"),
        tag: &hex!("007af223e7ac139eafd78d0a2c87ca25"),
    },
    TestVector {
        key: &hex!("f7b38d0d340373b98b89725fd889be49"),
        nonce: &hex!("bc2b87a883af1c0bff8388fb"),
        plaintext: &hex!("0a8de4df6e01bc7b2a36e4a123af8ce6240bec42cd4e4f09aa92520c1658103c"),
        aad: &hex!(""),
        ciphertext: &hex!("65ee08ab751bef3720db313491fca20a87cdfd6b8b028f53bf352304da504911"),
        tag: &hex!("abbc81ca718fcbc6a75c85ada74e466f"),
    },
    TestVector {
        key: &hex!("dc662c77a2d520a067cbd6bd7e119696"),
        nonce: &hex!("23aa76d1e8c3a72be862a5eb"),
        plaintext: &hex!("5fb66e144d2564e096832065647dae768659d6dcd10a1dbe00858ce4f5148912"),
        aad: &hex!(""),
        ciphertext: &hex!("612713f9e6bd8017f61410c10ba1bd21adc87565bafbd1839d9572e270e94210"),
        tag: &hex!("9d7616c3b486107cc74a8a2aa9c65209"),
    },
    TestVector {
        key: &hex!("5c5b3799a19098b9c5737783ef0c80e9"),
        nonce: &hex!("34fb9e101915639def30f40e"),
        plaintext: &hex!("05f15cd45a82f36bc4e5e3d6db7a60640faa0e929c00f0354e913bcb02d83118"),
        aad: &hex!(""),
        ciphertext: &hex!("ad60f53d51b6b00fc3366a4b4bc16b678ecd12473e8bd55c363bc0d94a844b70"),
        tag: &hex!("1a528398ee2c9f436743d1a08602c5b4"),
    },
    TestVector {
        key: &hex!("3a541317198a2fb1b90470e90d6d7f38"),
        nonce: &hex!("dfa6eb2b53177ff5d0924295"),
        plaintext: &hex!("3ac18af46d3fb15d477b849fe1ead087840742cbd8b2ec31b45b8ac2e4a53975"),
        aad: &hex!(""),
        ciphertext: &hex!("66755e7ec710a8ed7c776521f214ceb54e550220177eb89fe3949c9e74e2e108"),
        tag: &hex!("20425ac5f07868b49edf9896af64396a"),
    },
    TestVector {
        key: &hex!("8f85d36616a95fc10586c316b3053770"),
        nonce: &hex!("d320b500269609ace1be67ce"),
        plaintext: &hex!("3a758ee072fc70a64275b56e72cb23a15904589cefbeeb5848ec53ffc06c7a5d"),
        aad: &hex!(""),
        ciphertext: &hex!("fb2fe3eb40edfbd22a516bec359d4bb4238a0700a46fee1136a0618540229c41"),
        tag: &hex!("42269316cece7d882cc68c3ed9d2f0ae"),
    },
    TestVector {
        key: &hex!("5fe2650c0598d918e49bb33e3c31d5b4"),
        nonce: &hex!("dd9501aa9c0e452f6786ebef"),
        plaintext: &hex!("5a6b60ec0ac23f6d63ff2b1919ba6382927ef6de693a855f3e3efd49bd4453d8"),
        aad: &hex!(""),
        ciphertext: &hex!("f0ac2d9153f00be3fce82d24fd3df3ea49f8265137417468724ae1342c6d9f00"),
        tag: &hex!("6bab3332c8d370fa31634c6908a4b080"),
    },
    TestVector {
        key: &hex!("298efa1ccf29cf62ae6824bfc19557fc"),
        nonce: &hex!("6f58a93fe1d207fae4ed2f6d"),
        plaintext: &hex!("cc38bccd6bc536ad919b1395f5d63801f99f8068d65ca5ac63872daf16b93901"),
        aad: &hex!("021fafd238463973ffe80256e5b1c6b1"),
        ciphertext: &hex!("dfce4e9cd291103d7fe4e63351d9e79d3dfd391e3267104658212da96521b7db"),
        tag: &hex!("542465ef599316f73a7a560509a2d9f2"),
    },
    TestVector {
        key: &hex!("9b2ddd1af666b91e052d624b04e6b042"),
        nonce: &hex!("4ee12e62899c61f9520a13c1"),
        plaintext: &hex!("01e5dc87a242782ca3156a27446f386bd9a060ffef1f63c3bc11a93ce305175d"),
        aad: &hex!("e591e6ee094981b0e383429a31cceaaa"),
        ciphertext: &hex!("87b976488ac07750aa529e1602290db36f4d38d5c5ccb41292b66c3139617ebe"),
        tag: &hex!("c4e7ea53efd59354ec6b4b8d9f8b237c"),
    },
    TestVector {
        key: &hex!("8737490bdc02e3543c312e081e2785cd"),
        nonce: &hex!("cf3460b8010d410fd5524720"),
        plaintext: &hex!("aa0acbbf2b847910d56ee4da8a9f40973f85d6cce1d6326a777eff01173e66d0"),
        aad: &hex!("eba8c1ca49e977cf26eb52325e59afa8"),
        ciphertext: &hex!("893902594834c3a72da17bd73ccd53238a581a3e33edf8b9b901662b5f7e1d3a"),
        tag: &hex!("36a3a106d3c10a65da7d81942c98b349"),
    },
    TestVector {
        key: &hex!("f7fc73fc1c428e56af92e6b2870845e3"),
        nonce: &hex!("375b1a84fefaaa807ffeba18"),
        plaintext: &hex!("f871a9a695b74f9501942f99a3489d4befec6768d7c17d1c38f51fd6cd16adc4"),
        aad: &hex!("0d668901163a08a338c427342d31e799"),
        ciphertext: &hex!("ef65290d220227147154f66a12004ce292507527f17c5119c69fa4f81e56d0a1"),
        tag: &hex!("2d48c8b198610cdea73965f6ab1d9a12"),
    },
    TestVector {
        key: &hex!("e522d6715bb408401c5a7af3ef190caa"),
        nonce: &hex!("1a3b2a313418ed26de8ddf57"),
        plaintext: &hex!("d3f10233505f524ffb8d961d8321be88c975704bdd9df958f3795adf0085aaa7"),
        aad: &hex!("b993eb193e9d59382919ebbc9e3ad829"),
        ciphertext: &hex!("e1519156cc27905b8da24d29fb502d54042eb6fab10c5f6a99d1ef54c92c555d"),
        tag: &hex!("7fd04f637b748db17da7ee34099a112a"),
    },
    TestVector {
        key: &hex!("55190de13cfbbedf4a0787f9ecc34e45"),
        nonce: &hex!("87803bcf6a69962abae929e5"),
        plaintext: &hex!("ee5da0026ce103140873226149b75fa734888b00518aeac0224466bbb0d23d0c"),
        aad: &hex!("067c3857cc240c6bb5f628bcc7cf5559"),
        ciphertext: &hex!("06362d236e9618037d31d4f1ea0df6064e0bf06b6c5904530e1002e8479c16fb"),
        tag: &hex!("342a27aea0ef0aa26ad92ea3a92afa37"),
    },
    TestVector {
        key: &hex!("65f7a5ff7feaa8d50736dce3c8524cf9"),
        nonce: &hex!("dfa0822065b1ed4987685217"),
        plaintext: &hex!("a32d3aed1371cfcddf5e735a9d95b96d1ac59c3ab784be8364cc1cf3b71bf70e"),
        aad: &hex!("cc4fd4d82584059b5a165d632d56fe1e"),
        ciphertext: &hex!("bdf356a54a5cfa281edbe7e35966b5b8a68894f282cd7a734d502dfee6dcb1f5"),
        tag: &hex!("4ff05b2898df6edc27574a2eb395ffc8"),
    },
    TestVector {
        key: &hex!("df0ceb73dfbd06782f69cd51cc4fc1fb"),
        nonce: &hex!("c5fb4bf0b40477e10e5d15d4"),
        plaintext: &hex!("fa9da35d8d812585322fa1c0cf4633b06424272cfac1c5a51138b0b9b91d443d"),
        aad: &hex!("f292c4c2a2356e70feb0003a28708ed8"),
        ciphertext: &hex!("e81cd00a96dcb719fc2c3af7b5420cb5667fed53af8f561dc216fc7215ab16a1"),
        tag: &hex!("60848116706be55b4ea939ba899eb2b7"),
    },
    TestVector {
        key: &hex!("72205e651f03e2c16eea7689af43bc4a"),
        nonce: &hex!("42c47b2f95b0ec02652f1fff"),
        plaintext: &hex!("7fbe781650c396ca8cdc6b2efddae0007cb008c4fc7310fa17ec5ae060171391"),
        aad: &hex!("7f978fc1f1b2f9f37b88b96b8c14ebec"),
        ciphertext: &hex!("b3f3a8bfe2906ac1bbc93ddc701a5529c2cb156354cedf85928f605ed6005bdc"),
        tag: &hex!("9151c8000dc25eba4a57908b238afb21"),
    },
    TestVector {
        key: &hex!("a2c96c0b051c633ec10b2fccb43f4517"),
        nonce: &hex!("c4c13fc9f15f482bf6bd8d0b"),
        plaintext: &hex!("5f0a50d976eb2048bc481d7bca9b3e7367c3b12c9e98ac8521f45c715ae3bfff"),
        aad: &hex!("94afc74a7040c47705722627e05f159c"),
        ciphertext: &hex!("2bde225ca63b40ce64500c40c00fa5c50086c431e95d1f99678cb9a90bda2502"),
        tag: &hex!("6a296aa47e52737304eaafec0c3d0c65"),
    },
    TestVector {
        key: &hex!("108146de148bd4dba69c4ad2c11a35c0"),
        nonce: &hex!("9dfbe2fa46a46c3ebaf31c48"),
        plaintext: &hex!("0104c3da4cbe50f31ccfcc426d634d8d39686444a3b75bfb54d67349fb7e7017"),
        aad: &hex!("bc83808f9e884967c84d28ce981dfd1b"),
        ciphertext: &hex!("3f4424912dfaafd8f8b08ba7baea95effb3e4571720a2626b92ad8f7a69d4477"),
        tag: &hex!("eedec85ed9e14a5fcc2cd0ce50ff00a4"),
    },
    TestVector {
        key: &hex!("37b9352444bcaa9624b267566a59095a"),
        nonce: &hex!("d7a72473b99b2890ef7c4928"),
        plaintext: &hex!("93037b2b4814541f425ea0bcc88ce1486632919cef443a5374d9944edc7e42ed"),
        aad: &hex!("f7751af2dcbf5a7eb81d6bd73ced1220"),
        ciphertext: &hex!("491e0893a652a5975d3db72868b5619311a9cddad11c5522e95893c42e3b63a9"),
        tag: &hex!("fcd8120512eb3f14295efd3b045b0868"),
    },
    TestVector {
        key: &hex!("dd1332f17e62b2be889e9a399fb0d3fe"),
        nonce: &hex!("3f0028cb7cb8f1091a4e2f4a"),
        plaintext: &hex!("9c2e07683c6ca06d012708ad6dae95082eebd36261ccc874226ad354cc8ba82e"),
        aad: &hex!("2f33c5f85f976811ef67533f488917fa"),
        ciphertext: &hex!("a4fa9311e3c02c3b068a3f11ae7657efc3a3e69991251280503940ac4a7e8950"),
        tag: &hex!("0e5e77baa0f36db11cc5bfc27ffc7a49"),
    },
    TestVector {
        key: &hex!("39e215f1a2572257efd939ac0365ec97"),
        nonce: &hex!("e1f4da712c4c1eb31027352c"),
        plaintext: &hex!("21f7d62bb2918dde6acf9b6c9b7afed4be7d623c3e2070444b087fb40de7e6f1"),
        aad: &hex!("9368e8d525e77707d316542dcd735c6e"),
        ciphertext: &hex!("3c93eb8df00556e3f42d54acfd635fbffc0f77f868a68f738ec2918213ba9a22"),
        tag: &hex!("0dd8352d507e5253ee0849688d2ee86d"),
    },
    TestVector {
        key: &hex!("06f36f4939473b540e71db35f398a53d"),
        nonce: &hex!("13efe211cb6ef3a374f4da85"),
        plaintext: &hex!("a5aafedc4c1ddb7f6b38f7974d16a1c88cf7ef1ebe5027ea4fb55db16101fc20"),
        aad: &hex!("8cbe3e3eb19818db197901bd4ee42de2"),
        ciphertext: &hex!("7d21fb06002d19f40741b275b72cdbabbe032460ecf13d98f1cafcb30f704af0"),
        tag: &hex!("dd4beca1670cf437372aba77bc3e9261"),
    },
    TestVector {
        key: &hex!("fedc7155192d00b23cdd98750db9ebba"),
        nonce: &hex!("a76b74f55c1a1756a08338b1"),
        plaintext: &hex!("6831435b8857daf1c513b148820d13b5a72cc490bda79a98a6f520d8763c39d1"),
        aad: &hex!("2ad206c4176e7e552aa08836886816fafa77e759"),
        ciphertext: &hex!("15823805da89a1923bfc1d6f87784d56bad1128b4dffdbdeefbb2fa562c35e68"),
        tag: &hex!("d23dc455ced49887c717e8eabeec2984"),
    },
    TestVector {
        key: &hex!("8bdec458a733c52cd994b7c2a37947d9"),
        nonce: &hex!("bf8d954df5f1ee51fc3f1890"),
        plaintext: &hex!("9d5f1c905df900111f2052a60913d8a9d83cd40e43ba88203b05e3dbf0e37fbe"),
        aad: &hex!("ffe26874a54bd38a026c5c729e2852a748457412"),
        ciphertext: &hex!("f056cf8ea6c4f353f08d54c27a8ef3324ab927a641563f9f5dc5f02c3b2204b1"),
        tag: &hex!("2f8b9351426363f09f5d17f634a381a9"),
    },
    TestVector {
        key: &hex!("0a651f95b6fe5d9442fd311cee245229"),
        nonce: &hex!("b7b2349b60ac5cf09885ef4e"),
        plaintext: &hex!("1cd7be7611d8f7c9d75fdf3f53d28172ae4d462c06da56cb386687f2c098e28b"),
        aad: &hex!("725a089a37ba50e53143722140ce5c37bc0a48e7"),
        ciphertext: &hex!("e2926f34c30883a3b7eb0dc47627aad090111654a4980fc4fc952fe7a7b6b60a"),
        tag: &hex!("617345dab8973c21ad711c2a51885f83"),
    },
    TestVector {
        key: &hex!("fec2452d0883a54c0e33fccc092ddcf6"),
        nonce: &hex!("9e3e354d30c2c77cd0d9a0fe"),
        plaintext: &hex!("95b9c5e6adb7fcce212abf535095bd955c3aa0f7ac2428841f4de9035263446a"),
        aad: &hex!("6c12b112110ebf36930910f1bfc9ed49e14440b1"),
        ciphertext: &hex!("a85754f451b40f3ab576327b4b99fa09adc95380299f61c5c7a8e28188d2a40b"),
        tag: &hex!("94b979f7718ec13412e03f3461440100"),
    },
    TestVector {
        key: &hex!("e5f6d9f2c8ad08a1500157e027b92219"),
        nonce: &hex!("94358eeb6829f1be4de3abfc"),
        plaintext: &hex!("3204856040edd9401a890769875cc252e5dcb4a77e951e6eaef6d7318a06bcf4"),
        aad: &hex!("b3b860929cdc3fb0e393f21287f3dddc4a1c927a"),
        ciphertext: &hex!("b1ba514ae4c41270d7beafaa1bac2fa993cf5af3607a008c6bb4aee2a1212dd4"),
        tag: &hex!("7e0f5aa40553128f2c15cb9567c950e1"),
    },
    TestVector {
        key: &hex!("aeccfc65063c3fccfc5a0b29193d1ef4"),
        nonce: &hex!("70649c9d2848d21c575d6914"),
        plaintext: &hex!("46ac375da56527c3c6fd5f28f33c63b1ffaf06c33b8f329eae37f8579a62291b"),
        aad: &hex!("637dc392cfe3a8e2fe5e871799a46dbe38f59610"),
        ciphertext: &hex!("7f8841d3c82907596c4aa6ed433b9eb33b24d66f0a0cdd846d5ea51668975d9d"),
        tag: &hex!("dfbab7a42d60cda73b03189034e44ff5"),
    },
    TestVector {
        key: &hex!("1dbaf0bdd974b48ae373f686a961aeba"),
        nonce: &hex!("a3a6454d17ac622248ae9857"),
        plaintext: &hex!("83a131f7737b4e881fb255ab9225f7faba96476626ed27168d6342ccca8d3e75"),
        aad: &hex!("393843360c388a6e2f83c7202e8da6fa7041a6be"),
        ciphertext: &hex!("2471d23957d6305a86520b757c54890a57f665a44a19af2f8d55e6833659e730"),
        tag: &hex!("4693b10c8998580e986be0bb26a22e3f"),
    },
    TestVector {
        key: &hex!("540f40fe8ac2e506b69bb2ba356ff8db"),
        nonce: &hex!("0502e51ac42f641d7a0176b0"),
        plaintext: &hex!("910a000c5e99245870f08dd658b648f944d04426a70d6d46d8e88ec8eddfb324"),
        aad: &hex!("9b1f2b2fd7265792852628df926abc5609aaa762"),
        ciphertext: &hex!("9381d4b72d740b58c3f27f8dff01d8bef45e769b834539a439173c88a6d18e62"),
        tag: &hex!("7c678893a122a50f777dfcebf514f81d"),
    },
    TestVector {
        key: &hex!("55d0e0560a2027bb873d84a39ff87046"),
        nonce: &hex!("616d61ba94216c9c7c0903b0"),
        plaintext: &hex!("1610431777c01136c0a0073f5c114c357f0216d5eaa31cd40b8cd605ac56dfab"),
        aad: &hex!("a0203e1f31f66bfdc819d086a48b705d1eb7721b"),
        ciphertext: &hex!("5d846a8dfe02cf2454e11075a236b2a6acc59819e9ca6af580690664c195edd3"),
        tag: &hex!("24cd0dd950859ab9d1ae654ef7174f98"),
    },
    TestVector {
        key: &hex!("b7ff8402f1325d945c98662003323db7"),
        nonce: &hex!("6b6163fb2d1641bce33459e6"),
        plaintext: &hex!("a2a653ee98df41fe873bc036a5fa7ddfea8d63ff0949ae8e1489cdb0c3a80c7f"),
        aad: &hex!("50a7649f5ac25f110f9408ecf3289d978a55620a"),
        ciphertext: &hex!("820a373f446a8341c8d928d223a5aea854b643ff07902b0c5bd0c6319b42d855"),
        tag: &hex!("764c69deed533ab29bd85dd35d4dcf9a"),
    },
    TestVector {
        key: &hex!("48c901ba4e905bd68afdaec739ae00c2"),
        nonce: &hex!("5bbe3dede5ebbd8cb845a9b6"),
        plaintext: &hex!("80b845888bd2f25defcd62b72b6bdeebd6152b3aa6b006891b0d69769fcc06d3"),
        aad: &hex!("0c0cbcdcdbb35a35116b12b62715df4b647d78c5"),
        ciphertext: &hex!("512779582d1fe1831f333bb563634acef8021c3c76b06beb6c7da98daac4c229"),
        tag: &hex!("15fd32f96a4b9505bc1373525d40eeb7"),
    },
    TestVector {
        key: &hex!("c82cc4d9ff0681968839991afd0dfc2a"),
        nonce: &hex!("26a95931946fd2118ccd01cb"),
        plaintext: &hex!("7516c4a781be02cafc36df4a07d2c9ffb978fdecf5217240097d5c26ff1e77bd"),
        aad: &hex!("8bbe80d4f4cd6c61b4fe3d24e98853acd4dd83fc"),
        ciphertext: &hex!("f98436fe4bf6e5993adab0f0001bebfb449735eb365b9e7ce4b151f82005c5c7"),
        tag: &hex!("c83be461e1fedbb4ddf3ee72b9debe20"),
    },
    TestVector {
        key: &hex!("748a88bf4e264a1180bfd665072aba65"),
        nonce: &hex!("b0a768b62de3cbbc1bcfe93f"),
        plaintext: &hex!("1e1df61a9f10c7b4057d684ccef74e09f2a87f7e4aed393a451461d574c8ddbc"),
        aad: &hex!("f4b102d885495fb893189aa216d8ab653bb97b99"),
        ciphertext: &hex!("5e1af9511989069a615a6850402547ef4788197452461f1241e24be674c60074"),
        tag: &hex!("734e1cc937ca384e282410fd9fc4bff2"),
    },
    TestVector {
        key: &hex!("2393180bb81320965a58424b287c9b3e"),
        nonce: &hex!("480053c69ac54b93f5e81338"),
        plaintext: &hex!("d46fcbf950bfcfca3906769f922821473d3005d5a1d81278622d4d3cd9721a33"),
        aad: &hex!("f6a2a3ac8e462fb01bbedcc9b0f8686ad4477929"),
        ciphertext: &hex!("125874ff5a7f8936a76b11587bbebd461e27638bff5a1e993465c9cde82f2bd4"),
        tag: &hex!("9b625b4c2f66cf2fc88043b9b4c6f2fa"),
    },
    TestVector {
        key: &hex!("d651166baf42b75adb26e370b76016e5"),
        nonce: &hex!("4af70e3be1357501cbb16bca"),
        plaintext: &hex!("21d76d04488d4c33a7e8822797f785b43540bd374206966c9ef7832c51cc009f"),
        aad: &hex!("2c1072d5df5306e20d323a9897abac120bfb4d04"),
        ciphertext: &hex!("bc557572490f4d63811f8d83e58214ba4d8d24290264381838328a2962f010b2"),
        tag: &hex!("8bd1f65c551c4affa517a8b03b6337e2"),
    },
    TestVector {
        key: &hex!("48b7f337cdf9252687ecc760bd8ec184"),
        nonce: &hex!("3e894ebb16ce82a53c3e05b2"),
        plaintext: &hex!("bb2bac67a4709430c39c2eb9acfabc0d456c80d30aa1734e57997d548a8f0603"),
        aad: &hex!(
            "7d924cfd37b3d046a96eb5e132042405c8731e06509787bbeb41f258275746495e884d69871f77634c584bb007312234"
        ),
        ciphertext: &hex!("d263228b8ce051f67e9baf1ce7df97d10cd5f3bc972362055130c7d13c3ab2e7"),
        tag: &hex!("71446737ca1fa92e6d026d7d2ed1aa9c"),
    },
    TestVector {
        key: &hex!("35a7eabe7de2d176e97cdb905c0b7f17"),
        nonce: &hex!("2fa0cfef89fd9849df559c98"),
        plaintext: &hex!("08f23fc6fde45fe044cc2c397390bb362524bb16cfab7c548de89faf3ad98947"),
        aad: &hex!(
            "314e0423ac429f43ed90d731fcb5bdc7849595ee16553a1b7f91412bf98ac4cb052ca91c62a33b3928ee2887ebc273b7"
        ),
        ciphertext: &hex!("cf040174f8e280d10aa65eb59db8bf3e4e2a8aa01b1f320564314946b3749af2"),
        tag: &hex!("94f78c8ab96107437826050e1a89b9e2"),
    },
    TestVector {
        key: &hex!("23c31e0e50ed44fae7e6df38abf0b16a"),
        nonce: &hex!("779034aee3e3b1942ef3e713"),
        plaintext: &hex!("681d498d7e85684c5996ce27270fe8065089e58617cc6deae49cceb27dc1e967"),
        aad: &hex!(
            "6a7877001fb018519c7f660d77cae7bd892af075ae2d68940071f9156bda7010eb25d57885913544d4922a21347c808e"
        ),
        ciphertext: &hex!("7b14a15674755b66af08d581ee6f8b98691927cb1f5c43e5589de61c1b3883c9"),
        tag: &hex!("2fa40d9c65eed28a99f95af468293006"),
    },
    TestVector {
        key: &hex!("4b4f9155d8db85e0e2b36bf3aa981e6c"),
        nonce: &hex!("7c8d933778e1414e7338d934"),
        plaintext: &hex!("f8a26c7a9a614a17151fcd54406891adf34e31a0d55046e1b413195b44113bb7"),
        aad: &hex!(
            "43b6c54526318efaa8f0a4979ccfa0f299f5d9889433b19971f60a663e359d1f2c1af393928c9b4165c07d7536c910de"
        ),
        ciphertext: &hex!("3f9bdea3c3561ad417c205887aea6ca1ee070057388dc80226f331ffb0017de5"),
        tag: &hex!("e8ea1d3077df2c3d20f02a5046fdae73"),
    },
    TestVector {
        key: &hex!("4148dd87bc6aaa908a0dbe1e5d2f6cc7"),
        nonce: &hex!("d01ffa7787117f8cb0b4014b"),
        plaintext: &hex!("bf1968a91d5da5c9e42ffb5cdf11e0d31b69935b22958c149c005d52576b262b"),
        aad: &hex!(
            "fdeceb385ed6de0d2d15453f022dd455b8db3bd9f13e44f085722a6935ea6631058e0cb5fcbd3b9e97db339b529de123"
        ),
        ciphertext: &hex!("bfc9ecbbaf49371107cec37f80171f94141e25a486e1b42d8258208a6038fa34"),
        tag: &hex!("f2dad0b16bb728cb957ad9ab0716d195"),
    },
    TestVector {
        key: &hex!("5d50961aa7fad7cae9a8d043e191c9c6"),
        nonce: &hex!("263f4dc6464e89110a77f24f"),
        plaintext: &hex!("0fed89fa86e5fbc4bf2e352caf8e1e8910f106db7b5092feec9fff5f4f768ae4"),
        aad: &hex!(
            "e74cd8621c2db03d6b47cda4ae0671dfe8bb62f26715bd4397adc679c987016bf305a1e555ebc91a048e2a7bdc7cb8b9"
        ),
        ciphertext: &hex!("2190380bee10ade973aea0db269835649f4e53e4724598e1a935704a40411b16"),
        tag: &hex!("0aa3d68d90ef3d329ff394451db0a2c2"),
    },
    TestVector {
        key: &hex!("c2428b54a781242f896bbc8816e8176b"),
        nonce: &hex!("715d8c8397ee55eb53f86a2a"),
        plaintext: &hex!("0088129bb514a66d5a208838e20c7978ea6389cbd56e85de87e0db0608d8c1a4"),
        aad: &hex!(
            "435bb2a96fae0ab64c0a499d6e50bf2e5560643338aadabaa795f82d6503588d6522a70e4e475297aa9c5bbca7138b05"
        ),
        ciphertext: &hex!("a9fb750c009ffd7fe76703e3588f747fa58cef68b1d9dd2f953bbf3ab6da2b59"),
        tag: &hex!("613bb91239aafdced8fb87b6ba0f9e5d"),
    },
    TestVector {
        key: &hex!("6a3408481a54a1d9231142ffb9fd354f"),
        nonce: &hex!("bb2fdedd1a33321ace0a5c66"),
        plaintext: &hex!("63c934eeea0dca9732734d800034e57616f4d339aedefd515a829300937e6d5f"),
        aad: &hex!(
            "448f17c604cb976cb527b3b1f8d40350420c94545d73ab72a3dc10a32cec537d78a17d32fe073b329e25bb2d538b5bc1"
        ),
        ciphertext: &hex!("b413a9c842fa51001b8949aa81dfc10408391892eda84785e725745378536d24"),
        tag: &hex!("1e323d12856a644a86f394f96185a07a"),
    },
    TestVector {
        key: &hex!("c5a7ef970a7f42b83194bfaa62dc092c"),
        nonce: &hex!("9505924d0b11200db3c40529"),
        plaintext: &hex!("84ba18d1e1503d1c512e0956380811bc70f2d97f65269712431a3720ddac91b3"),
        aad: &hex!(
            "c2b989d3d56d6dc0c3e846631e11f096a1c3f016984a2a60f593f5b45acd28319ac9828773c6d1e043c6213ce970e749"
        ),
        ciphertext: &hex!("b07c02dabffaa8f7b11f644e547f887f78bdc9babbaa0ca66e350e2b5a293b35"),
        tag: &hex!("11393df432636dc7d7a3f183f531166a"),
    },
    TestVector {
        key: &hex!("3f45c5c7d042ee34e8257bf83a46144e"),
        nonce: &hex!("0c732f208ec1f8e0e0de0eb0"),
        plaintext: &hex!("d46fafdf04468e91b9b87a84f71261bcd44b438e3a943590c6d1990786909ec1"),
        aad: &hex!(
            "991c82c9e48dc887f054bc0b45979dd8d244954ea910e30139da9dad476843691f32c7b494114e058d2b27284ea13a62"
        ),
        ciphertext: &hex!("54cbb18328682037bdddb8c585b731b18b5cfc495d9b899c9b8db8a11d9e46e9"),
        tag: &hex!("289349ea094839dc6e9570c1d7d62a91"),
    },
    TestVector {
        key: &hex!("10f0569b4e6c441858f8053a646b775f"),
        nonce: &hex!("863dbdc9eb8a9c1ac1af6ac9"),
        plaintext: &hex!("f99eead51bb2a17f370a50079d93167179af5c49965af2d3f06d211fd96d6ba0"),
        aad: &hex!(
            "41d372deba9b25bb982d8c4662f063f95d1859640550ee6177862644b028f42c435636cdc0cdc57509a5fcb75657e581"
        ),
        ciphertext: &hex!("566f59cf4fe7b14dca35575743867351f18b1fa7e39417f8e7fe4e8bf1052ca4"),
        tag: &hex!("df39c291b26f8ca2557abc6074694070"),
    },
    TestVector {
        key: &hex!("66f958e09896ab2b21eb36fc36fbfcad"),
        nonce: &hex!("371a4dbdf80e6d46508a9621"),
        plaintext: &hex!("c0458f59bac039a4349e39c259edf6cf62fbd87910064409c64d8f6ef55d96ef"),
        aad: &hex!(
            "19f19eafb6191fb0452807ba2ba6ae4ac36b37138f092cba1a63be58e4f8b994f2f6958799446b5d226fd23a95fe793b"
        ),
        ciphertext: &hex!("192474ad795e3e3e36abcef2d42c038d39ece8119fb058a752b7959fe46703f5"),
        tag: &hex!("d17dc61d1513fc1cc2df45283afeb556"),
    },
    TestVector {
        key: &hex!("0f46ef6999a3cbcc2e539a8952a7fbcc"),
        nonce: &hex!("ff8829c2fb56cdf74914ad2d"),
        plaintext: &hex!("37401d56052412f91aa9398f3ab3afe68ae500aaf40f7941c8a82ae56379fd5d"),
        aad: &hex!(
            "fc9a1c16b0f4cf133843a7664a17e97c02e7aa360153f5b4b881ed3825f7b2a414adae94c9a6479a9eeaaa206f99c3db"
        ),
        ciphertext: &hex!("6866aa7699a8ce2c747880001987c28393fea80acb7b24a9e6e61086df68f5b6"),
        tag: &hex!("c996fc3e44887ad4d703b72dc2ecb1b8"),
    },
    TestVector {
        key: &hex!("90838209bbc8d07846127667564dd696"),
        nonce: &hex!("febfb4dd04eb313933b9c278"),
        plaintext: &hex!("cec0527329847a7eece6afa65c7f50ff2d7df4bc4e8d2990c41bf42aa9bda615"),
        aad: &hex!(
            "01cbb3a7a70001027b064c337260ddde8cd07fc786d71e293fe0bd44c794dbf7b054114bcd259e115e3acc98cd2ed7b1"
        ),
        ciphertext: &hex!("e6275470454a9e0b6f6ea2a4d64cb93462a6cddc69e80f338098fe8b1d4bc364"),
        tag: &hex!("50ddc254d7504590c938a503048cc8fe"),
    },
    TestVector {
        key: &hex!("f94e9d80b48dc5bdca82f14daa46be16"),
        nonce: &hex!("29bf1931f0dc4fe3c807e234"),
        plaintext: &hex!("64971fdf74f93f8aae32a998e5acf2b09623795a77cb9ad888abe6c7756b0a9d"),
        aad: &hex!(
            "449e68d78fcaa2e0f2811a87a9c48a3cd18e4d644eb88ef05b91f4528e35c713f4df2ff97de251bc5b04a177d2e29299"
        ),
        ciphertext: &hex!("f317607d97ed51fcc2f6ff7b394470758df772abb33b7ba049c6748b39fc4005"),
        tag: &hex!("6c473bbc8881239f85eddc79f5daa0b9"),
    },
    TestVector {
        key: &hex!("8fbf7ca12fd525dde91e625873fe51c2"),
        nonce: &hex!("200bea517b9790a1cfadaf5e"),
        plaintext: &hex!("39d3e6277c4b4963840d1642e6faae0a5be2da97f61c4e55bb57ce021903d4c4"),
        aad: &hex!(
            "a414c07fe2e60bec9ccc409e9e899c6fe60580bb2607c861f7f08523e69cda1b9c3a711d1d9c35091771e4c950b9996d0ad04f2e00d1b3105853542a96e09ffffc2ec80f8cf88728f594f0aeb14f98a688234e8bfbf70327b364"
        ),
        ciphertext: &hex!("fe678ef76f69ac95db553b6dadd5a07a9dc8e151fe6a9fa3a1cd621636b87868"),
        tag: &hex!("7c860774f88332b9a7ce6bbd0272a727"),
    },
    TestVector {
        key: &hex!("93a45b16f2c06a487218d761eabf1873"),
        nonce: &hex!("f658ed7ce508e710d5815f18"),
        plaintext: &hex!("b6a2afb916a235c7fac5cd6a8e9057c2fff437b7544532a296a3c80c35f47c99"),
        aad: &hex!(
            "33156a775586e8c92c7e99c467a840281abc19483b9a320e707bf1ffe856ff1c473bb52f5b940e44df2c2f766cbe9ed360d844283f8daa3ef68def4bf5f2c3aae3028c2d348ca1963e9227cdfa6f6205dbd9f3832e46a4f552ec"
        ),
        ciphertext: &hex!("6564e15287e995886395353c65c830e6fdd295c7ec2633c7f8d280f2340cdd15"),
        tag: &hex!("e4f4dfef764270a068a9095b9618ffef"),
    },
    TestVector {
        key: &hex!("5015f6b267f7ba8f83b46ef9440a0083"),
        nonce: &hex!("b66dd42e69f8a614516ab6cf"),
        plaintext: &hex!("d1207549cc831a4afc7e82415776a5a42664bc33833d061da409fbe1fb1e84df"),
        aad: &hex!(
            "f06fe187ad55df4c1575043afb490c117c66e631b6a026ac8b3663d65f4e605b57f467ed6c0a3fde03db61f82d98a238955a3e0f51bac78d14b94a0b75057a432ff375a09b0a41def3c887fcb103ee99f4b9f4474a64600b87eb"
        ),
        ciphertext: &hex!("9600b7aa6f5d8e30d3bbca6800643ee764b59bcb83de3dfd03364bbc9a48252e"),
        tag: &hex!("49a0ad2dfbb49e8acc6ad1de4d9311d7"),
    },
    TestVector {
        key: &hex!("408722e80d9cae213180efc0f2675f32"),
        nonce: &hex!("e9ed15b1942f1ab5e9cf9421"),
        plaintext: &hex!("39ed45bdd73f72aa16ae833d05c6d9ab1fca2b5ea478db553027787857fc9fcd"),
        aad: &hex!(
            "19fb7034ac4f57035cf19f68d76c4581054edbabe884e076a0498542d42f0412f5eb87c2cafbe13b9936c6fcee4c7bb46df2274306fb1a86bae4660290c13eddeb8cfe8de585e415563bc1a6ca9823b66c8f2da5da5df8f41677"
        ),
        ciphertext: &hex!("9241526c638c2f0a2d1e52bb049f71039565bba5c59876eb136f92ac68ac7f6c"),
        tag: &hex!("a6a9b62c36b156ad4024e705c1d78360"),
    },
    TestVector {
        key: &hex!("678c4bf414452f1c5a659669646d4161"),
        nonce: &hex!("295d2762261d1a536e1c057c"),
        plaintext: &hex!("53f4ab78c16a20c07095afa50f7e96d66bdb5da90e7e3a8a49fac34652726edd"),
        aad: &hex!(
            "bc84743a0c42bb3423032a89857de5a9355ed7821980bf18379ae503b69da35601608f62bbfcb2e2ad9eff7e03fcb4b6d1768ad3a4d92831c5b2e3fc0eea3ab7b874f64e84c376a8f9e15b9aeb5392de10122605699f7d03a999"
        ),
        ciphertext: &hex!("2c821a0eb61cbdb09f84f086f69652b38ac9d07a90985f3ef36482a9ef8edbb2"),
        tag: &hex!("e6e042fe0894df45b7d9898e96e9b906"),
    },
    TestVector {
        key: &hex!("8df843ad9376d7326114143899b4ca6f"),
        nonce: &hex!("cdf3b88613e485fe6886e720"),
        plaintext: &hex!("c1fcfda327533d17e1a6ac7e25cca02546c66635a115cf3f6d008eba55947d60"),
        aad: &hex!(
            "e5bd7fa8a56f3c155120f3bccb0fa557063e7bb9517cd04d9996533ef3924ee6197ee7512c6ef09d2177e75b4909c6cff0e86cdadce20e279a0503956f4c2196391a8ffec2d17a1d6614be7847cd114df70b93959f1765826592"
        ),
        ciphertext: &hex!("71b822b6d39c9a801a4c2a2c9173b0f3d9b50cf18e8e95291136527a9778edc2"),
        tag: &hex!("b584a7e51d40ab28732c11ed602730a5"),
    },
    TestVector {
        key: &hex!("64b43dfcdcf30dfb97373d75d09ab733"),
        nonce: &hex!("9359d85361a3e4c110d715f4"),
        plaintext: &hex!("7c5c94ac7b138273de768d2bda16bef0774799df333fdd1a756e344ec35f2844"),
        aad: &hex!(
            "01acee6296478134999280ed47a5bc65dd5122c5d35092df54718900d04cfb81457ba9ec9d01e55dd8a65d6b3865fa0e7a45382f287c688c51ffcc951945e3e9c87b03c5545cec0d966926b8ee0453b69f25ce9fdf0a3065c81e"
        ),
        ciphertext: &hex!("5f9aa615e13b7b585bdc2d4c3a83d1304d6f78ebba0d5b329d86ca730a515702"),
        tag: &hex!("3cbf9fa530b049e067868433307425db"),
    },
    TestVector {
        key: &hex!("93a951295d4428902a5cce8fe2068763"),
        nonce: &hex!("8aed35ae4ae714cf756e686b"),
        plaintext: &hex!("0029b749b4db477dcf47d0296eb88806ef0b56060d598e48c9b5a6f9d046404d"),
        aad: &hex!(
            "8186788a93a764a866944a2056279ad7f1d2083a96ce224fe6de60e70b17db18022a1504e1bf45c326c6d6992d8c005b675715016e00ec965b398b2ea4ab09cca2ac4ac312e6840ce00a36f6467028328fa30d4086e5bcb677ba"
        ),
        ciphertext: &hex!("792cd1a143304fc737d0739be52b2e61841a908963832cff06ab6ec585be6467"),
        tag: &hex!("e1bb3eac7f570055fc2d2f0588c4935e"),
    },
    TestVector {
        key: &hex!("4f3114710c0e7f393b91c982beb3cfcc"),
        nonce: &hex!("03994d0b244f94d13cedce90"),
        plaintext: &hex!("36831744fd1c17a5df65a63d6642502075a0109f0f0c093ff33505140371136c"),
        aad: &hex!(
            "d294f939361af1bff5674a5235ba3e79bf30a5341b8634b5dac613e9a567ccce01b0596282ea584e579719206b2313f6675e7834f8a6d941e164169e97648ce77968ab4ecdfb3d639898468a1e8d285a9327dc958093eb33f8b1"
        ),
        ciphertext: &hex!("557e78350ebe53d1b7c1652669621db7a71a8fe2c0a84e61badf2dd9f034b91b"),
        tag: &hex!("bc6c1f1322064eab75737067973d56a7"),
    },
    TestVector {
        key: &hex!("f00a034ea2f732863f9030257c8dcbf9"),
        nonce: &hex!("2bd288fc2fabba6c44a04705"),
        plaintext: &hex!("85472091a37ec5f37d50fc09fb6b9d803577227b4c079ae64a9264e7a784c4fc"),
        aad: &hex!(
            "312de02725a53b8a3dca7f02876dd9a4665de7a3f3dab7e4ac37b71d9d02478829ca38d3ec76d7792eb32478b92552e90154cf5608dcad4f33496061161af933d066e146888d1b7fa9b0c5255d59a8fdd88da638d06ee6d16d93"
        ),
        ciphertext: &hex!("9aa27810c3761ae175560340144610c7d263ad35234ecc55feed1c5dd3a4dadf"),
        tag: &hex!("02724d14a7dcb5ef81ce8aa937f1419d"),
    },
    TestVector {
        key: &hex!("49dfbd368a541721d6cd5b2513ec6087"),
        nonce: &hex!("8b0214ec3a6a6af65be84ceb"),
        plaintext: &hex!("ef6cff08cbcb63a72e841340513f4e289ad34e89733731456cbfbc9a87b20f9b"),
        aad: &hex!(
            "6d3dc86af4bb9e92af0dec8cea981481341f37be457093d98a818d8cb4b68b9f7197b1fa310147701f047949af41d0b226af4a3b0b92e5342224766dab7830e1687aa3918a89d4d3b50d69595944f492d3d68b3609ca594e7f26"
        ),
        ciphertext: &hex!("e0802e60f73aa2fd669cf5870e963b1f33707ad4cc551f658b18bb72fd7cd9e3"),
        tag: &hex!("cd6d9a33458ac709385acfbcffa457e5"),
    },
    TestVector {
        key: &hex!("3c0f57982449fad339c7ac5f6501b9ec"),
        nonce: &hex!("4db6301b638bab6a833001eb"),
        plaintext: &hex!("d1d5e1f3d8b491b2345d4a020add93e31596a5a204045f75fad53305d6b5aab5"),
        aad: &hex!(
            "ea3872b0d48dad649a876a6b3672e9c7ffcd69695a4d2eb1853ed5c26eca0e8f21385563d42dfef2e1430e06561b8e0b73b5f62ba51a4aca78c56c06c479961c3d21c1fa3823cf80145f7b24e4740127e9e9960fa2480e36e4c4"
        ),
        ciphertext: &hex!("32c508251494d05ed9413b0011a028a1bb9bf7e18f72de4b750cc7ab96ec034d"),
        tag: &hex!("27c994680810f7b538c37b551b2f17df"),
    },
    TestVector {
        key: &hex!("8bb2aa3219c604544b4187d491586d9f"),
        nonce: &hex!("341d76da6e3094fc3570ae78"),
        plaintext: &hex!("274a2097708c53fd2a81444e13285691eec192c223b84dc9824c67ed3a050ba9"),
        aad: &hex!(
            "69c5e98cad9aa3327444b9625eabcd086367e64170d35c4586fa385a396b159425f8dd3969446529d651ce5a3b6432529487f91d193d05d2e345a28b50dffccc0396f76e418086e1fe2768e340c1fcffdb29e9514829548823f3"
        ),
        ciphertext: &hex!("ed8775001f33bafdb1ef577698116e9ae656085fca8b969740c7c697450f9879"),
        tag: &hex!("6c8936c42dc46321695d3af2a33ada14"),
    },
    TestVector {
        key: &hex!("4d8154426d1b12eaf98d09ac05b1f9e4"),
        nonce: &hex!("23e3916b9d64f98d122e6be6"),
        plaintext: &hex!("d8a69c57969c6551c328675f7d772faad6c2c6843bf4b209e483fbdfc5efcaa4"),
        aad: &hex!(
            "2355631b9d487f4a7ec98d497f251cb79acfc58c0517d5e7b92a1abbae6ae7353b874d02faaf6410438539e02710e4d7cdada686871fef7582d562f384a571ce1edc68effdb932462e648c712b4e1d4e2e46718abd3cc5973aa0"
        ),
        ciphertext: &hex!("2fa53c6fd1846db81002e9c14da634480b352225e9190ab03d2598ef49a3b2b8"),
        tag: &hex!("a4023fd8d0f076eed5992f680b154433"),
    },
    TestVector {
        key: &hex!("2c14b55dc1f8e3acf85258a12360053f"),
        nonce: &hex!("5b5930a7f63b1a8ec445dfa0"),
        plaintext: &hex!("41a7569d5f3f39ae06547d0ed681e8922382cfc940bc7e55da200ebf905bf476"),
        aad: &hex!(
            "dc8fb70d3afd3c67c9a86b3467ddfa23298c6523ebe7ef17b7bcdb2ef130c61bd5adca2eebc897fd4126470e0a9088e8ee4a60939024b9abc7ed551d0e79214edea566ca4d970198f9b3a20b6822f4e30fc2cbe76596a01817ff"
        ),
        ciphertext: &hex!("f64364ee15acf049d8bf90aaa914bffae9ac6073b8d56122276efe04b202d0f9"),
        tag: &hex!("fa09390c1ce9ec97fc10c55ef2da2425"),
    },
    TestVector {
        key: &hex!("594157ec4693202b030f33798b07176d"),
        nonce: &hex!("49b12054082660803a1df3df"),
        plaintext: &hex!(
            "3feef98a976a1bd634f364ac428bb59cd51fb159ec1789946918dbd50ea6c9d594a3a31a5269b0da6936c29d063a5fa2cc8a1c"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "c1b7a46a335f23d65b8db4008a49796906e225474f4fe7d39e55bf2efd97fd82d4167de082ae30fa01e465a601235d8d68bc69"
        ),
        tag: &hex!("ba92d3661ce8b04687e8788d55417dc2"),
    },
    TestVector {
        key: &hex!("7e6a5b6d296ac7a7494b72c93bad15ce"),
        nonce: &hex!("5225c255bc82949a1cdb86c8"),
        plaintext: &hex!(
            "8bd452633f9dae0639fe0e67e36401adf65b3edf6799ff9eec80d85c13c85e0ee09491d4f5acaf8ae920281801a2f5d12c9370"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "2348f512a3a8501be9eaa41d8a127fcd8f0368d5053981a5626f85405363d218af7ba52a2bdb87a1ff07329f21792f4c64fc39"
        ),
        tag: &hex!("8753cee020ac668e9e1a37f63231543e"),
    },
    TestVector {
        key: &hex!("0d54e78be0eba65446682721368567f2"),
        nonce: &hex!("aefce9f80307fbff0965881b"),
        plaintext: &hex!(
            "5b335be97a86c8c1a29b7408833f752c8c5d4c912e7f26c73b909239e1222fc851b4e3c0accc5148cc60af2f019f9ee0060131"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "7277aebd1beb239a3a610587b0d7cd71640291a4e4d6dca73a5d0e05f058e7a0e151a0d087ff256d08876e1fc3e0e5e69c72b0"
        ),
        tag: &hex!("bda879404fc226cfad834a3e85e04415"),
    },
    TestVector {
        key: &hex!("0bdbb7986a6026d17a9ded7700831f59"),
        nonce: &hex!("e3bdba2fe3b5cad727071202"),
        plaintext: &hex!(
            "77ec68b51f5eb0f2d80d3af696627f365b6e83e69f105c7bad8e4869b228a0c496aa05c96e97a6bfcb33aa172f22c6bf3d5116"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "e7a5a701e950ca26987e1c40c889b475dba50cea13f09e9d3bc3cf4c84382c15bde4c34ff05eb278b4b745e51cbf4f12c12689"
        ),
        tag: &hex!("b794991a8a4a9f3d59d9987e9fb7ac30"),
    },
    TestVector {
        key: &hex!("823e852ef0b9551b2700bed65edcc808"),
        nonce: &hex!("85798ee5fd33ef752a363d85"),
        plaintext: &hex!(
            "c1ebd968d861fddffab41857de7049bdee73acfea5564cf44ce40d75b960ca5453cda093a55c5527687f25433bd6dcde443030"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "e8e976e8175a41ec6a629a225cf277a1a7e2b839b2f581c88698a39300e4a54ef381f7b433e0ea9acffe59801d516cd4c61135"
        ),
        tag: &hex!("ccfdc010bd16ddd651d0a189255a7035"),
    },
    TestVector {
        key: &hex!("99c0001a7c12f331e7b3b164daf4616f"),
        nonce: &hex!("383e8df9db398c5e9842257c"),
        plaintext: &hex!(
            "9d8ab6774cbf486fc4378a05a7aabba7ba7ff4a0f5eeb51c54c2ae9a5dd829d2735089955d5ae240d28da8b79994cd72234ee6"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "23c5e30b40b0946cf5b4df15407ff2d973397a10e94a303b71a4a5de074644006a10fcab198f86c4156c59e28900b958efcb8a"
        ),
        tag: &hex!("8ecd6196137905263729dafc06860720"),
    },
    TestVector {
        key: &hex!("6fa5f5b79f6f2fa7c1051d2a374db822"),
        nonce: &hex!("d466bfcf72789143eade1e84"),
        plaintext: &hex!(
            "d9528856db087849264ac811689420ef2beea9c6767644f3ca8bfc6345a3e2e5c49e7e0fd9b1c2e1671bd1b6275b0bd43306c5"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "1128b1da86b71d3c0cb9904f2513d2329c033754fc0d40f87cdfc7ee53dbe3ab565719c8d1dc5d3314123bc9e096fc8509b85d"
        ),
        tag: &hex!("19092b9776c4a1f6e30354fa5115dc04"),
    },
    TestVector {
        key: &hex!("bce7d033f24ba8fbc237f06f40c6ae25"),
        nonce: &hex!("c0d68906e987fe22344cae52"),
        plaintext: &hex!(
            "e533180c0c73d75799025303d660e43d5795ad46b84a05741b441f855eeea299a6484c17f39e884aee28b7d384afb49c134c73"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "4723daa516b920ec039dd8c0704a37f0bbad9340a7e987888db120459c39cc069554638ab6b32cff585ed58e2d7c1808229776"
        ),
        tag: &hex!("1ae612e476f5beb99f65aa9b5f02b3db"),
    },
    TestVector {
        key: &hex!("f78a05cd2621e9385ca111f3a168fdab"),
        nonce: &hex!("a16aef83dbbd5f69c2569103"),
        plaintext: &hex!(
            "9e761d4b7bdce2b851e508f77faf447ff83505755494f1bb5169dc23bb02d9ba8fb8b4878c8a47dfd14ea0dcef3e83c688e597"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "7ead6bde964c35fcf5de23f19725387601f705ac11c5fe1fc531746bf2d871fda54264a623c70e72b5b5ecadc4434f9e696ffc"
        ),
        tag: &hex!("2f13e4bd9883c747f0c79c91e661aa8f"),
    },
    TestVector {
        key: &hex!("dc1b8569a8046e3f294c3cca018f6613"),
        nonce: &hex!("5b3cbbe0e948db8efe42062e"),
        plaintext: &hex!(
            "6a3a1a9815690106d1908bc7e63e25bfd801900e94a9fbc28b6d52b8f9b4de7003b066bbb18bba33da83c67809e3bcf98b5cbc"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "b02a253a17fb9248277cae0305473870c19e70b7930a0be9be905423479413dbe3702f42024d69476415290b1422f2c030e99e"
        ),
        tag: &hex!("f0fb85e3d6b3a5ddc5da3ec797f758dd"),
    },
    TestVector {
        key: &hex!("cebef154b3ca2167230daf3b8205f11e"),
        nonce: &hex!("e0dc23aa50a52cae644874b0"),
        plaintext: &hex!(
            "b8cb070ebf5b27a51f14f22c6b38fc29d04c431c484c117ad250ec4f97fc4df44b0ec847b69a363963d419ce9ad11a321686b0"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "4c0918e86b152be2c4dfe36c78b8a559c2c7f83fa7776d0341318a065c2a2f1b2678aaaff76cad30ccaa1dcd03a5bb16d00f3f"
        ),
        tag: &hex!("79267bdf70e74eaa011e889369f5831d"),
    },
    TestVector {
        key: &hex!("d7e95109127e83b4d43c81d7ef6d5972"),
        nonce: &hex!("43ac0d8895ed785e2cb69d48"),
        plaintext: &hex!(
            "b2601f216b5e6f60c518dc817c38be940ac03babf2e6f5ddca0874e819f9aabe046460e3ccf6511566bbde2d9b191fc16ac4b6"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "957e712dc34ad891cdb3adcce62b0454eae9c792e64eb4e08624de103089cc19499749e8ae6d8c92e2c04c5cb36ef097bb00dd"
        ),
        tag: &hex!("f569562cb94828fe71fbddcfd984bae5"),
    },
    TestVector {
        key: &hex!("39ab7819dbf944cccd2648445337158f"),
        nonce: &hex!("4594840e05c33bdbc0187174"),
        plaintext: &hex!(
            "834cb05681e9a7876bca891eb7824392c7ac29d4ff4c9a8ad96447d2cc5f0ff218043d3510201452ba5c789ba2a667bcf79b9c"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "362acf79df28c3c858e92c0c5f0a323b3ea2e81be67cfd903a627ed163c06393287b73fe33a435b96672b9bf1a5a2c2cff4a15"
        ),
        tag: &hex!("e58a30e2c91e6d25f423abde987cf2f7"),
    },
    TestVector {
        key: &hex!("73388f83e409ea236129e46dc9a9b20b"),
        nonce: &hex!("a9069b00e1cd29a2b07b8db6"),
        plaintext: &hex!(
            "a2e138d5611c5043214f7d9f9c87aab94e0b8e99b311d0cae90829078c3898c8fffa7de9789af0a6c05f375b2f710dd4ba2610"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "77e0fa6b2765428ae418b57ecf5a392230fa2a9bd1686b91df69845cfa0a2dd9add219229e65ff6a2f887b78ebe8c0c5d1be21"
        ),
        tag: &hex!("32385ced195a16dad5eea5a19fd0fa43"),
    },
    TestVector {
        key: &hex!("d590e53b695315cc0b917d9fa0aac643"),
        nonce: &hex!("102de7df461a5578e75c4975"),
        plaintext: &hex!(
            "7ee631fb685d4a94563e01480ec5526d04a4035d1f615fdbad6656e2495fe5d7f0d6c40dff659fc85f4ccd78433a192313c3d4"
        ),
        aad: &hex!(""),
        ciphertext: &hex!(
            "e1322d0c9265cd774d2e9d9b6771799600b79ba38374ee1756aa6871e204e5f6871cd50db15225ded64a9c8899bab37288a792"
        ),
        tag: &hex!("13e606a9a4c786b65e2260cdda4b1843"),
    },
    TestVector {
        key: &hex!("b61553bb854895b929751cd0c5f80384"),
        nonce: &hex!("8863f999ae64e55d0bbd7457"),
        plaintext: &hex!(
            "9b1b113217d0c4ea7943cf123c69c6ad2e3c97368c51c9754145d155dde1ee8640c8cafff17a5c9737d26a137eee4bf369096d"
        ),
        aad: &hex!("d914b5f2d1b08ce53ea59cb310587245"),
        ciphertext: &hex!(
            "acfab4632b8a25805112f13d85e082bc89dc49bd92164fa8a2dad242c3a1b2f2696f2fdff579025f3f146ea97da3e47dc34b65"
        ),
        tag: &hex!("5d9b5f4a9868c1c69cbd6fd851f01340"),
    },
    TestVector {
        key: &hex!("4324c97ba8c9f2a1bd447bde5e75938d"),
        nonce: &hex!("bcac68106a3fc22048462bc9"),
        plaintext: &hex!(
            "789fc14b7d4ec83ec783c0ef38faa6706031ade4e65ae91f0e1c579b8c8652e94e04c4ee5d85d23d0525c133a93a9539448ca1"
        ),
        aad: &hex!("2a893eec2eeef4c2e9c305428b9e3293"),
        ciphertext: &hex!(
            "2ba721de1aa7afba69cd0fa492fcad5fe639d855c1f280802b9cd5dff37f4bf54a117b8f400cb63906a3c78cdc1ae98b0c30d1"
        ),
        tag: &hex!("171df263a72252f2c44f5a63f089adb1"),
    },
    TestVector {
        key: &hex!("51e42ceb83175d1df09b8385a84fbdef"),
        nonce: &hex!("ec6b7f21db6eb16ce87f89b0"),
        plaintext: &hex!(
            "4c5a34b0acc8745f45c04d6c82716b83ec6be5146d1272835ea642b49f55353fbc72a3acd16624e5377cbab54e356e3af6be01"
        ),
        aad: &hex!("3a081b5734537305222f314ef39a8d20"),
        ciphertext: &hex!(
            "1b4bb70f3ed38f378e29edb7e65081f794725a0340daec5708a163a3a81272ac2bd4b3e3db8f8ad57d571b5eb24af652e3c87e"
        ),
        tag: &hex!("6a9f2a4b73290fc566f37c286887eded"),
    },
    TestVector {
        key: &hex!("9280e05a614d452f407aab696afad52f"),
        nonce: &hex!("099ef02922592254e44517cd"),
        plaintext: &hex!(
            "db91108d47f266dd9371698b194b3a183f2936782be417cf1a048c6504162d37e11a41e3bbfeb98f995ec8e35de94bffe0a363"
        ),
        aad: &hex!("12dc4da623d082c767a3f7efe9a6ebc9"),
        ciphertext: &hex!(
            "8ac070ab975218af0c22435174abcab01af5db9917095e67140b31feeb78b7d5be3186b4fc41f106303a519b5a32399d2de77b"
        ),
        tag: &hex!("7811b48513d9bcf1999b52304492b0ad"),
    },
    TestVector {
        key: &hex!("89be3c09ae7e2eff5b63f913aa8b575c"),
        nonce: &hex!("449d852d65585185bc4298f2"),
        plaintext: &hex!(
            "93ccf5d907dea9b0fed5507f8a26400d0a568c0ef53b9fa6bf9d6802b20fe672c9a9536fc75b85f08e4d2c45cf032422f30ea9"
        ),
        aad: &hex!("d232713c2b024b5affd4a15050dcba41"),
        ciphertext: &hex!(
            "5b38069d695b76a609318e93cde6e239465ac52264017c3e5169bddbda0d2ac76ef0451a3a39d07e8e8da3b0cd2ee808912b4c"
        ),
        tag: &hex!("e316e6032fff56e5242caa1b4ef2bb6e"),
    },
    TestVector {
        key: &hex!("04cbf7dbeba906e1d0e8a98d796e8613"),
        nonce: &hex!("b58059139429a6a6a38ccb07"),
        plaintext: &hex!(
            "8890c63ab730d9135e19ca3ada35b34a2d5bd9f4968d60e8c65bf43f0d6def7de472c26b89af9e5d6e48c125d84b0fef7d194e"
        ),
        aad: &hex!("7532c6237ba1da8b99c4a091c5159eb4"),
        ciphertext: &hex!(
            "52bc0be1920a4f1fb3ba3f9fc3e7969c75e40fade163897428f49fc52b6feffb61b65344ab3ac995e07dd5f615c24b447df9a7"
        ),
        tag: &hex!("239b60518f3c35b24c2557549179fd36"),
    },
    TestVector {
        key: &hex!("8f1c70136852dc27ae5162b8743c90ea"),
        nonce: &hex!("d372f92b0cf030aab042a6fa"),
        plaintext: &hex!(
            "0b6446af88c455d7f1ff5116c7af949803cc50bcf1ecfc81c6627141a42b363f7eb7fc628503bb6f037dae843fd2d319b61118"
        ),
        aad: &hex!("7eeff5d17e79f00d68e26cb7e6bee76c"),
        ciphertext: &hex!(
            "4f235f6cc2c0474ab50557e2cf612ab09ffc85975de082b9cb9649a522b8a47f24e1b2c48f3cd57dce49542bd3560fe5e44bca"
        ),
        tag: &hex!("c541b78244efd2b9e61e75296f164aad"),
    },
    TestVector {
        key: &hex!("1ac69a35f749c65d5d27ec109b58f336"),
        nonce: &hex!("f0b9c6e8cfc7ba4c880d99a8"),
        plaintext: &hex!(
            "9695507b944865587f27395c74468af6a845716b34db61e437b77d0107387b3fda581c466b6df40948da35906b77ff8ed09402"
        ),
        aad: &hex!("251d75d69ab64f1363efeaa771f3dc01"),
        ciphertext: &hex!(
            "f41dc7402768705dbe3bf7cdbeb4fc672d3a6c3d65520dab3082727dff084b6e0bab17f96c2b137a4bd564a13f77ee37347383"
        ),
        tag: &hex!("022edf7437b41653db3bf2479a9e74a1"),
    },
    TestVector {
        key: &hex!("16cbfdc8f9900f6702a430b0d8b624cf"),
        nonce: &hex!("28dd5c46e03680f2c01a7bba"),
        plaintext: &hex!(
            "e1562d6e6a469cfd9f0a6a15be9a033cd454959ef8b37b2da58164fff1d8dbd3fac2b97bf1b503046fd9cc68bc942d0f727a3c"
        ),
        aad: &hex!("b1bcbdd27c0ef4de462fce0be8855a36"),
        ciphertext: &hex!(
            "10915ff87b80e42d548950e53ff6642ad44afa695175d24c9b5197f64c15570ebe0bc969c0251be940b42889464cf562c3e1a4"
        ),
        tag: &hex!("f9606f7a0e41153a1b45c25f1784cace"),
    },
    TestVector {
        key: &hex!("4c12a54aa7bb7a0c0c798834f39b3fa8"),
        nonce: &hex!("e5854fac9adca3bb1bc549b7"),
        plaintext: &hex!(
            "7e7fe58f9f13907a694b47f053c9270c2e4d73b52642a71446943a5c5f3e2fcd554b376dd2f549aa7e0737b62c6414f542bba2"
        ),
        aad: &hex!("7f42a7791e705345888f00573be98980"),
        ciphertext: &hex!(
            "df46d7519910899b7c3d9e7d0dab82c93b7d8ee03f4f5aa82ecf64cacf3c9fb58f17a021536028744e412770e57562249e5f09"
        ),
        tag: &hex!("2823d4b59cf8f8837bebd5efdfb92929"),
    },
    TestVector {
        key: &hex!("32aced5414e267cf77844c0acbb8872c"),
        nonce: &hex!("3d108e912d53b88e0dff9d6c"),
        plaintext: &hex!(
            "c7fcf53c93a521c6e244f203cfc40b80bd8ab1e4e54cdb581fc14c31dc6a93805edbba32a729acf1a7c04c8b0366c2035c65b3"
        ),
        aad: &hex!("7be4c5df7935453d50f1c6c79ae6c13a"),
        ciphertext: &hex!(
            "80beec8c20c7e9514c38ac6e3775de206754433cb1d7c89bbefb33b1b41245e0d1baf7cc870b1f1ec387f2dded3e0f479ef160"
        ),
        tag: &hex!("d97f7d82b3ff97f2f6c652194c004748"),
    },
    TestVector {
        key: &hex!("6275270952263f5f008b16f2456c7ddc"),
        nonce: &hex!("1d1837ea4cb3732a6ea6487d"),
        plaintext: &hex!(
            "fd4de28a18a3de3b9660acf08eeac40e192b77c5264c80651c28628e61c3916f7ac03d849ae39c981a2808866a8292746a4793"
        ),
        aad: &hex!("6ee8ed2ed241f1d7cee55ca67001729b"),
        ciphertext: &hex!(
            "d69490708893f1638ad594c3a0ad8eb4f17da3203b18aced930976ee1abf4df1ae8a768ddc9df6ccdca2d579165023e52bb9d7"
        ),
        tag: &hex!("aa47cda3928f7a2ea42feae4dfb0800f"),
    },
    TestVector {
        key: &hex!("7796d479bcb213f19e2ed73ef1069fe6"),
        nonce: &hex!("f0ebb6fb1df60069b00a34c7"),
        plaintext: &hex!(
            "f72603b6e74bafc20f423bea2a1036ab44461b5e5a5631b013573d953e1fb073b855511860d1782c1f3b146b5c41eb946e2fca"
        ),
        aad: &hex!("87563b4d72e2f2c0094bff678e3b7975"),
        ciphertext: &hex!(
            "44c4d7ba2af1be22daa6352b58bf8cda28999bc33c420f8881001719fe639a9e9e5c48df120f7cbe73af4c1513a637b9de33e8"
        ),
        tag: &hex!("8b7002219f586318150132e0e5cbf2e9"),
    },
    TestVector {
        key: &hex!("f7c50f29479ff0f9945ab9df56872eaa"),
        nonce: &hex!("1bb94d7b399eb7a9a0efaf6e"),
        plaintext: &hex!(
            "fa86691b746424b3426dd9ce8cf0f132de5c575e001701324ca7ce474d5813a19904591055fc7f343e20d0f4c92118b14ce774"
        ),
        aad: &hex!("88a9f81078d6a0820c56c582a30333b9"),
        ciphertext: &hex!(
            "55024fc5e95e5f7c33bf948c167b13382236b2cf187cc09e37dce043f6293fe457a1dde728cf407c702d75a670397ffe28e8ba"
        ),
        tag: &hex!("645ca60cfc8046a0253f438e69b8e47c"),
    },
    TestVector {
        key: &hex!("f3e302a1568a5340b5745ae87f5a5bea"),
        nonce: &hex!("ce41f436f2e84643f673603e"),
        plaintext: &hex!(
            "e4abaa66875bd8d45b6ed5e7671b03e09423ea41b7d89039da92728151bd690ccdef4fa16392a7f85efc0bc2b1664bd3f15e77"
        ),
        aad: &hex!("87ba36d234ec508b308ff258c6bd427b"),
        ciphertext: &hex!(
            "123b69b2d0f10934da3fdb5c1b96b4ffc8ffc1446088b634b38e145e6dd98e8fea17214b5c9136f039577d4493b8bcf935ae19"
        ),
        tag: &hex!("97ca8cf064a408c7b764cf32d3b79c0a"),
    },
    TestVector {
        key: &hex!("fe47fcce5fc32665d2ae399e4eec72ba"),
        nonce: &hex!("5adb9609dbaeb58cbd6e7275"),
        plaintext: &hex!(
            "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063"
        ),
        aad: &hex!("88319d6e1d3ffa5f987199166c8a9b56c2aeba5a"),
        ciphertext: &hex!(
            "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269e5db3e"
        ),
        tag: &hex!("291ef1982e4defedaa2249f898556b47"),
    },
    TestVector {
        key: &hex!("ec0c2ba17aa95cd6afffe949da9cc3a8"),
        nonce: &hex!("296bce5b50b7d66096d627ef"),
        plaintext: &hex!(
            "b85b3753535b825cbe5f632c0b843c741351f18aa484281aebec2f45bb9eea2d79d987b764b9611f6c0f8641843d5d58f3a242"
        ),
        aad: &hex!("f8d00f05d22bf68599bcdeb131292ad6e2df5d14"),
        ciphertext: &hex!(
            "a7443d31c26bdf2a1c945e29ee4bd344a99cfaf3aa71f8b3f191f83c2adfc7a07162995506fde6309ffc19e716eddf1a828c5a"
        ),
        tag: &hex!("890147971946b627c40016da1ecf3e77"),
    },
    TestVector {
        key: &hex!("d441280905a33bcf02ac16f8cabe97cc"),
        nonce: &hex!("53294f8b440c82dbd9bd7543"),
        plaintext: &hex!(
            "5cd42b150db7d0bd6556e37e386dfafafabe2aefed2823be932f9daf1234aa0402bead485ebda3a0a6e392d5b0e603ae2dfca5"
        ),
        aad: &hex!("aecd49cb8890806d47a950c8e92ab294f325961d"),
        ciphertext: &hex!(
            "3ae74193c94ebb96fbb1bc5ecd180b2c0efa1ef4a9ecb6959631f8554f0eb237893476cc0d4fb55fa1880989c1616dd32b964f"
        ),
        tag: &hex!("0eae01a8473a8f603c6ae6b637e4aeba"),
    },
    TestVector {
        key: &hex!("4f66f21817d1865c2fb62d4de344e085"),
        nonce: &hex!("4c780a2707f56747b24a4aa0"),
        plaintext: &hex!(
            "04eade2d68dc3c5d83f2d3f1c44240bf86127c9f6b3966085ef41ef50107d042b18bbe80bd43cdd1585fc5a99df8271b9b8767"
        ),
        aad: &hex!("4c0ec2531542bc801b3ddf593c2e1ba4afeb603e"),
        ciphertext: &hex!(
            "dcdf8d2b0d388072ce273ad3502dea5122bac0020a7ae3b97705d3a2bb49a5cb4f95e6cbd74183758c2eabc9ea38155c7ef647"
        ),
        tag: &hex!("2558c59cc7d71a2fcedd13f1c6659a63"),
    },
    TestVector {
        key: &hex!("638276070f70a48dfdd3074905f4dd8b"),
        nonce: &hex!("08aa05eee9be39f28f61299c"),
        plaintext: &hex!(
            "bca63b1fd480b7c682f992b3ac40712cd412e5bd5141126311ea3c5cd91ff8d75b7ad7be0ac7f61d41292e673177e55e148b8c"
        ),
        aad: &hex!("7e3ef6f9d9d33a6bc5904b1317d235ce1a99ffb3"),
        ciphertext: &hex!(
            "fab16aaf8cce26586b50e794e889839e0edb63f14f927f353569cac1694604de593d72c52977bf7fe2b6fcecb2d8918d0de8e9"
        ),
        tag: &hex!("bd97aacdb02b80a01487d690b5e905bb"),
    },
    TestVector {
        key: &hex!("dc7fa9348b7fe1b3befa5a09b2dc0f7a"),
        nonce: &hex!("51e208cfa9b9d990013f50f3"),
        plaintext: &hex!(
            "0b65800b4dc2aaafbc837f9ece7a9111f3ba0309196babaa6b63ef0fedab779e0d352933536520e4ff1c7f079505ead882adf0"
        ),
        aad: &hex!("b7219b5b1801457d71cfbe342148849622592c40"),
        ciphertext: &hex!(
            "2caae5923cad79802d682172f58191349240a24e25891461ae65394b95413b34e03f3551baf1a055d22a53a8a38f8ef78f6d40"
        ),
        tag: &hex!("10769ae854f8298cd94c28c3e28e94e3"),
    },
    TestVector {
        key: &hex!("eaf1659e08d0f22a7042358ab0ee0f0d"),
        nonce: &hex!("d6911b68856038ef9dec1215"),
        plaintext: &hex!(
            "0e71b3765f17e016c3024be23d0af6cf50ce98d86943b38cbbe8f3dcb540dda64b77bf73c7cda108e1a5c4bdb590a7f747ecfd"
        ),
        aad: &hex!("433ae638214c48207fe9cdc76ef99e28913d6a8c"),
        ciphertext: &hex!(
            "bf4aff65fb7df0858962474bee9fbf95b0f06637c7d72bb1cbabe46662f455d3813665477b4badfb206a4d8f01346119e559ec"
        ),
        tag: &hex!("866f204b04a309d45e65ea890a17ed0d"),
    },
    TestVector {
        key: &hex!("382697fc2ca220a5d6a700f7fadbaae5"),
        nonce: &hex!("3fe9d400d10dc33545d6cc5c"),
        plaintext: &hex!(
            "7d187a1fd4d518197c1e843d613797d4a9fa9da6fe9f773b947dcc0023c43e917df575baadea90237d95f88c54692ef8be672e"
        ),
        aad: &hex!("a3cd4b0216378918a46252ca16f2ac9775e993f9"),
        ciphertext: &hex!(
            "8e640b879d473d7ce6689175808b925b6ba1177ad8b0c53208e1b7c6303844f52c8cae5791d0aeceea028dac107fad5e80866c"
        ),
        tag: &hex!("3849e4fefcecb108f83ddc039a21dd91"),
    },
    TestVector {
        key: &hex!("186f6a73ac82e33f69c5b158c7ee1cbe"),
        nonce: &hex!("bad41bfe8b67151131e85b2b"),
        plaintext: &hex!(
            "cc4d9dc2df86165343aada60cb5c1d9f991331d530d860dbf9166907d394721b2a22b53a6b070c5cb32ba3788ff55bc6a0d5f3"
        ),
        aad: &hex!("dab496ae14125af2fef47ee3b226a6c92e99b9e0"),
        ciphertext: &hex!(
            "41a17c3b18e67d84bfab344bff1429a87c3076879ea42383d1e622e710a60612eecf2fae8a56a95a08c958a52f873ecb303785"
        ),
        tag: &hex!("335015e14d2cd8eb9813799c5c703a89"),
    },
    TestVector {
        key: &hex!("14ba3901daf9db40d5dfbd828a361ab8"),
        nonce: &hex!("af37192707a3804beb57c836"),
        plaintext: &hex!(
            "85f016f83ceba76a068e5def3ed5ebac85e203c69e32676550c6ed864edfd2ccb2c8da415a42cc6ead791e869296091efe7ca0"
        ),
        aad: &hex!("1ac4a38e83649004727d2b2b71075264cfcade09"),
        ciphertext: &hex!(
            "2a682e5579d7f801fdbdddb2b5f8564c9e91c39cde47c48ac1dffdf7ef1674ed937e77215691110ab730af97349f84128eed56"
        ),
        tag: &hex!("b1b50298f48b96e679c3d71f3d17d623"),
    },
    TestVector {
        key: &hex!("c0552b2f54f4e8292119dbf61285fecd"),
        nonce: &hex!("b5a580ec23753690d6c7392f"),
        plaintext: &hex!(
            "88c04f3421de415f9ee9b47e033666c0d182d04f38e6faff5fee5ec89d1bd391079e90fb22c537efe4561718588eab313cfd5c"
        ),
        aad: &hex!("46cad83fbea4c47b9374bacb072472edcece9acf"),
        ciphertext: &hex!(
            "2ca83a4a63de404ad2306a4918420fe3105cf7f9a52d16aa610e3b69a0fed246da41768c801c19d7502ccccd5ba0a1bc0b50f6"
        ),
        tag: &hex!("8c03304e8a74dd52d4e3baec89cd397d"),
    },
    TestVector {
        key: &hex!("c6efbeedca979cb2c4fa5d6454a77dc1"),
        nonce: &hex!("4e57df4988d93d13dc512487"),
        plaintext: &hex!(
            "a52077491b20ac65eff89bd0bdb6150ca755cf469c42ebbc5c95bbcf3aba91a9002bf386fc9a126fae73dbb2daa7ceb79d0b5f"
        ),
        aad: &hex!("9e65d0542711fe57abfda27587ef4161eb3fe32e"),
        ciphertext: &hex!(
            "4dd803cf6c99d2ce3ee8a1996f52837e52c3bb386cfc2792318e1ba64c35b638c9508b2e21d1da6e635e59e37c02c0b0a2529d"
        ),
        tag: &hex!("af847ce419fa54045a8bf31062f6d349"),
    },
    TestVector {
        key: &hex!("3d68401d7c5f5c0a2529ede00724be14"),
        nonce: &hex!("3f3eaf76e786e8af54baa56f"),
        plaintext: &hex!(
            "8bfeae1dadfc55baca191a6a3f54ab721862c51ce684e4aea6e9a3e2f3d2aac14af1cb0252f29a4c8c0984ce867acebc7596c7"
        ),
        aad: &hex!("6a6e3ea815e01cda78a76b0fb8bdafb8a25a6b7e"),
        ciphertext: &hex!(
            "8a62b81a69e6e104dc075cc32730ffcb419b9f41711e06d7c2d9e891a88dc6e88817cf5bc2b87e95c4678daf0ca4b8f1e03927"
        ),
        tag: &hex!("9eebbcee46565fd4c34b8f47bcd94b31"),
    },
    TestVector {
        key: &hex!("0657bb596cc28eafd51cc09a3e6ec1f6"),
        nonce: &hex!("8e11a0625fba51698614f8f9"),
        plaintext: &hex!(
            "435f16f56aa71734dc6571e2714207f7ff85c7eeaa1879901f2ffa00ea45038db54329f0a2e78ac58a5d76314788d8351777fa"
        ),
        aad: &hex!("cf73715474e49d71f4f5ad08e209ff9774ae9639"),
        ciphertext: &hex!(
            "d876339f0db3bff022cb4504fe0a8ae26040102f575ecd4e4583b04959976254d07384141ba5748d3579815e3b5e1d1e8fddaa"
        ),
        tag: &hex!("7e6f7096e425911fe739ac90cca05fda"),
    },
    TestVector {
        key: &hex!("b2c645e0f2dd0d21e9511364f9355919"),
        nonce: &hex!("91f6f089f5e828d6fdf12510"),
        plaintext: &hex!(
            "3c01159e4787a74a707b4ead3be126b819831296821f1add394762ac97599cc810bd97205d0743548e7150bfbe6d9c1ba5d581"
        ),
        aad: &hex!("e6781ff89032df5e5398108f1d569d7f8327b25c"),
        ciphertext: &hex!(
            "1a06dec18eb4c9b361f1f2ec6391daf275f15d97a7f1a73fbe1d144bc1e1018200f725d52400c693a438edb595fd4558c4227a"
        ),
        tag: &hex!("451783874f9d925328208bc4c56eed33"),
    },
    TestVector {
        key: &hex!("3c50622868f450aa0928990c15e1eb36"),
        nonce: &hex!("811d5290768d57e7d87bb6c7"),
        plaintext: &hex!(
            "edd0a8f82833e919740fe2bf9edecf4ac86c72dc89490cef7b6983aaaf99fc856c5cc87d63f98a7c861bf3271fea6da86a15ab"
        ),
        aad: &hex!(
            "dae2c7e0a3d3fd2bc04eca19b15178a003b5cf84890c28c2a615f20f8adb427f70698c12b2ef87780c1193fbb8cd1674"
        ),
        ciphertext: &hex!(
            "a51425b0608d3b4b46d4ec05ca1ddaf02bdd2089ae0554ecfb2a1c84c63d82dc71ddb9ab1b1f0b49de2ad27c2b5173e7000aa6"
        ),
        tag: &hex!("bd9b5efca48008cd973a4f7d2c723844"),
    },
    TestVector {
        key: &hex!("a7268c7ef7bbc2be4a3ffc282019fba6"),
        nonce: &hex!("df2c5bd03f2cc45a07173144"),
        plaintext: &hex!(
            "f88beae931a68ed813a35bef54bd9999fd23ce4a1d258e34fac184ba799132a408bde4ced23748db5b35ea9692f4e1561d4cdc"
        ),
        aad: &hex!(
            "445b4ec6c505f132d3b012df624fe8f6e9cda0d8ec5e1ef7cde8b89259e167d68c1fb4dc4a78e5c59377f32ef5cea4b9"
        ),
        ciphertext: &hex!(
            "ea53e264e1b0f67ee37c81234d3b9c253ab1a94a4ad17779efcbeef0526129b0fd224b5884eb8b38e35ce0bdda222e30f576f3"
        ),
        tag: &hex!("38b5ef8d660f856d495db50f702bb462"),
    },
    TestVector {
        key: &hex!("183dc6bc9a497304011e5aa41dc575b4"),
        nonce: &hex!("0f4e2961d8ac4f81f559de7c"),
        plaintext: &hex!(
            "aaad38b847c7a6fce801ff4ba62639592c487382e7e3ab0f29d0dde432f31028c0b14c67c15cc3664c660c197b4792433924d4"
        ),
        aad: &hex!(
            "8ade36c0d68fa431838beb9f1d6a422365024bd5019979fa9b09b7c44b785e051dded5c9e21f342cf376e72cdae95207"
        ),
        ciphertext: &hex!(
            "38e09d7612a536a80d2e32a46b0e1e4ab1e1022e854461aa7e695d7aa4a003e379c0e270face29e19d74d40a60fb2e8c726aca"
        ),
        tag: &hex!("4004e9763f4a7d0fcb0ba57c7611f281"),
    },
    TestVector {
        key: &hex!("047dcb88c16bd0d32d9a6272b079e379"),
        nonce: &hex!("d174ed8d60c0d5c814dad4f6"),
        plaintext: &hex!(
            "f957104f1fd87e9e1d6d35171a1cbe8fb22cb4ea7aba31e763e77c6f291db81c63c910cf9b8d37bf93fa28fd4e2808480b5836"
        ),
        aad: &hex!(
            "c6567022bdb5f2f3a1e3d78e0202a5f6b457c0ebf46a4b0620afa2b5ba706f1a37f932058afdb8cf4eb9a3815ecad445"
        ),
        ciphertext: &hex!(
            "b7f83cb77ef93895a6721dfafde8930090d2a9f39a1d605bbb8d7fe0f0fa838fc6d1f0e5e532592d0c688231e24139e635b502"
        ),
        tag: &hex!("452368d42f8a1211b4a018ad1acf837d"),
    },
    TestVector {
        key: &hex!("7286fe98ac0c03252f3ab7eabb8988eb"),
        nonce: &hex!("e32e708c6302ce26902bd599"),
        plaintext: &hex!(
            "58fad037e6efa65630ca14698725538c686ced497c584afad218fa3b753beaa7a72fab9c4c108ad14bf5f024613f91a1155679"
        ),
        aad: &hex!(
            "4b9003a0259ed70aebfabc90abe750b888e9db453d9f95790d752d4ab9f208ee478046abaa9b2bf24564216071613297"
        ),
        ciphertext: &hex!(
            "ead0bc4e5902600598f9ca9e91cf4543420cd64e281a710fe890e0cffefa803d8c046390da6f50fd44b7e87861ac4088b5266d"
        ),
        tag: &hex!("970659d5170d654b55ca5f79a9e06957"),
    },
    TestVector {
        key: &hex!("0dc3090d2786eff167b291e895ac2261"),
        nonce: &hex!("6ac8f3a8a61448e1fec06d6d"),
        plaintext: &hex!(
            "3017261d20002fafdae4252dcc9b1214e9a9ee959533d34aab136249ca4ef52ab205ea69efe6fd21ed3c90f8933593fc63454c"
        ),
        aad: &hex!(
            "a85588d465b1ec2d935ce1ba5d6397bd57055915329830b1aa4a934f2080ecf48ab5f6269ccaaed8a10f398be64cdb8b"
        ),
        ciphertext: &hex!(
            "1fd7efc41a54374048e5d2a196bbb5b78452639db232c4c106fa8da6b1471ac14aaf2328e959a9c55f201d7271451151bfb48d"
        ),
        tag: &hex!("be7ff0322d4d42009dadf48e5aa939d5"),
    },
    TestVector {
        key: &hex!("d169282809ddae3384a10b908b8526c3"),
        nonce: &hex!("c9448a902e05f8ab10ad92e8"),
        plaintext: &hex!(
            "490b469f84939d62e00fdef53430232e5b0ef130d586bbfa8a3d3ba30d91614b64e0da092f16b83a46c9386ebed0bf9e863950"
        ),
        aad: &hex!(
            "71b1efec4e50041d0446e03b07ffdff05c6259d90aa7b33189e95360bfeba23afe914d0f17db6ba47ea165cc06d501e7"
        ),
        ciphertext: &hex!(
            "ca693b2350d23808840870c2371f49eda453f2e189c70b975af2531b9e8b0d8c262829e61f8990804844ac941b2fe47399a88d"
        ),
        tag: &hex!("8bc9e25a568987b427cfc5b42e412d7a"),
    },
    TestVector {
        key: &hex!("93814839da20b560268ad8fe257a9372"),
        nonce: &hex!("f157ac4a83a7b73b8085085d"),
        plaintext: &hex!(
            "bbad922de6dea7153724a333554e1aaf2e37aecd182b45885d04f3d11c3763fe59c26828d30c9da95adb75fbd5fbd2e6ece12c"
        ),
        aad: &hex!(
            "9b422e74f2109925264c1c0dda2b68c979afdac110e42b81afd2c59e2df3ff3f93832552b626b3821212a3e20c401949"
        ),
        ciphertext: &hex!(
            "be069b414d93d4f641b053f1ee7a61e23bf287a63b1d06c05393e8faa5856d22724bfc511a306ae4ba12c0a051b479e35c229a"
        ),
        tag: &hex!("53a62f9431b8e6124c9bf6298f1b2880"),
    },
    TestVector {
        key: &hex!("3262f2442b89a3641456cfa3d4d186fc"),
        nonce: &hex!("d0fc4f8f7bb74a1763862407"),
        plaintext: &hex!(
            "fcdd7cd83a366f94289d8b470345fccea2aff778edd9f60c6d8273b3277a843965f0d4ff8be1e61ee82caae8754b87e747b2d5"
        ),
        aad: &hex!(
            "bee1c8ed52bf347431babccac2a64275224045d5c1122eb8c2ac3d8791a5a9c37abf050c406ebeb947428bb60d58d062"
        ),
        ciphertext: &hex!(
            "d0e5cecf32ef65035546cf8a99dc7e6f4320376f8e16a51958dc796c9b9a37a0d74e7b9979a0ab5b88ad92988dc184b964a11f"
        ),
        tag: &hex!("37c52cd41ee2d519aa8363b186aadcc4"),
    },
    TestVector {
        key: &hex!("fc937348a4468afaa629f158dcff5a6e"),
        nonce: &hex!("783aa881ba0938ed8fe8ea30"),
        plaintext: &hex!(
            "0db6285ed23143762d6e9b708f0c84ed3f48d51e8b3da549f1ce130bd434d0c38238d0e2c6e2b7f6a35eba2cd84d28781dff19"
        ),
        aad: &hex!(
            "31b2892a669cce974c2b467d84c45189b335a5943d43b2f158d5c173be4fe31f8142f1b697c772f175a65dd87ae5fb52"
        ),
        ciphertext: &hex!(
            "29d665791fac09a72dd2178d69de16a5ea3432bf70acfaa174ec4cc93df7efff5f3c057c1ffacc80eb2991b1c79ab565c1f97a"
        ),
        tag: &hex!("113a2dd0be60dd45ea4f3d8b90c1122c"),
    },
    TestVector {
        key: &hex!("a9a33b71eb81d091ac1d15e48a19a067"),
        nonce: &hex!("bb86b999753142de6573e863"),
        plaintext: &hex!(
            "910246d2435786fdc8f950a0e3a79d081ea1c41eebb875de2eee9daaa8250850f636522cc953419767ad24982bf14427243971"
        ),
        aad: &hex!(
            "7a4ba8b30eeee2f457b74699d2ff77d8f9912f09757972bf8e5e8ec37684a8e1523b0afec0aeb5fababdd945fb55eac4"
        ),
        ciphertext: &hex!(
            "a4cb039956e398846bac343db72b72ded486f64fc58c8b3c3d8fbf1f91b00f4c7c2a560f88f73b7eda4bf2bcc9d4f7a6c62f9f"
        ),
        tag: &hex!("dd594f34a29fa02af3accf567d7c5206"),
    },
    TestVector {
        key: &hex!("7cb2f97b5609e76040712a95bfe84fad"),
        nonce: &hex!("1c2398ea67c1246540c469ab"),
        plaintext: &hex!(
            "ede4b5732c8fa7bebc87f72da2e243dd4173ddad700bef65adeeaa0c570392fc477b3d2b7d404bea40074a6d58a00f2466c1bc"
        ),
        aad: &hex!(
            "add3e89872e09f64d828463d5df7519de1a9db7639229b67901bd27ac3c3ea61ac1612067d72037adadd2e14475584a8"
        ),
        ciphertext: &hex!(
            "6c6dd8a691eb22294818e61e33afea9e49353d1bb6f645e821d7c4c31fb440dd8cc2651450a764a22038978651ffd33d4be108"
        ),
        tag: &hex!("ea246bb5e2ab3282c27927cd983a7297"),
    },
    TestVector {
        key: &hex!("402fc879126ff144792af40975f0a24c"),
        nonce: &hex!("bdbf6e81feff5a11df17e205"),
        plaintext: &hex!(
            "8c60dce80b0a5ef578d680d1c811967265cc7664c751faf4d1472dac5b96e26e3be439b19e3da83b1a19dc82ba00d435e03342"
        ),
        aad: &hex!(
            "de8443df44d93b3734d8820b9a26010d6ce09c1bb9a02260235a40299d38330f67792d0f54c0c0fb35ef9febcbccd02b"
        ),
        ciphertext: &hex!(
            "8753e01ee5c088bcae1309b2e4269d9fb15491831a1e17140808f30aee4fa528020a7fc7df8627cda9b7401c44b15aa1e7c644"
        ),
        tag: &hex!("0f457c92a99ac1eba1b6105d6d23ce53"),
    },
    TestVector {
        key: &hex!("ca5549614dc0324564002139fd6a360e"),
        nonce: &hex!("8a4de31b0ddc6d2a3570fac0"),
        plaintext: &hex!(
            "37610c187d287982e9afc15a9250aeb91933369dedc5910e4de584d70c27b7e4e0a7b02869299100fd8ef75bc66ae4bed2a853"
        ),
        aad: &hex!(
            "6b88709627c28825569d60772b6642a9dadbf3ea9904b290dc632a837d579d2e81284bf4350923c1863e0e8d5894a34b"
        ),
        ciphertext: &hex!(
            "29505af512768c89d84054cce8f8889e9b4a095098b9cec7e26a6afcf7aee5132fb43caf7edc068fb6aea3570ad9310a5c3329"
        ),
        tag: &hex!("d0918033b6db5f999f26bed94d352af6"),
    },
    TestVector {
        key: &hex!("a68b64267d0d1bc2d94b9f691ff8e9e4"),
        nonce: &hex!("a27706bd8eae8bb3dc95a1b9"),
        plaintext: &hex!(
            "4a99ab41c604d7210069d9228dd3223b6f7da215ddda16cf93bf6658784cbbfe08ef6a0152cef368415dff9f8d1d05ead043f9"
        ),
        aad: &hex!(
            "8734fa3cecb5793b2b7bcb4fcde7808303c27c2c002a27e0dbaa378b3df4909e37c238a24faf49b6cd134419948bdec6"
        ),
        ciphertext: &hex!(
            "43aa0432a1b468bec64de45b66b5fb3e8b2bd9277801ef53a1cd6757bfd45aab9c6b23f0a1f4b30fa33fe52fabe7bb86281964"
        ),
        tag: &hex!("fd39ef2e94707a1aba57ff2de7c17927"),
    },
    TestVector {
        key: &hex!("2c1f21cf0f6fb3661943155c3e3d8492"),
        nonce: &hex!("23cb5ff362e22426984d1907"),
        plaintext: &hex!(
            "42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea949c8a1a2dbc0d68b5615ba7c1220ff6510e259f06655d8"
        ),
        aad: &hex!(
            "5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b0333e701557a713e3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b391528514170084ccf587177f4488f33cfb5e979e42b6e1cfc0a60238982a7aec"
        ),
        ciphertext: &hex!(
            "81824f0e0d523db30d3da369fdc0d60894c7a0a20646dd015073ad2732bd989b14a222b6ad57af43e1895df9dca2a5344a62cc"
        ),
        tag: &hex!("57a3ee28136e94c74838997ae9823f3a"),
    },
    TestVector {
        key: &hex!("d9f7d2411091f947b4d6f1e2d1f0fb2e"),
        nonce: &hex!("e1934f5db57cc983e6b180e7"),
        plaintext: &hex!(
            "73ed042327f70fe9c572a61545eda8b2a0c6e1d6c291ef19248e973aee6c312012f490c2c6f6166f4a59431e182663fcaea05a"
        ),
        aad: &hex!(
            "0a8a18a7150e940c3d87b38e73baee9a5c049ee21795663e264b694a949822b639092d0e67015e86363583fcf0ca645af9f43375f05fdb4ce84f411dcbca73c2220dea03a20115d2e51398344b16bee1ed7c499b353d6c597af8"
        ),
        ciphertext: &hex!(
            "aaadbd5c92e9151ce3db7210b8714126b73e43436d242677afa50384f2149b831f1d573c7891c2a91fbc48db29967ec9542b23"
        ),
        tag: &hex!("21b51ca862cb637cdd03b99a0f93b134"),
    },
    TestVector {
        key: &hex!("b818752aa4452120808c3d211d57c224"),
        nonce: &hex!("d679a0be22c2daf619b11463"),
        plaintext: &hex!(
            "7ccdecf13130c20f67dd6f47adec33dfb52bc84a7700431b7fd398d652a123f086ae197328cfaed127a91866c95bdfdb4849ce"
        ),
        aad: &hex!(
            "bb853b60b5fd8bd24acc9db9dd3de48b775d4a5cb2a879c1dd78bde94cafee06db12a1574eade205dfd3a8c6f68599e120ec73b6b4559cd03d3118b2b1bbe340bb15320c6bf8d8a1c3c1247b4023ba2949ba6a5ab13f2d85b93b"
        ),
        ciphertext: &hex!(
            "bc1a886c9e5accc34f0c237f7ed996e940e4b0ec882638e69866ed24d86467f5433aee23448df39565a0ecfff2c40e6857f725"
        ),
        tag: &hex!("5ff9c449d0bfa870ebefe78d519a8d12"),
    },
    TestVector {
        key: &hex!("528b8948b534d5f780ae3f1e23a47a25"),
        nonce: &hex!("fec5eaf0a6d6f5c4adec9618"),
        plaintext: &hex!(
            "9c5280591311dc212d6ee2ad8b83dedf03b91e244d8a42690c9a5821ab971453c8b4f63e15bb8af96aeb4a3e35515b651bc68d"
        ),
        aad: &hex!(
            "d5134d84a96921537a17869c3ed08c55c29e0a67a30943cb248849843794c1c6fefc98659da9b0f505bdefc2e4ebe9523d2a165b63b5e3b2ba9535821d62aaf95b9c7e6ff1f8807a13e79b9fe589c0d9febbabf9372b01ac2051"
        ),
        ciphertext: &hex!(
            "bdf0b752160e64b626d5c543954570169e28b033f77b6ef8a37bcbae2a294a9e7060c3235b290f79c69c39a66b0d5ecc81d02a"
        ),
        tag: &hex!("f93768c97781ad0486f2f9e8210f2a22"),
    },
    TestVector {
        key: &hex!("824ca85e2e4b2a6c6e6a65ef8616c57b"),
        nonce: &hex!("d2bf92e7dc53676aac4e6d1d"),
        plaintext: &hex!(
            "cd4828e5977d7fc5bbf7f6d1870bf6333c204087639a3b494a4037170b73fc6b32c4555d1a02a8837441734d6835a54bf35a44"
        ),
        aad: &hex!(
            "465afd08d7260308d8d21025f31570e5dcd6bcbd6520ecb6ff85de58378d5af6eaf7cb2f1242c0c47b759c58dbc6e4b45c8b993514f14b82eda3fcb6a0df2075a0ab76fa0c5b6cb37d1d28f773dac591790887d2d72f03bcc5ae"
        ),
        ciphertext: &hex!(
            "4da02474ef189de863d53323ff6737c12efb3d60a890a8d53991de57ffc6cafd44c429a762a2154c5a937120db2161f2cf2ea1"
        ),
        tag: &hex!("949d399a7e2567b275c6f842de602605"),
    },
    TestVector {
        key: &hex!("4f60b753a36b4b1f2e4d8300ddc667a5"),
        nonce: &hex!("35fa2551581f8592134bba45"),
        plaintext: &hex!(
            "83807c042900611f50fd42557b7cf66315872225143d2cdf8c05ccf688ff21da8f6a2556b0051285b8e7cb8aee05b72816abd5"
        ),
        aad: &hex!(
            "9a006b7cea27f3b4a305ffb0c5bec7e3582c6a3be028ebf44bb2496dae1f492f765cc66c82d3a2212abd6142524e0727dab8ae506e6d5b9dd361e3a37df3bec95b14f1174e7f25c656aabb42981b91950755281c5ef8f52e57bf"
        ),
        ciphertext: &hex!(
            "cd2291ac182ab6d0f7b6b93e67abc4228ab63a4c1b214caa11698d40d2a8aa10164b48624d39dd967f4c35eebf09acdfe59f45"
        ),
        tag: &hex!("b231bb4e63dda90a11700f204dc2b175"),
    },
    TestVector {
        key: &hex!("07b122a618bb54b8c39d579fe5518a5c"),
        nonce: &hex!("26fa33d4c5b37f0c5d07e2d0"),
        plaintext: &hex!(
            "06cf2fa1c9057d4974ae9048b4878d75b0b4720ed2d7c340e6d983a7cf08d20013abeef881cc3213fe25b3f6ac1e17fe1c2e11"
        ),
        aad: &hex!(
            "20966308f57d3a3e7a4ea149cc1f3edeaef11e8af780a16534472d8df7f706152ee376614426094fd745d77cdca28682d0d2e689d28a50610168d638b23cb4dffa95dd260bc72e0098722cd00126a07fd23ffba1d10a3ce46b85"
        ),
        ciphertext: &hex!(
            "61a69d35967c85dd5e0741a9b88152c3b04b1824930cf6c03f1cb44c1258b71fa3f5233d2f4ee256353c0b8f6d470b53d7811a"
        ),
        tag: &hex!("e98a7a33748de95e22b520ba2254bce3"),
    },
    TestVector {
        key: &hex!("288e7efe62b93b990f2398c2460e415d"),
        nonce: &hex!("c7ebc0cd756d9501faf71a7d"),
        plaintext: &hex!(
            "5fafe873b9d30771f2ef8dad397a8b42af3fc8f7ebbea80d0132e1af14269a463dbd87e3e01a58c2d991eb3badcf156fe8260d"
        ),
        aad: &hex!(
            "fcb20124c58b29ef7e39800d1e11c4063774dd2c462dd9e07d140d9f4b5ebe4cba7bb8cc03bf357b22096c9897cdcdf112b7a5f7d1e38d5c74c16924522cbe2443c157cc93146c12bae4da2b2f1df07f334aa1cc99fd7f7e2899"
        ),
        ciphertext: &hex!(
            "e5e69100c77d57e05a41b28be74b1c8542fd1f15e73fc589535ea1fac2d263fd92cdaa9908eab6ffd9194586aa3fed5fcd109f"
        ),
        tag: &hex!("537516fb827cbf6ce0500c6feff4db34"),
    },
    TestVector {
        key: &hex!("f66c5b44e7a9dade5765c3f64fb2bab9"),
        nonce: &hex!("3482a46c8d4f173e62ce1dc5"),
        plaintext: &hex!(
            "80501408e23e2a656720b32b9f41f542fc64e9e8d824af115ece88d551a5f5d5f7fdb67e2339fc263dfdb18a78d423fd868caf"
        ),
        aad: &hex!(
            "1e77645efa4419b2c9696b8f989051929ad6a01fe2223ae68325f8176cc467fffbd198e008904b82af6469a3bbb095c4d00cfed143723ed6cf6ba4198c40eabd05c03e0260f8b2f55038e5c382690886280f6989357c50f74fe5"
        ),
        ciphertext: &hex!(
            "e778a946529444e2656505e4f5f6519d3ecad5458f8f1a04f31a8af97ca185ff717764bca6e99258a24dc97c322ac1c7f54fba"
        ),
        tag: &hex!("c5b2cb532cd05b162b47e94f6d79cb8e"),
    },
    TestVector {
        key: &hex!("41e8af55426edbe8f0339d0fba400497"),
        nonce: &hex!("07eb87d42e90a075d4b34911"),
        plaintext: &hex!(
            "adc5504d0a9735d7b73fc53bd0ff60f2c881394fdecfcce3483efe126bf148e48db9c0fd356f82e62d743ec09f8906431eb5e0"
        ),
        aad: &hex!(
            "bb2e5c52f2eacc9b7706a2efe4b607858922fd6914a1e22dfbecab2a06464942f769a9c544f046b88a7570e2cf6fd8146c86b2b4decb934f04a81e6d48affbce1f5381ab31a9736b63f5a4e744731726a36357e858c0980d3732"
        ),
        ciphertext: &hex!(
            "040d99698b2a5e0169f6f94e61159c135fb19c5917c015aaf8ebb4a451ffd8347428ebfdd80c83841d299318084c779dc91b0c"
        ),
        tag: &hex!("a16d6267efaeec13d6bc281316ab8be7"),
    },
    TestVector {
        key: &hex!("bbf947c0e805ac0641d540b471eb9d26"),
        nonce: &hex!("b57daf0004f43821f1ba86de"),
        plaintext: &hex!(
            "1211e9224ebb862f2d27de692362324942da12da441176c4742a228d7928d3c1fb3e83c66d68c619a10911fc2ed90226d4ae48"
        ),
        aad: &hex!(
            "e18d861dc9bb35a9efa63c7c1deaf53910256809a477f1c3db893b2389f1d137659033a5841b888cd6491bb574b782dec2c840f6350825406387d71340d275e62af3cc070c1389375d81ce98ad37c7afcadcd79f1c520a462e7d"
        ),
        ciphertext: &hex!(
            "a6f6aa1750118b402ee1b5f025d29007e3cb162ad9e363efb9ef2d24c850f62db925bbb7e9a83ca6cd6f74251db72622857b29"
        ),
        tag: &hex!("a72dcc29d358f794361f84202c9832f9"),
    },
    TestVector {
        key: &hex!("a56f4de6772b1242f1dff344ec9b512d"),
        nonce: &hex!("94d228087e821e301409f305"),
        plaintext: &hex!(
            "af537682c419eb7ca3fed65bcc364b01efc2455ff65128dedc88f2224603ef3d7246622269a12b269bbf6ac9d2d3b81abd366f"
        ),
        aad: &hex!(
            "6a9c61dbbfaa20a13320a5f1dead28bfbe5dcbe84fe0a3617c348bd702fbe746f439dfcabdad22ac2fa629793f545bc68459f1c0462453b5b31b747c3d29614f0ccd0745fbaa4b204d47d5cc7db35d6bc44bfcecdfae910faa72"
        ),
        ciphertext: &hex!(
            "55b60587eb879105ce4a36555d8f799618238bf1f7fd4df622662bd07f450a18375ab7eef02a8036470428c4834f881bf05cd4"
        ),
        tag: &hex!("8cbe48d46b5c1296b05b2b6f4b24f7c6"),
    },
    TestVector {
        key: &hex!("766067fa8f0dc348b77d55ab5317a609"),
        nonce: &hex!("8716219953becc2d8918f3aa"),
        plaintext: &hex!(
            "ab910f7300ec6bf57d7baf2b4474a26a7d7dfcd6b1044cd0b0b32995029a70627f8d2554429e13d14d78950fb1c79ed1f48c32"
        ),
        aad: &hex!(
            "8106f9cacb894dc2f0c93c67cc06cd54af6c6d94193bd0bd9673fc702fc6b995941476f2dc584ff753cdf24517c2153f1e1c6e37fe6d86c1e4fc63bceb25749f9372d62a1932749dd21ef6010b2942bd0464bd64171063a778a0"
        ),
        ciphertext: &hex!(
            "8bc822183f9e42f05429e064934d9f84dfe1713d71690e68981f94256fa4a60736607c5864e3b05e3730caed80004a9bb3adb6"
        ),
        tag: &hex!("439b0bcdd24a87429a4098fd8a05514c"),
    },
    TestVector {
        key: &hex!("557ef21e91f108f6ab451980837cf029"),
        nonce: &hex!("ac1010f6dcec713cba17cb13"),
        plaintext: &hex!(
            "a2ae838532cebfc9ff8fb62242b84df706ad1777a62f54c64d9b1777bdc0819438d34aa4c1906e0fae1e845b32d8fb65763dc6"
        ),
        aad: &hex!(
            "5d09aa2a302e3ec2bd71b25d52053463c9c38a3b460f7b980aad6c91d5011570be8c23b4db518701f4c5a157882695ba4ac140f94bda13d9824a8976d436492baaae6c4f8367683199695a1f6bcda2f645b188aa5c286fb91c8a"
        ),
        ciphertext: &hex!(
            "94c1941887ff94f34cb96cff2b6a25f660ce9b3ac54963960e70ee49500dae6a20d3307393f37d3a4a35c13b58f7bff0f5de7b"
        ),
        tag: &hex!("95e574f70f5efa14b8ee21961972ee3c"),
    },
    TestVector {
        key: &hex!("55c8bcb0021090e4b2c785c79cb966b8"),
        nonce: &hex!("5e9f1313282f73d7ffb92837"),
        plaintext: &hex!(
            "2d7c1b689189bbfa2be26ad5c1f296dee4c0f61456ffc94cf8e70aad0f09d0608c4115aa6ed5eba93ed5820b3f3426bbf4d64a"
        ),
        aad: &hex!(
            "f7e14a57e3bb6b99866b90573d7bc355baeb7ac347e43d0b65d97ecc2eb9c772401a8e3c7e9e2871c2b79579d44c139e62c33b42a9e0c87686960009d659d5e3874e168c334b6650c6d36168633757a7c20764232ce94a0de1a5"
        ),
        ciphertext: &hex!(
            "ba59002df3394c5b80983519dc163eca5c44df80f8c4c4e15d3ff73f13c170c80a59d87a2165a7b450be01031a8e41c505c89f"
        ),
        tag: &hex!("28418c564731bddf3d504d8ed32e66ee"),
    },
];

tests!(Aes128Gcm, TEST_VECTORS);

// Test vectors from Wycheproof
aead::new_test!(wycheproof, "wycheproof-128", Aes128Gcm);
