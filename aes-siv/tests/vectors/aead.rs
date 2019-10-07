#![allow(dead_code)]

pub use serde_json::Value as JsonValue;
use subtle_encoding::hex;

/// AES-SIV AEAD test vectors
// TODO(tarcieri): extract these from JSON format
const TEST_VECTORS: &str = r#"
{
    "examples:A<O>":[
        {
            "name:s":"AES-SIV Authenticted Encryption with Associated Data Example",
            "alg:s":"AES-SIV",
            "key:d16":"7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
            "ad:d16":"00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
            "nonce:d16":"09f911029d74e35bd84156c5635688c0",
            "plaintext:d16":"7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
            "ciphertext:d16":"85825e22e90cf2ddda2c548dc7c1b6310dcdaca0cebf9dc6cb90583f5bf1506e02cd48832b00e4e598b2b22a53e6199d4df0c1666a35a0433b250dc134d776"
        },
        {
            "name:s":"AES-PMAC-SIV Authenticted Encryption with Associated Data Example",
            "alg:s":"AES-PMAC-SIV",
            "key:d16":"7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
            "ad:d16":"00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
            "nonce:d16":"09f911029d74e35bd84156c5635688c0",
            "plaintext:d16":"7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
            "ciphertext:d16":"1463d1119b2a2797241bb1674633dff13b9de11e5e2f526048b36c40c7722667b2957018023bf0e52792b703a01e88aacd49898cecfce943d7f61a2337a097"
        }
    ]
}
"#;

/// AES-SIV test vectors for AEAD API (CMAC and PMAC)
#[derive(Debug)]
pub struct AesSivAeadExample {
    pub alg: String,
    pub key: Vec<u8>,
    pub ad: Vec<u8>,
    pub nonce: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl AesSivAeadExample {
    /// Load examples from aes_siv_aead.tjson
    pub fn load_all() -> Vec<Self> {
        let tjson: serde_json::Value =
            serde_json::from_str(TEST_VECTORS).expect("aes_siv.tjson parses successfully");

        let examples = &tjson["examples:A<O>"]
            .as_array()
            .expect("aes_siv_aead.tjson examples array");

        examples
            .into_iter()
            .map(|ex| Self {
                alg: ex["alg:s"].as_str().expect("algorithm name").to_owned(),
                key: hex::decode(ex["key:d16"].as_str().expect("encoded example").as_bytes())
                    .expect("hex encoded"),
                ad: hex::decode(ex["ad:d16"].as_str().expect("encoded example").as_bytes())
                    .expect("hex encoded"),
                nonce: hex::decode(
                    ex["nonce:d16"]
                        .as_str()
                        .expect("encoded example")
                        .as_bytes(),
                )
                .expect("hex encoded"),
                plaintext: hex::decode(
                    ex["plaintext:d16"]
                        .as_str()
                        .expect("encoded example")
                        .as_bytes(),
                )
                .expect("hex encoded"),
                ciphertext: hex::decode(
                    ex["ciphertext:d16"]
                        .as_str()
                        .expect("encoded example")
                        .as_bytes(),
                )
                .expect("hex encoded"),
            })
            .collect()
    }
}
