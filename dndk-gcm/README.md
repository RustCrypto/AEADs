# DNDK-GCM (no key commitment)

Pure Rust implementation of DNDK-GCM (Double Nonce Derive Key AES-GCM) with
key commitment disabled (KC_Choice = 0) as specified in
`draft-gueron-cfrg-dndkgcm`.

This crate provides a fixed 24-byte nonce variant: `DndkGcm24`.

## Usage

```rust
use dndk_gcm::{
    aead::{Aead, Key, KeyInit},
    DndkGcm, Nonce,
};

let key = Key::<DndkGcm>::from_slice(&[0u8; 32]);
let cipher = DndkGcm::new(key);

let nonce = Nonce::from_slice(&[0u8; 24]);
let ciphertext = cipher.encrypt(nonce, b"hello".as_ref()).unwrap();
let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
assert_eq!(&plaintext, b"hello");
```
