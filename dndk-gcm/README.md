# DNDK-GCM (no key commitment)

Pure Rust implementation of DNDK-GCM (Double Nonce Derive Key AES-GCM) with
key commitment disabled (KC_Choice = 0) as specified in
`draft-gueron-cfrg-dndkgcm`.

This crate provides two fixed-nonce variants:

- `DndkGcm24`: 24-byte nonce (recommended in the draft).
- `DndkGcm12`: 12-byte nonce (AES-GCM compatible length).

## Usage

```rust
use dndk_gcm::{
    aead::{Aead, Key, KeyInit},
    DndkGcm24, Nonce24,
};

let key = Key::<DndkGcm24>::from_slice(&[0u8; 32]);
let cipher = DndkGcm24::new(key);

let nonce = Nonce24::from_slice(&[0u8; 24]);
let ciphertext = cipher.encrypt(nonce, b"hello".as_ref()).unwrap();
let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
assert_eq!(&plaintext, b"hello");
```
