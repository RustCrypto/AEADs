<div align="center">

# Grain-128AEADv2

![Crates.io Total Downloads](https://img.shields.io/crates/d/grain-128aeadv2)
![Crates.io Version](https://img.shields.io/crates/v/grain-128aeadv2)

Efficient pure Rust implementation of Grain-128AEADv2.

Please see installation details and doc on [crates.io](https://crates.io/crates/grain-128aeadv2). 

</div>

***

Pure Rust implementation of Grain-128AEADv2, a lightweight stream cipher.

**It works without standard library and even without allocator if your disable the `vec` default feature** 

## Security Notes

> [!CAUTION]
> No security audits of this crate have ever been performed.
> **USE AT YOUR OWN RISK!**

## Minimum Supported Rust Version

This crate requires **Rust 1.85** at a minimum.

## Quickstart

With randomly sampled keys and nonces (requires `getrandom` feature):

```rust
use grain_128aeadv2::{Grain128, aead::{Aead, AeadCore, KeyInit}};

let key = Grain128::generate_key().expect("Unable to generate key");
let cipher = Grain128::new(&key);

// A nonce must be USED ONLY ONCE !
let nonce = Grain128::generate_nonce().expect("Unable to generate nonce");
let (ciphertext, tag) = cipher.encrypt_aead(
    &nonce,
    b"Some additional data",
    b"this is a secret message"
);

let plaintext = cipher.decrypt_aead(
    &nonce,
    b"Some additional data",
    &ciphertext,
    &tag
).expect("Tag verification failed");

assert_eq!(&plaintext, b"this is a secret message"); 
```

In-place encryption (requires `alloc` feature) :

```rust
use grain_128aeadv2::{
    Grain128, Key, Nonce,
    aead::{AeadCore, AeadInOut, KeyInit, arrayvec::ArrayVec}
};

let key = Grain128::generate_key().expect("Unable to generate key");
let cipher = Grain128::new(&key);

// A nonce must be USED ONLY ONCE !
let nonce = Grain128::generate_nonce().expect("Unable to generate nonce");
// Take care : 8 bytes overhead to store the tag
let mut buffer: Vec<u8> = vec![];
buffer.extend_from_slice(b"a secret message");

// Perform in place encryption inside 'buffer'
cipher.encrypt_in_place(&nonce, b"Some AD", &mut buffer).expect("Unable to encrypt");

// Perform in place decryption
cipher.decrypt_in_place(&nonce, b"Some AD", &mut buffer).expect("Tag verification failed");

assert_eq!(&buffer, b"a secret message");
```

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
[2]: https://doi.org/10.6028/NIST.SP.800-232