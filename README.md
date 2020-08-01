# RustCrypto: Authenticated Encryption with Associated Data (AEAD) Algorithms [![CodeCov Status][codecov-image]][codecov-link] ![Rust Version][rustc-image]

Collection of [Authenticated Encryption with Associated Data (AEAD)][AEAD]
algorithms written in pure Rust.

AEADs are high-level symmetric encryption primitives which defend against a
wide range of potential attacks (i.e. [IND-CCA3]).

## Usage

Crates functionality is expressed in terms of traits defined in the [`aead`]
crate.

## Crates

| Name                 | Algorithm                    | Crates.io | Documentation | Build |
|----------------------|------------------------------|-----------|---------------|-------|
| [`aes-gcm-siv`]      | [AES-GCM-SIV]                | [![crates.io](https://img.shields.io/crates/v/aes-gcm-siv.svg)](https://crates.io/crates/aes-gcm-siv) | [![Documentation](https://docs.rs/aes-gcm-siv/badge.svg)](https://docs.rs/aes-gcm-siv) | ![aes-gcm-siv](https://github.com/RustCrypto/AEADs/workflows/aes-gcm-siv/badge.svg?branch=master&event=push) |
| [`aes-gcm`]          | [AES-GCM]                    | [![crates.io](https://img.shields.io/crates/v/aes-gcm.svg)](https://crates.io/crates/aes-gcm) | [![Documentation](https://docs.rs/aes-gcm/badge.svg)](https://docs.rs/aes-gcm) | ![aes-gcm](https://github.com/RustCrypto/AEADs/workflows/aes-gcm/badge.svg?branch=master&event=push) |
| [`aes-siv`]          | [AES-SIV]                    | [![crates.io](https://img.shields.io/crates/v/aes-siv.svg)](https://crates.io/crates/aes-siv) | [![Documentation](https://docs.rs/aes-siv/badge.svg)](https://docs.rs/aes-siv) | ![aes-siv](https://github.com/RustCrypto/AEADs/workflows/aes-siv/badge.svg?branch=master&event=push) |
| [`ccm`]              | [CCM]                        | [![crates.io](https://img.shields.io/crates/v/ccm.svg)](https://crates.io/crates/ccm) | [![Documentation](https://docs.rs/ccm/badge.svg)](https://docs.rs/ccm) | ![ccm](https://github.com/RustCrypto/AEADs/workflows/ccm/badge.svg?branch=master&event=push) |
| [`chacha20poly1305`] | [(X)ChaCha20Poly1305]        | [![crates.io](https://img.shields.io/crates/v/chacha20poly1305.svg)](https://crates.io/crates/chacha20poly1305) | [![Documentation](https://docs.rs/chacha20poly1305/badge.svg)](https://docs.rs/chacha20poly1305) | ![chacha20poly1305](https://github.com/RustCrypto/AEADs/workflows/chacha20poly1305/badge.svg?branch=master&event=push)
| [`crypto_box`]       | [Curve25519XSalsa20Poly1305] | [![crates.io](https://img.shields.io/crates/v/crypto_box.svg)](https://crates.io/crates/crypto_box) | [![Documentation](https://docs.rs/crypto_box/badge.svg)](https://docs.rs/crypto_box) | ![crypto_box](https://github.com/RustCrypto/AEADs/workflows/crypto_box/badge.svg?branch=master&event=push) |
| [`eax`]              | [eax]                        | [![crates.io](https://img.shields.io/crates/v/eax.svg)](https://crates.io/crates/eax) | [![Documentation](https://docs.rs/eax/badge.svg)](https://docs.rs/eax) | ![eax](https://github.com/RustCrypto/AEADs/workflows/eax/badge.svg?branch=master&event=push) |
| [`mgm`]              | [MGM]                        | [![crates.io](https://img.shields.io/crates/v/mgm.svg)](https://crates.io/crates/mgm) | [![Documentation](https://docs.rs/mgm/badge.svg)](https://docs.rs/mgm) | ![mgm](https://github.com/RustCrypto/AEADs/workflows/mgm/badge.svg?branch=master&event=push) |
| [`xsalsa20poly1305`] | [XSalsa20Poly1305]           | [![crates.io](https://img.shields.io/crates/v/xsalsa20poly1305.svg)](https://crates.io/crates/xsalsa20poly1305) | [![Documentation](https://docs.rs/xsalsa20poly1305/badge.svg)](https://docs.rs/xsalsa20poly1305) | ![xsalsa20poly1305](https://github.com/RustCrypto/AEADs/workflows/xsalsa20poly1305/badge.svg?branch=master&event=push) |

NOTE: the [`aes-ccm`] crate also implements the [`aead`] traits
used by all of the other crates in this repository.

### Minimum Supported Rust Version
All crates in this repository support Rust 1.41 or higher. In future minimum
supported Rust version can be changed, but it will be done with the minor
version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[codecov-image]: https://codecov.io/gh/RustCrypto/AEADs/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/RustCrypto/AEADs
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg

[//]: # (general links)

[AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
[IND-CCA3]: https://eprint.iacr.org/2004/272.pdf

[//]: # (crates)

[`aead`]: https://docs.rs/aead
[`aes-ccm`]: https://crates.io/crates/aes-ccm
[`aes-gcm`]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
[`aes-gcm-siv`]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv
[`aes-siv`]: https://github.com/RustCrypto/AEADs/tree/master/aes-siv
[`chacha20poly1305`]: https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305
[`crypto_box`]: https://github.com/RustCrypto/AEADs/tree/master/crypto_box
[`xsalsa20poly1305`]: https://github.com/RustCrypto/AEADs/tree/master/xsalsa20poly1305 

[//]: # (algorithms)

[AES-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[AES-GCM-SIV]: https://en.wikipedia.org/wiki/AES-GCM-SIV
[AES-SIV]: https://github.com/miscreant/meta/wiki/AES-SIV
[CCM]: https://en.wikipedia.org/wiki/CCM_mode
[EAX]: https://en.wikipedia.org/wiki/EAX_mode
[MGM]: https://eprint.iacr.org/2019/123.pdf
[(X)ChaCha20Poly1305]: https://tools.ietf.org/html/rfc8439
[Curve25519XSalsa20Poly1305]: https://nacl.cr.yp.to/box.html
[XSalsa20Poly1305]: https://nacl.cr.yp.to/secretbox.html
