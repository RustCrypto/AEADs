# RustCrypto: Authenticated Encryption with Associated Data (AEAD) Algorithms

[![Dependency Status][deps-image]][deps-link]
[![Project Chat][chat-image]][chat-link]

Collection of [Authenticated Encryption with Associated Data (AEAD)][AEAD]
algorithms written in pure Rust.

AEADs are high-level symmetric encryption primitives which defend against a
wide range of potential attacks (i.e. [IND-CCA3]).

## Usage

Crates functionality is expressed in terms of traits defined in the [`aead`]
crate.

## Crates

| Name                 | Algorithm                    | Crates.io | Documentation | MSRV |
|----------------------|------------------------------|-----------|---------------|-------|
| [`aes-gcm-siv`]      | [AES-GCM-SIV]                | [![crates.io](https://img.shields.io/crates/v/aes-gcm-siv.svg)](https://crates.io/crates/aes-gcm-siv) | [![Documentation](https://docs.rs/aes-gcm-siv/badge.svg)](https://docs.rs/aes-gcm-siv) | 1.51 |
| [`aes-gcm`]          | [AES-GCM]                    | [![crates.io](https://img.shields.io/crates/v/aes-gcm.svg)](https://crates.io/crates/aes-gcm) | [![Documentation](https://docs.rs/aes-gcm/badge.svg)](https://docs.rs/aes-gcm) | 1.51 |
| [`aes-siv`]          | [AES-SIV]                    | [![crates.io](https://img.shields.io/crates/v/aes-siv.svg)](https://crates.io/crates/aes-siv) | [![Documentation](https://docs.rs/aes-siv/badge.svg)](https://docs.rs/aes-siv) | 1.51 |
| [`ascon-aead`]       | [Ascon]                      | [![crates.io](https://img.shields.io/crates/v/ascon-aead.svg)](https://crates.io/crates/ascon-aead) | [![Documentation](https://docs.rs/ascon-aead/badge.svg)](https://docs.rs/ascon-aead) | 1.56 |
| [`ccm`]              | [CCM]                        | [![crates.io](https://img.shields.io/crates/v/ccm.svg)](https://crates.io/crates/ccm) | [![Documentation](https://docs.rs/ccm/badge.svg)](https://docs.rs/ccm) | 1.41 |
| [`chacha20poly1305`] | [(X)ChaCha20Poly1305]        | [![crates.io](https://img.shields.io/crates/v/chacha20poly1305.svg)](https://crates.io/crates/chacha20poly1305) | [![Documentation](https://docs.rs/chacha20poly1305/badge.svg)](https://docs.rs/chacha20poly1305) | 1.56 |
| [`deoxys`]           | [Deoxys-I/II]                | [![crates.io](https://img.shields.io/crates/v/deoxys.svg)](https://crates.io/crates/deoxys) | [![Documentation](https://docs.rs/deoxys/badge.svg)](https://docs.rs/deoxys) | 1.51 |
| [`eax`]              | [EAX]                        | [![crates.io](https://img.shields.io/crates/v/eax.svg)](https://crates.io/crates/eax) | [![Documentation](https://docs.rs/eax/badge.svg)](https://docs.rs/eax) | 1.41 |
| [`mgm`]              | [MGM]                        | [![crates.io](https://img.shields.io/crates/v/mgm.svg)](https://crates.io/crates/mgm) | [![Documentation](https://docs.rs/mgm/badge.svg)](https://docs.rs/mgm) | 1.41 |

## MSRV Policy

Minimum Supported Rust Version (MSRV) can be changed in the future, but it will be
done with a minor version bump.

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

[deps-image]: https://deps.rs/repo/github/RustCrypto/AEADs/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/AEADs
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs

[//]: # (general links)

[AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
[IND-CCA3]: https://eprint.iacr.org/2004/272.pdf

[//]: # (crates)

[`aead`]: https://docs.rs/aead
[`aes-ccm`]: https://crates.io/crates/aes-ccm
[`aes-gcm`]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm
[`aes-gcm-siv`]: https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv
[`aes-siv`]: https://github.com/RustCrypto/AEADs/tree/master/aes-siv
[`ascon-aead`]: https://github.com/RustCrypto/AEADs/tree/master/ascon-aead
[`ccm`]: https://github.com/RustCrypto/AEADs/tree/master/ccm
[`chacha20poly1305`]: https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305
[`deoxys`]: https://github.com/RustCrypto/AEADs/tree/master/deoxys
[`eax`]: https://github.com/RustCrypto/AEADs/tree/master/eax
[`mgm`]: https://github.com/RustCrypto/AEADs/tree/master/mgm

[//]: # (algorithms)

[AES-GCM]: https://en.wikipedia.org/wiki/Galois/Counter_Mode
[AES-GCM-SIV]: https://en.wikipedia.org/wiki/AES-GCM-SIV
[AES-SIV]: https://github.com/miscreant/meta/wiki/AES-SIV
[Ascon]: https://ascon.iaik.tugraz.at/
[CCM]: https://en.wikipedia.org/wiki/CCM_mode
[Deoxys-I/II]: https://sites.google.com/view/deoxyscipher
[EAX]: https://en.wikipedia.org/wiki/EAX_mode
[MGM]: https://eprint.iacr.org/2019/123.pdf
[(X)ChaCha20Poly1305]: https://tools.ietf.org/html/rfc8439
