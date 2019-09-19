# RustCrypto: Authenticated Encryption with Associated Data
[![Build Status](https://travis-ci.org/RustCrypto/AEADs.svg?branch=master)](https://travis-ci.org/RustCrypto/AEADs) [![dependency status](https://deps.rs/repo/github/RustCrypto/AEADs/status.svg)](https://deps.rs/repo/github/RustCrypto/AEADs)

Collection of [Authenticated Encryption with Associated Data (AEAD)][1]
algorithms written in pure Rust.

## Warnings

Crates in this repository have not yet received any formal cryptographic and
security reviews.

**USE AT YOUR OWN RISK.**

## Crates
| Name | Crates.io | Documentation |
| ---- | :--------:| :------------:|
| `chacha20poly1305` | [![crates.io](https://img.shields.io/crates/v/chacha20poly1305.svg)](https://crates.io/crates/chacha20poly1305) | [![Documentation](https://docs.rs/chacha20poly1305/badge.svg)](https://docs.rs/chacha20poly1305) |

### Minimum Supported Rust Version
All crates in this repository support Rust 1.36 or higher. In future minimum
supported Rust version can be changed, but it will be done with the minor
version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the [`aead`][2]
crate.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
[2]: https://docs.rs/aead
