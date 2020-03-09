# ChaCha20Poly1305 [![crate][crate-image]][crate-link] [![Docs][docs-image]][docs-link] ![Apache2/MIT licensed][license-image] ![Rust Version][rustc-image] [![Build Status][build-image]][build-link]

Pure Rust implementation of **ChaCha20Poly1305** ([RFC 8439][1]): an
[Authenticated Encryption with Associated Data (AEAD)][2] cipher amenable to
fast, constant-time implementations in software, based on the [ChaCha20][3]
stream cipher and [Poly1305][4] universal hash function.

This crate also contains an implementation of **XChaCha20Poly1305**: a variant
of ChaCha20Poly1305 with an extended 192-bit (24-byte) nonce.

[Documentation][docs-link]

## Security Notes

This crate has received one [security audit by NCC Group][5], with no significant
findings. We would like to thank [MobileCoin][6] for funding the audit.

All implementations contained in the crate are designed to execute in constant
time, either by relying on hardware intrinsics (i.e. AVX2 on x86/x86_64), or
using a portable implementation which is only constant time on processors which
implement constant-time multiplication.

It is not suitable for use on processors with a variable-time multiplication
operation (e.g. short circuit on multiply-by-zero / multiply-by-one, such as
certain 32-bit PowerPC CPUs and some non-ARM microcontrollers).

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/chacha20poly1305.svg
[crate-link]: https://crates.io/crates/chacha20poly1305
[docs-image]: https://docs.rs/chacha20poly1305/badge.svg
[docs-link]: https://docs.rs/chacha20poly1305/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.40+-blue.svg
[build-image]: https://github.com/RustCrypto/AEADs/workflows/chacha20poly1305/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[1]: https://tools.ietf.org/html/rfc8439
[2]: https://en.wikipedia.org/wiki/Authenticated_encryption
[3]: https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20
[4]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
[5]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/
[6]: https://www.mobilecoin.com/
