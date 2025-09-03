# RustCrypto: AEAD-STREAM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Generic pure-Rust implementation of the STREAM online authenticated encryption construction
as described in the paper [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance][1].

## About

The STREAM construction supports encrypting/decrypting sequences of AEAD
message segments, which is useful in cases where the overall message is too
large to fit in a single buffer and needs to be processed incrementally.

STREAM defends against reordering and truncation attacks which are common
in naive schemes which attempt to provide these properties, and is proven
to meet the security definition of "nonce-based online authenticated
encryption" (nOAE) as given in the aforementioned paper.

## Diagram

![STREAM Diagram](https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/img/AEADs/rogaway-stream.svg)

Legend:

- 𝐄k: AEAD encryption under key `k`
- 𝐌: message
- 𝐍: nonce
- 𝐀: additional associated data
- 𝐂: ciphertext
- 𝜏: MAC tag

## License

Licensed under either of:

 * [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/aead-stream
[crate-link]: https://crates.io/crates/aead-stream
[docs-image]: https://docs.rs/aead-stream/badge.svg
[docs-link]: https://docs.rs/aead-stream/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/aead-stream/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[1]: https://eprint.iacr.org/2015/189.pdf
