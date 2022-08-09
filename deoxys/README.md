# RustCrypto: Deoxys Cipher

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Deoxys][1]
[Authenticated Encryption with Associated Data (AEAD)][2] cipher,
including the [Deoxys-II][3] variant which was selected by the
[CAESAR competition][4] as the best choice for in-depth security.

[Documentation][docs-link]

## Security Notes

This crate has *NOT* received any security audit.

Although encryption and decryption passes the test vector, there is no guarantee
of constant-time operation.

**USE AT YOUR OWN RISK.**

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

[crate-image]: https://buildstats.info/crate/deoxys
[crate-link]: https://crates.io/crates/deoxys
[docs-image]: https://docs.rs/deoxys/badge.svg
[docs-link]: https://docs.rs/deoxys/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/deoxys/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[1]: https://sites.google.com/view/deoxyscipher
[2]: https://en.wikipedia.org/wiki/Authenticated_encryption
[3]: https://competitions.cr.yp.to/round3/deoxysv141.pdf
[4]: https://competitions.cr.yp.to/index.html
