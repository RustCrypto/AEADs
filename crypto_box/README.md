# RustCrypto: `crypto_box`

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![CodeCov Status][codecov-image]][codecov-link]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of [NaCl]'s [`crypto_box`] primitive, providing
public-key authenticated encryption which combines the [X25519] Diffie-Hellman
function and the [XSalsa20Poly1305] authenticated encryption cipher into an
Elliptic Curve Integrated Encryption Scheme ([ECIES]).

[Documentation][docs-link]

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

[crate-image]: https://img.shields.io/crates/v/crypto_box.svg
[crate-link]: https://crates.io/crates/crypto_box
[docs-image]: https://docs.rs/crypto_box/badge.svg
[docs-link]: https://docs.rs/crypto_box/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.49+-blue.svg
[codecov-image]: https://codecov.io/gh/RustCrypto/AEADs/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/RustCrypto/AEADs
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/crypto_box/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[NaCl]: https://nacl.cr.yp.to/
[`crypto_box`]: https://nacl.cr.yp.to/box.html
[X25519]: https://cr.yp.to/ecdh.html
[XSalsa20Poly1305]: https://github.com/RustCrypto/AEADs/tree/master/xsalsa20poly1305
[ECIES]: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
