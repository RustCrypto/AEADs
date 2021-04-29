# RustCrypto: XSalsa20Poly1305

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![CodeCov Status][codecov-image]][codecov-link]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

**XSalsa20Poly1305** (a.k.a. NaCl [`crypto_secretbox`][1]) is an
[authenticated encryption][2] cipher amenable to fast, constant-time
implementations in software, based on the [Salsa20][3] stream cipher 
(with [XSalsa20][4] 192-bit nonce extension) and the [Poly1305][5] universal
hash function, which acts as a message authentication code.

This algorithm has largely been replaced by the newer [ChaCha20Poly1305][6]
(and the associated [XChaCha20Poly1305][7]) AEAD ciphers ([RFC 8439][8]),
but is useful for interoperability with legacy NaCl-based protocols. 

[Documentation][docs-link]

## Security Warning

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

USE AT YOUR OWN RISK!

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

[crate-image]: https://img.shields.io/crates/v/xsalsa20poly1305.svg
[crate-link]: https://crates.io/crates/xsalsa20poly1305
[docs-image]: https://docs.rs/xsalsa20poly1305/badge.svg
[docs-link]: https://docs.rs/xsalsa20poly1305/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.49+-blue.svg
[codecov-image]: https://codecov.io/gh/RustCrypto/AEADs/branch/master/graph/badge.svg
[codecov-link]: https://codecov.io/gh/RustCrypto/AEADs
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/xsalsa20poly1305/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[1]: https://nacl.cr.yp.to/secretbox.html
[2]: https://en.wikipedia.org/wiki/Authenticated_encryption
[3]: https://github.com/RustCrypto/stream-ciphers/tree/master/salsa20
[4]: https://cr.yp.to/snuffle/xsalsa-20081128.pdf
[5]: https://github.com/RustCrypto/universal-hashes/tree/master/poly1305
[6]: https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305
[7]: https://docs.rs/chacha20poly1305/latest/chacha20poly1305/struct.XChaCha20Poly1305.html
[8]: https://tools.ietf.org/html/rfc8439
