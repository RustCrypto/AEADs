# RustCrypto: Multilinear Galois Mode

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the Multilinear Galois Mode ([MGM]): an
Authenticated Encryption with Associated Data ([AEAD]) algorithm generic over
block ciphers with block size equal to 128 bits.

## Security Notes

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

[crate-image]: https://buildstats.info/crate/mgm
[crate-link]: https://crates.io/crates/mgm
[docs-image]: https://docs.rs/mgm/badge.svg
[docs-link]: https://docs.rs/mgm
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/mgm/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[RFC 3610]: https://tools.ietf.org/html/rfc3610
[MGM]: https://eprint.iacr.org/2019/123.pdf
[AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
