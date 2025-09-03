# RustCrypto: CCM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the Counter with CBC-MAC ([CCM]) mode ([RFC 3610]): an
Authenticated Encryption with Associated Data ([AEAD]) algorithm generic over
block ciphers with block size equal to 128 bits.

For example, it can be combined with AES into the various parametrizations of
AES-CCM.

[Documentation][docs-link]

## Security Notes

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

USE AT YOUR OWN RISK!

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

[crate-image]: https://img.shields.io/crates/v/ccm
[crate-link]: https://crates.io/crates/ccm
[docs-image]: https://docs.rs/ccm/badge.svg
[docs-link]: https://docs.rs/ccm
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/ccm/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[RFC 3610]: https://tools.ietf.org/html/rfc3610
[CCM]: https://en.wikipedia.org/wiki/CCM_mode
[AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
