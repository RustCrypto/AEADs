# RustCrypto: Ascon

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the lightweight
[Authenticated Encryption with Associated Data (AEAD)][1] algorithm
[Ascon-AEAD128][2].

## Security Notes

No security audits of this crate have ever been performed.

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

[crate-image]: https://img.shields.io/crates/v/ascon-aead128
[crate-link]: https://crates.io/crates/ascon-aead128
[docs-image]: https://docs.rs/ascon-aead128/badge.svg
[docs-link]: https://docs.rs/ascon-aead128
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/ascon-aead128/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
[2]: https://doi.org/10.6028/NIST.SP.800-232.ipd
