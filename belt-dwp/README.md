# RustCrypto: BeltDwp

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the `belt-dwp` [AEAD] algorithm
specified in the republic of Belarus standard [STB 34.101.31-2020].

## Security Notes

No security audits of this crate have ever been performed, and it has not been thoroughly assessed to ensure its operation is constant-time on common CPU architectures.

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

[crate-image]: https://buildstats.info/crate/belt-dwp
[crate-link]: https://crates.io/crates/belt-dwp
[docs-image]: https://docs.rs/belt-dwp/badge.svg
[docs-link]: https://docs.rs/belt-dwp/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[downloads-image]: https://img.shields.io/crates/d/chacha20poly1305.svg
[build-image]: https://github.com/RustCrypto/AEADs/workflows/belt-dwp/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[STB 34.101.31-2020]: https://apmi.bsu.by/assets/files/std/belt-spec372.pdf
[AEAD]: https://en.wikipedia.org/wiki/Authenticated_encryption
