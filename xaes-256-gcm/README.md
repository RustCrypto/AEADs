# RustCrypto: XAES-256-GCM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [XAES-256-GCM][4] extended-nonce
[Authenticated Encryption with Associated Data (AEAD)][1].

[Documentation][docs-link]
## Security Notes

This crate has *NOT* received any security audit.

Although encryption and decryption passes the test vector, there is no guarantee
of constant-time operation.

**USE AT YOUR OWN RISK.**

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

[crate-image]: https://img.shields.io/crates/v/xaes-256-gcm
[crate-link]: https://crates.io/crates/xaes-256-gcm
[docs-image]: https://docs.rs/xaes-256-gcm/badge.svg
[docs-link]: https://docs.rs/xaes-256-gcm/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/xaes-256-gcm/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
[2]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-xaes-256-gcm-and-chacha20poly1305-implementation-review/
[3]: https://www.mobilecoin.com/
[4]: https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
