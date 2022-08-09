# RustCrypto: AES-GCM-SIV (Misuse-Resistant Authenticated Encryption Cipher)

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

[AES-GCM-SIV][1] ([RFC 8452][2]) is a state-of-the-art high-performance
[Authenticated Encryption with Associated Data (AEAD)][3] cipher which also
provides [nonce reuse misuse resistance][4].

Suitable as a general purpose symmetric encryption cipher, AES-GCM-SIV also
removes many of the "sharp edges" of AES-GCM, providing significantly better
security bounds while simultaneously eliminating the most catastrophic risks
of nonce reuse that exist in AES-GCM.

Decryption performance is equivalent to AES-GCM.
Encryption is marginally slower.

See also:

- [Adam Langley: AES-GCM-SIV][5]
- [Coda Hale: Towards A Safer Footgun][6]

[Documentation][docs-link]

## Security Warning

No security audits of this crate have ever been performed.

Some of this crate's dependencies were [audited by by NCC Group][7] as part of
an audit of the `aes-gcm` crate, including the AES implementations (both AES-NI
and a portable software implementation), as well as the `polyval` crate which
is used as an authenticator. There were no significant findings.

All implementations contained in the crate are designed to execute in constant
time, either by relying on hardware intrinsics (i.e. AES-NI and CLMUL on
x86/x86_64), or using a portable implementation which is only constant time
on processors which implement constant-time multiplication.

It is not suitable for use on processors with a variable-time multiplication
operation (e.g. short circuit on multiply-by-zero / multiply-by-one, such as
certain 32-bit PowerPC CPUs and some non-ARM microcontrollers).

USE AT YOUR OWN RISK!

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/aes-gcm-siv
[crate-link]: https://crates.io/crates/aes-gcm-siv
[docs-image]: https://docs.rs/aes-gcm-siv/badge.svg
[docs-link]: https://docs.rs/aes-gcm-siv/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260038-AEADs
[build-image]: https://github.com/RustCrypto/AEADs/workflows/aes-gcm-siv/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/AEADs/actions

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/AES-GCM-SIV
[2]: https://tools.ietf.org/html/rfc8452
[3]: https://en.wikipedia.org/wiki/Authenticated_encryption
[4]: https://github.com/miscreant/meta/wiki/Nonce-Reuse-Misuse-Resistance
[5]: https://www.imperialviolet.org/2017/05/14/aesgcmsiv.html
[6]: https://codahale.com/towards-a-safer-footgun/
[7]: https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/
