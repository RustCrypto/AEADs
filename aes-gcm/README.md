# AES-GCM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
![Maintenance Status: Experimental][maintenance-image]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the AES-GCM
[Authenticated Encryption with Associated Data (AEAD)][1] cipher.

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

[crate-image]: https://img.shields.io/crates/v/aes-gcm.svg
[crate-link]: https://crates.io/crates/aes-gcm
[docs-image]: https://docs.rs/aes-gcm/badge.svg
[docs-link]: https://docs.rs/aes-gcm/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.37+-blue.svg
[maintenance-image]: https://img.shields.io/badge/maintenance-experimental-blue.svg
[build-image]: https://travis-ci.com/RustCrypto/AEADs.svg?branch=master
[build-link]: https://travis-ci.com/RustCrypto/AEADs

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption
