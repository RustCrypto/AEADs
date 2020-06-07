# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2020-06-06)
### Changed
- Bump `aead` crate dependency to v0.3; MSRV 1.41+ ([#146])
- Bump `chacha20` crate dependency to v0.4 ([#159])
- Bump `poly1305` crate dependency to v0.6 ([#158])

[#159]: https://github.com/RustCrypto/AEADs/pull/159
[#158]: https://github.com/RustCrypto/AEADs/pull/158
[#146]: https://github.com/RustCrypto/AEADs/pull/146

## 0.3.1 (2020-01-17)
### Changed
- Upgrade `salsa20` crate to v0.4 ([#71])

[#71]: https://github.com/RustCrypto/AEADs/pull/71

## 0.3.0 (2019-11-26)
### Added
- `heapless` feature ([#51])

### Changed
- Upgrade `aead` crate to v0.2; `alloc` now optional ([#43])

[#51]: https://github.com/RustCrypto/AEADs/pull/51
[#43]: https://github.com/RustCrypto/AEADs/pull/43

## 0.2.1 (2019-11-14)
### Changed
- Upgrade `zeroize` to 1.0 ([#36])

[#36]: https://github.com/RustCrypto/AEADs/pull/36

## 0.2.0 (2019-10-06)
### Added
- Expose "detached" in-place encryption/decryption APIs ([#21])

### Changed
- Upgrade `poly1305` crate to v0.5 ([#20])

[#21]: https://github.com/RustCrypto/AEADs/pull/21
[#20]: https://github.com/RustCrypto/AEADs/pull/20

## 0.1.0 (2019-10-01)

- Initial release
