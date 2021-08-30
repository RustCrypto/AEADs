# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.3 (2021-08-30)
### Changed
- Bump `salsa20` dependency to v0.9 ([#366])

[#366]: https://github.com/RustCrypto/AEADs/pull/366

## 0.7.2 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3 and `subtle` to v2.4 ([#349])

[#349]: https://github.com/RustCrypto/AEADs/pull/349

## 0.7.1 (2021-04-29)
### Changed
- Bump `rand_core` crate dependency to v0.6 ([#292])

[#292]: https://github.com/RustCrypto/AEADs/pull/292

## 0.7.0 (2021-04-29) [YANKED]
### Changed
- Bump `aead` crate dependency to v0.4 ([#270])
- MSRV 1.49+ ([#286], [#289])
- Bump `chacha20` crate dependency to v0.7 ([#286])
- Bump `poly1305` crate dependency to v0.7 ([#289])

[#270]: https://github.com/RustCrypto/AEADs/pull/270
[#286]: https://github.com/RustCrypto/AEADs/pull/286
[#289]: https://github.com/RustCrypto/AEADs/pull/289

## 0.6.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#229])
- Bump `salsa20` dependency to v0.7 ([#229])

[#229]: https://github.com/RustCrypto/AEADs/pull/229

## 0.5.0 (2020-09-17)
### Added
- Optional `std` feature; disabled by default ([#217])

### Changed
- Bump `salsa20` to v0.6; `stream-cipher` to v0.7 ([#207])

[#217]: https://github.com/RustCrypto/AEADs/pull/217
[#207]: https://github.com/RustCrypto/AEADs/pull/207

## 0.4.2 (2020-06-11)
### Added
- `KEY_SIZE` constant ([#172])

[#172]: https://github.com/RustCrypto/AEADs/pull/172

## 0.4.1 (2020-06-11)
### Added
- `Key` and `Nonce` type aliases + docs ([#167])

[#167]: https://github.com/RustCrypto/AEADs/pull/159

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
