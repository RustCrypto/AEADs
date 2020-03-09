# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.1 (2020-03-09)
### Fixed
- `Clone` impl on `ChaChaPoly1305` ([#103])

[#103]: https://github.com/RustCrypto/AEADs/pull/103

## 0.4.0 (2020-03-07)
### Added
- `chacha20` cargo feature; ; replace macros with generics ([#99])

[#99]: https://github.com/RustCrypto/AEADs/pull/99

## 0.3.3 (2020-02-27)
### Fixed
- Wording in documentation about security audit ([#84])

[#84]: https://github.com/RustCrypto/AEADs/pull/84

## 0.3.2 (2020-02-26)
### Added
- Notes about NCC audit to documentation ([#80])

[#80]: https://github.com/RustCrypto/AEADs/pull/80

## 0.3.1 (2020-01-16)
### Added
- `ChaCha8Poly1305`/`ChaCha12Poly1305` reduced round variants ([#69])
- `criterion`-based benchmark ([#66])

### Changed
- Upgrade to `chacha20` v0.3; adds AVX2 backend w\ +60% perf ([#67])

[#66]: https://github.com/RustCrypto/AEADs/pull/66
[#67]: https://github.com/RustCrypto/AEADs/pull/67
[#69]: https://github.com/RustCrypto/AEADs/pull/69

## 0.3.0 (2019-11-26)
### Added
- `heapless` feature ([#51])

### Changed
- Upgrade `aead` crate to v0.2; `alloc` now optional ([#43])

[#51]: https://github.com/RustCrypto/AEADs/pull/51
[#43]: https://github.com/RustCrypto/AEADs/pull/43

## 0.2.2 (2019-11-14)
### Changed
- Upgrade to `zeroize` 1.0 ([#36])

[#36]: https://github.com/RustCrypto/AEADs/pull/36

## 0.2.1 (2019-10-15)
### Changed
- Documentation improvements ([#34])

[#34]: https://github.com/RustCrypto/AEADs/pull/34

## 0.2.0 (2019-10-06)
### Added
- Expose "detached" in-place encryption/decryption APIs ([#21])

### Changed
- Upgrade to `poly1305` crate v0.5 ([#20])

[#21]: https://github.com/RustCrypto/AEADs/pull/21
[#20]: https://github.com/RustCrypto/AEADs/pull/20

## 0.1.2 (2019-10-01)
### Changed
- Update to `zeroize` 1.0.0-pre ([#17])

[#17]: https://github.com/RustCrypto/AEADs/pull/17

## 0.1.1 (2019-09-19)
### Changed
- Update to `poly1305` v0.4 ([#8])

[#8]: https://github.com/RustCrypto/AEADs/pull/8

## 0.1.0 (2019-08-30)

- Initial release
