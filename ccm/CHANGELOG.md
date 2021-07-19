# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.4 (2021-07-20)
### Changed
- Pin `subtle` dependency to v2.4 ([#349])

[#349]: https://github.com/RustCrypto/AEADs/pull/349

## 0.4.3 (2021-07-09)
### Fixed
- Doc links to `typenum` constants. ([#333])

[#333]: https://github.com/RustCrypto/AEADs/pull/333

## 0.4.2 (2021-07-09)
### Added
- `From<BlockCipher>` and `Clone` impls. ([#332])

### Changed
- Use the `ctr` crate for encryption and decryption. ([#332])

[#332]: https://github.com/RustCrypto/AEADs/pull/332

## 0.4.1 (2021-07-09)
### Added
- Make `NonceSize` and `TagSize` traits publicly visible. ([#331])

[#331]: https://github.com/RustCrypto/AEADs/pull/331

## 0.4.0 (2021-04-29)
### Changed
- Bump `aead` dependency to v0.4 ([#270])
- Bump `cipher` dependency to v0.3 ([#283])

### Fixed
- Panic on 32-bit targets ([#263])

[#263]: https://github.com/RustCrypto/AEADs/pull/263
[#270]: https://github.com/RustCrypto/AEADs/pull/270
[#283]: https://github.com/RustCrypto/AEADs/pull/283

## 0.3.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#229])

[#229]: https://github.com/RustCrypto/AEADs/pull/229

## 0.2.0 (2020-09-17)
### Added
- Optional `std` feature; disabled by default ([#217])

### Changed
- Upgrade `aes` to v0.5; `block-cipher` to v0.8 ([#209])

[#217]: https://github.com/RustCrypto/AEADs/pull/217
[#209]: https://github.com/RustCrypto/AEADs/pull/209

## 0.1.0 (2020-07-01)
- Initial release ([#174])

[#174]:  https://github.com/RustCrypto/AEADs/pull/174
