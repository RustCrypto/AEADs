# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 (2022-07-30)
### Added
- `getrandom` feature ([#446])

### Changed
- Relax `zeroize` requirement to `^1` ([#360], [#401])
- Bump `aes` crate to v0.8 ([#431])
- Rust 2021 edition upgrade; MSRV 1.56+ ([#435])
- Bump `aead` crate dependency to v0.5 ([#444])

[#360]: https://github.com/RustCrypto/AEADs/pull/360
[#401]: https://github.com/RustCrypto/AEADs/pull/401
[#431]: https://github.com/RustCrypto/AEADs/pull/431
[#435]: https://github.com/RustCrypto/AEADs/pull/435
[#444]: https://github.com/RustCrypto/AEADs/pull/444
[#446]: https://github.com/RustCrypto/AEADs/pull/446

## 0.6.2 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3 ([#349])

[#349]: https://github.com/RustCrypto/AEADs/pull/349

## 0.6.1 (2021-06-26)
### Fixed
- `pmac` crate feature ([#321])

[#321]: https://github.com/RustCrypto/AEADs/pull/321

## 0.6.0 (2021-04-29)
### Added
- AES-SIV-CMAC Wycheproof test vectors ([#276])

### Changed
- Bump `aead` crate dependency to v0.4 ([#270])
- Bump `aes` and `ctr` crate dependencies to v0.7 ([#283])
- Bump `cmac` and `pmac` deps to v0.6 releases ([#285])

[#270]: https://github.com/RustCrypto/AEADs/pull/270
[#276]: https://github.com/RustCrypto/AEADs/pull/276
[#283]: https://github.com/RustCrypto/AEADs/pull/283
[#285]: https://github.com/RustCrypto/AEADs/pull/285

## 0.5.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#229])
- Bump `aes` dependency to v0.6 ([#229])

[#229]: https://github.com/RustCrypto/AEADs/pull/229

## 0.4.0 (2020-09-17)
### Added
- Optional `std` feature; disabled by default ([#217])

### Changed
- Upgrade `aes` to v0.5; `block-cipher` to v0.8 ([#209])

[#217]: https://github.com/RustCrypto/AEADs/pull/217
[#209]: https://github.com/RustCrypto/AEADs/pull/209

## 0.3.0 (2019-06-06)
### Changed
- Bump `aead` crate dependency to v0.3.0; MSRV 1.41+ ([#143])
- Use `copy_within` ([#57])

[#143]: https://github.com/RustCrypto/AEADs/pull/143
[#57]: https://github.com/RustCrypto/AEADs/pull/57

## 0.2.0 (2019-11-26)
### Added
- `heapless` feature ([#51])

### Changed
- Switch from `AeadMut` to `Aead` ([#47])
- Make `Siv::new` type-safe via `typenum` arithmetic ([#45])
- Upgrade `aead` crate to v0.2; `alloc` now optional ([#44])

[#51]: https://github.com/RustCrypto/AEADs/pull/51
[#47]: https://github.com/RustCrypto/AEADs/pull/47
[#45]: https://github.com/RustCrypto/AEADs/pull/45
[#44]: https://github.com/RustCrypto/AEADs/pull/44

## 0.1.2 (2019-11-14)
### Changed
- Upgrade to `zeroize` 1.0 ([#36])

[#36]: https://github.com/RustCrypto/AEADs/pull/36

## 0.1.1 (2019-10-06)

- Initial release
