# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.0 (UNRELEASED)
### Added
- `rand_core` feature ([#467])
- `arrayvec` support ([#503])

### Changed
- Bump `aead` from `0.5` to `0.6` ([#583])
- Bump `cipher` from `0.4` to `0.5` ([#583])
- Bump `cmac` from `0.8` to `0.9` ([#583])
- Bump `ctr` from `0.9` to `0.10` ([#583])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#662])
- Relax MSRV policy and allow MSRV bumps in patch releases
- `getrandom` feature renamed as `os_rng` ([#662])

## Removed
- `std` and `stream` features ([#662])

[#467]: https://github.com/RustCrypto/AEADs/pull/467
[#503]: https://github.com/RustCrypto/AEADs/pull/503
[#583]: https://github.com/RustCrypto/AEADs/pull/583
[#662]: https://github.com/RustCrypto/AEADs/pull/662

## 0.5.0 (2022-07-30)
### Added
- `getrandom` feature ([#446])

### Changed
- Relax `subtle` and `zeroize` requirements ([#360])
- Rust 2021 edition upgrade; MSRV 1.56+ ([#435])
- Bump `aead` crate dependency to v0.5 ([#444])
- Bump `cipher` to v0.4 ([#451])

[#360]: https://github.com/RustCrypto/AEADs/pull/360
[#435]: https://github.com/RustCrypto/AEADs/pull/435
[#444]: https://github.com/RustCrypto/AEADs/pull/444
[#446]: https://github.com/RustCrypto/AEADs/pull/446
[#451]: https://github.com/RustCrypto/AEADs/pull/451

## 0.4.1 (2021-07-20)
### Changed
- Pin `subtle` dependency to v2.4 ([#349])

[#349]: https://github.com/RustCrypto/AEADs/pull/349

## 0.4.0 (2021-04-29)
### Added
- Allow variable tag length ([#231])

### Changed
- Bump `aead` crate dependency to v0.4 ([#270])
- Bump `aes` and `ctr` crate dependencies to v0.7 ([#283])
- Bump `cmac` and `pmac` deps to v0.6 releases ([#285])

[#231]: https://github.com/RustCrypto/AEADs/pull/231
[#270]: https://github.com/RustCrypto/AEADs/pull/270
[#283]: https://github.com/RustCrypto/AEADs/pull/283
[#285]: https://github.com/RustCrypto/AEADs/pull/285

## 0.3.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#229])

[#229]: https://github.com/RustCrypto/AEADs/pull/229

## 0.2.0 (2020-09-30
### Added
- API for online encryption/decryption ([#214])
- Optional `std` feature; disabled by default ([#217])

### Changed
- Use `aead` crate; MSRV 1.41+
- Upgrade `aes` to v0.5, `block-cipher` to v0.8, `cmac` to v0.4, `ctr` to v0.5 ([#209])

[#217]: https://github.com/RustCrypto/AEADs/pull/217
[#214]: https://github.com/RustCrypto/AEADs/pull/214
[#209]: https://github.com/RustCrypto/AEADs/pull/209

## 0.1.0 (2019-03-29)
- Initial release
