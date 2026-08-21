# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.1 (206-08-21)
### Changed
- Replace `subtle` with `ctutils` ([#879])

[#879]: https://github.com/RustCrypto/AEADs/pull/879

## 0.6.0 (2026-08-12)
### Added
- `rand_core` feature ([#467])
- `arrayvec` feature ([#503])
- `bytes` feature ([#631])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#662])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Migrate to `AeadInOut` ([#665])
- Bump `cipher` to v0.5 ([#793])
- Bump `aes` to v0.9 ([#821])
- Bump `ctr` to v0.10 ([#821])
- Bump `aead` to v0.6 ([#831])

### Removed
- `std` and `stream` features ([#662])

[#467]: https://github.com/RustCrypto/AEADs/pull/467
[#503]: https://github.com/RustCrypto/AEADs/pull/503
[#631]: https://github.com/RustCrypto/AEADs/pull/631
[#662]: https://github.com/RustCrypto/AEADs/pull/662
[#665]: https://github.com/RustCrypto/AEADs/pull/665
[#793]: https://github.com/RustCrypto/AEADs/pull/793
[#821]: https://github.com/RustCrypto/AEADs/pull/821
[#831]: https://github.com/RustCrypto/AEADs/pull/831

## 0.5.0 (2022-07-30)
### Added
- `getrandom` feature ([#446])

### Changed
- Relax `zeroize` requirement to `^1` ([#360])
- Bump `ctr`, `cipher`, and `hex-literal` dependencies ([#432])
- Rust 2021 edition upgrade; MSRV 1.56+ ([#435])
- Bump `aead` crate dependency to v0.5 ([#444])

### Removed
- `subtle` pinning ([#408])

[#360]: https://github.com/RustCrypto/AEADs/pull/360
[#408]: https://github.com/RustCrypto/AEADs/pull/408
[#432]: https://github.com/RustCrypto/AEADs/pull/432
[#435]: https://github.com/RustCrypto/AEADs/pull/435
[#444]: https://github.com/RustCrypto/AEADs/pull/444
[#446]: https://github.com/RustCrypto/AEADs/pull/446

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
