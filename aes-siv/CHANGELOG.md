# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
