# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2021-04-29)
### Changed
- Bump `aead` dependency to v0.4.0 release ([#270])

[#270]: https://github.com/RustCrypto/AEADs/pull/270

## 0.3.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#229])

[#229]: https://github.com/RustCrypto/AEADs/pull/229

## 0.2.1 (2020-08-14)
### Added
- `Clone` and `fmt::Debug` trait implementations ([#192])

[192]: https://github.com/RustCrypto/AEADs/pull/192

## 0.2.0 (2020-08-12)
### Changed
- Bump `block-cipher` crate dependency to v0.8 ([#191])

### Added
- `From<BlockCipher>` trait implementation ([#191])

[191]: https://github.com/RustCrypto/AEADs/pull/191

## 0.1.1 (2020-08-01)
- Fix README ([#187])

[187]: https://github.com/RustCrypto/AEADs/pull/187

## 0.1.0 (2020-08-01)
- Initial release
