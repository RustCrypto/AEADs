# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.6 (2021-09-01)
### Added
- Target feature autodetection on x86(-64) targets ([#371])

[#371]: https://github.com/RustCrypto/AEADs/pull/371

## 0.4.5 (2021-08-26)
### Added
- Use parallel block encryption if possible ([#358])

[#358]: https://github.com/RustCrypto/AEADs/pull/358

## 0.4.4 (2021-08-24)
### Changed
- Decrypt ciphertext only after tag verification ([#356])

[#356]: https://github.com/RustCrypto/AEADs/pull/356

## 0.4.3 (2021-07-20)
### Changed
- Pin `subtle` dependency to v2.4 ([#349])

[#349]: https://github.com/RustCrypto/AEADs/pull/349

## 0.4.2 (2021-07-13)
### Added
- Add support of 64 bit block ciphers ([#343])

[#343]: https://github.com/RustCrypto/AEADs/pull/343

## 0.4.1 (2021-05-20)
### Changed
- Remove unnecessary `NewBlockCipher` bounds ([#314])

[#314]: https://github.com/RustCrypto/AEADs/pull/314

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
