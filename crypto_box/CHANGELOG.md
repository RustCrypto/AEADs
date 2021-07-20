# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.1 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3 ([#349])

[#349]: https://github.com/RustCrypto/AEADs/pull/349

## 0.6.0 (2021-04-29)
### Changed
- Bump `chacha20poly1305` crate dependency to v0.8 ([#290])
- Bump `xsalsa20poly1305` crate dependency to v0.7 ([#291])
- Bump `rand_core` crate dependency to v0.6 ([#292])

### SECURITY
- Fix XChaCha20Poly1305 key derivation ([#295])

[#290]: https://github.com/RustCrypto/AEADs/pull/290
[#291]: https://github.com/RustCrypto/AEADs/pull/291
[#292]: https://github.com/RustCrypto/AEADs/pull/292
[#295]: https://github.com/RustCrypto/AEADs/pull/295

## 0.5.0 (2020-10-16)
### Added
- `ChaChaBox` ([#225])

### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#229])
- Bump `xsalsa20poly1305` dependency to v0.6 ([#229])

[#229]: https://github.com/RustCrypto/AEADs/pull/229
[#225]: https://github.com/RustCrypto/AEADs/pull/225

## 0.4.0 (2020-09-17)
### Added
- Optional `std` feature; disabled by default ([#217])

### Changed
- Upgrade `xsalsa20poly1305` to v0.5 ([#218])

[#218]: https://github.com/RustCrypto/AEADs/pull/218
[#217]: https://github.com/RustCrypto/AEADs/pull/217

## 0.3.0 (2020-08-18)
### Changed
- Bump `x25519-dalek` dependency to 1.0 ([#194])

[#194]: https://github.com/RustCrypto/AEADs/pull/194

## 0.2.0 (2020-06-06)
### Changed
- Bump `aead` crate dependency to v0.3; MSRV 1.41+ ([#146])
- Bump `xsalsa20poly1305` dependency to v0.4 ([#164])

[#146]: https://github.com/RustCrypto/AEADs/pull/146
[#164]: https://github.com/RustCrypto/AEADs/pull/164

## 0.1.0 (2020-02-25)
- Initial release
