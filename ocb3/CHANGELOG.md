# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (2026-08-24)
### Added
- `bytes` feature ([#631])

### Changed
- Use `dbl` crate ([#606])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#662])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Migrate to `AeadInOut` ([#665])
- `L_TABLE_SIZE` is now a const generic parameter on `Ocb3` ([#763])
- Bump `cipher` to v0.5 ([#793])
- Bump `aes` to v0.9 ([#793])
- Bump `ctr` to v0.10  ([#793])
- Bump `aead` to v0.6 ([#831])
- Replace `subtle` with `ctutils` ([#879])

### Fixed
- Return error on large plaintexts or associated data instead of panicking ([#763])

### Removed
- `std` and `stream` features ([#662])

[#606]: https://github.com/RustCrypto/AEADs/pull/606
[#631]: https://github.com/RustCrypto/AEADs/pull/631
[#662]: https://github.com/RustCrypto/AEADs/pull/662
[#665]: https://github.com/RustCrypto/AEADs/pull/665
[#763]: https://github.com/RustCrypto/AEADs/pull/763
[#793]: https://github.com/RustCrypto/AEADs/pull/793
[#831]: https://github.com/RustCrypto/AEADs/pull/831
[#879]: https://github.com/RustCrypto/AEADs/pull/879

## 0.1.0 (2024-03-07)
- Initial release
