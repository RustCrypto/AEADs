# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (UNRELEASED)
### Changed
- Bump `aead` from `0.5` to `0.6` ([#583])
- Bump `cipher` from `0.4` to `0.5` ([#583])
- Bump `ctr` from `0.9` to `0.10` ([#583])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#662])
- Relax MSRV policy and allow MSRV bumps in patch releases
- `getrandom` feature renamed as `os_rng` ([#662])
- `L_TABLE_SIZE` is now a const generic parameter on `Ocb3` ([#763])

### Fixed
- Return error on large plaintexts or associated data instead of panicking ([#763])

## Removed
- `std` and `stream` features ([#662])

[#583]: https://github.com/RustCrypto/AEADs/pull/583
[#662]: https://github.com/RustCrypto/AEADs/pull/662
[#763]: https://github.com/RustCrypto/AEADs/pull/763

## 0.1.0 (2024-03-07)
- Initial release
