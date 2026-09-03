# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Build against the released `ascon` v0.5.0: the permutation state is now a
  plain array with free `permute*` functions, and the state is zeroized by
  this crate under the `zeroize` feature since `ascon` no longer has one

## 0.1.1 (2026-08-21)
### Changed
- Replace `subtle` with `ctutils` ([#879])

[#879]: https://github.com/RustCrypto/AEADs/pull/879

## 0.1.0 (2026-08-11)
Initial release
