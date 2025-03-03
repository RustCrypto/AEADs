# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.3 (2025-03-03)
### Fixed
- Zeroize buffer during decryption on failed tag check ([#659])

[#659]: https://github.com/RustCrypto/AEADs/pull/659

## 0.4.2 (2023-03-21)
### Changed
- Drop MSRV back to 1.56 and keep it in sync with `ascon` ([#514])
- Relicense as Apache-2.0 or MIT ([#514])

[#514]: https://github.com/RustCrypto/AEADs/pull/514

## 0.4.1 (2023-03-17)

* Replace `ascon-core` with `ascon`.
* Bump MSRV to 1.60.

## 0.4 (2022-08-01)

* Port to aead 0.5.

## 0.3 (2022-06-03)

* Remove implementation of the Ascon permutation
  * Add dependency on `ascon-core`
* Remove parameters from the public interface

## 0.2 (2022-05-28)

* Implement support for Ascon-80pq
  * Change interface to closer resemble `aead`
  * `Key`, `Tag` and `Nonce` are now re-exported from `aead`
* Reduce the number of re-exports
* Bump `zeroize` dependency to 1.5

## 0.1.4 (2022-03-14)

* Bump edition to 2021 and MSRV to 1.56
* Remove dependency on `cipher`

## 0.1.3 (2021-10-22)

* Declare MSRV as 1.51
* Avoid `>=` dependencies

## 0.1.2 (2021-10-19)

* Bump `aead` dependency to 0.4
* Bump `cipher` dependency to 0.3

## 0.1.1 (2021-10-19)

* Add benchmarks
* Minor code improvements

## 0.1 (2021-04-28)

* Initial release
