# RustCrypto: COLM Cipher

Pure Rust implementation of the [COLM][1]
[Authenticated Encryption with Associated Data (AEAD)][2] cipher,
which was selected by the [CAESAR competition][3] as the second choice for in-depth security.

## Security Notes

This crate has *NOT* received any security audit.

Although encryption and decryption passes the test vector, there is no guarantee
of constant-time operation.

**USE AT YOUR OWN RISK.**

[//]: # (general links)

[1]: https://competitions.cr.yp.to/round3/colmv1.pdf
[2]: https://en.wikipedia.org/wiki/Authenticated_encryption
[3]: https://competitions.cr.yp.to/index.html
