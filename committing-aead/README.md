# RustCrypto: Committing AEAD Wrappers

Marker traits for committing AEADs, along with pure Rust implementations of a
number of constructions that wrap a generic AEAD and provide commitment properties.
The module documentation contains further explanations about committing AEADs and
when they are necessary.

## About

The following constructions are included:

| Committing AEAD Construction | Encryption? | Decryption? | Commitment Security | Overhead |
|------------------------------|-------------|-------------|---------------------|---------|
| ["Padding Fix"]              | Yes         | Yes         | Key only            | `ctxt+=3*key_size` |
| [CTX]                        | Yes         | No          | All inputs          | `tag+=hash_len-orig_tag_len` |
| CTXish-HMAC (see code docs)  | Yes         | Yes         | All inputs          | `tag+=hash_len` |

CTX decryption is not implemented because verifying the tag at decryption time
requires accessing the expected original tag of the wrapped AEAD, which is
currently not accessible with the current AEAD trait interfaces. CTXish-HMAC,
documented in the code docs, is a modification of CTX that does not require
recomputing the expected original tag, at the cost of additional tag overhead.

## Security Notes

No security audits of this crate have ever been performed.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

This crate requires **Rust 1.56** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

["Padding Fix"]: https://eprint.iacr.org/2020/1456.pdf
[CTX]: https://eprint.iacr.org/2022/1260.pdf
