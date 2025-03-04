Pure Rust implementation of [HS1-SIV][0].

HS1-SIV is based on the [ChaCha][1] stream cipher.
The tag is generated using a new hashing algorithm.
It also doubles as a SIV (synthetic IV),
providing resistance against nonce reuse.

The algorithm is configurable:
- `B`: Block size, as a multiple of 16.
- `T`: "collision level" (higher is more secure).
- `R`: ChaCha rounds.
- `L`: Tag length in bytes.

3 standard settings are provided:

| Name       | `B` | `T` | `R` | `L` |
|------------|-----|-----|-----|-----|
| `Hs1SivLo` |   4 |   2 |   8 |   8 |
| `Hs1SivMe` |   4 |   4 |  12 |  16 |
| `Hs1SivHi` |   4 |   6 |  20 |  32 |

Security per setting is (`n` = amount of messages generated):

| Name       | Key search  | SIV collision                   |
|------------|-------------|---------------------------------|
| `Hs1SivLo` | `n/(2^256)` | `(n^2)/(2^56)  + (n^2)/(2^64) ` |
| `Hs1SivMe` | `n/(2^256)` | `(n^2)/(2^112) + (n^2)/(2^128)` |
| `Hs1SivHi` | `n/(2^256)` | `(n^2)/(2^168) + (n^2)/(2^256)` |


[0]: https://krovetz.net/csus/papers/hs1-siv_v2.2.pdf
[1]: https://docs.rs/chacha20/
