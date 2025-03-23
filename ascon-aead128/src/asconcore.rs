use aead::{
    Error,
    array::{Array, ArraySize},
    consts::U16,
};
use ascon::State;
use subtle::ConstantTimeEq;

/// Produce mask for padding.
#[inline(always)]
const fn pad(n: usize) -> u64 {
    0x01_u64 << (8 * n)
}

/// Clear bytes from a 64 bit word.
#[inline(always)]
const fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff << (n * 8))
}

// Helper functions to convert &[u8] to u64. Once the `processing_*`
// functions are rewritten with `as_chunks`, they can be dropped.

#[inline]
fn u64_from_bytes(input: &[u8]) -> u64 {
    // Soundness: function is always called with slices of the correct size
    u64::from_le_bytes(input.try_into().unwrap())
}

#[inline]
fn u64_from_bytes_partial(input: &[u8]) -> u64 {
    let mut tmp = [0u8; 8];
    tmp[0..input.len()].copy_from_slice(input);
    u64::from_le_bytes(tmp)
}

/// Helper trait for handling differences in key usage of Ascon-128
///
/// For internal use-only.
pub(crate) trait InternalKey<KS: ArraySize>:
    Sized + Clone + for<'a> From<&'a Array<u8, KS>>
{
    /// Return K1.
    fn get_k1(&self) -> u64;
    /// Return K2.
    fn get_k2(&self) -> u64;
}

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub(crate) struct InternalKey16(u64, u64);

impl InternalKey<U16> for InternalKey16 {
    #[inline(always)]
    fn get_k1(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_k2(&self) -> u64 {
        self.1
    }
}

impl From<&Array<u8, U16>> for InternalKey16 {
    fn from(key: &Array<u8, U16>) -> Self {
        Self(u64_from_bytes(&key[..8]), u64_from_bytes(&key[8..]))
    }
}

/// Parameters of an Ascon instance
pub(crate) trait Parameters {
    /// Size of the secret key
    ///
    /// For internal use-only.
    type KeySize: ArraySize;
    /// Internal storage for secret keys
    ///
    /// For internal use-only.
    type InternalKey: InternalKey<Self::KeySize>;

    /// Initialization vector used to initialize Ascon's state
    ///
    /// For internal use-only
    const IV: u64;
}

/// Parameters for Ascon-128
pub(crate) struct Parameters128;

impl Parameters for Parameters128 {
    type KeySize = U16;
    type InternalKey = InternalKey16;

    const IV: u64 = 0x00001000808c0001;
}

/// Core implementation of Ascon for one encryption/decryption operation
pub(crate) struct AsconCore<'a, P: Parameters> {
    state: State,
    key: &'a P::InternalKey,
}

impl<'a, P: Parameters> AsconCore<'a, P> {
    pub(crate) fn new(internal_key: &'a P::InternalKey, nonce: &Array<u8, U16>) -> Self {
        let mut state = State::new(
            P::IV,
            internal_key.get_k1(),
            internal_key.get_k2(),
            u64_from_bytes(&nonce[..8]),
            u64_from_bytes(&nonce[8..]),
        );

        state.permute_12();
        state[3] ^= internal_key.get_k1();
        state[4] ^= internal_key.get_k2();

        Self {
            state,
            key: internal_key,
        }
    }

    /// Permutation with 12 rounds and application of the key at the end
    fn permute_12_and_apply_key(&mut self) {
        self.state.permute_12();
        self.state[3] ^= self.key.get_k1();
        self.state[4] ^= self.key.get_k2();
    }

    /// Permutation with 6 or 8 rounds based on the parameters
    #[inline(always)]
    fn permute_state(&mut self) {
        self.state.permute_8();
    }

    fn process_associated_data(&mut self, associated_data: &[u8]) {
        if !associated_data.is_empty() {
            // TODO: replace with as_chunks once stabilized
            // https://github.com/rust-lang/rust/issues/74985

            let mut blocks = associated_data.chunks_exact(16);
            for block in blocks.by_ref() {
                // process full block of associated data
                self.state[0] ^= u64_from_bytes(&block[..8]);
                self.state[1] ^= u64_from_bytes(&block[8..16]);
                self.permute_state();
            }

            // process partial block if it exists
            let mut last_block = blocks.remainder();
            let sidx = if last_block.len() >= 8 {
                self.state[0] ^= u64_from_bytes(&last_block[..8]);
                last_block = &last_block[8..];
                1
            } else {
                0
            };
            self.state[sidx] ^= pad(last_block.len());
            if !last_block.is_empty() {
                self.state[sidx] ^= u64_from_bytes_partial(last_block);
            }
            self.permute_state();
        }

        // domain separation
        self.state[4] ^= 0x8000000000000000;
    }

    fn process_encrypt_inplace(&mut self, message: &mut [u8]) {
        let mut blocks = message.chunks_exact_mut(16);
        for block in blocks.by_ref() {
            // process full block of message
            self.state[0] ^= u64_from_bytes(&block[..8]);
            block[..8].copy_from_slice(&u64::to_le_bytes(self.state[0]));
            self.state[1] ^= u64_from_bytes(&block[8..16]);
            block[8..16].copy_from_slice(&u64::to_le_bytes(self.state[1]));
            self.permute_state();
        }

        // process partial block if it exists
        let mut last_block = blocks.into_remainder();
        let sidx = if last_block.len() >= 8 {
            self.state[0] ^= u64_from_bytes(&last_block[..8]);
            last_block[..8].copy_from_slice(&u64::to_le_bytes(self.state[0]));
            last_block = &mut last_block[8..];
            1
        } else {
            0
        };
        self.state[sidx] ^= pad(last_block.len());
        if !last_block.is_empty() {
            self.state[sidx] ^= u64_from_bytes_partial(last_block);
            last_block.copy_from_slice(&u64::to_le_bytes(self.state[sidx])[0..last_block.len()]);
        }
    }

    fn process_decrypt_inplace(&mut self, ciphertext: &mut [u8]) {
        let mut blocks = ciphertext.chunks_exact_mut(16);
        for block in blocks.by_ref() {
            // process full block of ciphertext
            let cx = u64_from_bytes(&block[..8]);
            block[..8].copy_from_slice(&u64::to_le_bytes(self.state[0] ^ cx));
            self.state[0] = cx;
            let cx = u64_from_bytes(&block[8..16]);
            block[8..16].copy_from_slice(&u64::to_le_bytes(self.state[1] ^ cx));
            self.state[1] = cx;
            self.permute_state();
        }

        // process partial block if it exists
        let mut last_block = blocks.into_remainder();
        let sidx = if last_block.len() >= 8 {
            let cx = u64_from_bytes(&last_block[..8]);
            last_block[..8].copy_from_slice(&u64::to_le_bytes(self.state[0] ^ cx));
            self.state[0] = cx;
            last_block = &mut last_block[8..];
            1
        } else {
            0
        };
        self.state[sidx] ^= pad(last_block.len());
        if !last_block.is_empty() {
            let cx = u64_from_bytes_partial(last_block);
            self.state[sidx] ^= cx;
            last_block.copy_from_slice(&u64::to_le_bytes(self.state[sidx])[0..last_block.len()]);
            self.state[sidx] = clear(self.state[sidx], last_block.len()) ^ cx;
        }
    }

    fn process_final(&mut self) -> [u8; 16] {
        self.state[2] ^= self.key.get_k1();
        self.state[3] ^= self.key.get_k2();
        self.permute_12_and_apply_key();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&u64::to_le_bytes(self.state[3]));
        tag[8..].copy_from_slice(&u64::to_le_bytes(self.state[4]));
        tag
    }

    pub(crate) fn encrypt_inplace(
        &mut self,
        message: &mut [u8],
        associated_data: &[u8],
    ) -> Array<u8, U16> {
        self.process_associated_data(associated_data);
        self.process_encrypt_inplace(message);
        Array::from(self.process_final())
    }

    pub(crate) fn decrypt_inplace(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        expected_tag: &Array<u8, U16>,
    ) -> Result<(), Error> {
        self.process_associated_data(associated_data);
        self.process_decrypt_inplace(ciphertext);

        let tag = self.process_final();
        if bool::from(tag.ct_eq(expected_tag)) {
            Ok(())
        } else {
            ciphertext.fill(0);
            Err(Error)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn clear_0to7() {
        assert_eq!(clear(0x0123456789abcdef, 1), 0x0123456789abcd00);
        assert_eq!(clear(0x0123456789abcdef, 2), 0x0123456789ab0000);
        assert_eq!(clear(0x0123456789abcdef, 3), 0x0123456789000000);
        assert_eq!(clear(0x0123456789abcdef, 4), 0x0123456700000000);
        assert_eq!(clear(0x0123456789abcdef, 5), 0x0123450000000000);
        assert_eq!(clear(0x0123456789abcdef, 6), 0x0123000000000000);
        assert_eq!(clear(0x0123456789abcdef, 7), 0x0100000000000000);
    }
}
