//! Counter mode implementation

use block_cipher_trait::generic_array::{
    typenum::{U12, U16, U8},
    GenericArray,
};
use block_cipher_trait::BlockCipher;
use core::{convert::TryInto, mem};

/// AES blocks
type Block128 = GenericArray<u8, U16>;

/// 8 * AES blocks (to be encrypted in parallel)
type Block128x8 = GenericArray<Block128, U8>;

/// Size of an AES block in bytes
const BLOCK_SIZE: usize = 16;

/// Size of an 8-AES block buffer in bytes
pub(super) const BLOCK8_SIZE: usize = BLOCK_SIZE * 8;

/// CTR mode with a 32-bit big endian counter
pub(crate) struct Ctr32<'c, B>
where
    B: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    cipher: &'c B,
    counter_block: Block128,
    buffer: Block128x8,
}

impl<'c, B> Ctr32<'c, B>
where
    B: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    /// Instantiate a new CTR instance
    pub fn new(cipher: &'c B, nonce: &GenericArray<u8, U12>) -> Self {
        let mut counter_block = GenericArray::default();
        counter_block[..12].copy_from_slice(nonce.as_slice());
        counter_block[15] = 1;

        Self {
            cipher,
            counter_block,
            buffer: unsafe { mem::zeroed() },
        }
    }

    /// "Seek" to the given NIST SP800-38D counter value. Note that the
    /// serialized big endian value is 1 larger than the provided "counter value"
    pub fn seek(&mut self, new_counter_value: u32) {
        self.counter_block[12..].copy_from_slice(&new_counter_value.wrapping_add(1).to_be_bytes());
    }

    /// Apply AES-CTR keystream to the given input buffer
    pub fn apply_keystream(&mut self, msg: &mut [u8]) {
        for chunk in msg.chunks_mut(BLOCK8_SIZE) {
            self.apply_8block_keystream(chunk);
        }
    }

    /// Perform AES-CTR (32-bit big endian counter) encryption on up to
    /// 8 AES blocks
    pub fn apply_8block_keystream(&mut self, msg: &mut [u8]) {
        let mut counter = u32::from_be_bytes(self.counter_block[12..].try_into().unwrap());
        let n_blocks = msg.chunks(BLOCK_SIZE).count();

        for block in self.buffer.iter_mut().take(n_blocks) {
            *block = self.counter_block;
            counter = counter.wrapping_add(1);
            self.counter_block[12..].copy_from_slice(&counter.to_be_bytes());
        }

        if n_blocks == 1 {
            self.cipher.encrypt_block(&mut self.buffer[0]);
        } else {
            self.cipher.encrypt_blocks(&mut self.buffer);
        }

        for (i, chunk) in msg.chunks_mut(BLOCK_SIZE).enumerate() {
            let keystream_block = &self.buffer[i];

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream_block[i];
            }
        }
    }
}
