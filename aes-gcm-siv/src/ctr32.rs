use aead::generic_array::{
    typenum::{U16, U8},
    GenericArray,
};
use aes::block_cipher_trait::BlockCipher;
use core::{convert::TryInto, mem};

/// AES blocks
type Block128 = GenericArray<u8, U16>;

/// 8 * AES blocks (to be encrypted in parallel)
type Block128x8 = GenericArray<Block128, U8>;

/// Size of an AES block in bytes
const BLOCK_SIZE: usize = 16;

/// Size of an 8-AES block buffer in bytes
pub(super) const BLOCK8_SIZE: usize = BLOCK_SIZE * 8;

/// CTR mode with a 32-bit little endian counter
pub(crate) struct Ctr32<'c, C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    cipher: &'c C,
    counter_block: Block128,
    buffer: Block128x8,
}

impl<'c, C> Ctr32<'c, C>
where
    C: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    /// Instantiate a new CTR instance
    pub fn new(cipher: &'c C, mut counter_block: Block128) -> Self {
        counter_block[15] |= 0x80;

        Self {
            cipher,
            counter_block,
            buffer: unsafe { mem::zeroed() },
        }
    }

    /// Apply AES-CTR keystream to the given input buffer
    pub fn apply_keystream(mut self, msg: &mut [u8]) {
        for chunk in msg.chunks_mut(BLOCK8_SIZE) {
            self.apply_8block_keystream(chunk);
        }
    }

    /// Perform AES-CTR (32-bit little endian counter) encryption on up to
    /// 8 AES blocks
    pub fn apply_8block_keystream(&mut self, msg: &mut [u8]) {
        let mut counter = u32::from_le_bytes(self.counter_block[..4].try_into().unwrap());
        let n_blocks = msg.chunks(BLOCK_SIZE).count();

        for block in self.buffer.iter_mut().take(n_blocks) {
            *block = self.counter_block;
            counter = counter.wrapping_add(1);
            self.counter_block[..4].copy_from_slice(&counter.to_le_bytes());
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
