//! Counter mode implementation

use block_cipher_trait::generic_array::{
    typenum::{Unsigned, U16},
    ArrayLength, GenericArray,
};
use block_cipher_trait::BlockCipher;
use core::{convert::TryInto, marker::PhantomData, mem};

/// AES blocks
type Block128 = GenericArray<u8, U16>;

/// Size of an AES block in bytes
pub(crate) const BLOCK_SIZE: usize = 16;

/// CTR mode with a 32-bit little endian counter
pub(crate) struct Ctr32<B>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
{
    /// Block cipher
    block_cipher: PhantomData<B>,

    /// Keystream buffer
    buffer: GenericArray<Block128, B::ParBlocks>,

    /// Current CTR value
    counter_block: Block128,
}

impl<B> Ctr32<B>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
{
    /// Instantiate a new CTR instance
    pub fn new(counter_block: &Block128) -> Self {
        let mut counter_block = *counter_block;
        counter_block[15] |= 0x80;

        Self {
            block_cipher: PhantomData,
            buffer: unsafe { mem::zeroed() },
            counter_block,
        }
    }

    /// Apply AES-CTR keystream to the given input buffer
    pub fn apply_keystream(&mut self, block_cipher: &B, msg: &mut [u8]) {
        for chunk in msg.chunks_mut(BLOCK_SIZE * B::ParBlocks::to_usize()) {
            self.apply_keystream_blocks(block_cipher, chunk);
        }
    }

    /// Apply `B::ParBlocks` parallel blocks of keystream to the input buffer
    fn apply_keystream_blocks(&mut self, block_cipher: &B, msg: &mut [u8]) {
        let mut counter = u32::from_le_bytes(self.counter_block[..4].try_into().unwrap());
        let n_blocks = msg.chunks(BLOCK_SIZE).count();
        debug_assert!(n_blocks <= B::ParBlocks::to_usize());

        for block in self.buffer.iter_mut().take(n_blocks) {
            *block = self.counter_block;
            counter = counter.wrapping_add(1);
            self.counter_block[..4].copy_from_slice(&counter.to_le_bytes());
        }

        if n_blocks == 1 {
            block_cipher.encrypt_block(&mut self.buffer[0]);
        } else {
            block_cipher.encrypt_blocks(&mut self.buffer);
        }

        for (i, chunk) in msg.chunks_mut(BLOCK_SIZE).enumerate() {
            let keystream_block = &self.buffer[i];

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream_block[i];
            }
        }
    }
}
