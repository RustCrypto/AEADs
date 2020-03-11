//! Counter mode implementation

use block_cipher_trait::generic_array::{
    typenum::{Unsigned, U12, U16},
    ArrayLength, GenericArray,
};
use block_cipher_trait::BlockCipher;
use core::{convert::TryInto, marker::PhantomData, mem};

/// AES blocks
type Block128 = GenericArray<u8, U16>;

/// Size of an AES block in bytes
pub(crate) const BLOCK_SIZE: usize = 16;

/// CTR mode with a 32-bit big endian counter
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
    pub fn new(nonce: &[u8]) -> Self {
        let mut counter_block = GenericArray::default();
        if nonce.len() == 12 {
            counter_block[..12].copy_from_slice(nonce);
            counter_block[15] = 1;
        } else {
            counter_block[..].copy_from_slice(nonce);
        }

        Self {
            block_cipher: PhantomData,
            buffer: unsafe { mem::zeroed() },
            counter_block,
        }
    }

    /// "Seek" to the given NIST SP800-38D counter value. Note that the
    /// serialized big endian value is 1 larger than the provided "counter value"
    pub fn seek(&mut self, new_counter_value: u32) {
        self.counter_block[12..].copy_from_slice(&new_counter_value.wrapping_add(1).to_be_bytes());
    }

    /// Apply AES-CTR keystream to the given input buffer
    pub fn apply_keystream(&mut self, block_cipher: &B, msg: &mut [u8]) {
        for chunk in msg.chunks_mut(BLOCK_SIZE * B::ParBlocks::to_usize()) {
            self.apply_keystream_blocks(block_cipher, chunk);
        }
    }

    /// Apply `B::ParBlocks` parallel blocks of keystream to the input buffer
    fn apply_keystream_blocks(&mut self, block_cipher: &B, msg: &mut [u8]) {
        let mut counter = u32::from_be_bytes(self.counter_block[12..].try_into().unwrap());
        let n_blocks = msg.chunks(BLOCK_SIZE).count();
        debug_assert!(n_blocks <= B::ParBlocks::to_usize());

        for block in self.buffer.iter_mut().take(n_blocks) {
            *block = self.counter_block;
            counter = counter.wrapping_add(1);
            self.counter_block[12..].copy_from_slice(&counter.to_be_bytes());
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
