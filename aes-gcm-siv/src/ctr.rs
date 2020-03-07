//! Counter mode implementation

use aead::generic_array::{
    typenum::{U1, U16, U8},
    ArrayLength, GenericArray,
};
use block_cipher_trait::BlockCipher;
use core::{convert::TryInto, marker::PhantomData, mem};

/// AES blocks
type Block128 = GenericArray<u8, U16>;

/// 8 * AES blocks (to be encrypted in parallel)
type Block128x8 = GenericArray<Block128, U8>;

/// Size of an AES block in bytes
const BLOCK_SIZE: usize = 16;

/// Size of an 8-AES block buffer in bytes
pub(super) const BLOCK8_SIZE: usize = BLOCK_SIZE * 8;

/// Counter mode
pub trait Ctr<B>
where
    B: BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, B::BlockSize>>,
{
    /// Instantiate a new CTR instance
    fn new(counter_block: &Block128) -> Self;

    /// Apply keystream to the given input buffer
    fn apply_keystream(&mut self, block_cipher: &B, msg: &mut [u8]);
}

/// CTR mode with a 32-bit little endian counter which operates over one AES
/// block at a time.
pub struct Ctr32<B: BlockCipher<BlockSize = U16, ParBlocks = U1>> {
    /// Block cipher
    block_cipher: PhantomData<B>,

    /// Keystream buffer
    buffer: Block128,

    /// Current CTR value
    counter_block: Block128,
}

impl<B> Ctr<B> for Ctr32<B>
where
    B: BlockCipher<BlockSize = U16, ParBlocks = U1>,
{
    /// Instantiate a new CTR instance
    fn new(counter_block: &Block128) -> Self {
        let mut counter_block = *counter_block;
        counter_block[15] |= 0x80;

        Self {
            block_cipher: PhantomData,
            buffer: unsafe { mem::zeroed() },
            counter_block,
        }
    }

    /// Apply AES-CTR keystream to the given input buffer
    fn apply_keystream(&mut self, block_cipher: &B, msg: &mut [u8]) {
        let mut counter = u32::from_le_bytes(self.counter_block[..4].try_into().unwrap());

        for chunk in msg.chunks_mut(BLOCK_SIZE) {
            self.buffer.copy_from_slice(&self.counter_block);
            counter = counter.wrapping_add(1);
            self.counter_block[..4].copy_from_slice(&counter.to_le_bytes());

            block_cipher.encrypt_block(&mut self.buffer);

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= self.buffer[i];
            }
        }
    }
}

/// CTR mode with a 32-bit little endian counter which operates over 8 blocks
/// in parallel (to optimize performance on x86/x86_64 architectures)
pub struct Ctr32x8<B: BlockCipher<BlockSize = U16, ParBlocks = U8>> {
    /// Block cipher
    block_cipher: PhantomData<B>,

    /// Keystream buffer
    buffer: Block128x8,

    /// Current CTR value
    counter_block: Block128,
}

impl<B> Ctr<B> for Ctr32x8<B>
where
    B: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    /// Instantiate a new CTR instance
    fn new(counter_block: &Block128) -> Self {
        let mut counter_block = *counter_block;
        counter_block[15] |= 0x80;

        Self {
            block_cipher: PhantomData,
            buffer: unsafe { mem::zeroed() },
            counter_block,
        }
    }

    /// Apply AES-CTR keystream to the given input buffer
    fn apply_keystream(&mut self, block_cipher: &B, msg: &mut [u8]) {
        for chunk in msg.chunks_mut(BLOCK8_SIZE) {
            self.apply_8block_keystream(block_cipher, chunk);
        }
    }
}

impl<B> Ctr32x8<B>
where
    B: BlockCipher<BlockSize = U16, ParBlocks = U8>,
{
    /// Perform AES-CTR (32-bit little endian counter) encryption on up to
    /// 8 AES blocks
    fn apply_8block_keystream(&mut self, block_cipher: &B, msg: &mut [u8]) {
        let mut counter = u32::from_le_bytes(self.counter_block[..4].try_into().unwrap());
        let n_blocks = msg.chunks(BLOCK_SIZE).count();

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
