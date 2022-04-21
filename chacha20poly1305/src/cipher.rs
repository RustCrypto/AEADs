//! Core AEAD cipher implementation for (X)ChaCha20Poly1305.

use core::cmp;
use core::marker::PhantomData;

use ::cipher::{StreamBackend, StreamCipherCore, StreamCipherSeekCore, StreamClosure, Unsigned};
use aead::generic_array::GenericArray;
use aead::Error;
use cipher::inout::InOutBuf;
use poly1305::{
    universal_hash::{
        crypto_common::{BlockSizeUser as UhfBlockSizeUser, KeySizeUser},
        KeyInit, UhfBackend, UhfClosure, UniversalHash,
    },
    Poly1305,
};
use zeroize::Zeroize;

use super::Tag;

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = core::u32::MAX as usize;

/// ChaCha20Poly1305 instantiated with a particular nonce
pub(crate) struct Cipher<C>
where
    C: StreamCipherCore + StreamCipherSeekCore,
{
    cipher: C,
    mac: Poly1305,
}

impl<C> Cipher<C>
where
    C: StreamCipherCore + StreamCipherSeekCore,
{
    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new(mut cipher: C) -> Self {
        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut mac_key = [GenericArray::default()];
        cipher.apply_keystream_blocks(&mut mac_key);

        let mac = Poly1305::new(GenericArray::from_slice(
            &mac_key[0][..<Poly1305 as KeySizeUser>::KeySize::USIZE],
        ));
        mac_key[0].zeroize();

        // We've consumed an entire ChaCha20 block, so its counter is now 1.

        Self { cipher, mac }
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);

        self.cipher.process_with_backend(PaddedEncryptor {
            buffer,
            cipher: PhantomData::<C>::default(),
            mac: &mut self.mac,
        });

        self.authenticate_lengths(associated_data, buffer)?;
        Ok(self.mac.finalize())
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);

        self.cipher.process_with_backend(PaddedDecryptor {
            buffer,
            cipher: PhantomData::<C>::default(),
            mac: &mut self.mac,
        });

        // This performs a constant-time comparison using the `subtle` crate
        if self.authenticate_lengths(associated_data, buffer).is_ok()
            && self.mac.verify(tag).is_ok()
        {
            Ok(())
        } else {
            // On MAC verify failure, re-encrypt the plaintext buffer to prevent
            // accidental exposure.
            let pos_1 = match 1.try_into() {
                Ok(counter) => counter,
                // Counter trait has no Debug bound, so we can't use Result::unwrap.
                Err(_) => panic!(),
            };
            self.cipher.set_block_pos(pos_1);
            self.cipher.apply_keystream_partial(buffer.into());
            Err(Error)
        }
    }

    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths(&mut self, associated_data: &[u8], buffer: &[u8]) -> Result<(), Error> {
        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;

        let mut block = GenericArray::default();
        block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
        block[8..].copy_from_slice(&buffer_len.to_le_bytes());
        self.mac.update(&[block]);

        Ok(())
    }
}

/// Returns the least common multiple of `a` and `b`.
const fn lcm(a: usize, b: usize) -> usize {
    a * (b / gcd::binary_usize(a, b))
}

struct PaddedEncryptor<'a, C: StreamCipherCore> {
    buffer: &'a mut [u8],
    cipher: PhantomData<C>,
    mac: &'a mut Poly1305,
}

impl<'a, C: StreamCipherCore> ::cipher::BlockSizeUser for PaddedEncryptor<'a, C> {
    type BlockSize = C::BlockSize;
}

impl<'a, C: StreamCipherCore> StreamClosure for PaddedEncryptor<'a, C> {
    #[inline(always)]
    #[allow(clippy::needless_range_loop)]
    fn call<B: StreamBackend<BlockSize = C::BlockSize>>(self, cipher_backend: &mut B) {
        // This simulates a nested closure.
        self.mac.update_with_backend(PaddedEncryptorInner {
            buffer: self.buffer,
            cipher_backend,
        })
    }
}

struct PaddedEncryptorInner<'a, CB: StreamBackend> {
    buffer: &'a mut [u8],
    cipher_backend: &'a mut CB,
}

impl<'a, CB: StreamBackend> UhfBlockSizeUser for PaddedEncryptorInner<'a, CB> {
    type BlockSize = <Poly1305 as UhfBlockSizeUser>::BlockSize;
}

impl<'a, CB: StreamBackend> UhfClosure for PaddedEncryptorInner<'a, CB> {
    #[inline(always)]
    fn call<MB: UhfBackend<BlockSize = Self::BlockSize>>(self, mac_backend: &mut MB) {
        // We want to ensure that the "fast path" (processing multiple blocks at once via
        // SIMD instructions) is used for both ChaCha and Poly1305. For ChaCha this is
        // relatively easy: blocks are derived in counter mode, so multiple ChaCha blocks
        // in a row can be generated at any point in the stream by setting the counters to
        // the correct offset.
        //
        // Poly1305, on the other hand, is incrementally constructing a polynomial; SIMD
        // implementations break this into `MB::ParBlocksSize` independent polynomials
        // that are combined at the end. For these implementations, alignment of the
        // ciphertext on `MB::BlockSize * MB::ParBlocksSize` byte boundaries is critical
        // to ensuring that the Poly1305 backend's fast path can be used.
        //
        // The associated data is added to Poly1305 before the ciphertext, and while it is
        // padded to a multiple of `MB::BlockSize`, it is unlikely to be a multiple of
        // `MB::ParBlocksSize`. This means that processing `MB::ParBlocksSize` blocks at a
        // time would reliably take the slower single block pathway. More precisely, when
        // we reach this point, we are in the following state:
        //
        // - We have used 1 ChaCha block to initialise Poly1305, and are at a ChaCha block
        //   boundary.
        // - We have processed N Poly1305 blocks where
        //   `MB::BlockSize * N = padded(len(associated_data))`, and are at a Poly1305
        //   block boundary.
        //
        // We also know that `CB::BlockSize = 4 * MB::BlockSize` (because the block sizes
        // of ChaCha and Poly1305 are 64 bytes and 16 bytes respectively). We therefore
        // have the following system of constraints to satisfy for the number of plaintext
        // bytes `x` that need to be processed via the slow path before we can switch to
        // the fast path for both ChaCha and Poly1305:
        //
        //                         x = 0 mod (MB::BlockSize * 4)
        //     MB::BlockSize * N + x = 0 mod (MB::BlockSize * MB::ParBlocksSize)
        //
        // And here we see a problem: if `MB::ParBlocksSize` is even (which it is for the
        // SIMD backends in the `poly1305` crate), this system of constraints is
        // unsatisfiable for odd `N`. It is therefore impossible to align both ChaCha and
        // Poly1305 backends for arbitrary associated data.
        //
        // Instead, we process `x < MB::BlockSize * MB::ParBlocksSize` bytes of plaintext
        // as single blocks to align the Poly1305 backend, and then use a buffer to store
        // the ChaCha output between that plaintext position and the nearest ChaCha block
        // boundary. Subsequent plaintext bytes can then be processed (in chunks of the
        // least common multiple of the backends' fast path sizes) via the fast paths
        // of both ChaCha and Poly1305, along with some unaligned XORs and a copy of less
        // than `CB::BlockSize` bytes per chunk.
        let blocks_to_align = mac_backend.blocks_needed_to_align();
        let (slow_buffer, fast_buffer) = self.buffer.split_at_mut(cmp::min(
            MB::BlockSize::USIZE * blocks_to_align,
            self.buffer.len(),
        ));

        // Start by processing the slow prefix.
        let mut unused_stream = slow_enc(self.cipher_backend, mac_backend, slow_buffer, None);

        // Calculate the least common multiple of the number of bytes which can be
        // processed by each backend in parallel.
        let lcm_block_size = lcm(
            CB::BlockSize::USIZE * CB::ParBlocksSize::USIZE,
            MB::BlockSize::USIZE * MB::ParBlocksSize::USIZE,
        );

        let mut iter = fast_buffer.chunks_exact_mut(lcm_block_size);
        for lcm_segment in &mut iter {
            // Cast the segment into `&mut [[Block<CB::BlockSize>; CB::ParBlocksSize]]`.
            let cipher_chunks = {
                let (lcm_blocks, _) = InOutBuf::from(&mut *lcm_segment).into_chunks();
                lcm_blocks.into_chunks().0
            };

            // Encrypt the blocks.
            let mut tmp = Default::default();
            for mut chunk in cipher_chunks {
                self.cipher_backend.gen_par_ks_blocks(&mut tmp);
                if let Some((offset, data)) = unused_stream {
                    // We need to realign the newly-generated keystream blocks, prepend
                    // the currently unused data, and save the trailing data that will now
                    // become unused.
                    //
                    //     offset
                    // | ... /   A   | <------------------------------ Currently unused
                    //               |  B  /   C   |  D  /   E   | <-- New keystream blocks
                    //       |   A   /  B  |   C   /  D  | <---------- Keystream "blocks" to XOR
                    //            shifted          | ... /   E   | <-- Newly unused
                    //
                    // This can be replaced once the inout crate provides an unaligned XOR
                    // operation.
                    let new_unused = tmp.last().expect("at least one block").clone();
                    let shifted = CB::BlockSize::USIZE - offset;

                    let mut tmp_slice = &mut tmp[..];
                    while let Some((cur_block, rest)) = tmp_slice.split_last_mut() {
                        let prev_block = rest.last().unwrap_or(&data);
                        cur_block.copy_within(0..offset, shifted);
                        cur_block[..shifted].copy_from_slice(&prev_block[offset..]);
                        tmp_slice = rest;
                    }

                    unused_stream = Some((offset, new_unused));
                }
                chunk.xor_in2out(&tmp);
            }

            // Cast the segment into `&mut [[Block<MB::BlockSize>; MB::ParBlocksSize]]`.
            let mac_blocks = {
                let (lcm_blocks, _) = InOutBuf::from(lcm_segment).into_chunks();
                lcm_blocks.into_chunks().0
            };

            // Update the MAC with the encrypted blocks.
            for par_blocks in mac_blocks {
                mac_backend.proc_par_blocks(par_blocks.get_in());
            }
        }

        // The remaining tail bytes can't be nicely interleaved, so we process them with
        // the cipher and MAC separately using the same logic as the slow prefix.
        let tail = iter.into_remainder();
        slow_enc(self.cipher_backend, mac_backend, tail, unused_stream);
    }
}

#[inline(always)]
fn slow_enc<CB: StreamBackend, MB: UhfBackend>(
    cipher_backend: &mut CB,
    mac_backend: &mut MB,
    buffer: &mut [u8],
    unused_stream: Option<(usize, GenericArray<u8, CB::BlockSize>)>,
) -> Option<(usize, GenericArray<u8, CB::BlockSize>)> {
    // First, use up any unused stream output provided to us.
    let (cipher_buffer, remaining_unused) = if let Some((offset, data)) = unused_stream {
        let buffer_len = buffer.len();
        let unused_len = CB::BlockSize::USIZE - offset;

        if buffer_len <= unused_len {
            let remaining_offset = offset + buffer_len;
            InOutBuf::from(&mut *buffer).xor_in2out(&data[offset..remaining_offset]);
            (
                &mut [][..],
                (buffer_len < unused_len).then(|| (remaining_offset, data)),
            )
        } else {
            let (prefix, suffix) = buffer.split_at_mut(unused_len);
            InOutBuf::from(prefix).xor_in2out(&data[offset..]);
            (suffix, None)
        }
    } else {
        (&mut *buffer, None)
    };

    let (cipher_blocks, mut cipher_tail) = InOutBuf::from(cipher_buffer).into_chunks();
    let cipher_blocks = if CB::ParBlocksSize::USIZE > 1 {
        let (chunks, tail) = cipher_blocks.into_chunks();

        // Encrypt the remaining blocks that can be parallelized by the cipher.
        for mut chunk in chunks {
            let mut tmp = Default::default();
            cipher_backend.gen_par_ks_blocks(&mut tmp);
            chunk.xor_in2out(&tmp);
        }

        tail
    } else {
        cipher_blocks
    };

    // Encrypt any remaining complete blocks.
    let n = cipher_blocks.len();
    let mut tmp = GenericArray::<GenericArray<u8, CB::BlockSize>, CB::ParBlocksSize>::default();
    let ks = &mut tmp[..n];
    cipher_backend.gen_tail_blocks(ks);
    for (mut block, data) in cipher_blocks.into_iter().zip(ks) {
        block.xor_in2out(&data);
    }

    // Encrypt any remaining bytes, which are smaller than a cipher block.
    let unused_stream = if !cipher_tail.is_empty() {
        debug_assert_eq!(remaining_unused, None);
        let mut t = Default::default();
        cipher_backend.gen_ks_block(&mut t);
        cipher_tail.xor_in2out(&t[..cipher_tail.len()]);
        Some((cipher_tail.len(), t))
    } else {
        remaining_unused
    };

    let (mac_blocks, mac_tail) = InOutBuf::from(buffer).into_chunks();
    let mac_blocks = if MB::ParBlocksSize::USIZE > 1 {
        let (par_blocks, tail) = mac_blocks.into_chunks();
        for par_block in par_blocks {
            mac_backend.proc_par_blocks(par_block.get_in());
        }
        tail
    } else {
        mac_blocks
    };
    for block in mac_blocks {
        mac_backend.proc_block(block.get_in());
    }

    // Pad any remaining bytes with zeroes to create the final MAC block.
    if !mac_tail.is_empty() {
        let mut padded_block = GenericArray::default();
        padded_block[..mac_tail.len()].copy_from_slice(mac_tail.get_in());
        mac_backend.proc_block(&padded_block);
    }

    // Return the unused ChaCha output.
    unused_stream
}

struct PaddedDecryptor<'a, C: StreamCipherCore> {
    buffer: &'a mut [u8],
    cipher: PhantomData<C>,
    mac: &'a mut Poly1305,
}

impl<'a, C: StreamCipherCore> ::cipher::BlockSizeUser for PaddedDecryptor<'a, C> {
    type BlockSize = C::BlockSize;
}

impl<'a, C: StreamCipherCore> StreamClosure for PaddedDecryptor<'a, C> {
    #[inline(always)]
    #[allow(clippy::needless_range_loop)]
    fn call<B: StreamBackend<BlockSize = C::BlockSize>>(self, cipher_backend: &mut B) {
        // This simulates a nested closure.
        self.mac.update_with_backend(PaddedDecryptorInner {
            buffer: self.buffer,
            cipher_backend,
        })
    }
}

struct PaddedDecryptorInner<'a, CB: StreamBackend> {
    buffer: &'a mut [u8],
    cipher_backend: &'a mut CB,
}

impl<'a, CB: StreamBackend> UhfBlockSizeUser for PaddedDecryptorInner<'a, CB> {
    type BlockSize = <Poly1305 as UhfBlockSizeUser>::BlockSize;
}

impl<'a, CB: StreamBackend> UhfClosure for PaddedDecryptorInner<'a, CB> {
    #[inline(always)]
    fn call<MB: UhfBackend<BlockSize = Self::BlockSize>>(self, mac_backend: &mut MB) {
        // Calculate the least common multiple of the number of bytes which can be
        // processed by each backend in parallel.
        let lcm_block_size = lcm(
            CB::BlockSize::USIZE * CB::ParBlocksSize::USIZE,
            MB::BlockSize::USIZE * MB::ParBlocksSize::USIZE,
        );

        let mut iter = self.buffer.chunks_exact_mut(lcm_block_size);
        for lcm_segment in &mut iter {
            // Cast the segment into `&mut [[Block<MB::BlockSize>; MB::ParBlocksSize]]`.
            let mac_blocks = {
                let (lcm_blocks, _) = InOutBuf::from(&mut *lcm_segment).into_chunks();
                lcm_blocks.into_chunks().0
            };

            // Update the MAC with the encrypted blocks.
            for par_blocks in mac_blocks {
                mac_backend.proc_par_blocks(par_blocks.get_in());
            }

            // Cast the segment into `&mut [[Block<CB::BlockSize>; CB::ParBlocksSize]]`.
            let cipher_chunks = {
                let (lcm_blocks, _) = InOutBuf::from(lcm_segment).into_chunks();
                lcm_blocks.into_chunks().0
            };

            // Decrypt the blocks.
            let mut tmp = Default::default();
            for mut chunk in cipher_chunks {
                self.cipher_backend.gen_par_ks_blocks(&mut tmp);
                chunk.xor_in2out(&tmp);
            }
        }

        // The remaining tail bytes can't be nicely interleaved, so we process them with
        // the cipher and MAC separately.
        let tail = iter.into_remainder();

        let (mac_blocks, mac_tail) = InOutBuf::from(&mut *tail).into_chunks();
        if MB::ParBlocksSize::USIZE > 1 {
            let (par_blocks, tail) = mac_blocks.into_chunks();
            for par_block in par_blocks {
                mac_backend.proc_par_blocks(par_block.get_in());
            }
            for block in tail {
                mac_backend.proc_block(block.get_in());
            }
        } else {
            for block in mac_blocks {
                mac_backend.proc_block(block.get_in());
            }
        }

        // Pad any remaining bytes with zeroes to create the final MAC block.
        if !mac_tail.is_empty() {
            let mut padded_block = GenericArray::default();
            padded_block[..mac_tail.len()].copy_from_slice(mac_tail.get_in());
            mac_backend.proc_block(&padded_block);
        }

        let (cipher_blocks, mut cipher_tail) = InOutBuf::from(tail).into_chunks();
        if CB::ParBlocksSize::USIZE > 1 {
            let (chunks, mut tail) = cipher_blocks.into_chunks();

            // Decrypt the remaining blocks that can be parallelized by the cipher.
            for mut chunk in chunks {
                let mut tmp = Default::default();
                self.cipher_backend.gen_par_ks_blocks(&mut tmp);
                chunk.xor_in2out(&tmp);
            }

            // Decrypt any remaining complete blocks.
            let n = tail.len();
            let mut tmp =
                GenericArray::<GenericArray<u8, CB::BlockSize>, CB::ParBlocksSize>::default();
            let ks = &mut tmp[..n];
            self.cipher_backend.gen_tail_blocks(ks);
            for i in 0..n {
                tail.get(i).xor_in2out(&ks[i]);
            }
        } else {
            // Decrypt any remaining complete blocks.
            for mut block in cipher_blocks {
                let mut t = Default::default();
                self.cipher_backend.gen_ks_block(&mut t);
                block.xor_in2out(&t);
            }
        }

        // Decrypt any remaining bytes, which are smaller than a cipher block.
        if !cipher_tail.is_empty() {
            let mut t = Default::default();
            self.cipher_backend.gen_ks_block(&mut t);
            cipher_tail.xor_in2out(&t[..cipher_tail.len()]);
        }
    }
}
