use aead::array::Array;
use aead::consts::U16;
use aead::{KeyInit, KeySizeUser};
use belt_block::cipher::{BlockSizeUser, ParBlocksSizeUser};
use universal_hash::{ParBlocks, UhfBackend, UhfClosure, UniversalHash};

/// GHASH keys (16-bytes)
pub type Key = Array<u8, U16>;

/// GHASH blocks (16-bytes)
pub type Block = Array<u8, U16>;

/// GHASH tags (16-bytes)
pub type Tag = Array<u8, U16>;

/// Convert a block between STB 34.101.31's and NIST SP 800-38D's representations.
///
/// Both standards use the same field, but STB numbers the bits of every byte in the opposite
/// order, so the conversion is a bit reversal within each byte.
#[inline(always)]
fn convert(block: &Block) -> Block {
    let x = u128::from_le_bytes((*block).into());
    x.reverse_bits().swap_bytes().to_le_bytes().into()
}

#[derive(Clone)]
pub struct GHash {
    ghash: ghash::GHash,
    /// Initial `T` value in GHASH's representation, folded into the first processed block.
    init: u128,
}

impl KeySizeUser for GHash {
    type KeySize = U16;
}

impl BlockSizeUser for GHash {
    type BlockSize = U16;
}

impl KeyInit for GHash {
    fn new(h: &Key) -> Self {
        Self::new_with_init_block(h, 0)
    }
}

impl GHash {
    pub(crate) fn new_with_init_block(h: &Key, s: u128) -> Self {
        let init = convert(&s.to_le_bytes().into());

        Self {
            ghash: ghash::GHash::new(&convert(h)),
            init: u128::from_le_bytes(init.into()),
        }
    }
}

/// Backend which converts blocks into GHASH's representation on the way in, folding the initial
/// `t` value into the first block it processes.
struct BeltBackend<'a, B: UhfBackend<BlockSize = U16>> {
    backend: &'a mut B,
    init: &'a mut u128,
}

impl<B: UhfBackend<BlockSize = U16>> BeltBackend<'_, B> {
    /// Convert a block, folding in the initial `t` value.
    #[inline(always)]
    fn convert(&mut self, block: &Block) -> Block {
        let x = u128::from_le_bytes(convert(block).into()) ^ core::mem::take(self.init);
        x.to_le_bytes().into()
    }
}

impl<B: UhfBackend<BlockSize = U16>> BlockSizeUser for BeltBackend<'_, B> {
    type BlockSize = U16;
}

impl<B: UhfBackend<BlockSize = U16>> ParBlocksSizeUser for BeltBackend<'_, B> {
    type ParBlocksSize = B::ParBlocksSize;
}

impl<B: UhfBackend<BlockSize = U16>> UhfBackend for BeltBackend<'_, B> {
    fn proc_block(&mut self, x: &Block) {
        let x = self.convert(x);
        self.backend.proc_block(&x);
    }

    fn proc_par_blocks(&mut self, blocks: &ParBlocks<Self>) {
        let blocks = ParBlocks::<Self>::from_fn(|i| self.convert(&blocks[i]));
        self.backend.proc_par_blocks(&blocks);
    }
}

impl UniversalHash for GHash {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        struct BeltClosure<'a, C: UhfClosure> {
            f: C,
            init: &'a mut u128,
        }

        impl<C: UhfClosure> BlockSizeUser for BeltClosure<'_, C> {
            type BlockSize = C::BlockSize;
        }

        impl<C: UhfClosure<BlockSize = U16>> UhfClosure for BeltClosure<'_, C> {
            fn call<B: UhfBackend<BlockSize = U16>>(self, backend: &mut B) {
                self.f.call(&mut BeltBackend {
                    backend,
                    init: self.init,
                });
            }
        }

        self.ghash.update_with_backend(BeltClosure {
            f,
            init: &mut self.init,
        });
    }

    /// Get GHASH output
    #[inline]
    fn finalize(self) -> Tag {
        convert(&self.ghash.finalize())
    }
}

/// Tests from Appendix A, table 18 of [STB 34.101.31-2020](https://apmi.bsu.by/assets/files/std/belt-spec372.pdf)
#[test]
fn test_a18() {
    use hex_literal::hex;

    let test_vectors = [
        (
            hex!("34904055 11BE3297 1343724C 5AB793E9"),
            hex!("22481783 8761A9D6 E3EC9689 110FB0F3"),
            hex!("0001D107 FC67DE40 04DC2C80 3DFD95C3"),
        ),
        (
            hex!("703FCCF0 95EE8DF1 C1ABF8EE 8DF1C1AB"),
            hex!("2055704E 2EDB48FE 87E74075 A5E77EB1"),
            hex!("4A5C9593 8B3FE8F6 74D59BC1 EB356079"),
        ),
    ];

    for (u, v, w) in test_vectors {
        let mut hash = GHash::new(&Block::from(v));
        hash.update(&[Block::from(u)]);
        assert_eq!(hash.finalize(), Block::from(w));
    }
}
