use aead::array::Array;
use aead::consts::{U4, U16};
use aead::{KeyInit, KeySizeUser};
use belt_block::cipher::{BlockSizeUser, ParBlocksSizeUser};
use polyval::{Polyval, hazmat::FieldElement};
use universal_hash::{ParBlocks, UhfBackend, UhfClosure, UniversalHash};

/// GHASH keys (16-bytes)
pub type Key = Array<u8, U16>;

/// GHASH blocks (16-bytes)
pub type Block = Array<u8, U16>;

/// GHASH tags (16-bytes)
pub type Tag = Array<u8, U16>;

/// Convert a block between the STB and POLYVAL
#[inline(always)]
fn convert(block: &Block) -> u128 {
    u128::from_le_bytes((*block).into()).reverse_bits()
}

#[derive(Clone)]
pub struct GHash {
    polyval: Polyval,
    /// Initial `t` value in POLYVAL's representation, folded into the first processed block.
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
        let h = FieldElement::from(convert(h)).mulx();

        Self {
            polyval: Polyval::new(&h.into()),
            init: s,
        }
    }
}

impl ParBlocksSizeUser for GHash {
    type ParBlocksSize = U4;
}

impl UhfBackend for GHash {
    fn proc_block(&mut self, x: &Block) {
        let x = convert(x) ^ core::mem::take(&mut self.init);
        self.polyval.proc_block(&x.to_le_bytes().into());
    }

    fn proc_par_blocks(&mut self, blocks: &ParBlocks<Self>) {
        let init = core::mem::take(&mut self.init);
        let blocks = ParBlocks::<Self>::from_fn(|i| {
            let x = convert(&blocks[i]) ^ if i == 0 { init } else { 0 };
            x.to_le_bytes().into()
        });
        self.polyval.proc_par_blocks(&blocks);
    }
}

impl UniversalHash for GHash {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    /// Get GHASH output
    #[inline]
    fn finalize(self) -> Tag {
        convert(&self.polyval.finalize()).to_le_bytes().into()
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
