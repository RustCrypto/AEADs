use aead::{
    consts::{U0, U16, U32, U8},
    AeadCore, AeadInPlace, Key, KeyInit, KeySizeUser, Nonce, Tag,
};
use belt_block::{belt_block_raw, BeltBlock};
use ghash::{
    universal_hash::{Block, UniversalHash},
    GHash,
};

use crate::utils::{from_u32, to_u32};

mod utils;

pub const P_MAX: u128 = 1 << 64;
pub const A_MAX: u128 = 1 << 64;
pub const C_MAX: u128 = (1 << 64) + 8;

pub struct BeltDwp {
    key: Key<BeltBlock>,
}

impl KeySizeUser for BeltDwp {
    type KeySize = U32;
}

impl AeadInPlace for BeltDwp {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag<Self>> {
        let _s = to_u32::<4>(nonce);
        let _k = to_u32::<8>(&self.key);
        // 2.1. 𝑠 ← belt-block(𝑆, 𝐾);
        let s = belt_block_raw(_s, &_k);
        // 2.2. 𝑟 ← belt-block(𝑠, 𝐾);
        let r = belt_block_raw(s, &_k);
        let r = from_u32::<16>(&r);
        let ghash_key = *Key::<GHash>::from_slice(&r);
        // 2.3. 𝑡 ← B194BAC80A08F53B366D008E584A5DE4
        let t = 0xB194BAC80A08F53B366D008E584A5DE4u128;

        // let r = Key::from_slice(from_u32(&r));

        let mut ghash = GHash::new_with_init_block(&ghash_key, t);
        let mut i_blocks = associated_data.chunks_exact(16);
        // 3.1. 𝑡 ← 𝑡 ⊕ (𝐼𝑖 ‖ 0^{128−|𝐼𝑖|})
        for i in i_blocks {
            let block = Block::<GHash>::from_slice(i);
            ghash.update(&[*block]);
        }

        // And have no idea, what to do next.
        todo!()
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> aead::Result<()> {
        todo!()
    }
}

impl KeyInit for BeltDwp {
    fn new(key: &Key<Self>) -> Self {
        Self { key: *key }
    }
}

impl AeadCore for BeltDwp {
    type NonceSize = U16;
    type TagSize = U8;
    type CiphertextOverhead = U0;
}

#[cfg(test)]
mod test {
    use aead::{AeadInPlace, KeyInit};
    use hex_literal::hex;
    use crate::BeltDwp;

    #[test]
    fn test() {
        let i = hex!("8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B");
        let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
        let s = hex!("BE329713 43FC9A48 A02A885F 194B09A1");
        let mut x = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4");

        let y = hex!("52C9AF96 FF50F644 35FC43DE F56BD797");
        let t = hex!("3B2E0AEB 2B91854B");

        let beltdwp = BeltDwp::new_from_slice(&k).unwrap();
        beltdwp.encrypt_in_place_detached(&s.into(), &i, &mut x);

    }
}



