use crate::{
    DecArgs, EncArgs, MgmBlockSize,
    gf::GfElement,
    sealed::{Counter, Sealed},
};
use aead::{
    Error,
    array::{Array, typenum::Unsigned},
    consts::{U8, U16},
    inout::InOutBuf,
};
use cipher::{Block, BlockCipherEncrypt};
use ctutils::CtEq;

/// Number of blocks passed to the cipher at once, so it can use its parallel backend.
const PAR_BLOCKS: usize = 8;

pub(crate) fn encrypt<C, E64, E128>(args: EncArgs<'_, C>) -> Result<Block<C>, Error>
where
    C: BlockCipherEncrypt,
    C::BlockSize: MgmBlockSize,
    E64: GfElement<N = U8>,
    E128: GfElement<N = U16>,
{
    let (cipher, nonce, adata, mut buffer) = args;
    apply_keystream(cipher, nonce, buffer.reborrow());
    // ideally we would use type-level branching here
    match C::BlockSize::USIZE {
        8 => calc_tag::<C, E64>(cipher, nonce, adata, buffer.get_out()),
        16 => calc_tag::<C, E128>(cipher, nonce, adata, buffer.get_out()),
        _ => unreachable!(),
    }
}

pub(crate) fn decrypt<C, E64, E128>(args: DecArgs<'_, C>) -> Result<(), Error>
where
    C: BlockCipherEncrypt,
    C::BlockSize: MgmBlockSize,
    E64: GfElement<N = U8>,
    E128: GfElement<N = U16>,
{
    let (cipher, nonce, adata, buffer, expected_tag) = args;
    // ideally we would use type-level branching here
    let tag = match C::BlockSize::USIZE {
        8 => calc_tag::<C, E64>(cipher, nonce, adata, buffer.get_in()),
        16 => calc_tag::<C, E128>(cipher, nonce, adata, buffer.get_in()),
        _ => unreachable!(),
    }?;

    if !expected_tag.ct_eq(&tag).to_bool() {
        return Err(Error);
    }

    apply_keystream(cipher, nonce, buffer);
    Ok(())
}

// E::N must be equal to C::BlockSize
fn calc_tag<C, E>(
    cipher: &C,
    nonce: &Block<C>,
    adata: &[u8],
    data: &[u8],
) -> Result<Block<C>, Error>
where
    C: BlockCipherEncrypt,
    C::BlockSize: MgmBlockSize,
    E: GfElement,
{
    let fin_block = C::BlockSize::lengths2block(adata.len(), data.len())?;

    let mut tag_ctr = nonce.clone();
    tag_ctr[0] |= 0b1000_0000;
    cipher.encrypt_block(&mut tag_ctr);
    let mut tag_ctr = C::BlockSize::block2ctr(&tag_ctr);

    let mut tag = E::new();
    let bs = C::BlockSize::USIZE;

    // adata and data are padded with zeros to the block size separately
    for chunk in adata
        .chunks(PAR_BLOCKS * bs)
        .chain(data.chunks(PAR_BLOCKS * bs))
    {
        let mut par_h: [Block<C>; PAR_BLOCKS] = Default::default();
        let par_h = &mut par_h[..chunk.len().div_ceil(bs)];
        for h in par_h.iter_mut() {
            *h = C::BlockSize::ctr2block(&tag_ctr);
            C::BlockSize::incr_l(&mut tag_ctr);
        }
        cipher.encrypt_blocks(par_h);

        for (h, block) in par_h.iter().zip(chunk.chunks(bs)) {
            let mut padded = Block::<C>::default();
            padded[..block.len()].copy_from_slice(block);
            mul_sum(&mut tag, h, &padded);
        }
    }

    let mut h = C::BlockSize::ctr2block(&tag_ctr);
    cipher.encrypt_block(&mut h);
    mul_sum(&mut tag, &h, &fin_block);

    let mut tag = Block::<C>::try_from(&tag.into_bytes()[..]).map_err(|_| Error)?;
    cipher.encrypt_block(&mut tag);
    Ok(tag)
}

// panics if E::N != C::BlockSize
#[inline(always)]
fn mul_sum<E: GfElement>(tag: &mut E, h: &[u8], block: &[u8]) {
    let h: &Array<u8, E::N> = h.try_into().expect("E::N == C::BlockSize");
    let block: &Array<u8, E::N> = block.try_into().expect("E::N == C::BlockSize");
    tag.mul_sum(h, block);
}

fn apply_keystream<C>(cipher: &C, nonce: &Block<C>, mut buffer: InOutBuf<'_, '_, u8>)
where
    C: BlockCipherEncrypt,
    C::BlockSize: MgmBlockSize,
{
    let mut ctr = nonce.clone();
    ctr[0] &= 0b0111_1111;
    cipher.encrypt_block(&mut ctr);
    let mut ctr: Counter<C> = C::BlockSize::block2ctr(&ctr);

    let bs = C::BlockSize::USIZE;
    while !buffer.is_empty() {
        let n = buffer.len().min(PAR_BLOCKS * bs);
        let (mut chunk, tail) = buffer.split_at(n);

        let mut par_ks: [Block<C>; PAR_BLOCKS] = Default::default();
        let par_ks = &mut par_ks[..n.div_ceil(bs)];
        for ks in par_ks.iter_mut() {
            *ks = C::BlockSize::ctr2block(&ctr);
            C::BlockSize::incr_r(&mut ctr);
        }
        cipher.encrypt_blocks(par_ks);

        let mut ks_bytes = [0u8; PAR_BLOCKS * 16];
        for (dst, ks) in ks_bytes.chunks_mut(bs).zip(par_ks.iter()) {
            dst.copy_from_slice(ks);
        }
        chunk.xor_in2out(&ks_bytes[..n]);

        buffer = tail;
    }
}
