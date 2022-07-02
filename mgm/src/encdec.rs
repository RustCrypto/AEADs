use crate::{
    gf::GfElement,
    sealed::{Counter, Sealed},
    DecArgs, EncArgs, MgmBlockSize,
};
use aead::{
    generic_array::{
        typenum::{Unsigned, U16, U8},
        GenericArray,
    },
    Error,
};
use cipher::{Block, BlockEncrypt, ParBlocks};
use subtle::ConstantTimeEq;

pub(crate) fn encrypt<C, E64, E128>(args: EncArgs<'_, C>) -> Result<Block<C>, Error>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
    E64: GfElement<N = U8>,
    E128: GfElement<N = U16>,
{
    // ideally we would use type-level branching here
    match C::BlockSize::USIZE {
        8 => encrypt_inner::<C, E64>(args),
        16 => encrypt_inner::<C, E128>(args),
        _ => unreachable!(),
    }
}

pub(crate) fn decrypt<C, E64, E128>(args: DecArgs<'_, C>) -> Result<(), Error>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
    E64: GfElement<N = U8>,
    E128: GfElement<N = U16>,
{
    // ideally we would use type-level branching here
    match C::BlockSize::USIZE {
        8 => decrypt_inner::<C, E64>(args),
        16 => decrypt_inner::<C, E128>(args),
        _ => unreachable!(),
    }
}

// E::N must be equal to C::BlockSize
fn encrypt_inner<C, E>(args: EncArgs<'_, C>) -> Result<Block<C>, Error>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
    E: GfElement,
{
    let (cipher, nonce, mut adata, mut buffer) = args;

    let fin_block = C::BlockSize::lengths2block(adata.len(), buffer.len())?;

    let mut tag_ctr = nonce.clone();
    tag_ctr[0] |= 0b1000_0000;
    cipher.encrypt_block(&mut tag_ctr);
    let mut tag_ctr = C::BlockSize::block2ctr(&tag_ctr);

    let mut tag = E::new();

    let pb = C::ParBlocks::USIZE;
    let bs = C::BlockSize::USIZE;

    // process adata
    if pb > 1 {
        let mut iter = adata.chunks_exact(pb * bs);
        for chunk in &mut iter {
            update_par_tag(cipher, &mut tag, &mut tag_ctr, chunk);
        }
        adata = iter.remainder();
    };

    let mut iter = adata.chunks_exact(bs);
    for block in (&mut iter).map(Block::<C>::from_slice) {
        update_tag(cipher, &mut tag, &mut tag_ctr, block);
    }
    let rem = iter.remainder();
    if !rem.is_empty() {
        let mut block: Block<C> = Default::default();
        block[..rem.len()].copy_from_slice(rem);
        update_tag(cipher, &mut tag, &mut tag_ctr, &block);
    }

    let mut enc_ctr = nonce.clone();
    enc_ctr[0] &= 0b0111_1111;
    cipher.encrypt_block(&mut enc_ctr);
    let mut enc_ctr = C::BlockSize::block2ctr(&enc_ctr);

    // process plaintext
    if pb > 1 {
        let mut iter = buffer.chunks_exact_mut(pb * bs);
        for chunk in &mut iter {
            apply_par_ks_blocks(cipher, &mut enc_ctr, chunk);
            update_par_tag(cipher, &mut tag, &mut tag_ctr, chunk);
        }
        buffer = iter.into_remainder();
    }

    let mut iter = buffer.chunks_exact_mut(bs);
    for block in (&mut iter).map(Block::<C>::from_mut_slice) {
        apply_ks_block(cipher, &mut enc_ctr, block);
        update_tag(cipher, &mut tag, &mut tag_ctr, block);
    }
    let rem = iter.into_remainder();
    if !rem.is_empty() {
        apply_ks_block(cipher, &mut enc_ctr, rem);

        let mut block = Block::<C>::default();
        let n = rem.len();
        block[..n].copy_from_slice(rem);
        update_tag(cipher, &mut tag, &mut tag_ctr, &block);
    }

    update_tag(cipher, &mut tag, &mut tag_ctr, &fin_block);

    let mut tag = GenericArray::clone_from_slice(&tag.into_bytes());
    cipher.encrypt_block(&mut tag);

    Ok(tag)
}

// E::N must be equal to C::BlockSize
fn decrypt_inner<C, E>(args: DecArgs<'_, C>) -> Result<(), Error>
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
    E: GfElement,
{
    let (cipher, nonce, mut adata, mut buffer, expected_tag) = args;

    let fin_block = C::BlockSize::lengths2block(adata.len(), buffer.len())?;

    let mut tag_ctr = nonce.clone();
    tag_ctr[0] |= 0b1000_0000;
    cipher.encrypt_block(&mut tag_ctr);

    let mut tag_ctr = C::BlockSize::block2ctr(&tag_ctr);
    let mut tag = E::new();

    let pb = C::ParBlocks::USIZE;
    let bs = C::BlockSize::USIZE;

    // calculate tag
    // process adata
    if pb > 1 {
        let mut iter = adata.chunks_exact(pb * bs);
        for chunk in &mut iter {
            update_par_tag(cipher, &mut tag, &mut tag_ctr, chunk);
        }
        adata = iter.remainder();
    };

    let mut iter = adata.chunks_exact(bs);
    for block in (&mut iter).map(Block::<C>::from_slice) {
        update_tag(cipher, &mut tag, &mut tag_ctr, block);
    }
    let rem = iter.remainder();
    if !rem.is_empty() {
        let mut block: Block<C> = Default::default();
        block[..rem.len()].copy_from_slice(rem);
        update_tag(cipher, &mut tag, &mut tag_ctr, &block);
    }

    // process ciphertext
    let buf = if pb > 1 {
        let mut iter = buffer.chunks_exact(pb * bs);
        for chunk in &mut iter {
            update_par_tag(cipher, &mut tag, &mut tag_ctr, chunk);
        }
        iter.remainder()
    } else {
        #[allow(clippy::needless_borrow)]
        &buffer
    };

    let mut iter = buf.chunks_exact(bs);
    for block in (&mut iter).map(Block::<C>::from_slice) {
        update_tag(cipher, &mut tag, &mut tag_ctr, block);
    }
    let rem = iter.remainder();
    if !rem.is_empty() {
        let n = rem.len();

        let mut block = Block::<C>::default();
        block[..n].copy_from_slice(rem);

        update_tag(cipher, &mut tag, &mut tag_ctr, &block);
    }

    update_tag(cipher, &mut tag, &mut tag_ctr, &fin_block);

    let mut tag = GenericArray::clone_from_slice(&tag.into_bytes());
    cipher.encrypt_block(&mut tag);

    if expected_tag.ct_eq(&tag).unwrap_u8() == 0 {
        return Err(Error);
    }

    // decrypt ciphertext
    let mut dec_ctr = nonce.clone();
    dec_ctr[0] &= 0b0111_1111;
    cipher.encrypt_block(&mut dec_ctr);
    let mut dec_ctr = C::BlockSize::block2ctr(&dec_ctr);

    if pb > 1 {
        let mut iter = buffer.chunks_exact_mut(pb * bs);
        for chunk in &mut iter {
            apply_par_ks_blocks(cipher, &mut dec_ctr, chunk);
        }
        buffer = iter.into_remainder();
    }

    let mut iter = buffer.chunks_exact_mut(bs);
    for block in (&mut iter).map(Block::<C>::from_mut_slice) {
        apply_ks_block(cipher, &mut dec_ctr, block);
    }
    let rem = iter.into_remainder();
    if !rem.is_empty() {
        apply_ks_block(cipher, &mut dec_ctr, rem);
    }

    Ok(())
}

#[inline(always)]
fn apply_ks_block<C>(cipher: &C, ctr: &mut Counter<C>, buf: &mut [u8])
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    let mut block = C::BlockSize::ctr2block(ctr);
    cipher.encrypt_block(&mut block);
    for i in 0..core::cmp::min(block.len(), buf.len()) {
        buf[i] ^= block[i];
    }
    C::BlockSize::incr_r(ctr);
}

#[inline(always)]
fn apply_par_ks_blocks<C>(cipher: &C, ctr: &mut Counter<C>, par_blocks: &mut [u8])
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
{
    let pb = C::ParBlocks::USIZE;
    let bs = C::BlockSize::USIZE;
    assert_eq!(par_blocks.len(), pb * bs);

    let mut par_ks = ParBlocks::<C>::default();
    for ks in par_ks.iter_mut() {
        *ks = C::BlockSize::ctr2block(ctr);
        C::BlockSize::incr_r(ctr);
    }
    cipher.encrypt_par_blocks(&mut par_ks);

    let iter = par_blocks.chunks_exact_mut(bs);
    for (ks, block) in par_ks.iter().zip(iter) {
        for i in 0..bs {
            block[i] ^= ks[i];
        }
    }
}

#[inline(always)]
fn update_tag<C, E>(cipher: &C, tag: &mut E, tag_ctr: &mut Counter<C>, block: &Block<C>)
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
    E: GfElement,
{
    let mut h = C::BlockSize::ctr2block(tag_ctr);
    cipher.encrypt_block(&mut h);
    // panics if E::N != C::BlockSize
    tag.mul_sum(
        GenericArray::from_slice(&h),
        GenericArray::from_slice(block),
    );
    C::BlockSize::incr_l(tag_ctr);
}

#[inline(always)]
fn update_par_tag<C, E>(cipher: &C, tag: &mut E, tag_ctr: &mut Counter<C>, par_blocks: &[u8])
where
    C: BlockEncrypt,
    C::BlockSize: MgmBlockSize,
    E: GfElement,
{
    let pb = C::ParBlocks::USIZE;
    let bs = C::BlockSize::USIZE;
    assert_eq!(par_blocks.len(), pb * bs);

    let mut par_h = ParBlocks::<C>::default();
    for h in par_h.iter_mut() {
        *h = C::BlockSize::ctr2block(tag_ctr);
        C::BlockSize::incr_l(tag_ctr);
    }
    cipher.encrypt_par_blocks(&mut par_h);
    // panics if E::N != C::BlockSize
    let iter = par_blocks.chunks_exact(bs).map(GenericArray::from_slice);
    for (h, block) in par_h.iter().zip(iter) {
        tag.mul_sum(GenericArray::from_slice(h), block);
    }
}
