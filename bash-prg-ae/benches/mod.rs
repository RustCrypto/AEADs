//! bash-prg-ae benchmarks.

#![feature(test)]
extern crate test;

macro_rules! bench {
    ($name:ident, $aead:ty) => {
        mod $name {
            use bash_prg_ae::{AeadInOut, KeyInit};
            use test::Bencher;

            type Aead = $aead;

            #[bench]
            fn encrypt_aad_only_16kb(b: &mut Bencher) {
                let c = Aead::new(&Default::default());
                let nonce = Default::default();
                let aad = vec![0; 16 * 1024];
                let mut buf = [];

                b.iter(|| {
                    let (aad, buf, nonce) = test::black_box((&aad, &mut buf[..], &nonce));
                    let res = c.encrypt_inout_detached(nonce, aad, buf.into()).unwrap();
                    test::black_box(res);
                });

                b.bytes = 16 * 1024;
            }

            #[bench]
            fn encrypt_msg_only_16kb(b: &mut Bencher) {
                let c = Aead::new(&Default::default());
                let nonce = Default::default();
                let aad = [];
                let mut buf = vec![0; 16 * 1024];

                b.iter(|| {
                    let (aad, buf, nonce) = test::black_box((&aad, &mut buf[..], &nonce));
                    let res = c.encrypt_inout_detached(nonce, aad, buf.into()).unwrap();
                    test::black_box(res);
                });

                b.bytes = 16 * 1024;
            }

            #[bench]
            fn decrypt_aad_only_16kb(b: &mut Bencher) {
                let c = Aead::new(&Default::default());
                let nonce = Default::default();
                let aad = vec![0; 16 * 1024];
                let mut buf = [];
                let tag = c
                    .encrypt_inout_detached(&nonce, &aad, (&mut buf[..]).into())
                    .unwrap();

                b.iter(|| {
                    let (aad, buf, nonce, tag) =
                        test::black_box((&aad, &mut buf[..], &nonce, &tag));
                    let res = c.decrypt_inout_detached(nonce, aad, buf.into(), tag);
                    let _ = test::black_box(res);
                });

                b.bytes = 16 * 1024;
            }

            #[bench]
            fn decrypt_msg_only_16kb(b: &mut Bencher) {
                let c = Aead::new(&Default::default());
                let nonce = Default::default();
                let aad = [];
                let mut ct_buf = vec![0u8; 16 * 1024];
                let tag = c
                    .encrypt_inout_detached(&nonce, &aad, (&mut ct_buf[..]).into())
                    .unwrap();

                let mut buf = ct_buf.clone();
                b.iter(|| {
                    let (aad, buf, nonce, tag) =
                        test::black_box((&aad, &mut buf[..], &nonce, &tag));
                    let res = c.decrypt_inout_detached(nonce, aad, buf.into(), tag);
                    let _ = test::black_box(res);
                    buf.copy_from_slice(&ct_buf);
                });

                b.bytes = 16 * 1024;
            }
        }
    };
}

bench!(bash_prg_ae1281, bash_prg_ae::BashPrgAe1281);
bench!(bash_prg_ae1282, bash_prg_ae::BashPrgAe1282);
bench!(bash_prg_ae1921, bash_prg_ae::BashPrgAe1921);
bench!(bash_prg_ae1922, bash_prg_ae::BashPrgAe1922);
bench!(bash_prg_ae2561, bash_prg_ae::BashPrgAe2561);
bench!(bash_prg_ae2562, bash_prg_ae::BashPrgAe2562);
