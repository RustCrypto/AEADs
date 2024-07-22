use aead::generic_array::{ArrayLength, GenericArray};

mod utils;

pub(crate) mod gf128_soft64;

pub trait GfElement {
    type N: ArrayLength<u8>;

    fn new() -> Self;
    fn into_bytes(self) -> GenericArray<u8, Self::N>;
    fn mul_sum(&mut self, a: &GenericArray<u8, Self::N>, b: &GenericArray<u8, Self::N>);
}

/// Tests from Appendix A, table 18 of [STB 34.101.31-2020](https://apmi.bsu.by/assets/files/std/belt-spec372.pdf)
#[test]
fn test_a18() {
    use crate::gf::gf128_soft64::Element;
    use aead::consts::U16;
    use hex_literal::hex;

    type Block = GenericArray<u8, U16>;

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
        let a = Block::clone_from_slice(&u);
        let b = Block::clone_from_slice(&v);
        let c = Block::clone_from_slice(&w);

        let mut elem = Element::new();
        elem.mul_sum(&a, &b);

        assert_eq!(c, elem.into_bytes());
    }
}
