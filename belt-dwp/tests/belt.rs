use aead::AeadInPlaceDetached;
use belt_dwp::{BeltDwp, KeyInit};
use hex_literal::hex;

/// Test from Appendix A, tables 19-20 of STB 34.101.31-2020:
/// https://apmi.bsu.by/assets/files/std/belt-spec372.pdf
#[test]
fn test_belt_dwp() {
    struct TestVector {
        i: [u8; 32],
        k: [u8; 32],
        s: [u8; 16],
        x: [u8; 16],
        y: [u8; 16],
        t: [u8; 8],
    }

    let test_vectors = [
        TestVector {
            i: hex!("8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B"),
            k: hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6"),
            s: hex!("BE329713 43FC9A48 A02A885F 194B09A1"),
            x: hex!("B194BAC8 0A08F53B 366D008E 584A5DE4"),
            y: hex!("52C9AF96 FF50F644 35FC43DE F56BD797"),
            t: hex!("3B2E0AEB 2B91854B"),
        },
        TestVector {
            i: hex!("C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B 637C306A DD4EA779 9EB23D31"),
            k: hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511"),
            s: hex!("7ECDA4D0 1544AF8C A58450BF 66D2E88A"),
            x: hex!("DF181ED0 08A20F43 DCBBB936 50DAD34B"),
            y: hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1"),
            t: hex!("6A2C2C94 C4150DC0"),
        },
    ];

    for vec in test_vectors {
        let mut x = vec.x;
        let beltdwp = BeltDwp::new_from_slice(&vec.k).unwrap();
        let tag = beltdwp.encrypt_in_place_detached(&vec.s.into(), &vec.i, &mut x);
        assert_eq!(vec.t, *tag.unwrap());
        assert_eq!(vec.y, x);
        beltdwp
            .decrypt_in_place_detached(&vec.s.into(), &vec.i, &mut x, &tag.unwrap())
            .unwrap();
        assert_eq!(x, vec.x);
    }
}
