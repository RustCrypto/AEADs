use aead::{AeadInOut, KeyInit};
use belt_che::BeltChe;
use hex_literal::hex;

/// Test from Appendix A, tables 19-20 of STB 34.101.31-2020:
/// https://apmi.bsu.by/assets/files/std/belt-spec372.pdf
#[test]
fn test_belt_che() {
    struct TestVector {
        i: Vec<u8>,
        k: [u8; 32],
        s: [u8; 16],
        x: Vec<u8>,
        y: Vec<u8>,
        t: [u8; 8],
    }

    let test_vectors = [
        TestVector {
            i: hex!("8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B")
                .to_vec(),
            k: hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6"),
            s: hex!("BE329713 43FC9A48 A02A885F 194B09A1"),
            x: hex!("B194BAC8 0A08F53B 366D008E 584A5D").to_vec(),
            y: hex!("BF3DAEAF 5D18D2BC C30EA62D 2E70A4").to_vec(),
            t: hex!("548622B8 44123FF7"),
        },
        TestVector {
            i: hex!("C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B 637C306A DD4EA779 9EB23D31")
                .to_vec(),
            k: hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511"),
            s: hex!("7ECDA4D0 1544AF8C A58450BF 66D2E88A"),
            x: hex!("2BABF43E B37B5398 A9068F31 A3C758B7 62F44AA9").to_vec(),
            y: hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638").to_vec(),
            t: hex!("7D9D4F59 D40D197D"),
        },
    ];

    for vec in test_vectors {
        let mut buffer = vec.x.clone();
        let belt_che = BeltChe::new(&vec.k.into());

        let tag = belt_che
            .encrypt_inout_detached(&vec.s.into(), &vec.i, (&mut buffer[..]).into())
            .unwrap();

        assert_eq!(&vec.t[..], tag.as_slice());
        assert_eq!(&vec.y, &buffer);

        belt_che
            .decrypt_inout_detached(&vec.s.into(), &vec.i, (&mut buffer[..]).into(), &tag)
            .unwrap();

        assert_eq!(&vec.x, &buffer);
    }
}
