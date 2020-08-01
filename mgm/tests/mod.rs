use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use hex_literal::hex;
use kuznyechik::Kuznyechik;
use mgm::Mgm;

/// Test vector from:
/// https://tools.ietf.org/html/draft-smyshlyaev-mgm-17#appendix-A
#[test]
#[rustfmt::skip]
fn ietf_draft() {
    let key = hex!("
        8899AABBCCDDEEFF0011223344556677
        FEDCBA98765432100123456789ABCDEF
    ");
    let nonce = hex!("
        1122334455667700FFEEDDCCBBAA9988
    ");
    let aad = hex!("
        02020202020202020101010101010101
        04040404040404040303030303030303
        EA0505050505050505
    ");
    let pt = hex!("
        1122334455667700FFEEDDCCBBAA9988
        00112233445566778899AABBCCEEFF0A
        112233445566778899AABBCCEEFF0A00
        2233445566778899AABBCCEEFF0A0011
        AABBCC
    ");
    let ct = hex!("
        A9757B8147956E9055B8A33DE89F42FC
        8075D2212BF9FD5BD3F7069AADC16B39
        497AB15915A6BA85936B5D0EA9F6851C
        C60C14D4D3F883D0AB94420695C76DEB
        2C7552
    ");
    let tag = hex!("
        CF5D656F40C34F5C46E8BB0E29FCDB4C
    ");

    let key = GenericArray::from_slice(&key);
    let nonce = GenericArray::from_slice(&nonce);
    let c = Mgm::<Kuznyechik>::new(key);

    let mut buf = pt.clone();
    let calc_tag = c.encrypt_in_place_detached(nonce, &aad, &mut buf).unwrap();
    assert_eq!(&buf[..], &ct[..]);
    assert_eq!(&calc_tag[..], &tag[..]);

    let mut buf = ct.clone();
    let res = c.decrypt_in_place_detached(nonce, &aad, &mut buf, &(tag.into()));
    assert!(res.is_ok());
    assert_eq!(&buf[..], &pt[..]);

    // corrupted AD
    let mut buf = ct.clone();
    let mut bad_aad = aad.clone();
    bad_aad[0] = 0;
    let res = c.decrypt_in_place_detached(nonce, &bad_aad, &mut buf, &(tag.into()));
    assert!(res.is_err());

    // corrupted ciphertext
    let mut buf = ct.clone();
    buf[0] = 0;
    let res = c.decrypt_in_place_detached(nonce, &aad, &mut buf, &(tag.into()));
    assert!(res.is_err());

    // corrupted tag
    let mut buf = ct.clone();
    let mut bad_tag = tag.clone();
    bad_tag[0] = 0;
    let res = c.decrypt_in_place_detached(nonce, &aad, &mut buf, &(bad_tag.into()));
    assert!(res.is_err());
    
    // Check that implementation returns an error for nonces with the first bit equal to 1
    let bad_nonce = GenericArray::from_slice(&hex!("
        80000000000000000000000000000000
    "));
    let mut buf = pt.clone();
    let res = c.encrypt_in_place_detached(bad_nonce, &aad, &mut buf);
    assert!(res.is_err());
    
    let mut buf = ct.clone();
    let res = c.decrypt_in_place_detached(bad_nonce, &aad, &mut buf, &(tag.into()));
    assert!(res.is_err());
}
