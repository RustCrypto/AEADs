use ascon_aead128::AsconAead128;

// Test vectors are taken from the reference Ascon implementation:
// https://github.com/ascon/ascon-c/blob/fdfca408/crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
aead::new_pass_test!(
    ascon_aead_reference_kats_pass,
    "reference_kats_pass",
    AsconAead128
);
aead::new_fail_test!(
    ascon_aead_reference_kats_fail,
    "reference_kats_fail",
    AsconAead128
);
