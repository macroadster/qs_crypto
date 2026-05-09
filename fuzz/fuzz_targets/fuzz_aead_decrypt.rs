#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 (key) + 16 (nonce) + 16 (tag) = 64 bytes of
    // structured input; the rest is split between AAD and ciphertext.
    if data.len() < 64 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let nonce: [u8; 16] = data[32..48].try_into().unwrap();
    let tag: [u8; 16] = data[48..64].try_into().unwrap();
    let remainder = &data[64..];
    // Split remainder: first half is AAD, second half is ciphertext.
    let mid = remainder.len() / 2;
    let aad = &remainder[..mid];
    let ciphertext = &remainder[mid..];
    // Must not panic — invalid inputs produce Err.
    let _ = qs_crypto::aead::decrypt(&key, &nonce, aad, ciphertext, &tag);
});
