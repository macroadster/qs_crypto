#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input — all malformed data produces Err.
    let _ = qs_crypto::Ciphertext::from_bytes(data);
});
