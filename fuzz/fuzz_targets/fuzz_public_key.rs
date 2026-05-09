#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = qs_crypto::PublicKey::from_bytes(data);
});
