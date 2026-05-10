//! Constant-time audit harnesses using dudect statistical testing.
//!
//! Run with:
//!   cargo run --release --bin dudect -- --continuous
//!
//! Each function is tested by sampling two classes of secret inputs and
//! measuring whether the runtime distributions are distinguishable.
//! A max |t| < 5 after millions of samples provides statistical
//! evidence of constant-time behavior.

use std::cell::RefCell;

use dudect_bencher::rand::Rng;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

use qs_crypto::*;

// ── SpinLattice::step() ────────────────────────────────────────────
// Class Left:  all-zero spins → many zero multiplications.
// Class Right: random spins   → diverse multiplication operands.
// A timing leak would show different runtimes for different spin values.
fn lattice_step(runner: &mut CtRunner, rng: &mut BenchRng) {
    let params = Params::default();
    let n = params.total_spins;
    let mut lattice = SpinLattice::new(&params);

    // Seed couplings once (they're the same for both classes).
    lattice.seed_from_bytes(b"dudect-coupling-seed");

    let n_inputs = 10_000;
    let mut classes = Vec::with_capacity(n_inputs);
    let mut inputs = Vec::with_capacity(n_inputs);

    for _ in 0..n_inputs {
        let left = rng.next_u32() & 1 == 0;
        let spins: Vec<u16> = if left {
            // Class Left: all zeros
            vec![0u16; n]
        } else {
            // Class Right: random spin values
            let mut buf = vec![0u8; n * 2];
            rng.fill_bytes(&mut buf);
            buf.chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]) % params.q)
                .collect()
        };
        classes.push(if left { Class::Left } else { Class::Right });
        inputs.push(spins);
    }

    for (class, spins) in classes.into_iter().zip(inputs) {
        let mut lat = lattice.clone();
        lat.set_spins(&spins);
        let cell = RefCell::new(lat);
        runner.run_one(class, || cell.borrow_mut().step());
    }
}

// ── AEAD encrypt ───────────────────────────────────────────────────
// Class Left:  all-zero key.
// Class Right: random key.
// Encrypt timing must not depend on key value.
fn aead_encrypt(runner: &mut CtRunner, rng: &mut BenchRng) {
    let nonce = [0u8; 16];
    let plaintext = [0u8; 64];

    let n_inputs = 10_000;
    let mut classes = Vec::with_capacity(n_inputs);
    let mut keys = Vec::with_capacity(n_inputs);

    for _ in 0..n_inputs {
        let left = rng.next_u32() & 1 == 0;
        let mut key = [0u8; 32];
        if !left {
            rng.fill_bytes(&mut key);
        }
        classes.push(if left { Class::Left } else { Class::Right });
        keys.push(key);
    }

    for (class, key) in classes.into_iter().zip(keys) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(aead::encrypt(&key, &nonce, b"", &plaintext));
        });
    }
}

// ── AEAD decrypt ───────────────────────────────────────────────────
// Class Left:  valid ciphertext (correct tag).
// Class Right: invalid ciphertext (flipped tag bit).
// Decrypt must take the same time regardless of whether auth succeeds.
fn aead_decrypt(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = [0x42u8; 32];
    let nonce = [0u8; 16];
    let plaintext = [0u8; 64];
    let ct = aead::encrypt(&key, &nonce, b"", &plaintext);

    let n_inputs = 10_000;
    let mut classes = Vec::with_capacity(n_inputs);
    let mut tags = Vec::with_capacity(n_inputs);

    for _ in 0..n_inputs {
        let left = rng.next_u32() & 1 == 0;
        let mut tag = ct.tag;
        if !left {
            tag[0] ^= 0xFF; // flip a byte to make it invalid
        }
        classes.push(if left { Class::Left } else { Class::Right });
        tags.push(tag);
    }

    for (class, tag) in classes.into_iter().zip(tags) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(aead::decrypt(&key, &nonce, b"", &ct.ciphertext, &tag));
        });
    }
}

// ── KEM decapsulation (FO rejection path) ──────────────────────────
// Class Left:  valid ciphertext → FO check passes.
// Class Right: random ciphertext → FO check fails, implicit rejection.
// The two paths must be indistinguishable in timing.
fn kem_decaps(runner: &mut CtRunner, rng: &mut BenchRng) {
    let params = Params::default();
    let kp = generate_keypair(&params);
    let valid_result = encapsulate(&kp.public_key);
    let valid_ct_bytes = valid_result.ciphertext.as_bytes().to_vec();

    let n_inputs = 2_000;
    let mut classes = Vec::with_capacity(n_inputs);
    let mut cts = Vec::with_capacity(n_inputs);

    for _ in 0..n_inputs {
        let left = rng.next_u32() & 1 == 0;
        let ct_bytes = if left {
            valid_ct_bytes.clone()
        } else {
            // Random ciphertext (keeps valid level byte so decaps runs
            // the full code path instead of erroring on length).
            let mut random_ct = valid_ct_bytes.clone();
            rng.fill_bytes(&mut random_ct[1..]);
            random_ct
        };
        classes.push(if left { Class::Left } else { Class::Right });
        cts.push(Ciphertext::from_bytes(&ct_bytes).unwrap());
    }

    for (class, ct) in classes.into_iter().zip(cts) {
        runner.run_one(class, || {
            let _ = std::hint::black_box(decapsulate(&kp.private_key, &ct));
        });
    }
}

ctbench_main!(lattice_step, aead_encrypt, aead_decrypt, kem_decaps);
