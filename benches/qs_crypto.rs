use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qs_crypto::kem::{poly_mul, schoolbook_poly_mul, uses_ntt_mul, Poly};
use qs_crypto::*;

fn bench_keygen(c: &mut Criterion) {
    let params = Params::default();
    c.bench_function("keygen_qs256", |b| {
        b.iter(|| generate_keypair(black_box(&params)))
    });
}

fn bench_encaps_decaps(c: &mut Criterion) {
    let params = Params::default();
    let kp = generate_keypair(&params);
    let pk = &kp.public_key;
    c.bench_function("encaps", |b| b.iter(|| encapsulate(black_box(pk))));
    let res = encapsulate(pk);
    c.bench_function("decaps", |b| {
        b.iter(|| decapsulate(black_box(&kp.private_key), black_box(&res.ciphertext)).unwrap())
    });
}

fn bench_hybrid(c: &mut Criterion) {
    let params = Params::default();
    let hkp = hybrid::hybrid_generate_keypair(&params);
    let hpk = hkp.public_key();
    c.bench_function("hybrid_encaps", |b| {
        b.iter(|| hybrid::hybrid_encapsulate(black_box(&hpk)))
    });
    let (hct, _) = hybrid::hybrid_encapsulate(&hpk);
    c.bench_function("hybrid_decaps", |b| {
        b.iter(|| {
            hybrid::hybrid_decapsulate(black_box(&hkp.private_key()), black_box(&hct)).unwrap()
        })
    });
}

/// Confirm QS128 poly_mul is on the NTT path (`uses_ntt_mul`) and compare timing.
/// Agreement tests alone cannot prove the NTT branch; this bench plus the
/// `uses_ntt_mul` gate in `poly_mul` are the path-activation evidence.
/// NTT O(N log N) should be clearly faster than schoolbook O(N²) at N=128.
fn bench_poly_mul_qs128(c: &mut Criterion) {
    let n = 128usize;
    assert!(
        uses_ntt_mul(n),
        "bench precondition: QS128 must use NTT-128"
    );
    let a = Poly::from_coeffs(
        (0..n)
            .map(|i| ((i * 17 + 3) % FIELD_MODULUS as usize) as u16)
            .collect(),
    );
    let b = Poly::from_coeffs(
        (0..n)
            .map(|i| ((i * 41 + 11) % FIELD_MODULUS as usize) as u16)
            .collect(),
    );

    let mut group = c.benchmark_group("poly_mul_n128");
    group.bench_function("ntt_poly_mul", |ben| {
        ben.iter(|| poly_mul(black_box(&a), black_box(&b)))
    });
    group.bench_function("schoolbook_poly_mul", |ben| {
        ben.iter(|| schoolbook_poly_mul(black_box(&a), black_box(&b)))
    });
    group.finish();
}

fn bench_keygen_qs128(c: &mut Criterion) {
    let params = Params::from_security_level(SecurityLevel::QS128);
    assert_eq!(params.ring_dim, 128);
    c.bench_function("keygen_qs128", |b| {
        b.iter(|| generate_keypair(black_box(&params)))
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_keygen_qs128,
    bench_encaps_decaps,
    bench_hybrid,
    bench_poly_mul_qs128
);
criterion_main!(benches);
