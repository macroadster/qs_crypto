use criterion::{black_box, criterion_group, criterion_main, Criterion};
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

criterion_group!(benches, bench_keygen, bench_encaps_decaps, bench_hybrid);
criterion_main!(benches);
