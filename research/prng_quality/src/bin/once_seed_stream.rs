//! Emit 1 GiB of continuous SplitMix seeded once from sponge keys (no re-key).
use qs_crypto::core::sponge::SpinSponge;
use qs_crypto::params::{Params, SecurityLevel};
use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "research/prng_quality/out/probe_once_splitmix_1g.bin".into());
    let mib: usize = env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let n = mib * 1024 * 1024;

    let params = Params::from_security_level(SecurityLevel::QS256);
    let mut sponge = SpinSponge::new(&params);
    let mut input = vec![0x01, 0x02, 0x03];
    input.extend_from_slice(b"opso-once-seed");
    sponge.absorb(&input);
    sponge.permute_fast();

    let rate = params.sponge_rate;
    let spins = &sponge.lattice().spins()[..rate];
    let mut key0 = 0u64;
    let mut key1 = 0u64;
    for i in 0..rate {
        let s = spins[i] as u64;
        key0 ^= s.wrapping_mul(
            0x9e3779b97f4a7c15_u64.wrapping_add((i as u64).wrapping_mul(0x517cc1b727220a95)),
        );
        key1 ^= s.wrapping_mul(
            0x6c62272e07bb0142_u64.wrapping_add((i as u64).wrapping_mul(0x6b2b82d7cf4da4a1)),
        );
    }
    let mut state = key0
        .wrapping_add(key1.rotate_left(13))
        .wrapping_mul(0x9e3779b97f4a7c15)
        ^ key1.rotate_left(31);

    let mut f = File::create(&path).expect("create");
    let mut left = n;
    let mut buf = [0u8; 65536];
    while left > 0 {
        let mut pos = 0;
        while pos + 8 <= buf.len() && left >= 8 {
            state = state.wrapping_add(0x9e3779b97f4a7c15);
            let mut w = state;
            w ^= w >> 30;
            w = w.wrapping_mul(0xbf58476d1ce4e5b9);
            w ^= w >> 27;
            w = w.wrapping_mul(0x94d049bb133111eb);
            w ^= w >> 31;
            buf[pos..pos + 8].copy_from_slice(&w.to_le_bytes());
            pos += 8;
            left -= 8;
        }
        f.write_all(&buf[..pos]).unwrap();
    }
    eprintln!("wrote {mib} MiB once-seed SplitMix → {path}");
}
