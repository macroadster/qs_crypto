#!/usr/bin/env python3
"""
Independent Python validation of the Kyber/ML-KEM NTT.

Computes the NTT from first principles (ζ = 17, Q = 3329) and compares
with the Rust ZETAS table and butterfly structure to pinpoint any bugs.
"""

Q = 3329
N = 256
ZETA_PRIM = 17  # primitive 256th root of unity: 17^128 ≡ -1 mod 3329

# ---------- derive zetas from scratch ----------

def pow_mod(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        exp >>= 1
        base = base * base % mod
    return result

def verify_primitive_root():
    """Verify that 17 is a primitive 256th root of unity mod 3329."""
    assert pow_mod(ZETA_PRIM, 256, Q) == 1, "17^256 != 1 mod Q"
    assert pow_mod(ZETA_PRIM, 128, Q) == Q - 1, "17^128 != -1 mod Q"
    print(f"✓ ζ = {ZETA_PRIM}: ζ^256 ≡ 1, ζ^128 ≡ -1 (mod {Q})")

def bit_rev_7(x):
    """7-bit bit-reversal."""
    result = 0
    for _ in range(7):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result

def build_zetas_from_scratch():
    """
    Build the ZETAS table used by the Kyber NTT.
    
    The Cooley-Tukey NTT uses twiddle factors in bit-reversed order.
    zetas[k] for k=1..127 are powers of ζ in the order determined
    by the butterfly decomposition.
    
    Specifically, the pqcrystals reference builds them as:
      zetas[i] = ζ^{br7(i)} for i in 0..128
    """
    zetas = [0] * 128
    for i in range(128):
        zetas[i] = pow_mod(ZETA_PRIM, bit_rev_7(i), Q)
    return zetas

# ---------- Rust's ZETAS table ----------

ZETAS_RUST = [
       1, 1729, 2580, 3289, 2642,  630, 1897,  848, 1062, 1919,  193,  797, 2786, 3260,  569, 1746,
     296, 2447, 1339, 1476, 1197,  193, 2198, 2627,  268,  307, 3096, 2555,  939, 2367, 2532, 1216,
    1794,  285, 2187,  667, 2784, 1595, 2727,  536, 2573,  470, 1291,   77, 2093, 1396,  910,  834,
    2101, 2423,  803, 1935, 2822,  257,  185, 1069,    5, 1284,   16,  375,  609, 2621,   76,  621,
     790, 1720, 1368, 2337,  584, 1901,  354, 2427, 1597, 3254, 2538, 2383,  341, 1275,  857,  144,
    1052, 2336, 3160, 2647, 2800, 3016,  922, 3105,  689, 3097,   81,  440,  146,  215, 2076,  835,
     269, 2927,  986,  818, 3002, 3108,   52, 3276, 2365,   83,  636, 3227, 3116, 1914, 1840,   26,
    3282,  189, 1395,  680, 1080, 2199, 1548, 3018, 1390,  360, 1735, 2806,  826, 1680, 1617, 2905,
]

# ---------- NTT / INTT implementations ----------

def ntt_forward(r, zetas):
    """Forward NTT (Cooley-Tukey, 7 layers) — matches Rust structure."""
    r = list(r)
    k = 1
    l = 7
    while l >= 1:
        length = 1 << l
        start = 0
        while start < N:
            zeta = zetas[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * r[j + length]) % Q
                r[j + length] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
            start += 2 * length
        l -= 1
    return r

def inv_ntt(r, zetas):
    """Inverse NTT (Gentleman-Sande, 7 layers) — matches Rust structure."""
    r = list(r)
    k = 127
    for l in range(1, 8):
        length = 1 << l
        start = 0
        while start < N:
            zeta = zetas[k]
            k -= 1
            for j in range(start, start + length):
                r_j = r[j]
                r_jl = r[j + length]
                r[j] = (r_j + r_jl) % Q
                r[j + length] = (zeta * (r_jl - r_j)) % Q
            start += 2 * length
    # Scale by 128^{-1} mod Q = 3303
    f = 3303
    r = [(x * f) % Q for x in r]
    return r

def inv_ntt_refsign(r, zetas):
    """Inverse NTT with reference sign convention: zeta * (r_j - r_jl)."""
    r = list(r)
    k = 127
    for l in range(1, 8):
        length = 1 << l
        start = 0
        while start < N:
            zeta = zetas[k]
            k -= 1
            for j in range(start, start + length):
                r_j = r[j]
                r_jl = r[j + length]
                r[j] = (r_j + r_jl) % Q
                r[j + length] = (zeta * (r_j - r_jl)) % Q
            start += 2 * length
    f = 3303
    r = [(x * f) % Q for x in r]
    return r

# ---------- Schoolbook polynomial mul mod (X^N+1, Q) ----------

def schoolbook_mul(a, b):
    """Schoolbook multiplication in Z_Q[X]/(X^N+1)."""
    temp = [0] * (2 * N)
    for i in range(N):
        for j in range(N):
            temp[i + j] = (temp[i + j] + a[i] * b[j]) % Q
    result = [0] * N
    for k in range(N):
        result[k] = (temp[k] - temp[k + N]) % Q
    return result

# ---------- Tests ----------

def test_roundtrip(zetas, inv_fn, label):
    """Test NTT -> INTT roundtrip on all 256 basis vectors."""
    passing = []
    failing = []
    for idx in range(N):
        r = [0] * N
        r[idx] = 1
        fwd = ntt_forward(r, zetas)
        back = inv_fn(fwd, zetas)
        if back == r:
            passing.append(idx)
        else:
            failing.append(idx)
    print(f"  {label}: {len(passing)}/256 basis vectors pass roundtrip")
    if failing:
        print(f"    First 20 failing: {failing[:20]}")
    else:
        print(f"    ALL PASS ✓")
    return len(failing) == 0

def test_ntt_e0(zetas):
    """NTT([1,0,...,0]) should give [1,0,1,0,...,1,0]."""
    r = [0] * N
    r[0] = 1
    out = ntt_forward(r, zetas)
    expected = [1 if i % 2 == 0 else 0 for i in range(N)]
    ok = out == expected
    print(f"  NTT(e_0) = [1,0,1,0,...]: {'✓' if ok else '✗'}")
    return ok

def test_ntt_e1(zetas):
    """NTT([0,1,0,...,0]) should give [0,1,0,1,...,0,1]."""
    r = [0] * N
    r[1] = 1
    out = ntt_forward(r, zetas)
    expected = [1 if i % 2 == 1 else 0 for i in range(N)]
    ok = out == expected
    print(f"  NTT(e_1) = [0,1,0,1,...]: {'✓' if ok else '✗'}")
    return ok

def print_ntt_e2(zetas):
    """Print NTT(e_2) for debugging."""
    r = [0] * N
    r[2] = 1
    out = ntt_forward(r, zetas)
    print(f"  NTT(e_2)[0:16] = {out[0:16]}")

def main():
    verify_primitive_root()
    
    # Build ZETAS from scratch and compare with Rust table
    zetas_computed = build_zetas_from_scratch()
    
    print("\n--- ZETAS table comparison ---")
    mismatches = []
    for i in range(128):
        if zetas_computed[i] != ZETAS_RUST[i]:
            mismatches.append((i, zetas_computed[i], ZETAS_RUST[i]))
    
    if mismatches:
        print(f"  {len(mismatches)} MISMATCHES between computed and Rust ZETAS:")
        for idx, comp, rust in mismatches[:20]:
            print(f"    ZETAS[{idx}]: computed={comp}, Rust={rust}")
    else:
        print(f"  All 128 ZETAS entries match ✓")
    
    # Test with computed (ground-truth) zetas
    print("\n--- Tests with COMPUTED zetas ---")
    test_ntt_e0(zetas_computed)
    test_ntt_e1(zetas_computed)
    print_ntt_e2(zetas_computed)
    
    print("\n  Roundtrip with Rust-style INTT (zeta * (r_jl - r_j)):")
    test_roundtrip(zetas_computed, inv_ntt, "Rust sign")
    
    print("\n  Roundtrip with reference-style INTT (zeta * (r_j - r_jl)):")
    test_roundtrip(zetas_computed, inv_ntt_refsign, "Ref sign")
    
    # Test with Rust ZETAS
    print("\n--- Tests with RUST zetas ---")
    test_ntt_e0(ZETAS_RUST)
    test_ntt_e1(ZETAS_RUST)
    print_ntt_e2(ZETAS_RUST)
    
    print("\n  Roundtrip with Rust-style INTT:")
    test_roundtrip(ZETAS_RUST, inv_ntt, "Rust sign")
    
    print("\n  Roundtrip with reference-style INTT:")
    test_roundtrip(ZETAS_RUST, inv_ntt_refsign, "Ref sign")
    
    # If computed zetas differ from Rust, test schoolbook cross-validation
    print("\n--- Schoolbook cross-validation ---")
    a = [(i * 17 + 42) % Q for i in range(N)]
    b = [(i * 7 + 13) % Q for i in range(N)]
    sb = schoolbook_mul(a, b)
    
    # Try NTT mul with computed zetas
    for label, zetas in [("computed", zetas_computed), ("Rust", ZETAS_RUST)]:
        aa = ntt_forward(a, zetas)
        bb = ntt_forward(b, zetas)
        # basemul
        rr = [0] * N
        for i in range(N // 4):
            z = zetas[64 + i]
            neg_z = (Q - z) % Q
            j = 4 * i
            rr[j]   = (aa[j]*bb[j]     + aa[j+1]*bb[j+1]*z)       % Q
            rr[j+1] = (aa[j]*bb[j+1]   + aa[j+1]*bb[j])           % Q
            j = 4 * i + 2
            rr[j]   = (aa[j]*bb[j]     + aa[j+1]*bb[j+1]*neg_z)   % Q
            rr[j+1] = (aa[j]*bb[j+1]   + aa[j+1]*bb[j])           % Q
        
        # Try both INTT signs
        for inv_label, inv_fn in [("Rust sign", inv_ntt), ("Ref sign", inv_ntt_refsign)]:
            result = inv_fn(list(rr), zetas)
            diffs = sum(1 for i in range(N) if result[i] != sb[i])
            status = "✓" if diffs == 0 else f"✗ ({diffs} diffs)"
            print(f"  NTT mul ({label} zetas, {inv_label}): {status}")
            if diffs > 0 and diffs <= 5:
                for i in range(N):
                    if result[i] != sb[i]:
                        print(f"    [{i}]: got {result[i]}, expected {sb[i]}")

    # Print computed ZETAS for reference
    print("\n--- Computed ZETAS table (for use in Rust) ---")
    for row in range(8):
        vals = zetas_computed[row*16:(row+1)*16]
        line = ", ".join(f"{v:4d}" for v in vals)
        print(f"    {line},")

if __name__ == "__main__":
    main()
