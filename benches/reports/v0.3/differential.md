# Differential Cryptanalysis Report

**Date:** 2026-06-30
**Parameters:** N=256, q=3329, full_rounds=32
**Trials per (weight, round):** 2000

## Metric definitions

| Column | Meaning |
|--------|----------|
| Avg Output Weight | Mean Hamming weight of the output differential (number of spins that differ) |
| Fraction Changed | Avg Output Weight / N (avalanche fraction) |
| Mode weight Pr | `max_w Pr[wt(Δ_out) = w]` — concentration of the weight histogram |
| Max id rate | `max_i Pr[out_i unchanged]` — worst-case over positions |
| Mean id rate | `mean_i Pr[out_i unchanged]` — compare to ideal 1/q |
| log2(Max id) | log₂ of Max id rate |

**Max vs mean:** Under i.i.d. identity with rate p = 1/q, the **maximum** over N positions is stochastically larger than p (multiple-testing). Mean id rate is the direct estimator of p; Max id rate is a conservative worst-case probe.

**Historical note:** Earlier revisions labeled the mode-weight probability as "Max DP (per spin)". That was incorrect: under full avalanche the weight concentrates near N, so mode-weight Pr plateaus near ~0.9 even for an ideal random permutation. That plateau is *not* evidence of high-probability truncated differentials. Classical DP(Δ_in → Δ_out) for a specific nonzero output difference cannot be measured at 2⁻¹²⁸ resolution with feasible trials.

## Weight-1 Differentials

| Rounds | Avg Output Weight (spins) | Fraction Changed | Mode weight Pr | Max id rate | Mean id rate | log2(Max id) |
|--------|--------------------------|------------------|----------------|-------------|--------------|--------------|
| 1 | 7.00 | 0.0273 | 0.998500 | 0.974000 | 0.972662 | -0.0 |
| 2 | 18.99 | 0.0742 | 0.991000 | 0.927500 | 0.925816 | -0.1 |
| 4 | 60.97 | 0.2382 | 0.973500 | 0.764000 | 0.761824 | -0.4 |
| 8 | 213.94 | 0.8357 | 0.941000 | 0.168000 | 0.164299 | -2.6 |
| 12 | 255.92 | 0.9997 | 0.926500 | 0.001500 | 0.000295 | -9.4 |
| 16 | 255.93 | 0.9997 | 0.930500 | 0.001500 | 0.000287 | -9.4 |
| 20 | 255.93 | 0.9997 | 0.928500 | 0.002000 | 0.000289 | -9.0 |
| 24 | 255.93 | 0.9997 | 0.927500 | 0.002000 | 0.000293 | -9.0 |
| 28 | 255.92 | 0.9997 | 0.926000 | 0.002000 | 0.000299 | -9.0 |
| 32 | 255.91 | 0.9997 | 0.914000 | 0.002000 | 0.000342 | -9.0 |

## Weight-2 Differentials

| Rounds | Avg Output Weight (spins) | Fraction Changed | Mode weight Pr | Max id rate | Mean id rate | log2(Max id) |
|--------|--------------------------|------------------|----------------|-------------|--------------|--------------|
| 1 | 13.84 | 0.0541 | 0.928000 | 0.948500 | 0.945941 | -0.1 |
| 2 | 36.67 | 0.1432 | 0.758500 | 0.860500 | 0.856768 | -0.2 |
| 4 | 107.67 | 0.4206 | 0.161000 | 0.586500 | 0.579414 | -0.8 |
| 8 | 249.21 | 0.9735 | 0.183000 | 0.031500 | 0.026539 | -5.0 |
| 12 | 255.91 | 0.9997 | 0.919500 | 0.002000 | 0.000334 | -9.0 |
| 16 | 255.92 | 0.9997 | 0.921500 | 0.001500 | 0.000324 | -9.4 |
| 20 | 255.93 | 0.9997 | 0.931500 | 0.001500 | 0.000283 | -9.4 |
| 24 | 255.92 | 0.9997 | 0.921000 | 0.002000 | 0.000320 | -9.0 |
| 28 | 255.94 | 0.9998 | 0.939500 | 0.002000 | 0.000250 | -9.0 |
| 32 | 255.93 | 0.9997 | 0.932000 | 0.002000 | 0.000283 | -9.0 |

## Weight-3 Differentials

| Rounds | Avg Output Weight (spins) | Fraction Changed | Mode weight Pr | Max id rate | Mean id rate | log2(Max id) |
|--------|--------------------------|------------------|----------------|-------------|--------------|--------------|
| 1 | 20.51 | 0.0801 | 0.795500 | 0.923000 | 0.919883 | -0.1 |
| 2 | 53.03 | 0.2072 | 0.411000 | 0.798000 | 0.792840 | -0.3 |
| 4 | 143.26 | 0.5596 | 0.034000 | 0.451000 | 0.440406 | -1.1 |
| 8 | 254.89 | 0.9956 | 0.630000 | 0.008500 | 0.004352 | -6.9 |
| 12 | 255.92 | 0.9997 | 0.925000 | 0.002000 | 0.000303 | -9.0 |
| 16 | 255.93 | 0.9997 | 0.927000 | 0.002000 | 0.000291 | -9.0 |
| 20 | 255.93 | 0.9997 | 0.932000 | 0.001500 | 0.000273 | -9.4 |
| 24 | 255.93 | 0.9997 | 0.927500 | 0.001500 | 0.000291 | -9.4 |
| 28 | 255.93 | 0.9997 | 0.929500 | 0.001500 | 0.000281 | -9.4 |
| 32 | 255.92 | 0.9997 | 0.924500 | 0.002500 | 0.000313 | -8.6 |

## Analysis

### Finding: the ~0.92 plateau was a mislabeled metric

The previous report's "Max DP (per spin) ≈ 0.92 at 32 rounds" measured **mode weight probability** (how often the Hamming weight of Δ_out takes its most common value), not per-position differential probability. Once avalanche is essentially complete (fraction changed ≈ 0.9997), nearly every trial has wt(Δ_out) ∈ {255, 256}, so the mode probability naturally sits near ~0.9. An ideal random permutation over ℤ_q^N would show the same plateau.

### Corrected expectations

For a secure permutation we expect:
- Avalanche: fraction changed → 1 − 1/q ≈ 0.999700 (here q = 3329)
- **Mean** per-position identity rate → 1/q ≈ 0.000300 (direct estimator of p)
- **Max** identity rate over N=256 positions is elevated vs 1/q under H0 (multiple-testing); with 2000 trials the single-cell floor is 1/2000 ≈ 0.000500, so observed max around a few × 1/T remains consistent with random mixing
- Mode weight Pr stays O(1) under full avalanche (not a security failure)
- At 32 rounds, near-perfect avalanche plus mean id rate near 1/q supports that position-wise differentials are consistent with random mixing within measurement resolution (~2^{-11.0})

### Impact on security claims

No evidence of high-probability truncated differentials was found once the metric is interpreted correctly. Security claims based on avalanche / diffusion of the SpinLattice permutation are **unaffected**. Classical DP < 2⁻¹²⁸ cannot be established empirically with feasible trial counts; the corrected metrics only confirm diffusion within Monte-Carlo resolution.

**Note:** With 2000 trials, identity-rate resolution is ~2^{-11.0}. Empirically verifying DP < 2^{-128} for a specific differential characteristic would require an astronomically large number of trials.