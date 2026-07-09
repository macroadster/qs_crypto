# QS-Crypto ProVerif Model

Formal verification model for the QS-Crypto PAKE + Double Ratchet composition.

## What is modeled

| Component | Abstraction |
|-----------|-------------|
| Spin KEM | Ideal IND-CCA2 KEM (encaps/decaps) |
| SHAKE256 KDF | Random oracle (`shake_kdf`, `shake_session`) |
| AEAD | Perfect authenticated encryption (`aead_enc`/`aead_dec`) |
| Password KDF | Deterministic function of `(password, salt)` |
| Symmetric ratchet | One-way chain: `chain_next`, `chain_msgkey` |
| KEM ratchet | `ratchet_root(old_root, kem_ss)` |

## Security queries (model targets)

| # | Property | Description | Status |
|---|----------|-------------|--------|
| Q1 | Session key secrecy | Attacker cannot learn `secret_test` encrypted under session key | *not yet run* |
| Q2 | Message secrecy | Messages `msg1_test`, `msg2_test` are protected by symmetric ratchet | *not yet run* |
| Q3 | Forward secrecy | `msg_after_ratchet` is protected (post-KEM-ratchet) | *not yet run* |
| Q4 | Mutual authentication | Client session key implies server responded | *not yet run* |
| Q5 | Key agreement | Both parties derive the same session key | *not yet run* |
| — | Break-in recovery | Post-compromise security via KEM ratchet (see model comments) | *not yet run* |

Fill the Status column with `true` / `cannot be proved` / `false` after a successful ProVerif run.

## Running

Install [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/):

```bash
# From source (recommended; Homebrew has no `proverif` formula as of 2026-06)
git clone https://gitlab.inria.fr/bblanche/proverif.git
cd proverif && ./build && export PATH=$PWD:$PATH

# Or via opam (if OCaml toolchain is available)
opam install proverif
```

Run the model from the repository root:

```bash
proverif docs/proverif/qs_crypto.pv
```

When run successfully, interpret output as: queries reporting
`RESULT ... true` (properties hold) or `RESULT ... cannot be proved`
(ProVerif cannot find an attack, but also cannot prove the property —
typical for some authentication correspondences in unbounded sessions).
These are **not** recorded results yet — capture stdout and update the
Status column above after a real run (see attempt log).

### Attempt log (2026-06-30)

| Check | Result |
|-------|--------|
| `brew install proverif` | **failed** — no Homebrew formula named `proverif` (suggested `prover9`, unrelated) |
| `opam` / OCaml on host | not installed |
| `proverif` on PATH | not found |
| Model file | present at `docs/proverif/qs_crypto.pv` |

Verification results are **not recorded** because ProVerif could not be installed in this environment. Re-run on a machine with ProVerif and document Q1–Q5 outcomes here.

## Limitations

- The KEM is modeled as an **ideal** black-box; this does not verify the
  Ring-LWE or SG-LWE hardness assumptions themselves.
- Password entropy is assumed sufficient (modeled as `[private]`).
- Out-of-order message delivery is not modeled (the ratchet does not
  support it in the current implementation).
- The model uses a simplified 2-message PAKE flow matching the implementation.