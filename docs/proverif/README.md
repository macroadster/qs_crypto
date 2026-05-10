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

## Security queries verified

| # | Property | Description |
|---|----------|-------------|
| Q1 | Session key secrecy | Attacker cannot learn `secret_test` encrypted under session key |
| Q2 | Message secrecy | Messages `msg1_test`, `msg2_test` are protected by symmetric ratchet |
| Q3 | Forward secrecy | `msg_after_ratchet` is protected (post-KEM-ratchet) |
| Q4 | Mutual authentication | Client session key implies server responded |
| Q5 | Key agreement | Both parties derive the same session key |

## Running

Install [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/):

```bash
# macOS
brew install proverif

# Or from source
git clone https://gitlab.inria.fr/bblanche/proverif.git
cd proverif && ./build && export PATH=$PWD:$PATH
```

Run the model:

```bash
proverif docs/proverif/qs_crypto.pv
```

Expected output: all queries should report `RESULT ... true` (properties hold)
or `RESULT ... cannot be proved` (ProVerif cannot find an attack, but also
cannot prove the property — typical for some authentication correspondences
in unbounded sessions).

## Limitations

- The KEM is modeled as an **ideal** black-box; this does not verify the
  Ring-LWE or SG-LWE hardness assumptions themselves.
- Password entropy is assumed sufficient (modeled as `[private]`).
- Out-of-order message delivery is not modeled (the ratchet does not
  support it in the current implementation).
- The model uses a simplified 2-message PAKE flow matching the implementation.