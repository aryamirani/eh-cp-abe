# EH-CP-ABE — implementation (Part 1: 35%)

An implementation of **Extendable Hierarchical Ciphertext-Policy Attribute-Based Encryption**
from M. Xiao, H. Li, Q. Huang, S. Yu and W. Susilo, *"Attribute-Based Hierarchical Access
Control With Extendable Policy"*, IEEE Transactions on Information Forensics and Security,
vol. 17, pp. 1868–1883, 2022.

## Status

| | Component | Status |
|---|---|---|
| ✅ | Pairing-group layer (BLS12-381), H₁ hash-to-curve, H₂ key derivation | Part 1 |
| ✅ | Access trees: attribute leaves, AND / OR / k-of-n threshold gates | Part 1 |
| ✅ | **Setup**, **KeyGen** | Part 1 |
| ✅ | **Encrypt / Decrypt** for a single access policy (one message at the root) | Part 1 |
| ✅ | Tests, demo, KeyGen/Encrypt/Decrypt benchmark | Part 1 |
| ⏳ | Hierarchical Encrypt: one message per internal node, in one pass | Part 2 |
| ⏳ | ExExtension (external) and InExtension (internal, case 1 and case 2) | Part 2 |
| ⏳ | Remaining experiments of the paper's Sect. VI | Part 2 |

## Running

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python demo.py            # one policy, four users (incl. a collusion attempt)
.venv/bin/python -m pytest          # tests
.venv/bin/python bench.py           # KeyGen / Encrypt / Decrypt vs #attributes
```

## Usage

```python
from ehcpabe import And, Or, setup, keygen, encrypt, decrypt

pp, msk = setup()
T = And("taskX", Or("TeamA", "TeamB"), name="M")   # the paper's motivating policy
ct, _ = encrypt(pp, T, {"M": b"project plan"})

sk = keygen(pp, msk, {"TeamB", "taskX"})
decrypt(pp, sk, ct, "M")                            # b'project plan'
```

A key whose attributes don't satisfy the policy raises `NotAuthorized`. Keys from different
users can't be combined: each key is randomised with its own `r`, so pooled components fail
the AES-GCM authentication check.

## How the paper maps to the code

| Paper | Here |
|---|---|
| Setup: `Param = {g, h = g^β, e(g,g)^α, H₁, H₂}`, `MSK = {β, g^α}` | `setup()` — `g₁, g₂, h₁ = g₁^β, h₂ = g₂^β, e(g₁,g₂)^α`, `MSK = {β, g₂^α}` |
| KeyGen: `D = g^α h^r`, `Dᵢ = g^r H₁(i)^{rᵢ}`, `D′ᵢ = h^{rᵢ}` | `keygen()` — `D, Dᵢ ∈ G₂`, `D′ᵢ ∈ G₁` |
| Encrypt: `C⁽¹⁾ = R̂·e(g,g)^{ασ}`, `C⁽²⁾ = g^σ`, `C⁽³⁾ = E_K(M)`, `C_y = h^{q_y(0)}`, `C′_y = H₁(att(y))^{q_y(0)}` | `encrypt()` — Shamir sharing down the tree; `C⁽²⁾, C_y ∈ G₁`, `C′_y ∈ G₂` |
| Decrypt: recursive `DecNode` with Lagrange interpolation, `R̂ = C⁽¹⁾·DecNode(root)/e(C⁽²⁾, D)` | `decrypt()` |

- **Pairing group.** The paper uses a symmetric Type-A pairing `e: G₀ × G₀ → G_T` (Java JPBC).
  This uses the asymmetric BLS12-381 pairing `e: G₁ × G₂ → G_T` from `py_ecc`. Each element is
  placed in G₁ or G₂ so that every pairing in Decrypt is `e(G₁, G₂)`. The algebra is the
  paper's, with `e(g,g)` replaced by `e(g₁,g₂)`; the derivation is in `ehcpabe/group.py`.
- **H₁ / H₂ / (E, D).** H₁ is the IETF hash-to-curve onto G₂. H₂ is SHA-256 over
  `C⁽¹⁾ ‖ C⁽²⁾ ‖ R̂`, giving an AES-256 key, and `(E, D)` is AES-256-GCM.
- **Faster Decrypt.** A full pairing costs ≈ 0.42 s in pure Python. Decrypt computes only
  Miller loops (≈ 0.03 s each), applies the Lagrange exponents before the final
  exponentiation, and does one final exponentiation (≈ 0.12 s) per message. That makes it
  ≈ 12× faster than pairing naively (3.6 s instead of ≈ 42 s at 50 attributes).
- **Not production code.** `py_ecc` is pure Python and not constant-time. This is for studying
  and benchmarking the scheme.

## Results

See [`RESULTS.md`](RESULTS.md). KeyGen, Encrypt and Decrypt all grow linearly with the number
of attributes, matching the paper's Figs. 8 and 10.

## Layout

```
ehcpabe/group.py    pairing-group wrapper (BLS12-381 via py_ecc), H1, H2
ehcpabe/policy.py   access trees: Attr / And / Or / Threshold
ehcpabe/scheme.py   Setup, KeyGen, Encrypt, Decrypt
tests/              correctness, refusal, collusion resistance, threshold gates, validation
demo.py             one policy, four users
bench.py            KeyGen / Encrypt / Decrypt vs number of attributes
```
