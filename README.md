# EH-CP-ABE — implementation

A working implementation of **Extendable Hierarchical Ciphertext-Policy Attribute-Based
Encryption** from M. Xiao, H. Li, Q. Huang, S. Yu, W. Susilo, *"Attribute-Based Hierarchical
Access Control With Extendable Policy"*, IEEE TIFS vol. 17, 2022 (`../p05.pdf`).

All six algorithms of the paper are implemented:

| Paper | Function | What it does |
|---|---|---|
| Setup | `setup()` | public parameters + master key |
| KeyGen | `keygen(pp, msk, attrs)` | decryption key for an attribute set |
| Encrypt (Alg. 1) | `encrypt(pp, tree, messages)` | encrypts one message per named non-leaf node of a hierarchical tree in a single pass |
| Decrypt | `decrypt(pp, sk, ct, name)`, `decrypt_all(pp, sk, ct)` | recovers every message whose sub-policy the key satisfies |
| ExExtension (Alg. 2) | `ex_extend(pp, ct, owner, k, new_subtrees, messages, name=...)` | grows a new root above the tree; **no original component changes** |
| InExtension (Alg. 3/4) | `in_extend(pp, ct, owner, parent, new_subtree, messages, raise_threshold=False/True)` | grafts a new branch under a node; case 1 changes nothing, case 2 re-encrypts only the subtree below that node |

## Running

```bash
python3 -m venv .venv && .venv/bin/pip install py_ecc cryptography pytest
.venv/bin/python demo.py            # the paper's motivating example, end to end
.venv/bin/python -m pytest          # 16 tests, ~15 s
.venv/bin/python bench.py --quick   # Sect. VI experiments, small sweep (~25 s)
.venv/bin/python bench.py           # full sweep (writes results/*.csv)
```

## Usage

```python
from ehcpabe import *

pp, msk = setup()
t_a = Or("TeamA", "TeamB", name="M_A")            # policy of M_A
t_b = And("taskX", t_a, name="M_B")               # policy of M_B contains T_A
ct, owner = encrypt(pp, t_b, {"M_A": b"...", "M_B": b"..."})

sk = keygen(pp, msk, {"TeamB", "taskX"})
decrypt_all(pp, sk, ct)                           # {'M_B': ..., 'M_A': ...}

ct, owner, stats = ex_extend(pp, ct, owner, 1, [And("TeamC", "lead", name="M_C")],
                             {"M_C": b"...", "M_R": b"..."}, name="M_R")
ct, owner, stats = in_extend(pp, ct, owner, "M_A", "TeamD", {})                   # case 1
ct, owner, stats = in_extend(pp, ct, owner, "M_B", "senior", {}, raise_threshold=True)  # case 2
```

Extensions return a new ciphertext and leave the one passed in untouched, so the tests can
check component by component which parts changed.

## Layout

```
ehcpabe/group.py    pairing group wrapper (BLS12-381 via py_ecc), H1, H2
ehcpabe/policy.py   hierarchical access tree: Attr / And / Or / Threshold
ehcpabe/scheme.py   the six algorithms, Lagrange interpolation, owner state
tests/              correctness, access control, collusion, extension invariants
demo.py             walkthrough of the paper's Sect. I example
bench.py            re-runs the Sect. VI experiments
```

## How this maps to the paper, and where it differs

- **Pairing group.** The paper uses a symmetric Type-A pairing `e: G0 x G0 -> GT` (JPBC, 160-bit
  order). This uses the asymmetric BLS12-381 pairing `e: G1 x G2 -> GT` (255-bit order, ~128-bit
  security). Ciphertext elements `C_x^(2), C_y` live in G1 and `C'_y = H1(att)^q` in G2; key
  elements `D, D_i` live in G2 and `D'_i` in G1. With that placement every pairing in Decrypt is
  `e(G1, G2)` and the algebra is exactly the paper's with `e(g,g)` replaced by `e(g1,g2)`
  (derivation in `group.py`).
- **H1 / H2 / (E, D).** H1 is the IETF hash-to-curve onto G2 (SSWU). H2 is SHA-256 over
  `C1 || C2 || R_hat`, giving an AES-256 key. `(E, D)` is AES-256-GCM (authenticated, so it
  matches the paper's IND-CCA requirement on `(E, D)`).
- **Owner state.** The paper says the owner keeps `sigma_x = q_x(0)` for each non-leaf node
  (sealed as `C_sigma`). But InExtension case 1 computes `q_P(0) = q_C(num_C + 1)`, which needs
  *all* coefficients of `q_C`, not just `sigma_C`. So `OwnerState` keeps the full polynomials. It
  also keeps each `K_x`, so that case 2 can re-encrypt the affected `M_x` without being handed the
  plaintexts again. `OwnerState.seal()/unseal()` stores it under an owner AES key, as the paper
  suggests.
- **Unnamed nodes.** In the paper every non-leaf node carries data. Here, a non-leaf node without a
  `name` is a pure gate and gets no `C_x` components. Naming every node gives the paper's exact
  behaviour.
- **Decrypt** runs Miller loops for all needed pairings, applies the Lagrange exponents in the
  Miller-loop domain, and does a single final exponentiation per recovered message. It only
  descends into children that are already known to be satisfied.
- **Not production code.** py_ecc is pure Python and not constant-time. This is for studying and
  benchmarking the scheme, not for protecting real data.

## Benchmarks

See `results/` (CSV) after running `bench.py`; results from this machine are in `RESULTS.md`.
Absolute times are slower than the paper's Java numbers (pure-Python pairings on a larger curve),
but the paper's comparisons can be checked directly:

1. KeyGen / Encrypt / Decrypt grow linearly with the number of attributes.
2. Hierarchical encryption beats separately encrypting each file, and the gap widens with the
   number of files.
3. External extension and internal extension case 1 cost only the *added* part; encrypting the
   enlarged policy from scratch pays for the whole tree.
4. Internal extension case 2 grows with the number of attributes under the extended node, and
   approaches full re-encryption when that node covers the whole tree.
