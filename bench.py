"""Re-runs the experiments of Sect. VI (Figs. 8-13) of the paper at a smaller scale.

    .venv/bin/python bench.py            # default sweep
    .venv/bin/python bench.py --quick    # small sweep, ~30 s

Writes results/*.csv and prints markdown tables. Absolute times are for pure
Python py_ecc on BLS12-381, so expect them to be slower than the paper's Java
JPBC numbers; the relative trends are what the experiments are about.
"""

import argparse
import csv
import os
import statistics
import time

from ehcpabe import group
from ehcpabe import And, Threshold, decrypt, encrypt, ex_extend, in_extend, keygen, setup

PAYLOAD = os.urandom(300 * 1024)   # the paper's ~300 KB PDF


def timed(fn, reps):
    samples, out = [], None
    for _ in range(reps):
        t = time.perf_counter()
        out = fn()
        samples.append(time.perf_counter() - t)
    return statistics.mean(samples), out


def attrs(prefix, n):
    """Attribute names, with H1(name) pre-computed so that every timed operation sees
    the same (warm) hash cache; otherwise whichever call runs first pays for hashing."""
    names = [f"{prefix}{i}" for i in range(n)]
    for a in names:
        group.H1(a)
    return names


def chain(files, per_level):
    """Nested hierarchy of `files` data nodes, each level adding `per_level` attributes."""
    node = None
    for level in reversed(range(files)):
        kids = attrs(f"L{level}_", per_level) + ([node] if node else [])
        node = Threshold(len(kids), *kids, name=f"M{level}")
    return node


def emit(title, header, rows, fname):
    os.makedirs("results", exist_ok=True)
    with open(os.path.join("results", fname), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"\n### {title}\n")
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for r in rows:
        print("| " + " | ".join(f"{v:.3f}" if isinstance(v, float) else str(v) for v in r) + " |")


def bench_keygen_decrypt(pp, msk, sizes, reps):
    """Figs. 8 and 10: KeyGen / Encrypt / Decrypt vs number of attributes (single file)."""
    rows = []
    for n in sizes:
        names = attrs("a", n)
        tree = And(*names, name="M")
        t_kg, sk = timed(lambda: keygen(pp, msk, names), reps)
        t_enc, (ct, _) = timed(lambda: encrypt(pp, tree, {"M": PAYLOAD}), reps)
        t_dec, _ = timed(lambda: decrypt(pp, sk, ct, "M"), reps)
        rows.append([n, t_kg, t_enc, t_dec])
    emit("KeyGen / Encrypt / Decrypt vs #attributes (s)", ["attributes", "keygen", "encrypt", "decrypt"],
         rows, "keygen_encrypt_decrypt.csv")


def bench_hierarchical_vs_separate(pp, max_files, per_level, reps):
    """Fig. 11: one hierarchical Encrypt vs separately encrypting each file under its own policy."""
    rows = []
    for files in range(1, max_files + 1):
        tree = chain(files, per_level)
        msgs = {f"M{i}": PAYLOAD for i in range(files)}
        t_h, _ = timed(lambda: encrypt(pp, tree, msgs), reps)

        def separate():
            for i in range(files):
                # policy of file i alone = the subtree rooted at level i, encrypted on its own
                encrypt(pp, _only_root_named(chain(files - i, per_level)), {"M0": PAYLOAD})
        t_s, _ = timed(separate, reps)
        rows.append([files, files * per_level, t_s, t_h])
    emit(f"Hierarchical vs separate encryption ({per_level} attributes per level, 300 KB files) (s)",
         ["files", "attributes", "separate", "hierarchical"], rows, "hierarchical_vs_separate.csv")


def _only_root_named(tree):
    for n in tree.internal_nodes():
        n.name = None
    tree.name = "M0"
    return tree


def bench_extension(pp, base_attrs, sizes, reps):
    """Figs. 12 and 13: extension vs encrypting the enlarged policy from scratch."""
    rows = []
    for n in sizes:
        base = And(*attrs("b", base_attrs), name="MA")
        ct, owner = encrypt(pp, base, {"MA": PAYLOAD})
        added = attrs("n", n)
        new = lambda: And(*added, name="MN")

        t_ex, _ = timed(lambda: ex_extend(pp, ct, owner, 1, [new()], {"MN": PAYLOAD, "MR": PAYLOAD},
                                          name="MR"), reps)
        t_in, _ = timed(lambda: in_extend(pp, ct, owner, "MA", new(), {"MN": PAYLOAD}), reps)
        scratch = lambda: encrypt(pp, Threshold(1, And(*attrs("b", base_attrs), name="MA"), new(), name="MR"),
                                  {"MA": PAYLOAD, "MN": PAYLOAD, "MR": PAYLOAD})
        t_scratch, _ = timed(scratch, reps)
        rows.append([base_attrs, n, t_scratch, t_ex, t_in])
    emit(f"Extension vs re-encrypting from scratch (original policy: {base_attrs} attributes) (s)",
         ["original attrs", "added attrs", "from scratch", "external ext.", "internal ext. case 1"],
         rows, "extension_vs_scratch.csv")


def bench_case2(pp, total, sizes, reps):
    """Case 2 of InExtension: cost grows with the number of attributes below C."""
    rows = []
    group.H1("extra")
    for m in sizes:
        c = And(*attrs("c", m), name="MC")
        tree = And(c, *attrs("o", total - m), name="MA")
        ct, owner = encrypt(pp, tree, {"MA": PAYLOAD, "MC": PAYLOAD})
        t_c2, (_, _, stats) = timed(lambda: in_extend(pp, ct, owner, "MC", "extra", {},
                                                      raise_threshold=True), reps)
        t_full, _ = timed(lambda: encrypt(pp, And(And(*attrs("c", m), "extra", name="MC"),
                                                  *attrs("o", total - m), name="MA"),
                                          {"MA": PAYLOAD, "MC": PAYLOAD}), reps)
        rows.append([total, m, stats.reencrypted_leaves, t_c2, t_full])
    emit(f"Internal extension case 2 vs full re-encryption ({total} attributes in total) (s)",
         ["total attrs", "attrs under C", "leaves re-encrypted", "case 2", "full re-encrypt"],
         rows, "internal_case2.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--reps", type=int, default=None)
    args = ap.parse_args()
    reps = args.reps or (1 if args.quick else 3)
    step = [5, 10, 15] if args.quick else [10, 20, 30, 40, 50]

    pp, msk = setup()
    print(f"EH-CP-ABE benchmarks (BLS12-381 / py_ecc, AES-256-GCM, 300 KB payload, mean of {reps} runs)")
    bench_keygen_decrypt(pp, msk, step, reps)
    bench_hierarchical_vs_separate(pp, 4 if args.quick else 10, 3 if args.quick else 5, reps)
    bench_extension(pp, 10 if args.quick else 20, step, reps)
    bench_case2(pp, step[-1], step, reps)


if __name__ == "__main__":
    main()
