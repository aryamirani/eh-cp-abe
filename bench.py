"""Re-runs the experiments of Sect. VI of the paper (Figs. 8-15).

    .venv/bin/python bench.py            # paper-scale sweep (10..100 attributes), ~15-20 min
    .venv/bin/python bench.py --quick    # small sweep, ~1 min
    .venv/bin/python plot.py             # results/*.csv -> results/fig*.png

Writes results/*.csv and prints markdown tables. Absolute times are for pure
Python py_ecc on BLS12-381, so expect them to be slower than the paper's Java
JPBC numbers; the relative trends are what the experiments are about.

Setup used for each figure, following the paper where it says what it used:

  Fig. 8-10  KeyGen / Encrypt / Decrypt, AND policy of n attributes, one file.
  Fig. 11    hierarchical vs separate encryption of 1..10 nested files
             (5 attributes per level), 300 KB files and large files.
  Fig. 12-14 (a) original policy 50 attributes, extension adds 1..10 files carrying
             20 attributes in total; (b) the extension adds one file of 10..100 attributes.
             Internal case 2 attaches under a node that covers 10 original attributes.
  Fig. 15    original policy 100 attributes, extension adds 10 attributes, the
             extended node covers 10..100 of the original attributes.
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


def split(total, parts):
    """`total` attributes spread over `parts` levels as evenly as possible (each >= 1)."""
    return [total // parts + (1 if i < total % parts else 0) for i in range(parts)]


def chain(prefix, sizes):
    """Nested hierarchy: level i is AND(its own sizes[i] attributes, level i+1), named f'{prefix}{i}'.

    Every parent is an AND gate, so each file's policy is enforced exactly (see analysis.py).
    """
    node = None
    for level in reversed(range(len(sizes))):
        kids = attrs(f"{prefix}{level}_", sizes[level]) + ([node] if node else [])
        node = Threshold(len(kids), *kids, name=f"{prefix}{level}")
    return node


def messages_for(tree, payload=PAYLOAD):
    return {n.name: payload for n in tree.internal_nodes() if n.name is not None}


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
        print("| " + " | ".join(f"{v:.3f}" if isinstance(v, float) else str(v) for v in r) + " |",
              flush=True)


# ---------------------------------------------------------------- Figs. 8, 9, 10

def bench_keygen_encrypt_decrypt(pp, msk, sizes, reps):
    rows = []
    for n in sizes:
        names = attrs("a", n)
        tree = And(*names, name="M")
        t_kg, sk = timed(lambda: keygen(pp, msk, names), reps)
        t_enc, (ct, _) = timed(lambda: encrypt(pp, tree, {"M": PAYLOAD}), reps)
        t_dec, _ = timed(lambda: decrypt(pp, sk, ct, "M"), reps)
        rows.append([n, t_kg, t_enc, t_dec])
    emit("Figs. 8-10: KeyGen / Encrypt / Decrypt vs #attributes (s)",
         ["attributes", "keygen", "encrypt", "decrypt"], rows, "keygen_encrypt_decrypt.csv")


# ---------------------------------------------------------------- Fig. 11

def bench_hierarchical_vs_separate(pp, max_files, per_level, reps, payload, fname, label):
    rows = []
    for files in range(1, max_files + 1):
        tree = chain("M", [per_level] * files)
        msgs = messages_for(tree, payload)
        t_h, _ = timed(lambda: encrypt(pp, tree, msgs), reps)

        def separate():
            # file i alone, under its own policy (= the sub-tree rooted at level i)
            for i in range(files):
                sub = chain("M", [per_level] * (files - i))
                for n in sub.internal_nodes():
                    n.name = None
                sub.name = "M"
                encrypt(pp, sub, {"M": payload})
        t_s, _ = timed(separate, reps)
        rows.append([files, files * per_level, t_s, t_h])
    emit(f"Fig. 11: hierarchical vs separate encryption ({per_level} attributes per level, "
         f"{label} files) (s)", ["files", "attributes", "separate", "hierarchical"], rows, fname)


# ---------------------------------------------------------------- Figs. 12, 13, 14

def _original(base_attrs, c_attrs):
    """Original policy: MA = AND(MC, rest) where MC = AND(c_attrs attributes)."""
    c = And(*attrs("c", c_attrs), name="MC")
    return And(c, *attrs("o", base_attrs - c_attrs), name="MA")


def _extension_row(pp, base_attrs, c_attrs, new_tree_fn, reps):
    tree = _original(base_attrs, c_attrs)
    ct, owner = encrypt(pp, tree, messages_for(tree))
    new_msgs = messages_for(new_tree_fn())

    t_ex, _ = timed(lambda: ex_extend(pp, ct, owner, 2, [new_tree_fn()], {**new_msgs, "MR": PAYLOAD},
                                      name="MR"), reps)
    t_in1, _ = timed(lambda: in_extend(pp, ct, owner, "MC", new_tree_fn(), new_msgs), reps)
    t_in2, _ = timed(lambda: in_extend(pp, ct, owner, "MC", new_tree_fn(), new_msgs,
                                       raise_threshold=True), reps)

    def scratch():
        # Encryption without extension: the whole enlarged policy, every file, from zero.
        big = _original(base_attrs, c_attrs)
        big.find("MC").children.append(new_tree_fn())
        return encrypt(pp, big, messages_for(big))
    t_scratch, _ = timed(scratch, reps)
    return [t_scratch, t_ex, t_in1, t_in2]


def bench_extension_files(pp, base_attrs, c_attrs, new_attrs, max_files, reps):
    rows = []
    for files in range(1, max_files + 1):
        sizes = split(new_attrs, files)
        rows.append([files, new_attrs] + _extension_row(pp, base_attrs, c_attrs,
                                                        lambda: chain("N", sizes), reps))
    emit(f"Figs. 12a-14a: extension vs #files added ({base_attrs}-attribute original policy, "
         f"{new_attrs} added attributes) (s)",
         ["files added", "added attrs", "no extension", "external", "internal case 1",
          "internal case 2"], rows, "extension_vs_files.csv")


def bench_extension_attrs(pp, base_attrs, c_attrs, sizes, reps):
    rows = []
    for n in sizes:
        rows.append([base_attrs, n] + _extension_row(pp, base_attrs, c_attrs,
                                                     lambda: chain("N", [n]), reps))
    emit(f"Figs. 12b-14b: extension vs #attributes added ({base_attrs}-attribute original policy, "
         f"one file added) (s)",
         ["original attrs", "added attrs", "no extension", "external", "internal case 1",
          "internal case 2"], rows, "extension_vs_attrs.csv")


# ---------------------------------------------------------------- Fig. 15

def bench_case2_updated(pp, total, new_attrs, sizes, reps):
    rows = []
    for m in sizes:
        tree = _original(total, m)
        ct, owner = encrypt(pp, tree, messages_for(tree))
        new = lambda: And(*attrs("x", new_attrs), name="MX")
        t_c2, (_, _, stats) = timed(lambda: in_extend(pp, ct, owner, "MC", new(), {"MX": PAYLOAD},
                                                      raise_threshold=True), reps)

        def scratch():
            big = _original(total, m)
            big.find("MC").children.append(new())
            return encrypt(pp, big, messages_for(big))
        t_full, _ = timed(scratch, reps)
        rows.append([total, m, stats.reencrypted_leaves, t_c2, t_full])
    emit(f"Fig. 15: internal extension case 2 vs #attributes updated ({total} original + "
         f"{new_attrs} added attributes) (s)",
         ["original attrs", "attrs under C", "leaves re-encrypted", "internal case 2", "no extension"],
         rows, "internal_case2.csv")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--reps", type=int, default=None)
    ap.add_argument("--big-mb", type=int, default=30,
                    help="large-file size for the second Fig. 11 run (paper: 300 MB)")
    args = ap.parse_args()
    q = args.quick
    reps = args.reps or (1 if q else 3)
    sweep = [5, 10, 15] if q else list(range(10, 101, 10))
    files = 3 if q else 10

    pp, msk = setup()
    print(f"EH-CP-ABE benchmarks (BLS12-381 / py_ecc, AES-256-GCM, 300 KB payload, "
          f"mean of {reps} runs)", flush=True)
    bench_keygen_encrypt_decrypt(pp, msk, sweep, reps)
    bench_hierarchical_vs_separate(pp, files, 5, reps, PAYLOAD, "hierarchical_vs_separate.csv", "300 KB")
    big = os.urandom((1 if q else args.big_mb) * 1024 * 1024)
    bench_hierarchical_vs_separate(pp, files, 5, 1, big, "hierarchical_vs_separate_big.csv",
                                   f"{len(big) // 2**20} MB")
    del big
    bench_extension_files(pp, 15 if q else 50, 5 if q else 10, 6 if q else 20, files, reps)
    bench_extension_attrs(pp, 15 if q else 50, 5 if q else 10, sweep, reps)
    bench_case2_updated(pp, sweep[-1], 3 if q else 10, sweep, reps)


if __name__ == "__main__":
    main()
