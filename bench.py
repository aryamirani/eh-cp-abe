"""KeyGen / Encrypt / Decrypt vs number of attributes (paper Sect. VI, Figs. 8 and 10).

    python bench.py            # 10..50 attributes, mean of 3 runs
    python bench.py --quick    # 5..15 attributes, 1 run

Writes results/keygen_encrypt_decrypt.csv and prints a markdown table. Absolute
times are for pure-Python py_ecc on BLS12-381, so expect them to be slower than
the paper's Java JPBC numbers; the linear trend is what the experiment is about.
"""

import argparse
import csv
import os
import statistics
import time

from ehcpabe import And, decrypt, encrypt, group, keygen, setup

PAYLOAD = os.urandom(300 * 1024)   # the paper's ~300 KB PDF


def timed(fn, reps):
    samples, out = [], None
    for _ in range(reps):
        t = time.perf_counter()
        out = fn()
        samples.append(time.perf_counter() - t)
    return statistics.mean(samples), out


def attrs(n):
    """Attribute names, with H1(name) pre-computed so that every timed operation sees
    the same (warm) hash cache; otherwise whichever call runs first pays for hashing."""
    names = [f"a{i}" for i in range(n)]
    for a in names:
        group.H1(a)
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--reps", type=int, default=None)
    args = ap.parse_args()
    reps = args.reps or (1 if args.quick else 3)
    sizes = [5, 10, 15] if args.quick else [10, 20, 30, 40, 50]

    pp, msk = setup()
    rows = []
    for n in sizes:
        names = attrs(n)
        tree = And(*names, name="M")
        t_kg, sk = timed(lambda: keygen(pp, msk, names), reps)
        t_enc, (ct, _) = timed(lambda: encrypt(pp, tree, {"M": PAYLOAD}), reps)
        t_dec, _ = timed(lambda: decrypt(pp, sk, ct, "M"), reps)
        rows.append([n, t_kg, t_enc, t_dec])

    os.makedirs("results", exist_ok=True)
    with open("results/keygen_encrypt_decrypt.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attributes", "keygen", "encrypt", "decrypt"])
        w.writerows(rows)
    print(f"KeyGen / Encrypt / Decrypt (s), 300 KB payload, mean of {reps} run(s)\n")
    print("| attributes | keygen | encrypt | decrypt |\n|---|---|---|---|")
    for r in rows:
        print(f"| {r[0]} | {r[1]:.3f} | {r[2]:.3f} | {r[3]:.3f} |")


if __name__ == "__main__":
    main()
