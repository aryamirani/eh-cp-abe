"""Walks through the paper's motivating example (Sect. I) end to end.

    .venv/bin/python demo.py
"""

import os

from ehcpabe import (And, NotAuthorized, Or, OwnerState, decrypt, decrypt_all, encrypt, ex_extend,
                     in_extend, keygen, setup, to_string)


def show(title, pp, ct, users):
    print(f"\n== {title}\n   policy tree: {to_string(ct.tree)}")
    for label, sk in users.items():
        got = decrypt_all(pp, sk, ct)
        print(f"   {label:<28} -> {sorted(got) or '(nothing)'}")


def main():
    pp, msk = setup()
    users = {
        "Team A engineer": keygen(pp, msk, {"TeamA"}),
        "Team B engineer on task X": keygen(pp, msk, {"TeamB", "taskX"}),
        "female Team C engineer": keygen(pp, msk, {"TeamC", "female"}),
        "Team C lead": keygen(pp, msk, {"TeamC", "lead"}),
        "outsider on task X": keygen(pp, msk, {"taskX"}),
    }

    # T_A = TeamA OR TeamB;  T_B = taskX AND T_A.  One hierarchical Encrypt covers both.
    t_a = Or("TeamA", "TeamB", name="M_A")
    t_b = And("taskX", t_a, name="M_B")
    ct, owner = encrypt(pp, t_b, {"M_A": b"work task A", "M_B": b"work task B (task X only)"})
    show("Hierarchical encryption of M_A and M_B in one pass", pp, ct, users)

    try:
        decrypt(pp, users["outsider on task X"], ct, "M_B")
    except NotAuthorized as e:
        print(f"   outsider asking for M_B: refused ({e})")

    # The owner keeps its polynomials sealed next to the ciphertext (the paper's C_sigma).
    owner_key = os.urandom(32)
    sealed = owner.seal(owner_key)
    owner = OwnerState.unseal(owner_key, sealed)

    # External extension: a new root M_R = T_B OR (TeamC AND lead) is grown above the old tree.
    ct, owner, stats = ex_extend(pp, ct, owner, 1, [And("TeamC", "lead", name="M_C")],
                                 {"M_C": b"Team C planning notes", "M_R": b"department-wide memo"},
                                 name="M_R")
    show(f"External extension (original ciphertext untouched; {stats})", pp, ct, users)

    # Internal extension, case 1: add a new branch under T_A without changing its threshold,
    # so female Team C engineers now also get M_A.
    ct, owner, stats = in_extend(pp, ct, owner, "M_A", And("female", "TeamC", name="M_D"),
                                 {"M_D": b"women-in-engineering mentoring (Team C)"})
    show(f"Internal extension case 1 (original ciphertext untouched; {stats})", pp, ct, users)

    # Internal extension, case 2: T_B now also needs a 'senior' attribute (k_B: 2 -> 3).
    ct, owner, stats = in_extend(pp, ct, owner, "M_B", "senior", {}, raise_threshold=True)
    show(f"Internal extension case 2 (subtree under M_B re-encrypted; {stats})", pp, ct, users)


if __name__ == "__main__":
    main()
