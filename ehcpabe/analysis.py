"""A limitation of the paper's hierarchical construction, found while implementing it.

In Encrypt (Alg. 1) the secret of a child is a point on its parent's polynomial,
sigma_x = q_parent(x)(index(x)). Decrypt gives a user who satisfies a gate P the
values e(g,g)^(r*beta*q_P(j)) for k_P distinct indices j (one per satisfied child),
and Lagrange interpolation in the exponent works at any point, not only at 0. So
the user can compute

    e(g,g)^(r*beta*q_P(index(x))) = e(g,g)^(r*beta*sigma_x) = DecNode(x)

for every child x of P, and with it recover M_x, even when their attributes do
not satisfy T_x. In effect M_x is protected by T_x OR T_parent(x), not by T_x.

The policies are enforced exactly as written only when the parent of every named
node is an AND gate (k = num); then satisfying the parent implies satisfying the
child. The cases where the gap shows:

  * a named child of an OR or k-of-n gate inside Encrypt (paper Fig. 5 has both),
  * ExExtension with k_R < num_R: users who satisfy the new root R recover M_A of
    the original root A,
  * InExtension case 1: users who satisfy the original policy of C recover the
    new M_P, because q_P(0) = q_C(num_C + 1) is one more point on q_C.

The proof in Sect. V does not cover this: its challenge ciphertext carries a
single message under T*, so it never reasons about one sub-tree's message being
hidden from holders of another sub-tree's key.
"""

from . import group as grp
from .scheme import _dec_node, _sym_dec, p


def _lagrange_at(i, S, x):
    num, den = 1, 1
    for j in S:
        if j != i:
            num = num * (x - j) % p
            den = den * (i - j) % p
    return num * pow(den, -1, p) % p


def decrypt_child_via_parent(pp, sk, ct, parent_name, child_name):
    """Recover M_child using only the fact that sk satisfies the parent gate.

    Uses nothing but public ciphertext components and the user's own key.
    """
    parent = ct.tree.find(parent_name)
    child = ct.tree.find(child_name)
    idx = next(i for i, c in enumerate(parent.children, start=1) if c is child)
    if not parent.satisfied_by(sk.attrs):
        raise ValueError("this key does not satisfy the parent gate either")

    chosen = [(i, c) for i, c in enumerate(parent.children, start=1)
              if c.satisfied_by(sk.attrs)][:parent.k]
    S = [i for i, _ in chosen]
    memo, val = {}, grp.GT_ONE
    for i, c in chosen:
        val = val * _dec_node(c, sk, ct, memo) ** _lagrange_at(i, S, idx)

    c1, c2, c3 = ct.inner[child.uid]
    r_hat = c1 * grp.final_exp(val * grp.miller(grp.neg(c2), sk.D))
    return _sym_dec(grp.H2(c1, c2, r_hat), c3)


def leaking_nodes(tree):
    """Named nodes whose effective policy is weaker than their own sub-tree.

    A named non-root node is exposed when its parent is not an AND gate.
    """
    out = []
    for parent in tree.internal_nodes():
        if parent.k < len(parent.children):
            out += [c.name for c in parent.children if not c.is_leaf and c.name is not None]
    return out
