"""A limitation of the paper's hierarchical construction, found while implementing it.

In Encrypt (Alg. 1) the secret of a child is a point on its parent's polynomial,
sigma_x = q_parent(x)(index(x)). Decrypt gives a user, for every satisfied child y
of a gate P, the value e(g,g)^(r*beta*q_P(index(y))), and a user who knows
DecNode(P) also has the point at 0. Lagrange interpolation in the exponent works
at any point, not only at 0, so once a user holds k_P points of q_P they can
evaluate it at every child's index: they learn DecNode(x) for all children x of P,
and with it M_x, whether or not their attributes satisfy T_x. The knowledge then
flows on: DecNode(x) is the point at 0 of q_x, which counts towards x's own k_x.

So the gap compounds across levels. A named node x is protected exactly by T_x
only when every gate on the path from the root down to x is an AND gate
(k = num); one OR or k-of-n gate anywhere above x is enough to expose it (for
trees whose leaves carry distinct attributes). In particular:

  * a named child of an OR or k-of-n gate inside Encrypt,
  * a named node below an OR or k-of-n gate higher up, even through unnamed
    AND gates (unnamed gates carry no data but still pass shares on),
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


def recover_all(pp, sk, ct):
    """Every message this key can recover from public data, by propagating polynomial points.

    known[uid] holds e(g,g)^(r*beta*q_node(0)) (in the Miller-loop domain) for each node
    whose secret the key can reach. Satisfied leaves seed it; a gate with at least k
    known points (children's values, plus its own value at 0) yields all of them.
    """
    known, memo = {}, {}
    for leaf in ct.tree.leaves():
        if leaf.attr in sk.attrs:
            known[leaf.uid] = _dec_node(leaf, sk, ct, memo)
    changed = True
    while changed:
        changed = False
        for node in ct.tree.internal_nodes():
            pts = {i: known[c.uid] for i, c in enumerate(node.children, start=1) if c.uid in known}
            if node.uid in known:
                pts[0] = known[node.uid]
            if len(pts) < node.k:
                continue
            S = sorted(pts)[:node.k]
            targets = [(0, node)] + list(enumerate(node.children, start=1))
            for idx, n in targets:
                if n.uid not in known:
                    val = grp.GT_ONE
                    for i in S:
                        val = val * pts[i] ** _lagrange_at(i, S, idx)
                    known[n.uid] = val
                    changed = True

    out = {}
    for node in ct.tree.internal_nodes():
        if node.name is not None and node.uid in known:
            c1, c2, c3 = ct.inner[node.uid]
            r_hat = c1 * grp.final_exp(known[node.uid] * grp.miller(grp.neg(c2), sk.D))
            out[node.name] = _sym_dec(grp.H2(c1, c2, r_hat), c3)
    return out


def leaking_nodes(tree):
    """Named nodes whose effective policy is weaker than their own sub-tree:
    those with an OR or k-of-n gate anywhere on the path from the root."""
    out = []

    def walk(node, exposed):
        if node.is_leaf:
            return
        if exposed and node.name is not None:
            out.append(node.name)
        below = exposed or node.k < len(node.children)
        for c in node.children:
            walk(c, below)

    walk(tree, False)
    return out
