"""EH-CP-ABE (Xiao, Li, Huang, Yu, Susilo -- IEEE TIFS vol. 17, 2022) -- Part 1.

Setup, KeyGen, and Encrypt / Decrypt for a single access policy: one message
bound to the root of the access tree. Hierarchical multi-message encryption
(Alg. 1 in full), ExExtension and InExtension come in Part 2.
"""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import group as grp
from .policy import Node

p = grp.ORDER


class NotAuthorized(Exception):
    """The key's attribute set does not satisfy the access policy."""


# ---------------------------------------------------------------- polynomials

def _poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def _random_poly(constant, degree):
    return [constant % p] + [grp.rand_scalar() for _ in range(degree)]


def lagrange_at_zero(i, S):
    """Delta_{i,S}(0) = prod_{j in S, j != i} (0 - j) / (i - j)  mod p."""
    num, den = 1, 1
    for j in S:
        if j != i:
            num = num * (-j) % p
            den = den * (i - j) % p
    return num * pow(den, -1, p) % p


# ---------------------------------------------------------------- data types

@dataclass
class PublicParams:
    g1: tuple
    g2: tuple
    h1: tuple          # g1^beta
    h2: tuple          # g2^beta
    egg: object        # e(g1, g2), used to sample random R_hat in GT
    egg_alpha: object  # e(g1, g2)^alpha


@dataclass
class MasterKey:
    beta: int
    g2_alpha: tuple


@dataclass
class SecretKey:
    attrs: frozenset
    D: tuple
    comps: dict        # attribute -> (D_i in G2, D'_i in G1)

    def size_bytes(self):
        return grp.SIZE_G2 + len(self.comps) * (grp.SIZE_G2 + grp.SIZE_G1)


@dataclass
class Ciphertext:
    tree: Node
    inner: dict        # uid -> (C1 in GT, C2 in G1, C3 bytes)
    leaf: dict         # uid -> (C_y in G1, C'_y in G2)

    def size_bytes(self):
        body = sum(grp.SIZE_GT + grp.SIZE_G1 + len(c3) for _, _, c3 in self.inner.values())
        return body + len(self.leaf) * (grp.SIZE_G1 + grp.SIZE_G2)


# ---------------------------------------------------------------- symmetric (E, D)

def _sym_enc(key, message):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, message, None)


def _sym_dec(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


# ---------------------------------------------------------------- Setup / KeyGen

def setup():
    alpha, beta = grp.rand_scalar(), grp.rand_scalar()
    g1, g2 = grp.G1_GEN, grp.G2_GEN
    egg = grp.pair(g1, g2)
    pp = PublicParams(g1=g1, g2=g2, h1=grp.g1_mul(g1, beta), h2=grp.g2_mul(g2, beta),
                      egg=egg, egg_alpha=grp.gt_exp(egg, alpha))
    return pp, MasterKey(beta=beta, g2_alpha=grp.g2_mul(g2, alpha))


def keygen(pp, msk, attrs):
    r = grp.rand_scalar()
    g2_r = grp.g2_mul(pp.g2, r)
    comps = {}
    for a in attrs:
        ri = grp.rand_scalar()
        comps[a] = (grp.add(g2_r, grp.g2_mul(grp.H1(a), ri)), grp.g1_mul(pp.h1, ri))
    return SecretKey(attrs=frozenset(attrs), D=grp.add(msk.g2_alpha, grp.g2_mul(pp.h2, r)), comps=comps)


# ---------------------------------------------------------------- Encrypt

def _share(node, q0, shares):
    """Top-down Shamir sharing: q_node(0) = q0, q_child(0) = q_node(index(child)).

    Records q_y(0) for every leaf y in `shares`.
    """
    if node.is_leaf:
        shares[node.uid] = q0 % p
        return
    q = _random_poly(q0, node.k - 1)
    for idx, child in enumerate(node.children, start=1):
        _share(child, _poly_eval(q, idx), shares)


def _check_single_policy(tree, messages):
    named = [n.name for n in tree.internal_nodes() if n.name is not None]
    if named != [tree.name] or tree.name is None:
        raise ValueError("Part 1 supports one message bound to the root: name only the root node "
                         "(hierarchical multi-message encryption comes in Part 2)")
    if set(messages) != {tree.name}:
        raise ValueError(f"expected exactly one message for {tree.name!r}, got {sorted(messages)}")


def encrypt(pp, tree, messages):
    """Encrypt the message bound to the (named) root of `tree` under the tree's policy.

    Returns (ct, sigma). sigma = q_root(0) stays with the data owner; the paper's
    policy-extension algorithms (Part 2) are built on it.
    """
    if tree.is_leaf:
        raise ValueError("the access policy must be a threshold gate, not a single leaf")
    _check_single_policy(tree, messages)
    sigma = grp.rand_scalar()
    shares = {}
    _share(tree, sigma, shares)

    ct = Ciphertext(tree=tree, inner={}, leaf={})
    r_hat = grp.gt_exp(pp.egg, grp.rand_scalar())
    c1 = r_hat * grp.gt_exp(pp.egg_alpha, sigma)
    c2 = grp.g1_mul(pp.g1, sigma)
    ct.inner[tree.uid] = (c1, c2, _sym_enc(grp.H2(c1, c2, r_hat), messages[tree.name]))
    for leaf in tree.leaves():
        q0 = shares[leaf.uid]
        ct.leaf[leaf.uid] = (grp.g1_mul(pp.h1, q0), grp.g2_mul(grp.H1(leaf.attr), q0))
    return ct, sigma


# ---------------------------------------------------------------- Decrypt

def _dec_node(node, sk, ct):
    """DecNode(x) in the Miller-loop domain: final_exp() of it is e(g,g)^(r beta q_x(0)).

    Only called on nodes already known to be satisfied, so no pairing is wasted.
    """
    if node.is_leaf:
        di, di_prime = sk.comps[node.attr]
        cy, cy_prime = ct.leaf[node.uid]
        return grp.miller(cy, di) * grp.miller(grp.neg(di_prime), cy_prime)
    chosen = [(i, c) for i, c in enumerate(node.children, start=1) if c.satisfied_by(sk.attrs)][:node.k]
    S = [i for i, _ in chosen]
    val = grp.GT_ONE
    for i, c in chosen:
        val = val * _dec_node(c, sk, ct) ** lagrange_at_zero(i, S)
    return val


def decrypt(pp, sk, ct, name):
    """Recover the message `name` if sk's attributes satisfy the access policy."""
    root = ct.tree
    if root.name != name:
        raise KeyError(f"no message named {name!r}")
    if not root.satisfied_by(sk.attrs):
        raise NotAuthorized(f"attributes {sorted(sk.attrs)} do not satisfy the policy of {name!r}")
    c1, c2, c3 = ct.inner[root.uid]
    # C1 * DecNode(root) / e(C2, D) = R_hat, done with a single final exponentiation.
    r_hat = c1 * grp.final_exp(_dec_node(root, sk, ct) * grp.miller(grp.neg(c2), sk.D))
    return _sym_dec(grp.H2(c1, c2, r_hat), c3)
