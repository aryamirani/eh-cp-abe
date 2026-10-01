"""EH-CP-ABE (Xiao, Li, Huang, Yu, Susilo -- IEEE TIFS vol. 17, 2022).

Setup, KeyGen, Encrypt (Alg. 1), Decrypt, ExExtension (Alg. 2) and
InExtension case 1 / case 2 (Alg. 3 / Alg. 4).
"""

import copy
import json
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import group as grp
from .policy import Node, Threshold, _coerce

p = grp.ORDER


class NotAuthorized(Exception):
    """The key's attribute set does not satisfy the requested sub-policy."""


# ---------------------------------------------------------------- polynomials

def _poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def _poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % p
    return out


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


def _interpolate(points):
    """Coefficients of the unique degree-(len-1) polynomial through `points`."""
    xs = [x for x, _ in points]
    result = [0] * len(points)
    for xi, yi in points:
        basis, den = [1], 1
        for xj in xs:
            if xj != xi:
                basis = _poly_mul(basis, [-xj % p, 1])
                den = den * (xi - xj) % p
        scale = yi * pow(den, -1, p) % p
        for d, c in enumerate(basis):
            result[d] = (result[d] + c * scale) % p
    return result


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


@dataclass
class OwnerState:
    """What the data owner keeps to extend later (the paper's C_sigma).

    The paper says the owner preserves sigma_x for each non-leaf node. Case 1 of
    InExtension evaluates q_C at num_C + 1, which needs every coefficient of q_C,
    not only sigma_C = q_C(0), so the whole polynomial is kept. The symmetric
    keys K_x are kept so case 2 can re-encrypt M_x without the plaintexts.
    """
    polys: dict = field(default_factory=dict)   # uid -> coefficients of q_x
    keys: dict = field(default_factory=dict)    # uid -> K_x

    def sigma(self, uid):
        return self.polys[uid][0]

    def seal(self, key):
        """Encrypt the state under an owner-held AES key, to store beside CT."""
        blob = json.dumps({"polys": {str(k): v for k, v in self.polys.items()},
                           "keys": {str(k): v.hex() for k, v in self.keys.items()}}).encode()
        nonce = os.urandom(12)
        return nonce + AESGCM(key).encrypt(nonce, blob, b"EH-CP-ABE owner state")

    @classmethod
    def unseal(cls, key, sealed):
        d = json.loads(AESGCM(key).decrypt(sealed[:12], sealed[12:], b"EH-CP-ABE owner state"))
        return cls(polys={int(k): v for k, v in d["polys"].items()},
                   keys={int(k): bytes.fromhex(v) for k, v in d["keys"].items()})


@dataclass
class ExtensionStats:
    new_inner: int = 0
    new_leaves: int = 0
    reencrypted_inner: int = 0
    reencrypted_leaves: int = 0


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


# ---------------------------------------------------------------- shared encryption steps

def _share(node, q0, owner, shares, stop=None):
    """Top-down polynomial definition under `node` with q_node(0) = q0.

    Fills owner.polys for non-leaf nodes and shares[uid] = q_y(0) for leaves.
    Subtrees whose uid is in `stop` are left untouched.
    """
    if node.is_leaf:
        shares[node.uid] = q0 % p
        return
    q = _random_poly(q0, node.k - 1)
    owner.polys[node.uid] = q
    for idx, child in enumerate(node.children, start=1):
        if stop and child.uid in stop:
            continue
        _share(child, _poly_eval(q, idx), owner, shares, stop)


def _encrypt_inner(pp, node, sigma, message, ct, owner):
    r_hat = grp.gt_exp(pp.egg, grp.rand_scalar())
    c1 = r_hat * grp.gt_exp(pp.egg_alpha, sigma)
    c2 = grp.g1_mul(pp.g1, sigma)
    key = grp.H2(c1, c2, r_hat)
    ct.inner[node.uid] = (c1, c2, _sym_enc(key, message))
    owner.keys[node.uid] = key


def _encrypt_leaf(pp, node, q0, ct):
    ct.leaf[node.uid] = (grp.g1_mul(pp.h1, q0), grp.g2_mul(grp.H1(node.attr), q0))


def _encrypt_nodes(pp, nodes, shares, messages, ct, owner):
    """Compute C_x^(1..3) for named non-leaf nodes and C_y, C'_y for leaves."""
    count_inner = count_leaf = 0
    for n in nodes:
        if n.is_leaf:
            _encrypt_leaf(pp, n, shares[n.uid], ct)
            count_leaf += 1
        elif n.name is not None:
            _encrypt_inner(pp, n, owner.sigma(n.uid), messages[n.name], ct, owner)
            count_inner += 1
    return count_inner, count_leaf


def _named(nodes):
    return [n.name for n in nodes if not n.is_leaf and n.name is not None]


def _check_messages(all_nodes, new_nodes, messages):
    """Names are unique across the whole tree; messages cover exactly the new named nodes."""
    names = _named(all_nodes)
    if len(names) != len(set(names)):
        raise ValueError("node names must be unique")
    expected = set(_named(new_nodes))
    if expected != set(messages):
        raise ValueError(f"messages must be given exactly for named nodes {sorted(expected)}, "
                         f"got {sorted(messages)}")


# ---------------------------------------------------------------- Encrypt (Algorithm 1)

def encrypt(pp, tree, messages):
    """Encrypt {M_x} for every named non-leaf node x of `tree` in one pass."""
    nodes = list(tree.walk())
    _check_messages(nodes, nodes, messages)
    owner, shares = OwnerState(), {}
    _share(tree, grp.rand_scalar(), owner, shares)
    ct = Ciphertext(tree=tree, inner={}, leaf={})
    _encrypt_nodes(pp, nodes, shares, messages, ct, owner)
    return ct, owner


# ---------------------------------------------------------------- Decrypt

def _dec_node(node, sk, ct, memo):
    """DecNode(x) in the Miller-loop domain: final_exp() of it is e(g,g)^(r beta q_x(0)).

    Only called on nodes already known to be satisfied, so no pairing is wasted.
    """
    if node.uid in memo:
        return memo[node.uid]
    if node.is_leaf:
        di, di_prime = sk.comps[node.attr]
        cy, cy_prime = ct.leaf[node.uid]
        val = grp.miller(cy, di) * grp.miller(grp.neg(di_prime), cy_prime)
    else:
        chosen = [(i, c) for i, c in enumerate(node.children, start=1) if c.satisfied_by(sk.attrs)][:node.k]
        S = [i for i, _ in chosen]
        val = grp.GT_ONE
        for i, c in chosen:
            val = val * _dec_node(c, sk, ct, memo) ** lagrange_at_zero(i, S)
    memo[node.uid] = val
    return val


def _decrypt_at(node, sk, ct, memo):
    c1, c2, c3 = ct.inner[node.uid]
    # C1 * DecNode(x) / e(C2, D) = R_hat, done with a single final exponentiation.
    r_hat = c1 * grp.final_exp(_dec_node(node, sk, ct, memo) * grp.miller(grp.neg(c2), sk.D))
    return _sym_dec(grp.H2(c1, c2, r_hat), c3)


def decrypt(pp, sk, ct, name):
    """Recover M_name if sk's attributes satisfy the subtree rooted at node `name`."""
    node = ct.tree.find(name)
    if not node.satisfied_by(sk.attrs):
        raise NotAuthorized(f"attributes {sorted(sk.attrs)} do not satisfy the policy of {name!r}")
    return _decrypt_at(node, sk, ct, {})


def decrypt_all(pp, sk, ct):
    """Every message whose sub-policy sk satisfies; DecNode work is shared between them."""
    memo = {}
    return {n.name: _decrypt_at(n, sk, ct, memo)
            for n in ct.tree.internal_nodes()
            if n.name is not None and n.satisfied_by(sk.attrs)}


# ---------------------------------------------------------------- extension helpers

def _fork(ct, owner):
    """Copy CT/owner so the caller's originals stay intact (group elements are immutable)."""
    return (Ciphertext(tree=copy.deepcopy(ct.tree), inner=dict(ct.inner), leaf=dict(ct.leaf)),
            OwnerState(polys=dict(owner.polys), keys=dict(owner.keys)))


def _locate(tree, target):
    if isinstance(target, Node):
        for n in tree.walk():
            if n.uid == target.uid:
                return n
        raise KeyError("node not found in ciphertext tree")
    return tree.find(target)


# ---------------------------------------------------------------- ExExtension (Algorithm 2)

def ex_extend(pp, ct, owner, k, new_subtrees, messages, name=None, old_root_index=1):
    """External extension: a new root R = k-of-(old root + new_subtrees).

    q_R is interpolated through (index(A), sigma_A) and k_R - 1 random points,
    so no component of the original ciphertext changes.
    """
    ct, owner = _fork(ct, owner)
    old_root = ct.tree
    new_subtrees = [_coerce(s) for s in new_subtrees]
    children = list(new_subtrees)
    children.insert(old_root_index - 1, old_root)
    root = Threshold(k, *children, name=name)

    new_nodes = [root] + [n for s in new_subtrees for n in s.walk()]
    _check_messages(list(root.walk()), new_nodes, messages)

    others = [i for i in range(1, len(children) + 1) if i != old_root_index][:k - 1]
    points = [(old_root_index, owner.sigma(old_root.uid))] + [(i, grp.rand_scalar()) for i in others]
    q_root = _interpolate(points)
    owner.polys[root.uid] = q_root

    shares = {}
    for idx, child in enumerate(children, start=1):
        if child is not old_root:
            _share(child, _poly_eval(q_root, idx), owner, shares)

    ct.tree = root
    stats = ExtensionStats()
    stats.new_inner, stats.new_leaves = _encrypt_nodes(pp, new_nodes, shares, messages, ct, owner)
    return ct, owner, stats


# ---------------------------------------------------------------- InExtension (Algorithms 3 and 4)

def in_extend(pp, ct, owner, parent, new_subtree, messages, raise_threshold=False):
    """Internal extension: attach `new_subtree` as child num_C + 1 of node `parent`.

    raise_threshold=False -> case 1 (Alg. 3): k_C unchanged, original CT untouched.
    raise_threshold=True  -> case 2 (Alg. 4): k_C += 1; q_C is re-drawn keeping
    sigma_C, so everything strictly below C is re-encrypted but C and the rest of
    the tree are not.
    """
    ct, owner = _fork(ct, owner)
    c_node = _locate(ct.tree, parent)
    if c_node.is_leaf:
        raise ValueError("internal extension must attach to a non-leaf node")
    sub = _coerce(new_subtree)
    new_nodes = list(sub.walk())
    _check_messages(new_nodes + list(ct.tree.walk()), new_nodes, messages)

    original_below = [n for child in c_node.children for n in child.walk()]
    c_node.children.append(sub)
    idx_p = len(c_node.children)
    shares, stats = {}, ExtensionStats()

    if not raise_threshold:
        _share(sub, _poly_eval(owner.polys[c_node.uid], idx_p), owner, shares)
    else:
        c_node.k += 1
        old_keys = {n.uid: owner.keys[n.uid] for n in original_below if n.uid in owner.keys}
        # Re-define q_C with the same sigma_C and one more degree, then re-share below C.
        _share(c_node, owner.sigma(c_node.uid), owner, shares)
        for n in original_below:
            if n.is_leaf:
                _encrypt_leaf(pp, n, shares[n.uid], ct)
                stats.reencrypted_leaves += 1
            elif n.name is not None:
                message = _sym_dec(old_keys[n.uid], ct.inner[n.uid][2])
                _encrypt_inner(pp, n, owner.sigma(n.uid), message, ct, owner)
                stats.reencrypted_inner += 1

    stats.new_inner, stats.new_leaves = _encrypt_nodes(pp, new_nodes, shares, messages, ct, owner)
    return ct, owner, stats
