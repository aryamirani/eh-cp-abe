"""Thin wrapper over the BLS12-381 pairing from py_ecc.

The paper works in a symmetric (Type-A) group e: G0 x G0 -> GT. BLS12-381 is an
asymmetric (Type-3) group e: G1 x G2 -> GT, so every paper element is placed on
the side that makes each pairing in Decrypt line up:

    ciphertext:  C_x^(2) = g1^sigma,  C_y = h1^q,       C'_y = H1(att)^q   (H1 -> G2)
    secret key:  D = g2^alpha h2^r,   D_i = g2^r H1(i)^r_i,  D'_i = h1^r_i

    e(C_y, D_i) / e(D'_i, C'_y) = e(g1, g2)^(r*beta*q)     (DecNode on a leaf)
    e(C_x^(2), D)               = e(g1, g2)^(alpha*sigma) * e(g1, g2)^(r*beta*sigma)

which is exactly the paper's algebra with e(g, g) replaced by e(g1, g2).
"""

import hashlib
import secrets

from py_ecc import optimized_bls12_381 as bls
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.optimized_bls12_381 import optimized_pairing as op

ORDER = bls.curve_order
G1_GEN = bls.G1
G2_GEN = bls.G2
GT_ONE = bls.FQ12.one()

_H1_DST = b"EH-CP-ABE-H1-BLS12381G2_XMD:SHA-256_SSWU_RO_"
_h1_cache = {}


def rand_scalar():
    return secrets.randbelow(ORDER - 1) + 1


def g1_mul(p, k):
    return bls.multiply(p, k % ORDER)


def g2_mul(p, k):
    return bls.multiply(p, k % ORDER)


def add(p, q):
    return bls.add(p, q)


def neg(p):
    return bls.neg(p)


def gt_exp(x, k):
    return x ** (k % ORDER)


def pair(p1, q2):
    """e(P, Q) for P in G1, Q in G2."""
    return bls.pairing(q2, p1)


def miller(p1, q2):
    """Miller loop only; combine several of these and finish with final_exp()."""
    return op.miller_loop(q2, p1, final_exponentiate=False)


def final_exp(x):
    return op.final_exponentiate(x)


def H1(attribute):
    """Hash an attribute string onto G2 (IETF hash-to-curve, SSWU)."""
    pt = _h1_cache.get(attribute)
    if pt is None:
        pt = hash_to_G2(attribute.encode(), _H1_DST, hashlib.sha256)
        _h1_cache[attribute] = pt
    return pt


def _fq_bytes(v):
    return int(v).to_bytes(48, "big")


def ser_g1(p):
    x, y = bls.normalize(p)
    return _fq_bytes(x.n) + _fq_bytes(y.n)


def ser_gt(x):
    return b"".join(_fq_bytes(c) for c in x.coeffs)


def H2(c1, c2, r_hat):
    """H2: GT x G0 x GT -> {0,1}^256, used as the AES-256 key K_x."""
    h = hashlib.sha256(b"EH-CP-ABE-H2")
    h.update(ser_gt(c1))
    h.update(ser_g1(c2))
    h.update(ser_gt(r_hat))
    return h.digest()


# Compressed sizes, used only for reporting ciphertext/key sizes.
SIZE_G1, SIZE_G2, SIZE_GT = 48, 96, 576
