import os

import pytest
from cryptography.exceptions import InvalidTag

from ehcpabe import (And, NotAuthorized, Or, OwnerState, SecretKey, Threshold, decrypt, decrypt_all,
                     encrypt, ex_extend, in_extend, keygen, setup)
from ehcpabe.analysis import decrypt_child_via_parent, leaking_nodes
from ehcpabe.group import ORDER
from ehcpabe.scheme import _interpolate, _poly_eval, lagrange_at_zero

MSGS = {"MA": b"data A", "MB": b"data B", "MC": b"data C", "MD": b"data D"}


@pytest.fixture(scope="module")
def system():
    return setup()


def fig5_tree():
    """Shape of the paper's Fig. 5: every non-leaf node carries its own data."""
    d = And("d1", "d2", "d3", name="MD")
    b = Or("b1", d, name="MB")
    c = And("c1", "c2", name="MC")
    return Threshold(2, b, c, "a1", name="MA")


@pytest.fixture(scope="module")
def encrypted(system):
    pp, _ = system
    return encrypt(pp, fig5_tree(), MSGS)


def test_polynomial_helpers():
    pts = [(1, 11), (3, 29), (4, 101)]
    q = _interpolate(pts)
    assert all(_poly_eval(q, x) == y for x, y in pts)
    S = [1, 3, 4]
    assert sum(lagrange_at_zero(i, S) * y for i, y in pts) % ORDER == q[0]


@pytest.mark.parametrize("attrs, expected", [
    ({"b1"}, {"MB"}),
    ({"d1", "d2", "d3"}, {"MD", "MB"}),
    ({"c1", "c2"}, {"MC"}),
    ({"b1", "a1"}, {"MB", "MA"}),
    ({"c1", "c2", "a1"}, {"MC", "MA"}),
    ({"d1", "d2", "d3", "c1", "c2"}, {"MD", "MB", "MC", "MA"}),
    ({"d1", "d2", "c1", "a1"}, set()),
])
def test_hierarchical_decryption(system, encrypted, attrs, expected):
    pp, msk = system
    ct, _ = encrypted
    got = decrypt_all(pp, keygen(pp, msk, attrs), ct)
    assert got == {n: MSGS[n] for n in expected}


def test_unauthorized_raises(system, encrypted):
    pp, msk = system
    ct, _ = encrypted
    with pytest.raises(NotAuthorized):
        decrypt(pp, keygen(pp, msk, {"c1"}), ct, "MC")


def test_collusion_resistance(system, encrypted):
    """Two users who each hold half of MC's policy cannot pool their key components."""
    pp, msk = system
    ct, _ = encrypted
    alice, bob = keygen(pp, msk, {"c1"}), keygen(pp, msk, {"c2"})
    pooled = SecretKey(attrs=frozenset({"c1", "c2"}), D=alice.D,
                       comps={"c1": alice.comps["c1"], "c2": bob.comps["c2"]})
    with pytest.raises(InvalidTag):
        decrypt(pp, pooled, ct, "MC")


def test_message_validation(system):
    pp, _ = system
    with pytest.raises(ValueError):
        encrypt(pp, fig5_tree(), {"MA": b"only one"})
    with pytest.raises(ValueError):
        encrypt(pp, And(Or("x", name="dup"), Or("y", name="dup"), name="root"),
                {"dup": b"1", "root": b"2"})


def test_external_extension_keeps_original_ciphertext(system, encrypted):
    pp, msk = system
    ct, owner = encrypted
    new = And("e1", "e2", name="ME")
    ct2, owner2, stats = ex_extend(pp, ct, owner, 1, [new], {"ME": b"data E", "MR": b"data R"}, name="MR")

    assert all(ct2.inner[u] == ct.inner[u] for u in ct.inner)
    assert all(ct2.leaf[u] == ct.leaf[u] for u in ct.leaf)
    assert (stats.new_inner, stats.new_leaves, stats.reencrypted_inner + stats.reencrypted_leaves) == (2, 2, 0)

    assert decrypt_all(pp, keygen(pp, msk, {"e1", "e2"}), ct2) == {"ME": b"data E", "MR": b"data R"}
    old_user = decrypt_all(pp, keygen(pp, msk, {"b1", "a1"}), ct2)
    assert old_user == {"MB": b"data B", "MA": b"data A", "MR": b"data R"}
    # The caller's original ciphertext is unaffected and still works.
    assert decrypt(pp, keygen(pp, msk, {"b1", "a1"}), ct, "MA") == b"data A"


def test_external_extension_and_gate_twice(system, encrypted):
    pp, msk = system
    ct, owner = encrypted
    ct2, owner2, _ = ex_extend(pp, ct, owner, 2, ["dept"], {"MR": b"R"}, name="MR")
    ct3, _, _ = ex_extend(pp, ct2, owner2, 2, ["hq", "vp"], {"MS": b"S"}, name="MS", old_root_index=2)
    sk = keygen(pp, msk, {"b1", "a1", "dept", "hq"})
    assert decrypt_all(pp, sk, ct3) == {"MB": b"data B", "MA": b"data A", "MR": b"R", "MS": b"S"}
    assert "MR" not in decrypt_all(pp, keygen(pp, msk, {"b1", "a1"}), ct3)


def test_internal_extension_case1_keeps_original_ciphertext(system, encrypted):
    pp, msk = system
    ct, owner = encrypted
    ct2, _, stats = in_extend(pp, ct, owner, "MC", Or("f1", "f2", name="MF"), {"MF": b"data F"})

    assert all(ct2.inner[u] == ct.inner[u] for u in ct.inner)
    assert all(ct2.leaf[u] == ct.leaf[u] for u in ct.leaf)
    assert stats.reencrypted_inner == stats.reencrypted_leaves == 0
    # MC is still 2-of-3 now: c1 plus the new branch unlocks it.
    assert decrypt_all(pp, keygen(pp, msk, {"c1", "f2"}), ct2) == {"MC": b"data C", "MF": b"data F"}
    assert decrypt_all(pp, keygen(pp, msk, {"c1", "c2"}), ct2) == {"MC": b"data C"}


def test_internal_extension_case2_updates_only_subtree(system, encrypted):
    pp, msk = system
    ct, owner = encrypted
    tree = ct.tree
    ct2, _, stats = in_extend(pp, ct, owner, "MB", "g1", {}, raise_threshold=True)

    uid = lambda name: tree.find(name).uid
    # MB itself and everything outside its subtree are untouched ...
    for name in ("MA", "MB", "MC"):
        assert ct2.inner[uid(name)] == ct.inner[uid(name)]
    for leaf in tree.find("MC").leaves() + [n for n in tree.children if n.is_leaf]:
        assert ct2.leaf[leaf.uid] == ct.leaf[leaf.uid]
    # ... while every node strictly below MB was re-encrypted.
    assert ct2.inner[uid("MD")] != ct.inner[uid("MD")]
    assert (stats.reencrypted_inner, stats.reencrypted_leaves, stats.new_leaves) == (1, 4, 1)

    # MB is now b1 AND ... i.e. 2-of-3 (b1, MD, g1).
    assert decrypt_all(pp, keygen(pp, msk, {"b1"}), ct2) == {}
    assert decrypt_all(pp, keygen(pp, msk, {"b1", "g1"}), ct2) == {"MB": b"data B"}
    assert decrypt_all(pp, keygen(pp, msk, {"d1", "d2", "d3", "g1", "a1"}), ct2) == \
        {"MD": b"data D", "MB": b"data B", "MA": b"data A"}


def test_owner_state_seal_roundtrip(system, encrypted):
    pp, msk = system
    ct, owner = encrypted
    key = os.urandom(32)
    restored = OwnerState.unseal(key, owner.seal(key))
    assert restored.polys == owner.polys and restored.keys == owner.keys
    ct2, _, _ = ex_extend(pp, ct, restored, 1, ["z"], {"MZ": b"Z"}, name="MZ")
    assert decrypt(pp, keygen(pp, msk, {"z"}), ct2, "MZ") == b"Z"


def test_out_of_gate_external_extension(system, encrypted):
    """2-of-3 new root: the old tree plus one new branch, or both new branches."""
    pp, msk = system
    ct, owner = encrypted
    ct2, _, stats = ex_extend(pp, ct, owner, 2, [And("e1", "e2", name="ME"), "f"],
                              {"ME": b"E", "MR": b"R"}, name="MR")
    assert all(ct2.inner[u] == ct.inner[u] for u in ct.inner)
    assert decrypt_all(pp, keygen(pp, msk, {"e1", "e2", "f"}), ct2) == {"ME": b"E", "MR": b"R"}
    assert decrypt_all(pp, keygen(pp, msk, {"b1", "a1", "f"}), ct2) == \
        {"MB": b"data B", "MA": b"data A", "MR": b"R"}
    assert "MR" not in decrypt_all(pp, keygen(pp, msk, {"b1", "a1"}), ct2)


def test_tampered_ciphertext_is_rejected(system, encrypted):
    """(E, D) is AES-GCM and K_x binds C1 and C2, so a modified component fails to decrypt."""
    pp, msk = system
    ct, _ = encrypted
    sk = keygen(pp, msk, {"c1", "c2"})
    uid = ct.tree.find("MC").uid
    c1, c2, c3 = ct.inner[uid]
    for bad in [(c1, c2, c3[:-1] + bytes([c3[-1] ^ 1])),
                (c1 * pp.egg, c2, c3)]:
        forged = type(ct)(tree=ct.tree, inner={**ct.inner, uid: bad}, leaf=ct.leaf)
        with pytest.raises(InvalidTag):
            decrypt(pp, sk, forged, "MC")


# ---- limitation of the paper's construction (see ehcpabe/analysis.py) -------------------

def test_limitation_or_parent_reveals_named_child(system, encrypted):
    """{b1} satisfies MB = b1 OR T_D but not T_D, yet recovers M_D (sigma_D = sigma_B)."""
    pp, msk = system
    ct, _ = encrypted
    sk = keygen(pp, msk, {"b1"})
    assert not ct.tree.find("MD").satisfied_by(sk.attrs)
    assert decrypt_child_via_parent(pp, sk, ct, "MB", "MD") == b"data D"


def test_limitation_threshold_parent_reveals_named_child(system, encrypted):
    """{b1, a1} satisfies MA = 2-of-(MB, MC, a1) but not MC, yet recovers M_C."""
    pp, msk = system
    ct, _ = encrypted
    sk = keygen(pp, msk, {"b1", "a1"})
    assert not ct.tree.find("MC").satisfied_by(sk.attrs)
    assert decrypt_child_via_parent(pp, sk, ct, "MA", "MC") == b"data C"


def test_limitation_extensions(system, encrypted):
    pp, msk = system
    ct, owner = encrypted
    # ExExtension with an OR root: a user of the new branch only recovers the original M_A.
    ct2, _, _ = ex_extend(pp, ct, owner, 1, [And("e1", "e2", name="ME")], {"ME": b"E", "MR": b"R"},
                          name="MR")
    sk = keygen(pp, msk, {"e1", "e2"})
    assert not ct2.tree.find("MA").satisfied_by(sk.attrs)
    assert decrypt_child_via_parent(pp, sk, ct2, "MR", "MA") == b"data A"
    # InExtension case 1: a user of the original T_C recovers the newly attached M_F.
    ct3, _, _ = in_extend(pp, ct, owner, "MC", And("f1", "f2", name="MF"), {"MF": b"F"})
    sk = keygen(pp, msk, {"c1", "c2"})
    assert not ct3.tree.find("MF").satisfied_by(sk.attrs)
    assert decrypt_child_via_parent(pp, sk, ct3, "MC", "MF") == b"F"


def test_limitation_absent_under_and_parents(system):
    """With AND parents only, satisfying a parent implies satisfying each child: nothing to leak."""
    pp, msk = system
    tree = And("taskX", Or("TeamA", "TeamB", name="M_A"), name="M_B")   # paper's Sect. I example
    assert leaking_nodes(tree) == []
    assert sorted(leaking_nodes(fig5_tree())) == ["MB", "MC", "MD"]
