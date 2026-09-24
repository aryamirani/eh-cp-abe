import pytest
from cryptography.exceptions import InvalidTag

from ehcpabe import And, NotAuthorized, Or, SecretKey, Threshold, decrypt, encrypt, keygen, setup
from ehcpabe.group import ORDER
from ehcpabe.policy import Attr
from ehcpabe.scheme import _poly_eval, _random_poly, lagrange_at_zero

MSG = b"project plan"


@pytest.fixture(scope="module")
def system():
    return setup()


def policy():
    """The paper's motivating policy: taskX AND (TeamA OR TeamB)."""
    return And("taskX", Or("TeamA", "TeamB"), name="M")


@pytest.fixture(scope="module")
def encrypted(system):
    pp, _ = system
    ct, _ = encrypt(pp, policy(), {"M": MSG})
    return ct


def test_lagrange_recovers_constant_term():
    q = _random_poly(123456789, 3)
    S = [1, 3, 4, 7]
    assert sum(lagrange_at_zero(i, S) * _poly_eval(q, i) for i in S) % ORDER == 123456789


@pytest.mark.parametrize("attrs", [{"TeamB", "taskX"}, {"TeamA", "taskX"}, {"TeamA", "TeamB", "taskX", "extra"}])
def test_authorised_users_decrypt(system, encrypted, attrs):
    pp, msk = system
    assert decrypt(pp, keygen(pp, msk, attrs), encrypted, "M") == MSG


@pytest.mark.parametrize("attrs", [{"TeamA"}, {"taskX"}, {"TeamC", "taskX"}, set()])
def test_unauthorised_users_refused(system, encrypted, attrs):
    pp, msk = system
    with pytest.raises(NotAuthorized):
        decrypt(pp, keygen(pp, msk, attrs), encrypted, "M")


def test_collusion_resistance(system, encrypted):
    """A {taskX} user and a {TeamA} user cannot pool their key components."""
    pp, msk = system
    x, y = keygen(pp, msk, {"taskX"}), keygen(pp, msk, {"TeamA"})
    pooled = SecretKey(attrs=frozenset({"taskX", "TeamA"}), D=x.D, comps={**x.comps, **y.comps})
    with pytest.raises(InvalidTag):
        decrypt(pp, pooled, encrypted, "M")


def test_threshold_gate(system):
    pp, msk = system
    ct, _ = encrypt(pp, Threshold(2, "a", "b", "c", name="M"), {"M": MSG})
    for attrs in ({"a", "b"}, {"a", "c"}, {"b", "c"}):
        assert decrypt(pp, keygen(pp, msk, attrs), ct, "M") == MSG
    with pytest.raises(NotAuthorized):
        decrypt(pp, keygen(pp, msk, {"c"}), ct, "M")


def test_nested_gates(system):
    pp, msk = system
    tree = Threshold(2, And("d1", "d2"), Or("e1", "e2"), "f", name="M")
    ct, _ = encrypt(pp, tree, {"M": MSG})
    assert decrypt(pp, keygen(pp, msk, {"d1", "d2", "e2"}), ct, "M") == MSG
    assert decrypt(pp, keygen(pp, msk, {"e1", "f"}), ct, "M") == MSG
    with pytest.raises(NotAuthorized):
        decrypt(pp, keygen(pp, msk, {"d1", "f"}), ct, "M")


def test_input_validation(system):
    pp, _ = system
    with pytest.raises(ValueError):                       # message name must match the root
        encrypt(pp, policy(), {"other": MSG})
    with pytest.raises(ValueError):                       # only the root carries data in Part 1
        encrypt(pp, And("x", Or("y", "z", name="inner"), name="M"), {"M": MSG})
    with pytest.raises(ValueError):                       # threshold out of range
        Threshold(3, "a", "b")
    with pytest.raises(ValueError):                       # a bare attribute is not a policy
        encrypt(pp, Attr("a"), {"M": MSG})
