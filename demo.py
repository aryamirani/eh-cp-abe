"""One access policy, four users -- the Part 1 demo.

    python demo.py
"""

from cryptography.exceptions import InvalidTag

from ehcpabe import And, NotAuthorized, Or, SecretKey, decrypt, encrypt, keygen, setup, to_string


def main():
    pp, msk = setup()
    tree = And("taskX", Or("TeamA", "TeamB"), name="M")
    ct, _ = encrypt(pp, tree, {"M": b"project plan"})
    print(f"policy: {to_string(tree)}   ciphertext: {ct.size_bytes()} bytes\n")

    for attrs in ({"TeamB", "taskX"}, {"TeamA", "taskX"}, {"TeamA"}):
        try:
            result = decrypt(pp, keygen(pp, msk, attrs), ct, "M")
        except NotAuthorized:
            result = "refused (policy not satisfied)"
        print(f"  {str(sorted(attrs)):<24} -> {result}")

    # Two users who each hold half the policy pool their key components.
    x, y = keygen(pp, msk, {"taskX"}), keygen(pp, msk, {"TeamA"})
    pooled = SecretKey(attrs=frozenset({"taskX", "TeamA"}), D=x.D, comps={**x.comps, **y.comps})
    try:
        decrypt(pp, pooled, ct, "M")
        print("  colluding users         -> decrypted (unexpected!)")
    except InvalidTag:
        print("  colluding users         -> fails (collusion resistance)")


if __name__ == "__main__":
    main()
