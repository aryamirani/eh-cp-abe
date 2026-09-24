# Benchmark results — Part 1

KeyGen / Encrypt / Decrypt vs number of attributes (paper Sect. VI, Figs. 8 and 10).
Apple M1, Python 3.14, py_ecc on BLS12-381, AES-256-GCM, 300 KB payload, mean of 3 runs.
Reproduce with `python bench.py`; raw numbers in `results/keygen_encrypt_decrypt.csv`.

| attributes | keygen (s) | encrypt (s) | decrypt (s) |
|---|---|---|---|
| 10 | 0.347 | 0.357 | 0.845 |
| 20 | 0.643 | 0.647 | 1.509 |
| 30 | 0.954 | 0.961 | 2.208 |
| 40 | 1.241 | 1.278 | 2.951 |
| 50 | 1.538 | 1.547 | 3.621 |

**Expected (paper):** all three grow linearly with the number of attributes; decryption
≈ 1.1 s at 100 attributes (Java JPBC, 160-bit Type-A curve).

**Obtained:** linear, as expected — ≈ 30 ms per attribute for KeyGen and Encrypt and
≈ 69 ms per attribute for Decrypt. Absolute times are higher because the arithmetic is
pure Python on a larger curve (≈ 128-bit security).
