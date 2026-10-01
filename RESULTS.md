# Benchmark results (this machine: Apple M1, 2026-09-24)

`.venv/bin/python bench.py` — CSVs in `results/`.


### KeyGen / Encrypt / Decrypt vs #attributes (s)

| attributes | keygen | encrypt | decrypt |
|---|---|---|---|
| 10 | 0.347 | 0.357 | 0.845 |
| 20 | 0.643 | 0.647 | 1.509 |
| 30 | 0.954 | 0.961 | 2.208 |
| 40 | 1.241 | 1.278 | 2.951 |
| 50 | 1.538 | 1.547 | 3.621 |

### Hierarchical vs separate encryption (5 attributes per level, 300 KB files) (s)

| files | attributes | separate | hierarchical |
|---|---|---|---|
| 1 | 5 | 0.201 | 0.217 |
| 2 | 10 | 0.550 | 0.403 |
| 3 | 15 | 1.053 | 0.603 |
| 4 | 20 | 1.731 | 0.806 |
| 5 | 25 | 2.534 | 1.012 |
| 6 | 30 | 3.452 | 1.223 |
| 7 | 35 | 4.543 | 1.426 |
| 8 | 40 | 5.784 | 1.643 |
| 9 | 45 | 7.198 | 1.821 |
| 10 | 50 | 8.769 | 2.049 |

### Extension vs re-encrypting from scratch (original policy: 20 attributes) (s)

| original attrs | added attrs | from scratch | external ext. | internal ext. case 1 |
|---|---|---|---|---|
| 20 | 10 | 1.061 | 0.405 | 0.353 |
| 20 | 20 | 1.384 | 0.703 | 0.652 |
| 20 | 30 | 1.656 | 1.006 | 0.945 |
| 20 | 40 | 2.065 | 1.322 | 1.289 |
| 20 | 50 | 2.266 | 1.650 | 1.557 |

### Internal extension case 2 vs full re-encryption (50 attributes in total) (s)

| total attrs | attrs under C | leaves re-encrypted | case 2 | full re-encrypt |
|---|---|---|---|---|
| 50 | 10 | 10 | 0.331 | 1.634 |
| 50 | 20 | 20 | 0.632 | 1.637 |
| 50 | 30 | 30 | 0.928 | 1.635 |
| 50 | 40 | 40 | 1.240 | 1.629 |
| 50 | 50 | 50 | 1.538 | 1.629 |
