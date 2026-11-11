# Benchmark results (Apple M1, 8 GB, Python 3.15, 2026-11-11)

`.venv/bin/python bench.py` then `.venv/bin/python plot.py`. CSVs and figures (`fig*.png`) are in `results/`.
Each point is the mean of 3 runs (the paper averages 1000), so single points are noisy; read the trends.


### Figs. 8-10: KeyGen / Encrypt / Decrypt vs #attributes (s)

| attributes | keygen | encrypt | decrypt |
|---|---|---|---|
| 10 | 0.376 | 0.420 | 1.123 |
| 20 | 1.428 | 1.203 | 2.222 |
| 30 | 1.342 | 1.198 | 2.552 |
| 40 | 1.342 | 1.515 | 3.317 |
| 50 | 1.697 | 1.613 | 4.038 |
| 60 | 1.953 | 2.157 | 4.819 |
| 70 | 2.691 | 2.236 | 5.915 |
| 80 | 2.794 | 2.658 | 6.519 |
| 90 | 2.978 | 3.119 | 7.738 |
| 100 | 3.391 | 3.150 | 9.174 |

### Fig. 11: hierarchical vs separate encryption (5 attributes per level, 300 KB files) (s)

| files | attributes | separate | hierarchical |
|---|---|---|---|
| 1 | 5 | 0.240 | 0.248 |
| 2 | 10 | 0.570 | 0.418 |
| 3 | 15 | 1.286 | 0.634 |
| 4 | 20 | 1.827 | 1.070 |
| 5 | 25 | 2.696 | 1.086 |
| 6 | 30 | 3.663 | 1.427 |
| 7 | 35 | 4.901 | 1.513 |
| 8 | 40 | 6.738 | 2.316 |
| 9 | 45 | 8.927 | 2.214 |
| 10 | 50 | 9.656 | 2.169 |

### Fig. 11: hierarchical vs separate encryption (5 attributes per level, 30 MB files) (s)

| files | attributes | separate | hierarchical |
|---|---|---|---|
| 1 | 5 | 0.231 | 0.228 |
| 2 | 10 | 0.617 | 0.451 |
| 3 | 15 | 1.138 | 0.668 |
| 4 | 20 | 2.100 | 0.919 |
| 5 | 25 | 2.691 | 1.106 |
| 6 | 30 | 3.847 | 1.359 |
| 7 | 35 | 4.855 | 1.535 |
| 8 | 40 | 6.942 | 1.702 |
| 9 | 45 | 9.224 | 2.445 |
| 10 | 50 | 9.573 | 2.501 |

### Figs. 12a-14a: extension vs #files added (50-attribute original policy, 20 added attributes) (s)

| files added | added attrs | no extension | external | internal case 1 | internal case 2 |
|---|---|---|---|---|---|
| 1 | 20 | 2.594 | 0.740 | 0.793 | 1.019 |
| 2 | 20 | 2.456 | 0.854 | 0.789 | 1.221 |
| 3 | 20 | 2.770 | 0.851 | 0.788 | 1.131 |
| 4 | 20 | 2.837 | 0.989 | 0.932 | 1.233 |
| 5 | 20 | 2.941 | 1.066 | 0.996 | 1.500 |
| 6 | 20 | 2.923 | 1.045 | 0.993 | 1.427 |
| 7 | 20 | 2.800 | 1.254 | 1.210 | 1.504 |
| 8 | 20 | 2.910 | 1.204 | 1.167 | 1.500 |
| 9 | 20 | 2.936 | 1.250 | 1.169 | 1.468 |
| 10 | 20 | 3.317 | 1.310 | 1.248 | 1.537 |

### Figs. 12b-14b: extension vs #attributes added (50-attribute original policy, one file added) (s)

| original attrs | added attrs | no extension | external | internal case 1 | internal case 2 |
|---|---|---|---|---|---|
| 50 | 10 | 2.044 | 0.455 | 0.425 | 0.754 |
| 50 | 20 | 2.390 | 0.725 | 0.667 | 1.002 |
| 50 | 30 | 2.642 | 1.053 | 1.000 | 1.291 |
| 50 | 40 | 2.906 | 1.326 | 1.276 | 1.565 |
| 50 | 50 | 3.292 | 1.622 | 1.563 | 1.883 |
| 50 | 60 | 3.514 | 1.951 | 1.906 | 2.244 |
| 50 | 70 | 3.950 | 2.278 | 2.215 | 2.530 |
| 50 | 80 | 4.142 | 2.554 | 2.578 | 2.842 |
| 50 | 90 | 5.080 | 3.183 | 3.033 | 3.699 |
| 50 | 100 | 4.780 | 3.203 | 3.277 | 3.478 |

### Fig. 15: internal extension case 2 vs #attributes updated (100 original + 10 added attributes) (s)

| original attrs | attrs under C | leaves re-encrypted | internal case 2 | no extension |
|---|---|---|---|---|
| 100 | 10 | 10 | 0.913 | 3.537 |
| 100 | 20 | 20 | 0.972 | 3.495 |
| 100 | 30 | 30 | 1.267 | 3.627 |
| 100 | 40 | 40 | 1.598 | 3.825 |
| 100 | 50 | 50 | 1.969 | 3.659 |
| 100 | 60 | 60 | 2.174 | 3.695 |
| 100 | 70 | 70 | 2.903 | 3.573 |
| 100 | 80 | 80 | 2.823 | 3.542 |
| 100 | 90 | 90 | 3.085 | 3.539 |
| 100 | 100 | 100 | 3.380 | 3.478 |
