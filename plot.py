"""Draws results/*.csv (written by bench.py) as the paper's Figs. 8-15.

    .venv/bin/pip install matplotlib
    .venv/bin/python plot.py        # -> results/fig*.png
"""

import csv
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import MaxNLocator  # noqa: E402

RES = "results"
# Categorical slots in fixed order (validated colour-blind-safe for adjacent series).
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
MARKERS = ["o", "s", "^", "D"]       # second encoding, so series survive greyscale printing
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9, "axes.titlesize": 10,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.8, "legend.frameon": False,
})


def load(name):
    with open(os.path.join(RES, name)) as f:
        rows = list(csv.reader(f))
    header, data = rows[0], rows[1:]
    return {h: [float(r[i]) for r in data] for i, h in enumerate(header)}


def lines(ax, x, series, xlabel, title):
    for i, (label, ys) in enumerate(series):
        ax.plot(x, ys, color=COLORS[i], marker=MARKERS[i], markersize=4.5, linewidth=1.8, label=label)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("time (s)")
    ax.set_title(title, loc="left", color=INK)
    ax.set_ylim(bottom=0)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))


def legend(fig, ax, ncol):
    """One legend for the figure, in a row under the plots, so it never covers a line."""
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=ncol, bbox_to_anchor=(0.5, 0))


def save(fig, name):
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    fig.savefig(os.path.join(RES, name), dpi=200)
    plt.close(fig)
    print("wrote", os.path.join(RES, name))


def main():
    d = load("keygen_encrypt_decrypt.csv")
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    lines(ax, d["attributes"], [("KeyGen", d["keygen"]), ("Encrypt", d["encrypt"]),
                                ("Decrypt", d["decrypt"])],
          "number of attributes", "KeyGen / Encrypt / Decrypt (cf. Figs. 8-10)")
    legend(fig, ax, 3)
    save(fig, "fig8_10_keygen_encrypt_decrypt.png")

    fig, axes = plt.subplots(1, 2, figsize=(8.4, 3.4))
    for ax, fname, label in [(axes[0], "hierarchical_vs_separate.csv", "300 KB files"),
                             (axes[1], "hierarchical_vs_separate_big.csv", "30 MB files")]:
        if not os.path.exists(os.path.join(RES, fname)):
            continue
        d = load(fname)
        lines(ax, d["files"], [("separate", d["separate"]), ("hierarchical", d["hierarchical"])],
              "number of files", f"Hierarchical vs separate, {label}")
    legend(fig, axes[0], 2)
    save(fig, "fig11_hierarchical_vs_separate.png")

    fig, axes = plt.subplots(1, 2, figsize=(8.4, 3.6))
    for ax, fname, xcol, xlabel, title in [
            (axes[0], "extension_vs_files.csv", "files added", "number of files added", "(a) vs files added"),
            (axes[1], "extension_vs_attrs.csv", "added attrs", "number of attributes added",
             "(b) vs attributes added")]:
        d = load(fname)
        lines(ax, d[xcol], [("no extension", d["no extension"]), ("external", d["external"]),
                            ("internal case 1", d["internal case 1"]),
                            ("internal case 2", d["internal case 2"])], xlabel, title)
    legend(fig, axes[0], 4)
    save(fig, "fig12_14_extension.png")

    d = load("internal_case2.csv")
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    lines(ax, d["attrs under C"], [("no extension", d["no extension"]),
                                   ("internal case 2", d["internal case 2"])],
          "original attributes under the extended node", "Internal extension case 2 (cf. Fig. 15)")
    legend(fig, ax, 2)
    save(fig, "fig15_internal_case2.png")


if __name__ == "__main__":
    main()
