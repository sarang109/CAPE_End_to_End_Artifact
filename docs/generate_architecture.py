from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


OUT = Path(__file__).with_name("cape_operational_testbed.png")

fig, ax = plt.subplots(figsize=(11, 4.8), dpi=220)
ax.set_xlim(0, 11)
ax.set_ylim(0, 4.8)
ax.axis("off")


def box(x, y, w, h, text, face, edge="#24364B"):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.05,rounding_size=0.09",
        linewidth=1.4,
        edgecolor=edge,
        facecolor=face,
    )
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=10)


def arrow(x1, y1, x2, y2):
    ax.add_patch(
        FancyArrowPatch(
            (x1, y1),
            (x2, y2),
            arrowstyle="-|>",
            mutation_scale=13,
            linewidth=1.3,
            color="#44546A",
        )
    )


box(0.25, 2.95, 2.0, 0.9, "Manipulated or\nbenign agent proposal", "#EAF2F8")
box(2.85, 2.95, 2.0, 0.9, "Official AP2 SDK\nmandate verification", "#D9EAF7")
box(5.45, 2.95, 2.0, 0.9, "CAPE gateway\nCWR or DFMR", "#DDEBF7", "#17365D")
box(8.05, 2.95, 2.4, 0.9, "Idempotent local\npayment sandbox", "#E2F0D9", "#375623")

arrow(2.25, 3.4, 2.85, 3.4)
arrow(4.85, 3.4, 5.45, 3.4)
arrow(7.45, 3.4, 8.05, 3.4)

box(1.2, 0.75, 2.1, 0.85, "Merchant-derived\nevidence services", "#FCE4D6", "#843C0C")
box(4.1, 0.75, 2.1, 0.85, "Independent signed\nevidence services", "#FFF2CC", "#7F6000")
box(7.0, 0.75, 2.1, 0.85, "Trusted version and\nprovenance registry", "#E4DFEC", "#4F3B66")

arrow(2.25, 1.6, 6.0, 2.95)
arrow(5.15, 1.6, 6.25, 2.95)
arrow(8.05, 1.6, 6.75, 2.95)

ax.text(
    9.25,
    2.25,
    "Bound versions\nand cart digest",
    ha="center",
    va="center",
    fontsize=9,
    color="#375623",
)
arrow(7.25, 2.85, 8.3, 2.05)

fig.tight_layout(pad=0.4)
fig.savefig(OUT, bbox_inches="tight", facecolor="white")
print(OUT)
