"""Problem 1.4 — find X (the set of points equidistant from a, b, c) for n = 2."""

import numpy as np
import matplotlib.pyplot as plt


def bisector(p, q):
    """Bisector of p and q, returned as (normal, offset): the points x with

        normal . x = offset

    This is the equation from Problem 1.1, with normal = q - p and
    offset = (||q||^2 - ||p||^2) / 2.
    """
    return q - p, (q @ q - p @ p) / 2


def equidistant_point(a, b, c):
    """The point equidistant from a, b and c in R^2.

    X is the intersection of the bisector of (a, b) with the bisector of
    (b, c), i.e. the solution of a 2x2 linear system. The points are assumed
    distinct and not aligned, which makes the two normals independent, so the
    system has exactly one solution and X = {x}.
    """
    n1, o1 = bisector(a, b)
    n2, o2 = bisector(b, c)
    return np.linalg.solve(np.array([n1, n2]), np.array([o1, o2]))


def bisector_segment(p, q, half_length):
    """A long segment along the bisector of p and q, for plotting.

    The bisector runs through the midpoint, perpendicular to q - p. Rotating
    q - p by 90 degrees gives that direction; the segment is drawn far past
    the axis limits and matplotlib clips it.
    """
    midpoint = (p + q) / 2
    d = q - p
    direction = np.array([-d[1], d[0]])
    direction = direction / np.linalg.norm(direction)
    return np.array([midpoint - half_length * direction,
                     midpoint + half_length * direction])


if __name__ == "__main__":
    a = np.array([1.0, 0.0])
    b = np.array([3.0, 1.0])
    c = np.array([3.0, 4.0])

    x = equidistant_point(a, b, c)

    fig, ax = plt.subplots(figsize=(6, 7))

    # Triangle perimeter and the points themselves, in black.
    perimeter = np.array([a, b, c, a])
    ax.plot(perimeter[:, 0], perimeter[:, 1], color="black", linewidth=1.8)
    ax.scatter(*np.array([a, b, c]).T, color="black", s=70, zorder=5)

    # The three pairwise bisectors and midpoints, in blue.
    for p, q in ((a, b), (b, c), (a, c)):
        segment = bisector_segment(p, q, half_length=20.0)
        ax.plot(segment[:, 0], segment[:, 1], color="tab:blue", linewidth=1.3)
        ax.scatter(*(p + q) / 2, color="tab:blue", s=55, zorder=5)

    # X, in red. All three bisectors meet here.
    ax.scatter(*x, color="red", s=110, zorder=6)

    # Frame the triangle and X, with room to see the bisectors crossing.
    corners = np.array([a, b, c, x])
    lo = corners.min(axis=0) - 1.6
    hi = corners.max(axis=0) + 1.6
    ax.set_xlim(lo[0], hi[0])
    ax.set_ylim(lo[1], hi[1])
    ax.set_aspect("equal", adjustable="box")

    print("X =", x)
    for name, p in (("a", a), ("b", b), ("c", c)):
        print(f"  distance to {name}: {np.linalg.norm(x - p):.6f}")

    fig.savefig("bisectors.png", dpi=150, bbox_inches="tight")
    plt.show()
