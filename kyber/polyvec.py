"""Vectors and matrices of polynomials over R_q.

Kyber works with a module of rank k (2, 3, or 4 depending on the parameter
set). Key generation and encryption need:

  - vector add / sub
  - the inner (dot) product of two vectors  -> a single Poly
  - matrix-by-vector multiply                -> a PolyVec

All products go through Poly.__mul__ (schoolbook) for now; the NTT speedup
slots in later without changing this interface.
"""

from .poly import Poly


class PolyVec:
    __slots__ = ("polys",)

    def __init__(self, polys):
        self.polys = list(polys)

    @property
    def k(self):
        return len(self.polys)

    @classmethod
    def zero(cls, k):
        return cls([Poly.zero() for _ in range(k)])

    @classmethod
    def random(cls, k, rng=None):
        import random as _random
        rng = rng or _random
        return cls([Poly.random(rng) for _ in range(k)])

    def __add__(self, other):
        self._check(other)
        return PolyVec([a + b for a, b in zip(self.polys, other.polys)])

    def __sub__(self, other):
        self._check(other)
        return PolyVec([a - b for a, b in zip(self.polys, other.polys)])

    def dot(self, other):
        """Inner product: sum_i self[i] * other[i], returning one Poly."""
        self._check(other)
        acc = Poly.zero()
        for a, b in zip(self.polys, other.polys):
            acc = acc + a * b
        return acc

    def _check(self, other):
        if self.k != other.k:
            raise ValueError(f"length mismatch: {self.k} vs {other.k}")

    def __eq__(self, other):
        return isinstance(other, PolyVec) and self.polys == other.polys

    def __len__(self):
        return len(self.polys)

    def __getitem__(self, i):
        return self.polys[i]


class PolyMat:
    """A k-by-k matrix of polynomials, stored row-major."""

    __slots__ = ("rows",)

    def __init__(self, rows):
        self.rows = [list(r) for r in rows]

    @property
    def k(self):
        return len(self.rows)

    @classmethod
    def random(cls, k, rng=None):
        import random as _random
        rng = rng or _random
        return cls([[Poly.random(rng) for _ in range(k)] for _ in range(k)])

    def mul_vec(self, vec):
        """Matrix-vector product: (A @ vec)[i] = sum_j A[i][j] * vec[j]."""
        if self.k != vec.k:
            raise ValueError(f"shape mismatch: {self.k} vs {vec.k}")
        out = []
        for row in self.rows:
            acc = Poly.zero()
            for a_ij, v_j in zip(row, vec.polys):
                acc = acc + a_ij * v_j
            out.append(acc)
        return PolyVec(out)
