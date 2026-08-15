"""Polynomials in R_q = Z_q[X] / (X^N + 1).

A Poly is a length-N list of coefficients, each kept canonical in [0, Q).
Multiplication is the schoolbook negacyclic convolution: because X^N = -1 in
this ring, any product term landing at degree >= N wraps back down with a sign
flip. This schoolbook multiply is slow but obviously correct, and serves as the
oracle that the NTT-based multiply (Week 2) must agree with.
"""

import random

from .params import N, Q


class Poly:
    __slots__ = ("coeffs",)

    def __init__(self, coeffs=None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            if len(coeffs) != N:
                raise ValueError(f"expected {N} coefficients, got {len(coeffs)}")
            self.coeffs = [c % Q for c in coeffs]

    # -- constructors ------------------------------------------------------

    @classmethod
    def zero(cls):
        return cls()

    @classmethod
    def constant(cls, c):
        p = cls()
        p.coeffs[0] = c % Q
        return p

    @classmethod
    def random(cls, rng=random):
        return cls([rng.randrange(Q) for _ in range(N)])

    # -- arithmetic --------------------------------------------------------

    def __add__(self, other):
        return Poly([(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __sub__(self, other):
        return Poly([(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __neg__(self):
        return Poly([(-a) % Q for a in self.coeffs])

    def __mul__(self, other):
        """Schoolbook multiplication in R_q (negacyclic convolution)."""
        res = [0] * N
        a, b = self.coeffs, other.coeffs
        for i in range(N):
            ai = a[i]
            if ai == 0:
                continue
            for j in range(N):
                prod = ai * b[j]
                k = i + j
                if k < N:
                    res[k] = (res[k] + prod) % Q
                else:  # X^N = -1  ->  degree k folds to k-N with a sign flip
                    res[k - N] = (res[k - N] - prod) % Q
        return Poly(res)

    # -- misc --------------------------------------------------------------

    def __eq__(self, other):
        return isinstance(other, Poly) and self.coeffs == other.coeffs

    def __repr__(self):
        return f"Poly({self.coeffs})"
