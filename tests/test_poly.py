import random
import unittest

from kyber.params import N, Q
from kyber.poly import Poly


def reference_mul(a, b):
    """Independent oracle for the negacyclic product.

    Structurally different from Poly.__mul__: build the full length-(2N-1)
    convolution first with no reduction, then fold X^N = -1 in a second pass.
    If this and Poly.__mul__ agree on random inputs, the wraparound logic is
    almost certainly right. In Week 2 the NTT multiply becomes a third method
    that must also agree here.
    """
    conv = [0] * (2 * N - 1)
    for i in range(N):
        for j in range(N):
            conv[i + j] += a.coeffs[i] * b.coeffs[j]
    res = [0] * N
    for k in range(2 * N - 1):
        if k < N:
            res[k] += conv[k]
        else:
            res[k - N] -= conv[k]
    return Poly([c % Q for c in res])


class TestAddSub(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(0)

    def test_add_commutes(self):
        for _ in range(200):
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            self.assertEqual(a + b, b + a)

    def test_sub_is_add_inverse(self):
        for _ in range(200):
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            self.assertEqual((a + b) - b, a)

    def test_neg(self):
        for _ in range(200):
            a = Poly.random(self.rng)
            self.assertEqual(a + (-a), Poly.zero())


class TestMul(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(42)

    def test_matches_reference_oracle(self):
        for _ in range(300):
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            self.assertEqual(a * b, reference_mul(a, b))

    def test_identity(self):
        one = Poly.constant(1)
        for _ in range(100):
            a = Poly.random(self.rng)
            self.assertEqual(a * one, a)

    def test_mul_by_x_shifts_and_wraps(self):
        # Multiplying by X shifts coefficients up one degree; the top
        # coefficient wraps to the constant term negated (since X^N = -1).
        x = Poly()
        x.coeffs[1] = 1
        for _ in range(100):
            a = Poly.random(self.rng)
            expected = Poly([0] * N)
            for i in range(N - 1):
                expected.coeffs[i + 1] = a.coeffs[i]
            expected.coeffs[0] = (-a.coeffs[N - 1]) % Q
            self.assertEqual(a * x, expected)

    def test_commutes(self):
        for _ in range(100):
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            self.assertEqual(a * b, b * a)

    def test_distributes_over_add(self):
        for _ in range(100):
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            c = Poly.random(self.rng)
            self.assertEqual(a * (b + c), a * b + a * c)

    def test_associative(self):
        for _ in range(20):  # slow: schoolbook is O(N^2)
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            c = Poly.random(self.rng)
            self.assertEqual((a * b) * c, a * (b * c))


if __name__ == "__main__":
    unittest.main()
