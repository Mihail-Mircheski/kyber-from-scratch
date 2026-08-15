import unittest

from kyber.params import Q
from kyber.reduce import (
    mod_plus,
    mod_pm,
    barrett_reduce,
    montgomery_reduce,
    fqmul,
)

R = 1 << 16  # Montgomery factor


class TestRepresentatives(unittest.TestCase):
    def test_mod_plus_range(self):
        for a in range(-5 * Q, 5 * Q):
            r = mod_plus(a)
            self.assertTrue(0 <= r < Q)
            self.assertEqual((r - a) % Q, 0)

    def test_mod_pm_odd_range(self):
        lo, hi = -(Q - 1) // 2, (Q - 1) // 2
        for a in range(-5 * Q, 5 * Q):
            r = mod_pm(a)
            self.assertTrue(lo <= r <= hi)
            self.assertEqual((r - a) % Q, 0)

    def test_mod_pm_even_alpha(self):
        alpha = 16
        for a in range(-100, 100):
            r = mod_pm(a, alpha)
            self.assertTrue(-alpha // 2 < r <= alpha // 2)
            self.assertEqual((r - a) % alpha, 0)


class TestBarrett(unittest.TestCase):
    def test_congruent_over_int16(self):
        for a in range(-32768, 32768):
            r = barrett_reduce(a)
            self.assertEqual((r - a) % Q, 0)
            self.assertTrue(abs(r) < Q)


class TestMontgomery(unittest.TestCase):
    def test_congruent(self):
        # Valid input domain: |a| < Q * 2^15.
        for a in range(-Q * (1 << 15), Q * (1 << 15), 4099):
            r = montgomery_reduce(a)
            # r == a * R^{-1} (mod Q)  <=>  r * R == a (mod Q)
            self.assertEqual((r * R - a) % Q, 0)
            self.assertTrue(abs(r) < Q)

    def test_fqmul_matches_direct(self):
        import random
        rng = random.Random(1)
        for _ in range(5000):
            a = rng.randrange(Q)
            b = rng.randrange(Q)
            r = fqmul(a, b)
            self.assertEqual((r * R - a * b) % Q, 0)


if __name__ == "__main__":
    unittest.main()
