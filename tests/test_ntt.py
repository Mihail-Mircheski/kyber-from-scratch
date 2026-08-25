import random
import unittest

from kyber.params import N, Q
from kyber.poly import Poly
from kyber.polyvec import PolyVec, PolyMat
from kyber.ntt import ntt, invntt, ntt_mul, ntt_matvec


class TestNTTMul(unittest.TestCase):
    """The Week 2 gate: the NTT multiply must equal the schoolbook oracle."""

    def setUp(self):
        self.rng = random.Random(2024)

    def test_matches_schoolbook(self):
        for _ in range(200):
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            self.assertEqual(ntt_mul(a, b), a * b)

    def test_identity(self):
        one = Poly.constant(1)
        for _ in range(50):
            a = Poly.random(self.rng)
            self.assertEqual(ntt_mul(a, one), a)

    def test_zero(self):
        z = Poly.zero()
        for _ in range(50):
            a = Poly.random(self.rng)
            self.assertEqual(ntt_mul(a, z), z)

    def test_mul_by_x(self):
        x = Poly()
        x.coeffs[1] = 1
        for _ in range(50):
            a = Poly.random(self.rng)
            self.assertEqual(ntt_mul(a, x), a * x)

    def test_commutes(self):
        for _ in range(50):
            a = Poly.random(self.rng)
            b = Poly.random(self.rng)
            self.assertEqual(ntt_mul(a, b), ntt_mul(b, a))


class TestNTTRoundtrip(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(99)

    def test_forward_then_inverse_recovers_scaled(self):
        # invntt is the "to Montgomery" inverse, so invntt(ntt(f)) == f * R
        # (i.e. each coefficient times 2^16 mod q). Verifying this pins the
        # Montgomery bookkeeping independently of the multiply path.
        R = (1 << 16) % Q
        for _ in range(50):
            f = Poly.random(self.rng)
            back = Poly(invntt(ntt(f.coeffs)))
            expected = Poly([(c * R) % Q for c in f.coeffs])
            self.assertEqual(back, expected)


class TestModuleGate(unittest.TestCase):
    """Timeline deliverable: A . s in the NTT domain matches the naive result."""

    def setUp(self):
        self.rng = random.Random(7)

    def test_matvec_matches_schoolbook(self):
        for k in (2, 3, 4):
            A = PolyMat.random(k, self.rng)
            s = PolyVec.random(k, self.rng)
            self.assertEqual(ntt_matvec(A, s), A.mul_vec(s))


if __name__ == "__main__":
    unittest.main()
