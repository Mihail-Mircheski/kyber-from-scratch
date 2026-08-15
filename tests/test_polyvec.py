import random
import unittest

from kyber.poly import Poly
from kyber.polyvec import PolyVec, PolyMat


class TestPolyVec(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(7)

    def test_add_sub_roundtrip(self):
        for k in (2, 3, 4):
            u = PolyVec.random(k, self.rng)
            v = PolyVec.random(k, self.rng)
            self.assertEqual((u + v) - v, u)

    def test_dot_is_bilinear(self):
        # (u + w) . v  ==  u.v + w.v
        for k in (2, 3, 4):
            u = PolyVec.random(k, self.rng)
            w = PolyVec.random(k, self.rng)
            v = PolyVec.random(k, self.rng)
            self.assertEqual((u + w).dot(v), u.dot(v) + w.dot(v))

    def test_dot_matches_manual(self):
        for k in (2, 3, 4):
            u = PolyVec.random(k, self.rng)
            v = PolyVec.random(k, self.rng)
            acc = Poly.zero()
            for i in range(k):
                acc = acc + u[i] * v[i]
            self.assertEqual(u.dot(v), acc)


class TestPolyMat(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(11)

    def test_mul_vec_matches_manual(self):
        for k in (2, 3, 4):
            A = PolyMat.random(k, self.rng)
            v = PolyVec.random(k, self.rng)
            result = A.mul_vec(v)
            for i in range(k):
                expected = Poly.zero()
                for j in range(k):
                    expected = expected + A.rows[i][j] * v[j]
                self.assertEqual(result[i], expected)

    def test_distributes_over_vec_add(self):
        # A(u + v) == A u + A v
        for k in (2, 3, 4):
            A = PolyMat.random(k, self.rng)
            u = PolyVec.random(k, self.rng)
            v = PolyVec.random(k, self.rng)
            self.assertEqual(A.mul_vec(u + v), A.mul_vec(u) + A.mul_vec(v))


if __name__ == "__main__":
    unittest.main()
