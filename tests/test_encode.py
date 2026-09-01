import random
import unittest

from kyber.params import N, Q
from kyber.reduce import mod_pm
from kyber.poly import Poly
from kyber.polyvec import PolyVec
from kyber.encode import (
    compress,
    decompress,
    byte_encode,
    byte_decode,
    poly_tobytes,
    poly_frombytes,
    poly_compress,
    poly_decompress,
    polyvec_tobytes,
    polyvec_frombytes,
    polyvec_compress,
    polyvec_decompress,
)

# Compression widths that actually occur across the parameter sets.
DS = (4, 5, 10, 11)


def error_bound(d):
    """Spec eq. (2): |Decompress(Compress(x)) - x| <= round(q / 2^(d+1))."""
    return (Q + (1 << d)) >> (d + 1)


class TestCompress(unittest.TestCase):
    def test_output_range(self):
        for d in DS:
            for x in range(Q):
                y = compress(x, d)
                self.assertTrue(0 <= y < (1 << d))

    def test_error_within_bound(self):
        for d in DS:
            bound = error_bound(d)
            for x in range(Q):
                back = decompress(compress(x, d), d)
                err = abs(mod_pm(back - x))
                self.assertLessEqual(err, bound)


class TestByteEncode(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(3)

    def test_roundtrip_identity(self):
        for d in range(1, 13):
            coeffs = [self.rng.randrange(1 << d) for _ in range(N)]
            data = byte_encode(coeffs, d)
            self.assertEqual(len(data), 32 * d)
            self.assertEqual(byte_decode(data, d), coeffs)


class TestPolySerialize(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(11)

    def test_tobytes_roundtrip(self):
        for _ in range(50):
            p = Poly.random(self.rng)
            data = poly_tobytes(p)
            self.assertEqual(len(data), 384)
            self.assertEqual(poly_frombytes(data), p)

    def test_compress_roundtrip_within_bound(self):
        for d in (4, 10):
            bound = error_bound(d)
            for _ in range(20):
                p = Poly.random(self.rng)
                data = poly_compress(p, d)
                self.assertEqual(len(data), 32 * d)
                back = poly_decompress(data, d)
                for orig, got in zip(p.coeffs, back.coeffs):
                    self.assertLessEqual(abs(mod_pm(got - orig)), bound)


class TestPolyVecSerialize(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(13)

    def test_tobytes_roundtrip(self):
        for k in (2, 3, 4):
            v = PolyVec.random(k, self.rng)
            data = polyvec_tobytes(v)
            self.assertEqual(len(data), k * 384)
            self.assertEqual(polyvec_frombytes(data), v)

    def test_compress_lengths(self):
        for k, d in ((2, 10), (4, 11)):
            v = PolyVec.random(k, self.rng)
            data = polyvec_compress(v, d)
            self.assertEqual(len(data), k * 32 * d)
            back = polyvec_decompress(data, d, k)
            self.assertEqual(back.k, k)


if __name__ == "__main__":
    unittest.main()
