import unittest

from kyber.params import N, Q
from kyber.reduce import mod_pm
from kyber.sample import (
    bytes_to_bits,
    cbd,
    get_noise,
    prf,
    rej_uniform,
    gen_poly,
    gen_matrix,
)

RHO = bytes(range(32))
SIGMA = bytes(range(100, 132))


class TestBytesToBits(unittest.TestCase):
    def test_lsb_first(self):
        # 0b00000001 -> first bit 1; 0b10000000 -> eighth bit 1.
        self.assertEqual(bytes_to_bits(bytes([1]))[:8], [1, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(bytes_to_bits(bytes([0x80]))[:8], [0, 0, 0, 0, 0, 0, 0, 1])

    def test_length(self):
        self.assertEqual(len(bytes_to_bits(bytes(10))), 80)


class TestCBD(unittest.TestCase):
    def test_range(self):
        for eta in (2, 3):
            buf = prf(SIGMA, 0, 64 * eta)
            p = cbd(buf, eta)
            for c in p.coeffs:
                self.assertTrue(-eta <= mod_pm(c) <= eta)

    def test_deterministic(self):
        for eta in (2, 3):
            buf = prf(SIGMA, 5, 64 * eta)
            self.assertEqual(cbd(buf, eta), cbd(buf, eta))

    def test_all_zero_input_gives_zero_poly(self):
        for eta in (2, 3):
            p = cbd(bytes(64 * eta), eta)
            self.assertTrue(all(c == 0 for c in p.coeffs))

    def test_get_noise_matches_manual(self):
        for eta in (2, 3):
            n = get_noise(SIGMA, 3, eta)
            self.assertEqual(n, cbd(prf(SIGMA, 3, 64 * eta), eta))

    def test_distribution_is_centered(self):
        # Mean of B_eta is 0; over 256 coeffs the sum should be small.
        eta = 3
        total = sum(mod_pm(c) for c in get_noise(SIGMA, 9, eta).coeffs)
        self.assertLess(abs(total), 120)


class TestParse(unittest.TestCase):
    def test_coeffs_in_range(self):
        p = gen_poly(RHO, 0, 0)
        self.assertEqual(len(p.coeffs), N)
        for c in p.coeffs:
            self.assertTrue(0 <= c < Q)

    def test_deterministic(self):
        self.assertEqual(gen_poly(RHO, 1, 2), gen_poly(RHO, 1, 2))

    def test_index_order_matters(self):
        self.assertNotEqual(gen_poly(RHO, 1, 2), gen_poly(RHO, 2, 1))

    def test_rej_uniform_drops_out_of_range(self):
        # Bytes encoding 12-bit value 0xFFF (= 4095 >= q) should be rejected.
        buf = bytes([0xFF, 0xFF, 0xFF]) * 4
        coeffs, ctr = rej_uniform(buf, N)
        self.assertEqual(ctr, 0)
        self.assertEqual(coeffs, [])


class TestGenMatrix(unittest.TestCase):
    def test_shape_and_range(self):
        for k in (2, 3, 4):
            A = gen_matrix(RHO, k)
            self.assertEqual(A.k, k)
            for row in A.rows:
                self.assertEqual(len(row), k)
                for p in row:
                    for c in p.coeffs:
                        self.assertTrue(0 <= c < Q)

    def test_transpose_relationship(self):
        # A^T[i][j] should equal A[j][i].
        k = 3
        A = gen_matrix(RHO, k, transposed=False)
        At = gen_matrix(RHO, k, transposed=True)
        for i in range(k):
            for j in range(k):
                self.assertEqual(At.rows[i][j], A.rows[j][i])


if __name__ == "__main__":
    unittest.main()
