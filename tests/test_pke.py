import os
import random
import unittest

from kyber.params import Q
from kyber.poly import Poly
from kyber.polyvec import PolyVec
from kyber.symmetric import G
from kyber.sample import gen_matrix, get_noise
from kyber.ntt import poly_ntt, poly_invntt
from kyber.encode import POLYBYTES, polyvec_frombytes
from kyber.pke import (
    MSGBYTES,
    SYMBYTES,
    keygen,
    encrypt,
    decrypt,
    decryption_noise,
    get_params,
    public_key_bytes,
    secret_key_bytes,
    ciphertext_bytes,
)

LEVELS = (512, 768, 1024)

# Published Kyber sizes (spec section 1.4): (|pk|, |sk_cpa|, |c|).
EXPECTED_SIZES = {
    512:  (800, 768, 768),
    768:  (1184, 1152, 1088),
    1024: (1568, 1536, 1568),
}

# Decryption rounds each coefficient to the nearer of 0 and q/2, so the error
# term must stay strictly inside q/4 for the message bit to survive.
DECISION_BOUND = Q // 4


def _seed(rng):
    return bytes(rng.randrange(256) for _ in range(SYMBYTES))


class TestSizes(unittest.TestCase):
    def test_match_published_parameters(self):
        for level in LEVELS:
            pk_n, sk_n, ct_n = EXPECTED_SIZES[level]
            self.assertEqual(public_key_bytes(level), pk_n)
            self.assertEqual(secret_key_bytes(level), sk_n)
            self.assertEqual(ciphertext_bytes(level), ct_n)

    def test_generated_keys_have_those_sizes(self):
        rng = random.Random(1)
        for level in LEVELS:
            pk, sk = keygen(level, _seed(rng))
            ct = encrypt(pk, _seed(rng), _seed(rng), level)
            self.assertEqual((len(pk), len(sk), len(ct)), EXPECTED_SIZES[level])

    def test_unknown_level_rejected(self):
        with self.assertRaises(ValueError):
            get_params(384)


class TestKeyGen(unittest.TestCase):
    def test_deterministic_in_the_seed(self):
        d = bytes(range(32))
        for level in LEVELS:
            self.assertEqual(keygen(level, d), keygen(level, d))

    def test_distinct_seeds_give_distinct_keys(self):
        a = keygen(768, bytes(32))
        b = keygen(768, bytes([1]) + bytes(31))
        self.assertNotEqual(a[0], b[0])
        self.assertNotEqual(a[1], b[1])

    def test_public_key_ends_with_rho(self):
        d = bytes(range(32, 64))
        rho, _sigma = G(d)
        for level in LEVELS:
            pk, _sk = keygen(level, d)
            self.assertEqual(pk[-SYMBYTES:], rho)

    def test_random_keygen_differs_between_calls(self):
        self.assertNotEqual(keygen(512)[0], keygen(512)[0])

    def test_bad_seed_length_rejected(self):
        with self.assertRaises(ValueError):
            keygen(768, b"short")


class TestRoundTrip(unittest.TestCase):
    """The week 4 gate: encrypt/decrypt round-trips on all parameter sets."""

    def test_random_messages(self):
        rng = random.Random(7)
        for level in LEVELS:
            pk, sk = keygen(level, _seed(rng))
            for _ in range(4):
                msg = _seed(rng)
                ct = encrypt(pk, msg, _seed(rng), level)
                self.assertEqual(decrypt(sk, ct, level), msg,
                                 f"round-trip failed at Kyber{level}")

    def test_extreme_messages(self):
        # All-zero and all-one bits exercise both ends of the q/2 encoding.
        for msg in (bytes(MSGBYTES), b"\xff" * MSGBYTES):
            for level in LEVELS:
                pk, sk = keygen(level, bytes([level % 256]) * SYMBYTES)
                ct = encrypt(pk, msg, bytes(range(32)), level)
                self.assertEqual(decrypt(sk, ct, level), msg)

    def test_fresh_random_keys_and_os_randomness(self):
        for level in LEVELS:
            pk, sk = keygen(level)
            msg = os.urandom(MSGBYTES)
            ct = encrypt(pk, msg, os.urandom(SYMBYTES), level)
            self.assertEqual(decrypt(sk, ct, level), msg)


class TestDeterminism(unittest.TestCase):
    """Enc must be a pure function of (pk, m, coins) -- week 5's FO needs this."""

    def test_same_coins_same_ciphertext(self):
        pk, _sk = keygen(768, bytes(range(32)))
        msg, coins = bytes(range(32, 64)), bytes(range(64, 96))
        self.assertEqual(encrypt(pk, msg, coins, 768),
                         encrypt(pk, msg, coins, 768))

    def test_different_coins_different_ciphertext(self):
        pk, _sk = keygen(768, bytes(range(32)))
        msg = bytes(range(32, 64))
        c1 = encrypt(pk, msg, bytes(32), 768)
        c2 = encrypt(pk, msg, bytes([1]) + bytes(31), 768)
        self.assertNotEqual(c1, c2)


class TestWrongKey(unittest.TestCase):
    def test_unrelated_secret_key_does_not_decrypt(self):
        rng = random.Random(21)
        for level in LEVELS:
            pk, _sk = keygen(level, _seed(rng))
            _pk2, sk2 = keygen(level, _seed(rng))
            msg = _seed(rng)
            ct = encrypt(pk, msg, _seed(rng), level)
            self.assertNotEqual(decrypt(sk2, ct, level), msg)

    def test_garbage_ciphertext_decrypts_without_error(self):
        # CPA-PKE has no integrity check: any well-formed byte string decodes.
        # It must not raise -- week 5's implicit rejection depends on that.
        rng = random.Random(22)
        for level in LEVELS:
            _pk, sk = keygen(level, _seed(rng))
            ct = bytes(rng.randrange(256) for _ in range(ciphertext_bytes(level)))
            self.assertEqual(len(decrypt(sk, ct, level)), MSGBYTES)


class TestNoiseMargin(unittest.TestCase):
    """v - s^T.u must land within q/4 of the encoded message.

    Round-trips alone only show that it happened to work; this measures the
    margin, which is what the compression widths du and dv are chosen against.
    """

    def test_error_term_within_decision_boundary(self):
        rng = random.Random(31)
        for level in LEVELS:
            pk, sk = keygen(level, _seed(rng))
            worst = 0
            for _ in range(3):
                msg = _seed(rng)
                ct = encrypt(pk, msg, _seed(rng), level)
                worst = max(worst, max(abs(x) for x
                                       in decryption_noise(sk, ct, msg, level)))
            self.assertLess(worst, DECISION_BOUND,
                            f"Kyber{level}: error {worst} reaches the q/4 boundary")


class TestAgainstSchoolbookOracle(unittest.TestCase):
    """t_hat must equal NTT(A.s + e) computed with the week 1 schoolbook multiply.

    This is the check that pins the Montgomery bookkeeping. t_hat is the one
    value that stays in the NTT domain with no inverse transform to cancel the
    R^-1 that basemul leaves, so it needs an explicit poly_tomont. A missing or
    doubled correction would still round-trip inside this implementation --
    both sides would be consistently wrong -- but it would not match the
    structurally different oracle, and it would not match the reference
    implementation's key bytes in week 5.
    """

    def test_keygen_matches_naive_module_arithmetic(self):
        level, k = 512, 2
        eta1 = get_params(level)["eta1"]
        d = bytes(range(32))
        rho, sigma = G(d)

        # invntt of a pure NTT-domain value returns it scaled by R, so undo
        # that to recover A itself in the coefficient domain.
        inv_mont = pow(2285, -1, Q)  # 2285 = R mod q
        a_hat = gen_matrix(rho, k, transposed=False)
        a_plain = [
            [Poly([c * inv_mont % Q for c in poly_invntt(entry).coeffs])
             for entry in row]
            for row in a_hat.rows
        ]

        s = PolyVec([get_noise(sigma, i, eta1) for i in range(k)])
        e = PolyVec([get_noise(sigma, k + i, eta1) for i in range(k)])

        pk, _sk = keygen(level, d)
        t_hat = polyvec_frombytes(pk[:k * POLYBYTES])

        for i in range(k):
            acc = Poly.zero()
            for entry, s_j in zip(a_plain[i], s.polys):
                acc = acc + entry * s_j          # week 1 schoolbook multiply
            self.assertEqual(t_hat[i], poly_ntt(acc + e[i]),
                             f"t_hat[{i}] disagrees with the schoolbook oracle")

    def test_secret_key_is_the_ntt_of_the_sampled_secret(self):
        level, k = 512, 2
        eta1 = get_params(level)["eta1"]
        d = bytes(range(100, 132))
        _rho, sigma = G(d)
        s = PolyVec([get_noise(sigma, i, eta1) for i in range(k)])

        _pk, sk = keygen(level, d)
        s_hat = polyvec_frombytes(sk)
        for i in range(k):
            self.assertEqual(s_hat[i], poly_ntt(s.polys[i]))


class TestInputValidation(unittest.TestCase):
    def test_lengths_are_checked(self):
        pk, sk = keygen(768, bytes(32))
        msg, coins = bytes(32), bytes(32)

        with self.assertRaises(ValueError):      # pk sized for another level
            encrypt(pk, msg, coins, 512)
        with self.assertRaises(ValueError):
            encrypt(pk, b"short", coins, 768)
        with self.assertRaises(ValueError):
            encrypt(pk, msg, b"short", 768)
        with self.assertRaises(ValueError):
            decrypt(sk, bytes(10), 768)
        with self.assertRaises(ValueError):
            decrypt(bytes(10), bytes(ciphertext_bytes(768)), 768)


if __name__ == "__main__":
    unittest.main()
