"""Week 6: constant-time primitives, plus fuzzing of the rejection path.

Two jobs. First, pin the branchless rewrites against the branching versions
they replaced, so the hardening cannot silently change behaviour. Second,
hammer Decaps with malformed input and assert it stays silent -- the property
the whole FO transform rests on.
"""

import dis
import os
import random
import unittest

from kyber import kem, pke
from kyber.ct import eq_bytes, select_bytes, to_int16
from kyber.encode import byte_encode, byte_decode
from kyber.kem import SSBYTES, decaps, encaps, keygen
from kyber.params import N
from kyber.pke import ciphertext_bytes
from kyber.reduce import montgomery_reduce
from kyber.symmetric import H, kdf

LEVELS = (512, 768, 1024)


# Reference versions with the branches the hardening removed. These exist only
# so the tests can prove the rewrites are equivalent.

def _branching_to_int16(x):
    x &= 0xFFFF
    if x >= 0x8000:
        x -= 0x10000
    return x


def _branching_byte_encode(coeffs, d):
    out = bytearray((N * d + 7) // 8)
    pos = 0
    for c in coeffs:
        for j in range(d):
            if (c >> j) & 1:
                out[pos >> 3] |= 1 << (pos & 7)
            pos += 1
    return bytes(out)


class TestEquivalence(unittest.TestCase):
    """The rewrites must agree with the originals everywhere."""

    def test_to_int16_over_its_entire_domain(self):
        for x in range(0x10000):
            self.assertEqual(to_int16(x), _branching_to_int16(x))

    def test_byte_encode_matches_the_branching_version(self):
        rng = random.Random(1)
        for d in range(1, 13):
            for _ in range(5):
                coeffs = [rng.randrange(1 << d) for _ in range(N)]
                self.assertEqual(byte_encode(coeffs, d),
                                 _branching_byte_encode(coeffs, d))
                # and still round-trips
                self.assertEqual(byte_decode(byte_encode(coeffs, d), d), coeffs)

    def test_montgomery_reduce_still_correct(self):
        rng = random.Random(2)
        from kyber.params import Q
        inv_r = pow(1 << 16, -1, Q)
        for _ in range(2000):
            a = rng.randrange(-Q * 2**15, Q * 2**15)
            self.assertEqual(montgomery_reduce(a) % Q, (a * inv_r) % Q)


class TestConstantTimeHelpers(unittest.TestCase):
    def test_select_picks_the_right_operand(self):
        a, b = bytes(range(32)), bytes([0xFF]) * 32
        self.assertEqual(select_bytes(True, a, b), a)
        self.assertEqual(select_bytes(False, a, b), b)
        self.assertEqual(select_bytes(1, a, b), a)
        self.assertEqual(select_bytes(0, a, b), b)

    def test_select_on_random_pairs(self):
        rng = random.Random(3)
        for _ in range(200):
            a = bytes(rng.randrange(256) for _ in range(32))
            b = bytes(rng.randrange(256) for _ in range(32))
            self.assertEqual(select_bytes(True, a, b), a)
            self.assertEqual(select_bytes(False, a, b), b)

    def test_select_rejects_length_mismatch(self):
        with self.assertRaises(ValueError):
            select_bytes(True, bytes(4), bytes(5))

    def test_eq_bytes(self):
        self.assertTrue(eq_bytes(b"abc", b"abc"))
        self.assertFalse(eq_bytes(b"abc", b"abd"))
        self.assertFalse(eq_bytes(b"abc", b"abcd"))

    def test_to_int16_compiles_without_a_conditional_jump(self):
        """Regression guard: catch anyone reintroducing a branch here.

        to_int16 sits in every NTT butterfly over secret data, so a branch in
        it is the most damaging one in the package.
        """
        jumps = [i.opname for i in dis.get_instructions(to_int16)
                 if "JUMP_IF" in i.opname or i.opname.startswith("POP_JUMP")]
        self.assertEqual(jumps, [], f"conditional jump in to_int16: {jumps}")


class TestRejectionFuzz(unittest.TestCase):
    """Decaps must never raise, never agree, and never vary, on bad input."""

    def test_every_single_bit_flip_is_rejected(self):
        level = 512                       # smallest ciphertext, 768 bytes
        pk, sk = keygen(level, bytes(32), bytes(32))
        ct, ss = encaps(pk, level, bytes(range(32)))

        rng = random.Random(7)
        positions = rng.sample(range(len(ct)), 60)
        for pos in positions:
            for bit in (0, 3, 7):
                bad = bytearray(ct)
                bad[pos] ^= 1 << bit
                out = decaps(sk, bytes(bad), level)
                self.assertEqual(len(out), SSBYTES)
                self.assertNotEqual(out, ss,
                                    f"flip at byte {pos} bit {bit} was accepted")

    def test_random_ciphertexts_never_raise(self):
        rng = random.Random(8)
        for level in LEVELS:
            _pk, sk = keygen(level, bytes(32), bytes(32))
            for _ in range(20):
                junk = bytes(rng.randrange(256)
                             for _ in range(ciphertext_bytes(level)))
                self.assertEqual(len(decaps(sk, junk, level)), SSBYTES)

    def test_all_zero_and_all_one_ciphertexts(self):
        for level in LEVELS:
            _pk, sk = keygen(level, bytes(32), bytes(32))
            n = ciphertext_bytes(level)
            for junk in (bytes(n), b"\xff" * n):
                self.assertEqual(len(decaps(sk, junk, level)), SSBYTES)

    def test_rejection_output_depends_only_on_z_and_the_ciphertext(self):
        """KDF(z || H(c)) mentions neither the PKE key nor the message.

        Two unrelated key pairs sharing a rejection seed must therefore
        produce identical output on a ciphertext both of them reject. This
        pins the rejection branch structurally rather than just observing
        that it returns something.
        """
        z = bytes(range(100, 132))
        _pk_a, sk_a = keygen(768, bytes(32), z)
        pk_b, sk_b = keygen(768, bytes([3]) * 32, z)

        ct, _ss = encaps(pk_b, 768, bytes(range(32)))
        bad = bytes([ct[0] ^ 0xFF]) + ct[1:]

        out_a = decaps(sk_a, bad, 768)
        out_b = decaps(sk_b, bad, 768)
        self.assertEqual(out_a, out_b)
        self.assertEqual(out_a, kdf(z + H(bad), SSBYTES))

    def test_wrong_length_ciphertexts_do_raise(self):
        """Length is public, so rejecting loudly here leaks nothing."""
        _pk, sk = keygen(768, bytes(32), bytes(32))
        n = ciphertext_bytes(768)
        for bad_len in (0, n - 1, n + 1, 2 * n):
            with self.assertRaises(ValueError):
                decaps(sk, bytes(bad_len), 768)

    def test_honest_ciphertext_survives_the_fuzzing_neighbourhood(self):
        """Sanity: the untouched ciphertext still agrees."""
        for level in LEVELS:
            pk, sk = keygen(level, bytes(32), bytes(32))
            ct, ss = encaps(pk, level, os.urandom(32))
            self.assertEqual(decaps(sk, ct, level), ss)


if __name__ == "__main__":
    unittest.main()
