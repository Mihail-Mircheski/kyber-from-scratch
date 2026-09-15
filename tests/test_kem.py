import os
import unittest

from kyber import kem, pke
from kyber.kem import SSBYTES, decaps, encaps, keygen, secret_key_bytes
from kyber.pke import SYMBYTES, ciphertext_bytes, public_key_bytes
from kyber.symmetric import H, G

LEVELS = (512, 768, 1024)

# Published Kyber sizes: (|pk|, |sk_kem|, |c|). The KEM secret key is larger
# than the PKE one because it also carries pk, H(pk) and the rejection seed.
EXPECTED_SIZES = {
    512:  (800, 1632, 768),
    768:  (1184, 2400, 1088),
    1024: (1568, 3168, 1568),
}


def _seed(rng, n=SYMBYTES):
    return bytes(rng.randrange(256) for _ in range(n))


class TestSizes(unittest.TestCase):
    def test_match_published_parameters(self):
        for level in LEVELS:
            pk_n, sk_n, ct_n = EXPECTED_SIZES[level]
            self.assertEqual(public_key_bytes(level), pk_n)
            self.assertEqual(secret_key_bytes(level), sk_n)
            self.assertEqual(ciphertext_bytes(level), ct_n)

    def test_generated_objects_have_those_sizes(self):
        for level in LEVELS:
            pk, sk = keygen(level, bytes(32), bytes(32))
            ct, ss = encaps(pk, level, bytes(32))
            self.assertEqual((len(pk), len(sk), len(ct)), EXPECTED_SIZES[level])
            self.assertEqual(len(ss), SSBYTES)


class TestRoundTrip(unittest.TestCase):
    """The core guarantee: both parties derive the same shared secret."""

    def test_agreement(self):
        import random
        rng = random.Random(5)
        for level in LEVELS:
            pk, sk = keygen(level, _seed(rng), _seed(rng))
            for _ in range(3):
                ct, ss_sender = encaps(pk, level, _seed(rng))
                self.assertEqual(decaps(sk, ct, level), ss_sender,
                                 f"key agreement failed at Kyber{level}")

    def test_agreement_with_os_randomness(self):
        for level in LEVELS:
            pk, sk = keygen(level)
            ct, ss_sender = encaps(pk, level)
            self.assertEqual(decaps(sk, ct, level), ss_sender)


class TestSecretKeyLayout(unittest.TestCase):
    """sk = sk_cpa || pk || H(pk) || z."""

    def test_embeds_public_key_and_its_hash(self):
        for level in LEVELS:
            pk, sk = keygen(level, bytes(range(32)), bytes(range(32, 64)))
            n_cpa = pke.secret_key_bytes(level)
            n_pk = pke.public_key_bytes(level)
            self.assertEqual(sk[n_cpa:n_cpa + n_pk], pk)
            self.assertEqual(sk[n_cpa + n_pk:n_cpa + n_pk + SYMBYTES], H(pk))
            self.assertEqual(sk[n_cpa + n_pk + SYMBYTES:], bytes(range(32, 64)))

    def test_cpa_part_matches_a_bare_pke_keygen(self):
        d = bytes(range(64, 96))
        for level in LEVELS:
            pk_pke, sk_pke = pke.keygen(level, d)
            pk_kem, sk_kem = keygen(level, d, bytes(32))
            self.assertEqual(pk_kem, pk_pke)
            self.assertEqual(sk_kem[:pke.secret_key_bytes(level)], sk_pke)


class TestDeterminism(unittest.TestCase):
    def test_same_seeds_same_keys(self):
        d, z = bytes(range(32)), bytes(range(32, 64))
        for level in LEVELS:
            self.assertEqual(keygen(level, d, z), keygen(level, d, z))

    def test_same_seed_same_encapsulation(self):
        pk, _sk = keygen(768, bytes(32), bytes(32))
        s = bytes(range(32))
        self.assertEqual(encaps(pk, 768, s), encaps(pk, 768, s))

    def test_different_seeds_differ(self):
        pk, _sk = keygen(768, bytes(32), bytes(32))
        ct1, ss1 = encaps(pk, 768, bytes(32))
        ct2, ss2 = encaps(pk, 768, bytes([1]) + bytes(31))
        self.assertNotEqual(ct1, ct2)
        self.assertNotEqual(ss1, ss2)


class TestImplicitRejection(unittest.TestCase):
    """A bad ciphertext must yield a pseudo-random key, never an error.

    Anything that distinguishes "malformed" from "well-formed" to an attacker
    re-opens the chosen-ciphertext oracle the FO transform exists to close, so
    these tests check for silence rather than for failure.
    """

    def test_tampered_ciphertext_returns_a_different_key_without_raising(self):
        import random
        rng = random.Random(11)
        for level in LEVELS:
            pk, sk = keygen(level, _seed(rng), _seed(rng))
            ct, ss = encaps(pk, level, _seed(rng))
            for pos in (0, len(ct) // 2, len(ct) - 1):
                bad = bytearray(ct)
                bad[pos] ^= 0x01
                ss_bad = decaps(sk, bytes(bad), level)
                self.assertEqual(len(ss_bad), SSBYTES)
                self.assertNotEqual(ss_bad, ss)

    def test_rejection_is_deterministic(self):
        pk, sk = keygen(768, bytes(32), bytes(32))
        ct, _ss = encaps(pk, 768, bytes(32))
        bad = bytes([ct[0] ^ 0xFF]) + ct[1:]
        self.assertEqual(decaps(sk, bad, 768), decaps(sk, bad, 768))

    def test_rejection_key_depends_on_z(self):
        # Same PKE key pair, different rejection seed: honest ciphertexts still
        # agree, but the rejection output must differ.
        d = bytes(range(32))
        pk_a, sk_a = keygen(768, d, bytes(32))
        pk_b, sk_b = keygen(768, d, bytes([7]) * 32)
        self.assertEqual(pk_a, pk_b)

        ct, ss = encaps(pk_a, 768, bytes(range(32)))
        self.assertEqual(decaps(sk_a, ct, 768), ss)
        self.assertEqual(decaps(sk_b, ct, 768), ss)

        bad = bytes([ct[0] ^ 1]) + ct[1:]
        self.assertNotEqual(decaps(sk_a, bad, 768), decaps(sk_b, bad, 768))

    def test_random_ciphertext_decapsulates_silently(self):
        rng = os.urandom
        for level in LEVELS:
            _pk, sk = keygen(level, bytes(32), bytes(32))
            ss = decaps(sk, rng(ciphertext_bytes(level)), level)
            self.assertEqual(len(ss), SSBYTES)

    def test_unrelated_secret_key_does_not_agree(self):
        pk, _sk = keygen(768, bytes(32), bytes(32))
        _pk2, sk2 = keygen(768, bytes([9]) * 32, bytes([9]) * 32)
        ct, ss = encaps(pk, 768, bytes(range(32)))
        self.assertNotEqual(decaps(sk2, ct, 768), ss)


class TestReEncryptionCheckIsLive(unittest.TestCase):
    """The FO check must reject a ciphertext that is valid but not canonical.

    This is the test that proves the re-encryption step is doing real work.
    We build a ciphertext that decrypts to exactly the same message as an
    honest one, but was encrypted with different coins. The PKE layer is
    perfectly happy with it and recovers the right m. Only the KEM's
    re-encryption notices that the coins were not the ones G would have
    derived, so it must be rejected. If decaps returned the honest shared
    secret here, the transform would be vacuous and the scheme would still be
    malleable.
    """

    def test_same_message_wrong_coins_is_rejected(self):
        level = 768
        seed = bytes(range(32))
        pk, sk = keygen(level, bytes(32), bytes(32))

        # Reproduce what encaps does internally.
        m = H(seed)
        k_bar, r = G(m + H(pk))
        honest = pke.encrypt(pk, m, r, level)
        ct, ss = encaps(pk, level, seed)
        self.assertEqual(ct, honest)          # our reconstruction is faithful

        # Same plaintext, different coins -> a well-formed PKE ciphertext.
        forged = pke.encrypt(pk, m, bytes([0xAA]) * 32, level)
        self.assertNotEqual(forged, honest)

        # The PKE layer still recovers the message ...
        sk_cpa = sk[:pke.secret_key_bytes(level)]
        self.assertEqual(pke.decrypt(sk_cpa, forged, level), m)

        # ... but the KEM rejects it.
        self.assertNotEqual(decaps(sk, forged, level), ss)


class TestSelect(unittest.TestCase):
    def test_branchless_select(self):
        a, b = bytes(range(32)), bytes([0xFF]) * 32
        self.assertEqual(kem._select(True, a, b), a)
        self.assertEqual(kem._select(False, a, b), b)


class TestInputValidation(unittest.TestCase):
    def test_lengths_are_checked(self):
        pk, sk = keygen(768, bytes(32), bytes(32))
        ct, _ss = encaps(pk, 768, bytes(32))

        with self.assertRaises(ValueError):
            keygen(768, bytes(32), b"short")
        with self.assertRaises(ValueError):
            encaps(pk, 512)                       # pk sized for another level
        with self.assertRaises(ValueError):
            encaps(pk, 768, b"short")
        with self.assertRaises(ValueError):
            decaps(sk, ct, 512)
        with self.assertRaises(ValueError):
            decaps(bytes(10), ct, 768)
        with self.assertRaises(ValueError):
            decaps(sk, bytes(10), 768)


if __name__ == "__main__":
    unittest.main()
