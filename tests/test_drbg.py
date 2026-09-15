import unittest

from kyber.drbg import SBOX, AES256CTRDRBG, aes256_ecb, encrypt_block, expand_key


class TestAES(unittest.TestCase):
    def test_fips197_appendix_c3(self):
        """The published AES-256 worked example. This is the whole oracle."""
        key = bytes(range(32))
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(aes256_ecb(key, plaintext).hex(),
                         "8ea2b7ca516745bfeafc49904b496089")

    def test_sbox_is_a_permutation(self):
        self.assertEqual(len(SBOX), 256)
        self.assertEqual(sorted(SBOX), list(range(256)))
        self.assertEqual(SBOX[0x00], 0x63)      # affine constant, inv(0) = 0
        self.assertEqual(SBOX[0x53], 0xED)      # FIPS-197 worked example

    def test_key_schedule_shape(self):
        rk = expand_key(bytes(range(32)))
        self.assertEqual(len(rk), 15)                  # 14 rounds + initial
        self.assertTrue(all(len(k) == 16 for k in rk))
        self.assertEqual(rk[0], bytes(range(16)))      # first round key is the key
        self.assertEqual(rk[1], bytes(range(16, 32)))

    def test_distinct_keys_give_distinct_ciphertexts(self):
        block = bytes(16)
        a = aes256_ecb(bytes(32), block)
        b = aes256_ecb(bytes([1]) + bytes(31), block)
        self.assertNotEqual(a, b)

    def test_rejects_bad_sizes(self):
        with self.assertRaises(ValueError):
            expand_key(bytes(16))
        with self.assertRaises(ValueError):
            encrypt_block(expand_key(bytes(32)), bytes(15))


class TestDRBG(unittest.TestCase):
    ENTROPY = bytes(range(48))

    def test_deterministic_in_the_seed(self):
        a = AES256CTRDRBG(self.ENTROPY).random_bytes(64)
        b = AES256CTRDRBG(self.ENTROPY).random_bytes(64)
        self.assertEqual(a, b)

    def test_different_seeds_differ(self):
        other = bytes([0xFF]) + bytes(range(1, 48))
        self.assertNotEqual(AES256CTRDRBG(self.ENTROPY).random_bytes(32),
                            AES256CTRDRBG(other).random_bytes(32))

    def test_successive_calls_differ(self):
        d = AES256CTRDRBG(self.ENTROPY)
        self.assertNotEqual(d.random_bytes(32), d.random_bytes(32))

    def test_arbitrary_lengths(self):
        d = AES256CTRDRBG(self.ENTROPY)
        for n in (1, 15, 16, 17, 31, 32, 48, 100):
            self.assertEqual(len(d.random_bytes(n)), n)

    def test_state_advances_so_a_reseed_is_needed_to_repeat(self):
        d = AES256CTRDRBG(self.ENTROPY)
        first = d.random_bytes(32)
        d.random_bytes(32)
        self.assertNotEqual(d.random_bytes(32), first)

    def test_counter_carries(self):
        d = AES256CTRDRBG(self.ENTROPY)
        d.v = bytearray(b"\xff" * 16)
        d._increment()
        self.assertEqual(bytes(d.v), bytes(16))      # wraps to all zeros

        d.v = bytearray(b"\x00" * 15 + b"\xff")
        d._increment()
        self.assertEqual(bytes(d.v), bytes(14) + b"\x01\x00")

    def test_personalization_changes_the_stream(self):
        plain = AES256CTRDRBG(self.ENTROPY).random_bytes(32)
        personalized = AES256CTRDRBG(self.ENTROPY, bytes([1]) * 48).random_bytes(32)
        self.assertNotEqual(plain, personalized)

    def test_rejects_bad_seed_lengths(self):
        with self.assertRaises(ValueError):
            AES256CTRDRBG(bytes(32))
        with self.assertRaises(ValueError):
            AES256CTRDRBG(self.ENTROPY, bytes(32))


if __name__ == "__main__":
    unittest.main()
