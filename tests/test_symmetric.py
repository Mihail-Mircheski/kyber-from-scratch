import hashlib
import unittest

from kyber.symmetric import H, G, prf, xof, kdf

# Published NIST test vectors for the empty input.
SHA3_256_EMPTY = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
SHA3_512_EMPTY = (
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
)
SHAKE128_EMPTY_32 = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
SHAKE256_EMPTY_32 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"


class TestHashKAT(unittest.TestCase):
    def test_H_is_sha3_256(self):
        self.assertEqual(H(b"").hex(), SHA3_256_EMPTY)
        self.assertEqual(len(H(b"abc")), 32)

    def test_G_is_sha3_512_split(self):
        a, b = G(b"")
        self.assertEqual((a + b).hex(), SHA3_512_EMPTY)
        self.assertEqual(len(a), 32)
        self.assertEqual(len(b), 32)

    def test_kdf_is_shake256(self):
        self.assertEqual(kdf(b"", 32).hex(), SHAKE256_EMPTY_32)

    def test_shake128_primitive(self):
        # Confirms the SHAKE-128 that XOF is built on matches the KAT.
        self.assertEqual(hashlib.shake_128(b"").digest(32).hex(), SHAKE128_EMPTY_32)


class TestWrapperDefinitions(unittest.TestCase):
    def test_xof_absorb_order(self):
        seed = bytes(range(32))
        self.assertEqual(
            xof(seed, 1, 2, 64),
            hashlib.shake_128(seed + bytes([1, 2])).digest(64),
        )

    def test_prf_absorb_order(self):
        key = bytes(range(32))
        self.assertEqual(
            prf(key, 7, 128),
            hashlib.shake_256(key + bytes([7])).digest(128),
        )

    def test_xof_variable_length(self):
        seed = bytes(32)
        long = xof(seed, 0, 0, 200)
        short = xof(seed, 0, 0, 100)
        self.assertEqual(long[:100], short)  # SHAKE is a prefix stream


if __name__ == "__main__":
    unittest.main()
