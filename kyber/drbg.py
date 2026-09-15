"""AES-256 CTR DRBG -- the deterministic RNG the official KAT vectors use.

The NIST Known Answer Tests do not supply the random values a KEM consumes.
They supply a 48-byte entropy seed per test case and expect the implementation
to expand it with the AES-256 CTR DRBG from SP 800-90A, exactly as the
reference submission's `rng.c` does. To reproduce a published (pk, sk, ct, ss)
quadruple we therefore have to reproduce that generator bit for bit.

Two layers live here:

1. A small AES-256 block cipher. Python's standard library has SHA-3 but no
   AES, and the project's rule is no third-party dependencies, so it is built
   from scratch. Only single-block encryption is needed -- the DRBG never
   decrypts. Correctness is pinned by the FIPS-197 worked example in the tests.

2. The CTR DRBG itself, which is a thin wrapper: increment a 128-bit counter,
   encrypt it, emit the block, and afterwards stir the state forward so the
   generator never repeats.

Nothing in the scheme proper depends on this module. It exists only so the
week 5 KAT harness can line its randomness up with the published vectors.
"""

# -- GF(2^8) tables ---------------------------------------------------------


def _xtime(a):
    """Multiply by x in GF(2^8) modulo the AES polynomial x^8+x^4+x^3+x+1."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _build_tables():
    """Exp/log tables to the generator 3, then the S-box built from them."""
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _xtime(x) ^ x                  # multiply by 3
    for i in range(255, 512):
        exp[i] = exp[i - 255]

    sbox = []
    for a in range(256):
        inv = 0 if a == 0 else exp[255 - log[a]]
        # Affine map: s = inv ^ rotl(inv,1) ^ rotl(inv,2) ^ rotl(inv,3)
        #                 ^ rotl(inv,4) ^ 0x63
        s, r = inv, inv
        for _ in range(4):
            r = ((r << 1) | (r >> 7)) & 0xFF
            s ^= r
        sbox.append(s ^ 0x63)
    return exp, log, sbox


_EXP, _LOG, SBOX = _build_tables()


def _mul(a, b):
    """Multiply two field elements."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


# -- AES-256 ----------------------------------------------------------------

NK, NR = 8, 14        # 256-bit key = 8 words, 14 rounds


def expand_key(key):
    """AES-256 key schedule: 32 key bytes -> 15 round keys of 16 bytes."""
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes, got {len(key)}")

    w = [list(key[4 * i:4 * i + 4]) for i in range(NK)]
    rcon = 1
    for i in range(NK, 4 * (NR + 1)):
        t = list(w[i - 1])
        if i % NK == 0:
            t = t[1:] + t[:1]                    # RotWord
            t = [SBOX[b] for b in t]             # SubWord
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % NK == 4:                        # extra SubWord, 256-bit only
            t = [SBOX[b] for b in t]
        w.append([p ^ q for p, q in zip(w[i - NK], t)])

    return [bytes(b for word in w[4 * r:4 * r + 4] for b in word)
            for r in range(NR + 1)]


def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]


def _shift_rows(state):
    """Row r rotates left by r. The state is column-major: byte i is row i%4."""
    out = list(state)
    for r in range(1, 4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    state[:] = out


def _mix_columns(state):
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        state[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
        state[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
        state[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
        state[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)


def encrypt_block(round_keys, block):
    """Encrypt one 16-byte block under a prepared key schedule."""
    if len(block) != 16:
        raise ValueError(f"AES block must be 16 bytes, got {len(block)}")

    state = list(block)
    _add_round_key(state, round_keys[0])
    for r in range(1, NR):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    _sub_bytes(state)                 # final round drops MixColumns
    _shift_rows(state)
    _add_round_key(state, round_keys[NR])
    return bytes(state)


def aes256_ecb(key, block):
    """One-shot single-block AES-256 encryption."""
    return encrypt_block(expand_key(key), block)


# -- CTR DRBG (SP 800-90A, as wired up by the NIST KAT harness) -------------

class AES256CTRDRBG:
    """The generator the reference `rng.c` exposes as randombytes().

    Seeded with 48 bytes of entropy. Key and counter start at zero and are
    immediately stirred by the seed material, matching randombytes_init().
    """

    def __init__(self, entropy, personalization=None):
        if len(entropy) != 48:
            raise ValueError(f"entropy must be 48 bytes, got {len(entropy)}")

        seed = bytearray(entropy)
        if personalization is not None:
            if len(personalization) != 48:
                raise ValueError("personalization string must be 48 bytes")
            for i in range(48):
                seed[i] ^= personalization[i]

        self.key = bytes(32)
        self.v = bytearray(16)
        self._update(bytes(seed))
        self.reseed_counter = 1

    def _increment(self):
        """Big-endian increment of the 128-bit counter V."""
        for i in range(15, -1, -1):
            self.v[i] = (self.v[i] + 1) & 0xFF
            if self.v[i] != 0:
                break

    def _update(self, provided_data):
        """Refresh (key, V) by encrypting three counter blocks and XORing in."""
        schedule = expand_key(self.key)
        temp = bytearray()
        for _ in range(3):
            self._increment()
            temp += encrypt_block(schedule, bytes(self.v))
        if provided_data is not None:
            for i in range(48):
                temp[i] ^= provided_data[i]
        self.key = bytes(temp[:32])
        self.v = bytearray(temp[32:48])

    def random_bytes(self, length):
        """Generate `length` bytes, then stir the state forward."""
        schedule = expand_key(self.key)
        out = bytearray()
        while len(out) < length:
            self._increment()
            out += encrypt_block(schedule, bytes(self.v))
        self._update(None)
        self.reseed_counter += 1
        return bytes(out[:length])
