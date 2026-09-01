"""Symmetric primitives (spec section 2.3).

Kyber names five keyed/hashing primitives, all from the SHA-3 family:

    XOF = SHAKE-128            extendable-output, used to expand the matrix A
    PRF = SHAKE-256(s || b)    pseudorandom function for the noise
    H   = SHA3-256             hash to 32 bytes
    G   = SHA3-512             hash to 32 + 32 bytes
    KDF = SHAKE-256            key-derivation function for the shared secret

We wrap Python's hashlib rather than implementing Keccak by hand; the tests pin
these against the published NIST SHA-3 / SHAKE test vectors so the wiring (which
function, which output length, which absorb order) is verified.
"""

import hashlib


def H(data):
    """SHA3-256 : B* -> B^32."""
    return hashlib.sha3_256(bytes(data)).digest()


def G(data):
    """SHA3-512 : B* -> B^32 x B^32 (returned as two 32-byte halves)."""
    d = hashlib.sha3_512(bytes(data)).digest()
    return d[:32], d[32:]


def prf(key, nonce, length):
    """PRF = SHAKE-256(key || nonce), nonce a single byte."""
    return hashlib.shake_256(bytes(key) + bytes([nonce])).digest(length)


def xof(seed, i, j, length):
    """XOF = SHAKE-128(seed || i || j), i and j single bytes."""
    return hashlib.shake_128(bytes(seed) + bytes([i, j])).digest(length)


def kdf(data, length):
    """KDF = SHAKE-256 : B* -> B* (derives the shared secret)."""
    return hashlib.shake_256(bytes(data)).digest(length)


# Spec-cased aliases, so call sites can read like the specification.
PRF = prf
XOF = xof
KDF = kdf
