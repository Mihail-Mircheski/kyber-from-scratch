"""Compression and (de)serialization (spec section 1.1).

Two independent jobs:

1. Compress_q / Decompress_q throw away low-order bits of a coefficient, keeping
   only d bits. This is lossy: Decompress(Compress(x)) is close to x but not
   equal, with the error bounded by round(q / 2^(d+1)) (spec eq. 2). It shrinks
   ciphertexts and also performs the LWE "rounding" during en/decryption.

2. Encode_l / Decode_l pack/unpack polynomials to/from byte strings, treating
   each coefficient as an l-bit little-endian integer (256 coefficients ->
   32*l bytes). With l = 12 this serializes NTT-domain polynomials for keys;
   with l = d it packs compressed coefficients for ciphertexts.

Encode and Decode are exact inverses; Compress/Decompress are not (by design).
"""

from .params import N, Q
from .poly import Poly
from .polyvec import PolyVec
from .sample import bytes_to_bits

POLYBYTES = 32 * 12  # 384 bytes: one polynomial at 12 bits per coefficient


# -- Compression (spec section 1.1) ----------------------------------------

def compress(x, d):
    """Compress_q(x, d): map x in [0, q) to d bits in [0, 2^d).

    Integer form of round((2^d / q) * x) mod 2^d (round half up), matching the
    Kyber reference so no floating point is involved.
    """
    return (((x << d) + Q // 2) // Q) & ((1 << d) - 1)


def decompress(y, d):
    """Decompress_q(y, d): map y in [0, 2^d) back toward [0, q).

    Integer form of round((q / 2^d) * y).
    """
    return (y * Q + (1 << (d - 1))) >> d


# -- Byte (de)serialization: Encode_l / Decode_l ---------------------------

def byte_encode(coeffs, d):
    """Pack N d-bit coefficients into 32*d bytes (LSB-first bit order).

    The OR is unconditional: the shifted bit is simply 0 when unset. Week 6
    replaced a ``if (c >> j) & 1`` here, which branched on secret data --
    this routine serializes the secret key and, via poly_tomsg, the recovered
    message.
    """
    out = bytearray((N * d + 7) // 8)
    pos = 0
    for c in coeffs:
        for j in range(d):
            out[pos >> 3] |= ((c >> j) & 1) << (pos & 7)
            pos += 1
    return bytes(out)


def byte_decode(data, d):
    """Inverse of byte_encode: unpack 32*d bytes into N d-bit coefficients."""
    bits = bytes_to_bits(data)
    coeffs = [0] * N
    for i in range(N):
        c = 0
        for j in range(d):
            c |= bits[i * d + j] << j
        coeffs[i] = c
    return coeffs


# -- Polynomial (de)serialization ------------------------------------------

def poly_tobytes(p):
    """Serialize a polynomial (coeffs in [0, q)) to 384 bytes at 12 bits each."""
    return byte_encode([c % Q for c in p.coeffs], 12)


def poly_frombytes(data):
    """Deserialize 384 bytes back into a polynomial."""
    return Poly(byte_decode(data, 12))


def poly_compress(p, d):
    """Compress each coefficient to d bits and pack: yields 32*d bytes."""
    return byte_encode([compress(c % Q, d) for c in p.coeffs], d)


def poly_decompress(data, d):
    """Unpack 32*d bytes of d-bit values and decompress each coefficient."""
    return Poly([decompress(y, d) for y in byte_decode(data, d)])


# -- Vector (de)serialization ----------------------------------------------

def polyvec_tobytes(v):
    return b"".join(poly_tobytes(p) for p in v.polys)


def polyvec_frombytes(data):
    k = len(data) // POLYBYTES
    return PolyVec([poly_frombytes(data[i * POLYBYTES:(i + 1) * POLYBYTES])
                    for i in range(k)])


def polyvec_compress(v, d):
    return b"".join(poly_compress(p, d) for p in v.polys)


def polyvec_decompress(data, d, k):
    step = 32 * d
    return PolyVec([poly_decompress(data[i * step:(i + 1) * step], d)
                    for i in range(k)])
