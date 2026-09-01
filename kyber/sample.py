"""Sampling: the public matrix A and the noise (spec section 1.1).

Two sources of pseudorandomness, both from the SHA-3 family (spec section 2.3):

  - Parse / rej_uniform (Algorithm 1): rejection-sample uniform coefficients in
    Z_q from a SHAKE-128 (XOF) stream to build the matrix A directly in the NTT
    domain.
  - CBD (Algorithm 2): the centered binomial distribution B_eta, drawn from a
    SHAKE-256 (PRF) stream, used for the secret and error terms.

The XOF (SHAKE-128) and PRF (SHAKE-256) wrappers now live in kyber.symmetric;
this module imports them so there is a single definition of each primitive.
"""

from .params import N, Q
from .poly import Poly
from .polyvec import PolyMat
from .symmetric import xof, prf

XOF_BLOCKBYTES = 168  # SHAKE-128 rate


def bytes_to_bits(buf):
    """Spec BytesToBits: bit i is (buf[i//8] >> (i mod 8)) & 1 (LSB first)."""
    bits = []
    for byte in buf:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def cbd(buf, eta):
    """Centered binomial distribution B_eta (spec Algorithm 2).

    Consumes 64*eta bytes and returns a Poly whose coefficients are each a
    difference of two sums of eta bits, i.e. an integer in [-eta, eta].
    """
    if len(buf) != 64 * eta:
        raise ValueError(f"cbd expects {64 * eta} bytes, got {len(buf)}")
    bits = bytes_to_bits(buf)
    coeffs = [0] * N
    for i in range(N):
        a = sum(bits[2 * i * eta + j] for j in range(eta))
        b = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        coeffs[i] = (a - b) % Q
    return Poly(coeffs)


def get_noise(key, nonce, eta):
    """Sample a noise polynomial from B_eta (spec section 1.2, PRF + CBD)."""
    return cbd(prf(key, nonce, 64 * eta), eta)


def rej_uniform(buf, need=N):
    """Parse / rejection sampling (spec Algorithm 1).

    Reads 12-bit little-endian integers from buf, keeping those below q. Returns
    (coefficients, count); count < need means the buffer ran out.
    """
    coeffs = []
    pos = 0
    while len(coeffs) < need and pos + 3 <= len(buf):
        d1 = buf[pos] | ((buf[pos + 1] & 0xF) << 8)
        d2 = (buf[pos + 1] >> 4) | (buf[pos + 2] << 4)
        pos += 3
        if d1 < Q:
            coeffs.append(d1)
        if len(coeffs) < need and d2 < Q:
            coeffs.append(d2)
    return coeffs, len(coeffs)


def gen_poly(rho, i, j):
    """One NTT-domain matrix entry A[i][j], via Parse over a SHAKE-128 stream."""
    nblocks = 3
    length = nblocks * XOF_BLOCKBYTES
    while True:
        buf = xof(rho, i, j, length)
        coeffs, ctr = rej_uniform(buf, N)
        if ctr == N:
            return Poly(coeffs)
        length += XOF_BLOCKBYTES  # extremely rare: squeeze one more block


def gen_matrix(rho, k, transposed=False):
    """Generate the k-by-k public matrix A in the NTT domain (spec section 1.2).

    Matches the reference index convention: entry (i, j) is seeded with (i, j)
    when transposed, else (j, i).
    """
    rows = []
    for i in range(k):
        row = []
        for j in range(k):
            a, b = (i, j) if transposed else (j, i)
            row.append(gen_poly(rho, a, b))
        rows.append(row)
    return PolyMat(rows)
