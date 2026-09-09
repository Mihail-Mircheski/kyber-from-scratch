"""Number-theoretic transform for R_q (spec section 1.1, "NTTs, ...").

Because q = 3329 has 256-th roots of unity but not 512-th, X^256 + 1 factors
into 128 quadratics mod q, so the NTT of f is 128 degree-1 polynomials (the
"incomplete" NTT). Multiplication in R_q becomes:

    f * g = invntt( basemul( ntt(f), ntt(g) ) )

which is O(n log n) instead of the O(n^2) schoolbook multiply. This module
reproduces the Kyber reference NTT exactly; its correctness is pinned down by
the tests, which require ntt_mul to agree with Poly.__mul__ (the Week 1 oracle).

Montgomery bookkeeping: the zeta constants are stored in Montgomery form, so
each fqmul cancels one R factor and `ntt` maps to the NTT domain with no extra
factor. `basemul` leaves an R^-1 factor (Montgomery domain); `invntt` folds in a
compensating R via the final scale F, so the round trip lands exactly on f * g.
"""

from .params import N, Q
from .reduce import fqmul, barrett_reduce, montgomery_reduce
from .poly import Poly

# Precomputed twiddle factors (Montgomery form), from the Kyber reference.
# ZETAS[0] is unused; the forward transform consumes indices 1..127.
ZETAS = [
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
     -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
      422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
     -108,  -308,   996,   991,   958, -1460,  1522,  1628,
]

# Final scale for the inverse transform: mont^2 / 128 (mod q).
F = 1441


def ntt(r):
    """Forward NTT, in place on a copy. Input/output are length-N int lists."""
    r = list(r)
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = fqmul(zeta, r[j + length])
                r[j + length] = r[j] - t
                r[j] = r[j] + t
        length >>= 1
    return r


def invntt(r):
    """Inverse NTT (with the Montgomery-compensating final scale F)."""
    r = list(r)
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = r[j]
                r[j] = barrett_reduce(t + r[j + length])
                r[j + length] = r[j + length] - t
                r[j + length] = fqmul(zeta, r[j + length])
        length <<= 1
    for j in range(N):
        r[j] = fqmul(r[j], F)
    return r


def _basemul(a0, a1, b0, b1, zeta):
    """Multiply two degree-1 polynomials mod (X^2 - zeta)."""
    r0 = fqmul(fqmul(a1, b1), zeta) + fqmul(a0, b0)
    r1 = fqmul(a0, b1) + fqmul(a1, b0)
    return r0, r1


def basemul_poly(a, b):
    """Base-case multiply of two NTT-domain polynomials (length-N int lists)."""
    r = [0] * N
    for i in range(N // 4):
        zeta = ZETAS[64 + i]
        r[4 * i], r[4 * i + 1] = _basemul(
            a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1], zeta
        )
        r[4 * i + 2], r[4 * i + 3] = _basemul(
            a[4 * i + 2], a[4 * i + 3], b[4 * i + 2], b[4 * i + 3], -zeta
        )
    return r


# -- Montgomery-domain helpers ---------------------------------------------
#
# `basemul` (and therefore any accumulation of base products) leaves its result
# scaled by R^-1. Two callers care:
#
#   * A full multiply invntt(basemul(a, b)) needs no fix: `invntt` carries a
#     compensating R in its final scale F, so the R^-1 cancels exactly.
#   * A value that stays in the NTT domain -- t_hat in key generation -- has no
#     inverse transform to supply that R, so it is corrected explicitly with
#     `poly_tomont`.

# R^2 mod q. One montgomery_reduce turns a factor of R^2 into a factor of R.
TOMONT_F = (1 << 32) % Q


def poly_tomont(p):
    """Multiply every coefficient by R = 2^16 (mod q).

    Cancels the R^-1 that `basemul` leaves behind, for results kept in the NTT
    domain. Mirrors poly_tomont in the reference implementation.
    """
    return Poly([montgomery_reduce(c * TOMONT_F) for c in p.coeffs])


def basemul_acc(a_polys, b_polys):
    """Inner product of two NTT-domain vectors: sum_j a[j] o b[j].

    The result is one Poly, still in the NTT domain and still carrying the
    R^-1 factor from `basemul` (see the note above). Mirrors
    polyvec_basemul_acc_montgomery in the reference implementation.
    """
    acc = Poly.zero()
    for a, b in zip(a_polys, b_polys):
        acc = acc + poly_basemul(a, b)
    return acc


# -- Poly-level convenience wrappers ---------------------------------------

def poly_ntt(p):
    return Poly(ntt(p.coeffs))


def poly_invntt(p):
    return Poly(invntt(p.coeffs))


def poly_basemul(a, b):
    return Poly(basemul_poly(a.coeffs, b.coeffs))


def ntt_mul(a, b):
    """Full multiplication in R_q via the NTT. Equals Poly.__mul__ exactly."""
    return poly_invntt(poly_basemul(poly_ntt(a), poly_ntt(b)))


def ntt_matvec(A, s):
    """Compute A . s with the products done in the NTT domain.

    Base multiplications accumulate in the NTT (Montgomery) domain, and a single
    inverse transform per row brings the result back. Mirrors how Kyber's key
    generation and encryption actually compute A.s.
    """
    from .polyvec import PolyVec

    out = []
    for row in A.rows:
        acc = Poly.zero()
        for a_ij, s_j in zip(row, s.polys):
            acc = acc + poly_basemul(poly_ntt(a_ij), poly_ntt(s_j))
        out.append(poly_invntt(acc))
    return PolyVec(out)
