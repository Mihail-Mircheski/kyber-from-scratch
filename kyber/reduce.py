"""Modular reduction mod q = 3329.

Two layers:

1. ``mod_plus`` / ``mod_pm`` are the plain, obviously-correct representatives
   from the spec (section 1.1, "Modular reductions"). The polynomial layer uses
   these so its correctness is easy to see.

2. ``barrett_reduce`` and ``montgomery_reduce`` reproduce the fast fixed-width
   techniques from the Kyber reference implementation. They are verified against
   ``% Q`` in the tests. Montgomery is primarily needed for the NTT in Week 2.
"""

from .params import Q
from .ct import to_int16

# 2^16 mod Q, used as the Montgomery factor R.
MONT = 2285
# Q^{-1} mod 2^16, i.e. Q * QINV == 1 (mod 2^16).
QINV = 62209

# Barrett constant: round(2^26 / Q).
_BARRETT_V = ((1 << 26) + Q // 2) // Q


def mod_plus(a, alpha=Q):
    """Representative in [0, alpha) (spec: ``mod+``)."""
    return a % alpha


def mod_pm(a, alpha=Q):
    """Centered representative (spec: ``mod±``).

    For odd alpha the range is [-(alpha-1)/2, (alpha-1)/2].
    For even alpha the range is (-alpha/2, alpha/2].
    """
    r = a % alpha
    if alpha % 2 == 0:
        if r > alpha // 2:
            r -= alpha
    else:
        if r > (alpha - 1) // 2:
            r -= alpha
    return r


def _to_int16(x):
    """Interpret the low 16 bits of x as a signed 16-bit integer.

    Week 6 moved the body into kyber.ct and made it branchless. The original
    ``if x >= 0x8000`` was a branch on secret data: this runs inside every NTT
    butterfly, and the NTT is applied to the secret vectors s and r.
    """
    return to_int16(x)


def barrett_reduce(a):
    """Reduce a to a representative congruent to a mod Q.

    Matches the Kyber reference barrett_reduce. Valid for a in the signed
    16-bit range; the result is congruent to a (mod Q) with magnitude < Q.
    """
    t = (_BARRETT_V * a + (1 << 25)) >> 26
    t *= Q
    return a - t


def montgomery_reduce(a):
    """Return a * R^{-1} mod Q, where R = 2^16.

    Matches the Kyber reference montgomery_reduce. Valid for a in
    [-Q * 2^15, Q * 2^15); the result is congruent to a * R^{-1} (mod Q)
    with magnitude < Q.
    """
    t = _to_int16(a * QINV)
    t = (a - t * Q) >> 16  # Python >> is an arithmetic (floor) shift
    return t


def fqmul(a, b):
    """Montgomery multiplication: (a * b * R^{-1}) mod Q.

    This is the base-field multiply used by the NTT (Week 2). Included here so
    the whole reduction toolkit lives in one place.
    """
    return montgomery_reduce(a * b)
