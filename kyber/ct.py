"""Constant-time primitives (week 6).

A cryptographic implementation can be perfectly correct and still leak its
secret key through how long it takes to run, or through which cache lines it
touches. The defence is to make the *sequence of operations* independent of
secret data: no branch whose direction depends on a secret, no memory index
derived from one.

This module collects the handful of operations the rest of the package needs
in order to satisfy that. Keeping them in one place means the constant-time
argument lives somewhere auditable rather than being re-derived at each call
site.

A caveat stated plainly: **CPython offers no real timing guarantee.** Integers
are arbitrary-precision objects whose arithmetic cost varies with magnitude,
`bytes` objects allocate, and the interpreter itself introduces timing that
this code cannot control. What these helpers do buy is that the *source* has
no secret-dependent control flow, so the property is preserved through a later
port to C or Rust and can be checked by reading. Treating this Python as
timing-hardened in production would be a mistake, and the README says so.

What counts as secret here:

  secret  s, e, r, e1, e2 (all noise), the message m, the rejection seed z,
          the serialized secret key, the shared secret
  public  rho, the matrix A, the public key, the ciphertext once sent
"""

import hmac


def to_int16(x):
    """Interpret the low 16 bits of x as a signed 16-bit integer.

    Branchless replacement for `if x >= 0x8000: x -= 0x10000`. The subtracted
    term is 0x10000 exactly when the sign bit is set and 0 otherwise, so the
    same arithmetic runs either way.

    This sits inside `montgomery_reduce`, which every NTT butterfly calls, and
    the NTT runs over the secret vectors s and r. It is the hottest
    secret-dependent path in the package.
    """
    x &= 0xFFFF
    return x - ((x & 0x8000) << 1)


def select_bytes(condition, a, b):
    """Return a if condition else b, evaluating both operands either way.

    A conditional move, modelled on `cmov` in the reference implementation.
    The mask is all-ones or all-zeros, so the choice is arithmetic rather than
    a branch. Used by Decaps to substitute the rejection seed without
    revealing that it did.
    """
    if len(a) != len(b):
        raise ValueError(f"length mismatch: {len(a)} vs {len(b)}")
    mask = -int(bool(condition)) & 0xFF
    inverse = ~mask & 0xFF
    return bytes((x & mask) | (y & inverse) for x, y in zip(a, b))


def eq_bytes(a, b):
    """Constant-time equality for byte strings.

    `hmac.compare_digest` is the standard library's constant-time comparison;
    a plain `==` short-circuits at the first differing byte and so leaks how
    long a forged prefix was.
    """
    return hmac.compare_digest(a, b)
