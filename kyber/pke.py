"""Kyber.CPAPKE -- the IND-CPA public-key encryption scheme (spec section 1.2).

This is the layer everything so far has been building toward. It composes the
earlier weeks directly:

    week 1  Poly / PolyVec arithmetic
    week 2  gen_matrix (Parse over SHAKE-128) and the NTT
    week 3  G / PRF, Compress/Decompress, Encode/Decode

The scheme is Module-LWE in the plainest form. KeyGen publishes

    t = A.s + e

for a secret s and small error e, with A regenerated from a 32-byte seed rho
rather than transmitted. Encryption picks a fresh small r and sends

    u = A^T.r + e1                    v = t^T.r + e2 + Decompress(m, 1)

so that

    v - s^T.u = m*(q/2) + (e^T.r + e2 - s^T.e1)

and the error term is small enough that rounding each coefficient to the nearer
of 0 and q/2 recovers the message bit. Compression of u and v (with du and dv
bits) shrinks the ciphertext and folds extra rounding noise into that same term.

Three implementation details carry over from the earlier modules:

  * A is generated straight into the NTT domain, and s and t are stored there
    too, so the keys are byte-compatible with the reference implementation.
  * The matrix seeding order differs between KeyGen and Enc: KeyGen builds A
    (`transposed=False`, entry (i,j) from XOF(rho, j, i)), Enc builds A^T
    (`transposed=True`). Getting this backwards still round-trips for k = 1 but
    breaks every real parameter set, so both call sites name it explicitly.
  * Montgomery bookkeeping: t_hat stays in the NTT domain and so needs an
    explicit `poly_tomont`, while u and v come back through `poly_invntt`,
    which supplies the compensating factor itself. See kyber/ntt.py.

Randomness is injectable everywhere (`d` in KeyGen, `coins` in Enc). The FO
transform in week 5 requires derandomised encryption, and the KAT vectors
require a reproducible KeyGen.

Spec: Algorithm 4 (KeyGen), Algorithm 5 (Enc), Algorithm 6 (Dec).
"""

import os

from .params import N, Q, PARAMS
from .poly import Poly
from .polyvec import PolyVec
from .ntt import poly_ntt, poly_invntt, poly_tomont, basemul_acc
from .sample import gen_matrix, get_noise
from .symmetric import G
from .encode import (
    POLYBYTES,
    poly_compress,
    poly_decompress,
    polyvec_tobytes,
    polyvec_frombytes,
    polyvec_compress,
    polyvec_decompress,
)

# 32 bytes: the width of every seed, hash output and message in the scheme.
SYMBYTES = 32
MSGBYTES = 32


# -- Parameter-set plumbing -------------------------------------------------

def get_params(level):
    """Look up a parameter set by security level (512, 768 or 1024)."""
    try:
        return PARAMS[level]
    except KeyError:
        raise ValueError(
            f"unknown parameter set {level!r}; expected one of {sorted(PARAMS)}"
        ) from None


def public_key_bytes(level):
    """|pk| = Encode_12(t_hat) || rho."""
    return get_params(level)["k"] * POLYBYTES + SYMBYTES


def secret_key_bytes(level):
    """|sk| = Encode_12(s_hat). (The CCA-KEM in week 5 wraps this in more.)"""
    return get_params(level)["k"] * POLYBYTES


def ciphertext_bytes(level):
    """|c| = Encode_du(Compress(u)) || Encode_dv(Compress(v))."""
    p = get_params(level)
    return p["k"] * 32 * p["du"] + 32 * p["dv"]


def _require_length(name, data, expected):
    if len(data) != expected:
        raise ValueError(f"{name}: expected {expected} bytes, got {len(data)}")


# -- Message <-> polynomial (spec section 1.2) ------------------------------
#
# A message is 32 bytes = 256 bits = one bit per coefficient, at the coarsest
# possible compression width d = 1. So these are just week 3's Compress and
# Decompress with d = 1; the named wrappers exist because the spec talks about
# them as a distinct step and the intent is easy to lose otherwise.

def poly_frommsg(msg):
    """Decompress_q(Decode_1(m), 1): bit b becomes the coefficient b*round(q/2)."""
    _require_length("message", msg, MSGBYTES)
    return poly_decompress(msg, 1)


def poly_tomsg(p):
    """Encode_1(Compress_q(v, 1)): round each coefficient to the nearer of 0, q/2."""
    return poly_compress(p, 1)


# -- Noise sampling ---------------------------------------------------------

def _noise_vec(seed, nonce, eta, k):
    """k noise polynomials from B_eta with consecutive PRF nonces.

    Returns the vector and the next unused nonce, so call sites advance the
    counter the same way the spec's running `N` does.
    """
    vec = PolyVec([get_noise(seed, nonce + i, eta) for i in range(k)])
    return vec, nonce + k


def _ntt_vec(v):
    return PolyVec([poly_ntt(p) for p in v.polys])


# -- Algorithm 4: KeyGen ----------------------------------------------------

def keygen(level=768, d=None):
    """Kyber.CPAPKE.KeyGen(). Returns (pk, sk) as byte strings.

    `d` is the 32-byte seed the spec draws internally; pass it explicitly for
    deterministic tests and for the KAT harness in week 5.
    """
    p = get_params(level)
    k, eta1 = p["k"], p["eta1"]

    if d is None:
        d = os.urandom(SYMBYTES)
    _require_length("seed d", d, SYMBYTES)

    # (rho, sigma) := G(d) -- rho seeds the public matrix, sigma the noise.
    rho, sigma = G(d)

    # A is generated directly in the NTT domain: entry (i, j) from XOF(rho, j, i).
    a_hat = gen_matrix(rho, k, transposed=False)

    nonce = 0
    s, nonce = _noise_vec(sigma, nonce, eta1, k)
    e, nonce = _noise_vec(sigma, nonce, eta1, k)

    s_hat = _ntt_vec(s)
    e_hat = _ntt_vec(e)

    # t_hat := A_hat o s_hat + e_hat. The base products leave an R^-1 factor and
    # nothing here inverse-transforms, so it is cancelled explicitly.
    t_hat = PolyVec([
        poly_tomont(basemul_acc(a_hat.rows[i], s_hat.polys)) + e_hat[i]
        for i in range(k)
    ])

    pk = polyvec_tobytes(t_hat) + rho
    sk = polyvec_tobytes(s_hat)
    return pk, sk


# -- Algorithm 5: Enc -------------------------------------------------------

def encrypt(pk, msg, coins, level=768):
    """Kyber.CPAPKE.Enc(pk, m, r). Returns the ciphertext bytes.

    `coins` is the 32-byte randomness; encryption is a deterministic function
    of it, which is exactly what the FO transform in week 5 relies on.
    """
    p = get_params(level)
    k, eta1, eta2, du, dv = p["k"], p["eta1"], p["eta2"], p["du"], p["dv"]

    _require_length("public key", pk, public_key_bytes(level))
    _require_length("message", msg, MSGBYTES)
    _require_length("coins", coins, SYMBYTES)

    split = k * POLYBYTES
    t_hat = polyvec_frombytes(pk[:split])
    rho = pk[split:]

    # Enc needs A^T, seeded (i, j) rather than (j, i).
    at_hat = gen_matrix(rho, k, transposed=True)

    nonce = 0
    r, nonce = _noise_vec(coins, nonce, eta1, k)
    e1, nonce = _noise_vec(coins, nonce, eta2, k)
    e2 = get_noise(coins, nonce, eta2)

    r_hat = _ntt_vec(r)

    # u := invNTT(A_hat^T o r_hat) + e1
    u = PolyVec([
        poly_invntt(basemul_acc(at_hat.rows[i], r_hat.polys))
        for i in range(k)
    ]) + e1

    # v := invNTT(t_hat^T o r_hat) + e2 + Decompress_q(Decode_1(m), 1)
    v = poly_invntt(basemul_acc(t_hat.polys, r_hat.polys)) + e2 + poly_frommsg(msg)

    return polyvec_compress(u, du) + poly_compress(v, dv)


# -- Algorithm 6: Dec -------------------------------------------------------

def decrypt(sk, ct, level=768):
    """Kyber.CPAPKE.Dec(sk, c). Returns the 32-byte message."""
    p = get_params(level)
    k, du, dv = p["k"], p["du"], p["dv"]

    _require_length("secret key", sk, secret_key_bytes(level))
    _require_length("ciphertext", ct, ciphertext_bytes(level))

    split = k * 32 * du
    u = polyvec_decompress(ct[:split], du, k)
    v = poly_decompress(ct[split:], dv)

    s_hat = polyvec_frombytes(sk)

    # m := Encode_1(Compress_q(v - invNTT(s_hat^T o NTT(u)), 1))
    su = poly_invntt(basemul_acc(s_hat.polys, _ntt_vec(u).polys))
    return poly_tomsg(v - su)


# -- Diagnostics ------------------------------------------------------------

def decryption_noise(sk, ct, msg, level=768):
    """Centred error coefficients of v - s^T.u relative to the encoded message.

    Not part of the scheme. It exposes the quantity decryption actually depends
    on, so the tests can assert the margin to the q/4 decision boundary rather
    than only observing that round-trips happen to work.
    """
    from .reduce import mod_pm

    p = get_params(level)
    k, du, dv = p["k"], p["du"], p["dv"]

    split = k * 32 * du
    u = polyvec_decompress(ct[:split], du, k)
    v = poly_decompress(ct[split:], dv)
    s_hat = polyvec_frombytes(sk)

    mp = v - poly_invntt(basemul_acc(s_hat.polys, _ntt_vec(u).polys))
    expected = poly_frommsg(msg)
    return [mod_pm(a - b) for a, b in zip(mp.coeffs, expected.coeffs)]
