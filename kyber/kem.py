"""Kyber.CCAKEM -- the IND-CCA2 key encapsulation mechanism (spec section 4.3).

Week 4 built Kyber.CPAPKE, which is secure only against a passive eavesdropper.
An attacker who can submit ciphertexts of their own choosing and observe whether
decryption succeeds can recover the secret key from it. This module closes that
gap with the Fujisaki--Okamoto transform, which turns the CPA-secure encryption
scheme into a CCA-secure KEM.

The idea is to make the encryption deterministic and then have the receiver
check it. Encapsulation draws a random 32-byte message m, derives the encryption
coins from m itself, and encrypts. Decapsulation recovers m', re-derives the
coins the same way, re-encrypts, and compares the result against the ciphertext
it was handed. An honest ciphertext reproduces exactly; anything tampered with
does not. This is why week 4 made `coins` an explicit argument rather than
drawing them internally -- without that, the receiver could not repeat the
sender's work.

Implicit rejection is the other half. On mismatch the KEM does not raise or
return an error code; it returns a pseudo-random key derived from a secret
rejection seed z stored in the secret key. An attacker therefore cannot tell a
malformed ciphertext from a well-formed one: both yield 32 bytes that look
uniform, and only the legitimate holder of the matching ciphertext gets a key
that agrees with the sender's. Leaking which happened is exactly the oracle the
FO transform exists to remove, so this branch is implemented with a
constant-time compare and a branchless select rather than an `if`.

The secret key grows to carry everything decapsulation needs:

    sk = sk_cpa || pk || H(pk) || z

pk is there so decapsulation can re-encrypt, H(pk) is cached because it is
needed on every call, and z is the rejection seed.

Spec: Algorithm 7 (KeyGen), Algorithm 8 (Encaps), Algorithm 9 (Decaps).
"""

import os

from . import pke
from .pke import SYMBYTES, get_params, public_key_bytes, ciphertext_bytes
from .ct import eq_bytes, select_bytes
from .symmetric import H, G, kdf

# The shared secret is 32 bytes at every security level.
SSBYTES = 32


# -- Key sizes --------------------------------------------------------------

def secret_key_bytes(level):
    """|sk| = sk_cpa || pk || H(pk) || z."""
    return (pke.secret_key_bytes(level) + pke.public_key_bytes(level)
            + SYMBYTES + SYMBYTES)


def _split_secret_key(sk, level):
    """Cut the KEM secret key into (sk_cpa, pk, H(pk), z)."""
    n_cpa = pke.secret_key_bytes(level)
    n_pk = pke.public_key_bytes(level)
    return (sk[:n_cpa],
            sk[n_cpa:n_cpa + n_pk],
            sk[n_cpa + n_pk:n_cpa + n_pk + SYMBYTES],
            sk[n_cpa + n_pk + SYMBYTES:])


# Week 6 moved these into kyber.ct so the constant-time argument lives in one
# audited place. The alias keeps the original private name working.
_select = select_bytes


# -- Algorithm 7: KeyGen ----------------------------------------------------

def keygen(level=768, d=None, z=None):
    """Kyber.CCAKEM.KeyGen(). Returns (pk, sk).

    `d` seeds the underlying PKE key pair and `z` is the rejection seed; both
    are injectable so the KAT harness can drive the whole scheme from a
    deterministic RNG.
    """
    pk, sk_cpa = pke.keygen(level, d)

    if z is None:
        z = os.urandom(SYMBYTES)
    if len(z) != SYMBYTES:
        raise ValueError(f"rejection seed z: expected {SYMBYTES} bytes, got {len(z)}")

    return pk, sk_cpa + pk + H(pk) + z


# -- Algorithm 8: Encaps ----------------------------------------------------

def encaps(pk, level=768, seed=None):
    """Kyber.CCAKEM.Enc(pk). Returns (ciphertext, shared_secret).

    The spec hashes the sampled randomness before use (line 2, `m := H(m)`), so
    a caller cannot steer the plaintext even by supplying a biased seed.
    """
    if len(pk) != public_key_bytes(level):
        raise ValueError(
            f"public key: expected {public_key_bytes(level)} bytes, got {len(pk)}")

    if seed is None:
        seed = os.urandom(SYMBYTES)
    if len(seed) != SYMBYTES:
        raise ValueError(f"seed: expected {SYMBYTES} bytes, got {len(seed)}")

    m = H(seed)

    # (K_bar, r) := G(m || H(pk)). Binding the public key here stops a
    # ciphertext valid under one key from being replayed under another.
    k_bar, r = G(m + H(pk))

    ct = pke.encrypt(pk, m, r, level)
    ss = kdf(k_bar + H(ct), SSBYTES)
    return ct, ss


# -- Algorithm 9: Decaps ----------------------------------------------------

def decaps(sk, ct, level=768):
    """Kyber.CCAKEM.Dec(sk, c). Returns the 32-byte shared secret.

    Never raises on a bad ciphertext: a mismatch yields a pseudo-random key
    derived from z. That is the implicit rejection the FO transform requires.
    """
    if len(sk) != secret_key_bytes(level):
        raise ValueError(
            f"secret key: expected {secret_key_bytes(level)} bytes, got {len(sk)}")
    if len(ct) != ciphertext_bytes(level):
        raise ValueError(
            f"ciphertext: expected {ciphertext_bytes(level)} bytes, got {len(ct)}")

    sk_cpa, pk, h, z = _split_secret_key(sk, level)

    m2 = pke.decrypt(sk_cpa, ct, level)
    k_bar2, r2 = G(m2 + h)

    # Re-encrypt with the coins the sender would have used and compare.
    ct2 = pke.encrypt(pk, m2, r2, level)
    ok = eq_bytes(ct, ct2)

    # On failure substitute z for K_bar, then derive the key either way.
    pre = select_bytes(ok, k_bar2, z)
    return kdf(pre + H(ct), SSBYTES)
