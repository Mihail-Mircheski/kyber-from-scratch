"""Kyber from scratch — arithmetic, NTT, symmetric primitives, CPA-PKE and CCA-KEM.

The flat names below are the PKE layer, kept as they were. The KEM layer
reuses several of the same names (`keygen`, `secret_key_bytes`), so rather
than shadowing them it is reached through the module: `kyber.kem.keygen`,
`kyber.kem.secret_key_bytes`. `encaps` and `decaps` are unambiguous and are
exported flat.
"""

from .params import N, Q, K_BY_LEVEL, PARAMS
from .reduce import (
    mod_plus,
    mod_pm,
    barrett_reduce,
    montgomery_reduce,
    fqmul,
    MONT,
    QINV,
)
from .poly import Poly
from .polyvec import PolyVec, PolyMat
from .ntt import (
    ntt,
    invntt,
    ntt_mul,
    poly_ntt,
    poly_invntt,
    poly_basemul,
    poly_tomont,
    basemul_acc,
    ntt_matvec,
)
from .sample import cbd, get_noise, gen_poly, gen_matrix
from .symmetric import H, G, prf, xof, kdf
from .encode import (
    compress,
    decompress,
    byte_encode,
    byte_decode,
    poly_tobytes,
    poly_frombytes,
    poly_compress,
    poly_decompress,
    polyvec_tobytes,
    polyvec_frombytes,
    polyvec_compress,
    polyvec_decompress,
)
from .pke import (
    SYMBYTES,
    MSGBYTES,
    get_params,
    public_key_bytes,
    secret_key_bytes,
    ciphertext_bytes,
    poly_frommsg,
    poly_tomsg,
    keygen,
    encrypt,
    decrypt,
    decryption_noise,
)
from . import pke, kem, drbg, ct
from .ct import to_int16, select_bytes, eq_bytes
from .kem import SSBYTES, encaps, decaps

__all__ = [
    "N",
    "Q",
    "K_BY_LEVEL",
    "PARAMS",
    "mod_plus",
    "mod_pm",
    "barrett_reduce",
    "montgomery_reduce",
    "fqmul",
    "MONT",
    "QINV",
    "Poly",
    "PolyVec",
    "PolyMat",
    "ntt",
    "invntt",
    "ntt_mul",
    "poly_ntt",
    "poly_invntt",
    "poly_basemul",
    "poly_tomont",
    "basemul_acc",
    "ntt_matvec",
    "cbd",
    "get_noise",
    "gen_poly",
    "gen_matrix",
    "H",
    "G",
    "prf",
    "xof",
    "kdf",
    "compress",
    "decompress",
    "byte_encode",
    "byte_decode",
    "poly_tobytes",
    "poly_frombytes",
    "poly_compress",
    "poly_decompress",
    "polyvec_tobytes",
    "polyvec_frombytes",
    "polyvec_compress",
    "polyvec_decompress",
    "SYMBYTES",
    "MSGBYTES",
    "get_params",
    "public_key_bytes",
    "secret_key_bytes",
    "ciphertext_bytes",
    "poly_frommsg",
    "poly_tomsg",
    "keygen",
    "encrypt",
    "decrypt",
    "decryption_noise",
    "pke",
    "kem",
    "drbg",
    "ct",
    "to_int16",
    "select_bytes",
    "eq_bytes",
    "SSBYTES",
    "encaps",
    "decaps",
]
