# Kyber from scratch

A readable, from-scratch implementation of **Round-3 CRYSTALS-Kyber**, built
bottom-up following the [7-week timeline](kyber-timeline.md).

**This is Round-3 Kyber, not ML-KEM.** The decision was taken deliberately
before week 4. ML-KEM (FIPS 203, 2024) is the finalized NIST standard and the
one to ship in production; it differs from Round-3 Kyber by a domain-separation
byte in key generation, by dropping the ciphertext hash from the final key
derivation, and by tightened sampling bounds. Same underlying scheme,
incompatible outputs — an ML-KEM implementation and this one will not agree on
keys or shared secrets.

Round-3 was chosen because it is what the specification below documents and
what the available Known Answer Test vectors cover, which is what let the
correctness gate be closed. Porting to ML-KEM would be localized to the KEM
layer and a couple of hash inputs; weeks 1-4 would be essentially untouched,
and it would need NIST's separate ML-KEM vectors to validate against.

References:
- Round 3 specification: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
- Project site: https://pq-crystals.org/kyber/

## Status

**Weeks 1–6 done.** All official KAT vectors pass.

Week 1 — field and polynomial arithmetic:
- `kyber/params.py` — ring parameters (N = 256, q = 3329) and module ranks.
- `kyber/reduce.py` — modular reduction: plain representatives (`mod_plus`,
  `mod_pm`) plus the fast `barrett_reduce` / `montgomery_reduce` techniques
  from the reference implementation.
- `kyber/poly.py` — polynomials in R_q = Z_q[X]/(X^256+1) with add, sub, and
  the schoolbook negacyclic multiply that serves as the correctness oracle.
- `kyber/polyvec.py` — vectors and matrices of polynomials (module rank k).

Week 2 — NTT and sampling:
- `kyber/ntt.py` — the incomplete number-theoretic transform (`ntt`, `invntt`,
  base multiply), the fast `ntt_mul`, and `ntt_matvec` for A.s. Reproduces the
  Kyber reference NTT; validated against the Week 1 schoolbook multiply.
- `kyber/sample.py` — `Parse`/`rej_uniform` (Algorithm 1) to build the matrix A
  from a SHAKE-128 stream, and `cbd` (Algorithm 2) for the centered binomial
  noise from a SHAKE-256 stream. Uses Python's built-in SHAKE.

Week 3 — symmetric primitives and serialization:
- `kyber/symmetric.py` — the SHA-3/SHAKE wrappers Kyber names (`H`, `G`, `PRF`,
  `XOF`, `KDF`), verified against published NIST test vectors. `sample.py` now
  imports its `xof`/`prf` from here (single definition of each primitive).
- `kyber/encode.py` — `Compress_q`/`Decompress_q` (d-bit rounding) and
  `Encode_l`/`Decode_l` byte packing, plus polynomial and vector
  (de)serialization used for keys (12-bit) and ciphertexts (d-bit).
- `kyber/params.py` — full per-level parameter sets (`PARAMS`: k, eta1, eta2,
  du, dv).

Week 4 — Kyber.CPAPKE:
- `kyber/pke.py` — the IND-CPA scheme (spec Algorithms 4, 5, 6): `keygen`,
  `encrypt`, `decrypt` for all three parameter sets. Randomness is injectable
  (`d` for KeyGen, `coins` for Enc), so encryption is a deterministic function
  of its coins — what the FO transform needs in Week 5. Keys are stored in the
  NTT domain (`t_hat`, `s_hat`) so they are byte-compatible with the reference.
  `decryption_noise` is a diagnostic that exposes the error term the tests
  measure against the q/4 decision boundary.
- `kyber/ntt.py` — gained `poly_tomont` and `basemul_acc`. `basemul` leaves an
  R^-1 factor; `invntt` cancels it for u and v, but `t_hat` never leaves the NTT
  domain, so it needs the correction applied explicitly.

Sizes match the published parameters: public keys 800/1184/1568 bytes, CPA
secret keys 768/1152/1536, ciphertexts 768/1088/1568.

Week 5 — Kyber.CCAKEM:
- `kyber/kem.py` — the IND-CCA2 KEM (spec Algorithms 7, 8, 9) via the
  Fujisaki–Okamoto transform: `keygen`, `encaps`, `decaps`. Encapsulation
  derives its encryption coins from the message itself, so decapsulation can
  re-encrypt and compare. A mismatch triggers implicit rejection — a
  pseudo-random key derived from the secret seed `z`, never an error — chosen
  with a constant-time compare and a branchless select. The secret key grows to
  `sk_cpa || pk || H(pk) || z` (1632/2400/3168 bytes).
- `kyber/drbg.py` — AES-256 and the SP 800-90A CTR DRBG the official KAT
  harness uses. Python's standard library has SHA-3 but no AES, and the project
  takes no third-party dependencies, so the block cipher is built here and
  pinned against the FIPS-197 worked example.

Week 6 — hardening and constant-time:
- `kyber/ct.py` — the constant-time primitives in one auditable place:
  branchless sign extension, a conditional move, and a constant-time byte
  compare.
- Two secret-dependent branches removed. `reduce._to_int16` branched on the
  sign bit inside `montgomery_reduce`, which every NTT butterfly over the
  secret vectors s and r calls. `encode.byte_encode` branched per bit while
  serializing the secret key and the recovered message. Both are now
  arithmetic, and `tests/test_ct.py` pins each rewrite against the branching
  version it replaced — `to_int16` over all 65 536 inputs.
- Fuzzing of the rejection path: single-bit flips across the ciphertext,
  random and degenerate ciphertexts, and unrelated keys. Decaps must always
  return 32 bytes, never raise, and never agree.

**Caveat, stated plainly:** CPython gives no real timing guarantee — integers
are arbitrary-precision objects and `bytes` allocate. What this buys is source
with no secret-dependent control flow, which survives a port to C or Rust and
can be checked by reading. Do not treat this Python as timing-hardened in
production.

One week-6 item remains open: the constant-time review of `kyber/drbg.py`,
which uses secret-indexed S-box lookups. It is reachable only from the KAT
harness and never from the scheme, so it was left deliberately. The KATs
passing also settles the "compare against the reference" item -- agreement on
300 cases is a stronger check than spot-comparing intermediates.

## KAT status

**Passing.** All 300 official Known Answer Test cases — 100 per parameter set —
match byte for byte: public key, secret key, ciphertext and shared secret, plus
a decapsulation check on each that the vectors themselves do not record.

The vectors live in `tests/kat/` and come from the Round-3 NIST submission
package. Use the plain files, not the `-90s` variants: those substitute AES and
SHA-2 for the SHA-3 primitives and will not match this implementation.

```
tests/kat/PQCkemKAT_1632.rsp      Kyber512
tests/kat/PQCkemKAT_2400.rsp      Kyber768
tests/kat/PQCkemKAT_3168.rsp      Kyber1024
```

`tests/test_kat.py` re-seeds the AES-256 CTR DRBG from each recorded seed and
drives key generation and encapsulation in the same call order as
`PQCgenKAT_kem.c`. The tests skip if the files are removed, so the suite stays
green on a clone without them.

This is what upgrades the claim from "self-consistent" to "byte-compatible with
the reference implementation".

## Design note

The schoolbook multiply in `poly.py` is deliberately slow but obviously
correct. It is the oracle: the tests cross-check it against a structurally
different reference multiply, and the property tests (identity, multiply-by-X
wraparound, commutativity, distributivity, associativity) pin down the
negacyclic behavior. The Week 2 NTT multiply (`ntt_mul`) is then required to
agree with this oracle on random inputs, and the module gate checks that A.s
computed in the NTT domain matches the naive schoolbook A.s.

Week 4 keeps that oracle in play. Encrypt/decrypt round-trips only show the
implementation agrees with itself — a Montgomery factor dropped in both KeyGen
and Dec would cancel out and still round-trip. So `tests/test_pke.py` also
rebuilds `t = A.s + e` with the Week 1 schoolbook multiply and requires the
serialized `t_hat` to equal its NTT, and it measures the decryption error term
rather than only observing that the message came back.

Week 5 keeps the same discipline. Key agreement round-tripping only shows the
two sides agree with each other; it would still pass if the re-encryption check
were doing nothing at all. So `tests/test_kem.py` builds a ciphertext that
decrypts to exactly the right message but was encrypted with the wrong coins —
well-formed to the PKE layer, and correctly rejected only if the FO check is
live. The remaining gap is the reference implementation itself, which is what
the KAT vectors close.

## Running the tests

No third-party dependencies — the standard library is enough.

```sh
cd kyber-from-scratch
python3 -m unittest discover -s tests -v
```

(`python3 -m pytest` also works if you have pytest installed.)

## Roadmap

| Week | Focus |
|------|-------|
| 1 | Field and polynomial arithmetic ✅ |
| 2 | NTT and sampling ✅ |
| 3 | SHA-3/SHAKE and encode/compress ✅ |
| 4 | Kyber.CPAPKE ✅ |
| 5 | Kyber.CCAKEM (FO transform) + KAT validation ✅ |
| 6 | Constant-time and fuzzing ✅ |
| 7 | Optimization and docs |
