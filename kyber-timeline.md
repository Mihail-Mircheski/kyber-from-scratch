# Kyber Implementation Timeline (7 Weeks)

A plan for implementing Kyber (CRYSTALS-Kyber / ML-KEM) from scratch.

References:
- Round 3 specification: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
- Project site: https://pq-crystals.org/kyber/

The plan works bottom-up: primitives, then the public-key encryption scheme, then the KEM, then hardening. Each week produces something testable against the previous week.

## Week 0 — Prerequisites

Read before starting:
- Spec sections 1–2 (notation, math background: the ring R_q = Z_q[X]/(X^256+1), q = 3329, n = 256).
- Background on Module-LWE, enough to understand what the scheme relies on.

Pick a language. Python works well for a readable reference; port to C or Rust later if performance or constant-time behavior is a goal. This choice affects weeks 6 and 7.

## Week 1 — Field and Polynomial Arithmetic

Spec: sections 2 and 4 (parameter table).

- Modular arithmetic mod q = 3329 (add, sub, mul, Barrett/Montgomery reduction).
- Polynomials in R_q as coefficient arrays of length 256.
- Polynomial add/sub, and schoolbook multiply mod (X^256+1) to use as a correctness reference.
- Vectors and matrices of polynomials (module rank k = 2/3/4).

Deliverable: arithmetic library with unit tests. Random polynomial multiply agrees between schoolbook and, later, NTT.

## Week 2 — NTT and Sampling

Spec: section 1.1 (NTT), section 4.2 (sampling), Algorithm 1 (Parse), section 4.1 (CBD).

- Forward and inverse NTT and the base-case pointwise multiplication. Kyber's NTT is incomplete (128 degree-1 products); this detail needs care.
- Verify NTT-based multiply matches the schoolbook multiply from Week 1.
- Rejection sampling of the public matrix from a seed (Parse / XOF = SHAKE-128).
- Centered binomial distribution sampler CBD.

Deliverable: `A ∘ s` in the NTT domain matches the naive result. Budget the full week for this.

## Week 3 — Symmetric Primitives and Encoding

Spec: section 2.3 (symmetric primitives), section 1.1 (Compress/Decompress, Encode/Decode).

- Add SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 using an existing library.
- Kyber's PRF, XOF, H, G, and KDF wrappers.
- Compress and Decompress with d-bit rounding.
- Encode and Decode byte serialization for polynomials and vectors.

Deliverable: encode/decode round-trips are identity; compress/decompress error stays within the spec bounds. Verify the hash wrappers against published SHA-3 test vectors.

## Week 4 — Kyber.CPAPKE (public-key encryption)

Spec: section 4.2 (KeyGen, Enc, Dec).

- KeyGen: expand the matrix, sample s and e, compute t = A·s + e, serialize keys.
- Enc(pk, m, coins): sample r, e1, e2, compute u and v, compress, serialize the ciphertext.
- Dec(sk, c): recover the message via decompression and rounding.

Deliverable: encrypt/decrypt round-trips for random 32-byte messages across all three parameter sets (Kyber512/768/1024).

## Week 5 — Kyber.CCAKEM (KEM via Fujisaki–Okamoto)

Spec: section 4.3 (KeyGen, Encaps, Decaps).

- KEM KeyGen wraps PKE keygen and stores the hash of the public key plus a rejection secret.
- Encaps: derive the shared secret and ciphertext.
- Decaps: re-encrypt and compare. Implicit rejection returns a pseudo-random key on failure; implement this branch exactly.

Milestone: validate against the official Known Answer Test (KAT) vectors from the project site / NIST submission package. A match confirms correctness. Reproduce the deterministic RNG (AES-256 CTR DRBG) the KATs use so the randomness lines up.

## Week 6 — Hardening and Constant-Time

Spec: section 5 (design rationale), plus the reference C implementation for comparison.

- Remove secret-dependent branches and memory indexing (constant-time compare in Decaps, constant-time CBD and compress).
- Property and fuzz tests: malformed ciphertexts and wrong keys should trigger correct implicit-rejection behavior.
- Compare intermediate values against the reference C code to locate any drift.
- If you targeted ML-KEM instead of Round-3 Kyber, reconcile the FIPS 203 differences here (domain separation, no ciphertext hash in G).

Deliverable: constant-time-reviewed implementation still passing all KATs.

## Week 7 — Optimization, Docs, Wrap-up

- Profile and optimize the hot path (NTT, sampling) if performance matters.
- Optional: benchmark against the reference numbers on the project site.
- Write a README: parameter sets, build and test instructions, KAT results, known limitations.
- Clean the test suite and tag a release.

Deliverable: documented Kyber512/768/1024 implementation, all official KATs passing, constant-time-reviewed.

## Summary

| Week | Focus | Gate |
|------|-------|------|
| 1 | Field and polynomial arithmetic | Schoolbook multiply tested |
| 2 | NTT and sampling | NTT matches schoolbook |
| 3 | SHA-3/SHAKE and encode/compress | Round-trips and SHA-3 vectors |
| 4 | CPA-PKE | Enc/Dec round-trips, all params |
| 5 | CCA-KEM (FO) | Official KATs match |
| 6 | Constant-time and fuzzing | KATs still pass, no secret branches |
| 7 | Optimize and document | Tagged, documented release |

## Notes

Round-3 Kyber vs. FIPS 203 (ML-KEM): these references document Round-3 Kyber. The finalized NIST standard, ML-KEM (FIPS 203, 2024), differs in a few ways (domain separation, dropped ciphertext hash, sample bounds). For a deployable KEM, target ML-KEM and use this spec as background. To match these documents exactly, use Round-3. Decide before Week 4.

**Decided 2026-09-08: Round-3 Kyber.** Chosen because the existing code already followed Round-3 conventions and because the available KAT vectors are the Round-3 ones, which is what allowed the week 5 gate to close. The Week 6 item about reconciling FIPS 203 differences therefore does not apply.

Risk order: weeks 2 (NTT) and 5 (FO plus KATs) are the most likely to stall. Keeping a testable reference at each step means a bug in a later week can be traced back to a specific primitive.
