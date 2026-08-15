# Kyber from scratch

A readable, from-scratch implementation of Kyber (CRYSTALS-Kyber / ML-KEM),
built bottom-up following the [7-week timeline](kyber-timeline.md).

References:
- Round 3 specification: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
- Project site: https://pq-crystals.org/kyber/

## Status

**Week 1 — field and polynomial arithmetic.** Done.

- `kyber/params.py` — ring parameters (N = 256, q = 3329) and module ranks.
- `kyber/reduce.py` — modular reduction: plain representatives (`mod_plus`,
  `mod_pm`) plus the fast `barrett_reduce` / `montgomery_reduce` techniques
  from the reference implementation.
- `kyber/poly.py` — polynomials in R_q = Z_q[X]/(X^256+1) with add, sub, and
  the schoolbook negacyclic multiply that serves as the correctness oracle.
- `kyber/polyvec.py` — vectors and matrices of polynomials (module rank k).

## Design note

The schoolbook multiply in `poly.py` is deliberately slow but obviously
correct. It is the oracle: the tests cross-check it against a structurally
different reference multiply, and the property tests (identity, multiply-by-X
wraparound, commutativity, distributivity, associativity) pin down the
negacyclic behavior. When the NTT lands in Week 2, its fast multiply must agree
with this one on random inputs.

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
| 2 | NTT and sampling |
| 3 | SHA-3/SHAKE and encode/compress |
| 4 | Kyber.CPAPKE |
| 5 | Kyber.CCAKEM (FO transform) + KAT validation |
| 6 | Constant-time and fuzzing |
| 7 | Optimization and docs |
