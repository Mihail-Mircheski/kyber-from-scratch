"""Global Kyber parameters (Round-3 spec, section 1.1 and 1.4).

Only the values needed for Week 1 arithmetic are defined here. Noise and
compression parameters are added in later weeks.
"""

# Ring R_q = Z_q[X] / (X^N + 1)
N = 256
Q = 3329

# Module ranks per parameter set (spec section 1.4).
# Not used by the Week 1 arithmetic itself, but the vector/matrix code is
# written to work for any of these k values.
K_BY_LEVEL = {
    512: 2,
    768: 3,
    1024: 4,
}
