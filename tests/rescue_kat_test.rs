//! Known-answer tests and an independent reference implementation for the
//! Rescue permutation.
//!
//! # Why this file exists
//!
//! Every other Rescue test in this workspace is *self-referential*: it checks
//! determinism, order-sensitivity, `MDS x MDS_INV = I`, or that the constants
//! match a JSON artifact generated from those same constants. None of them
//! constrain the permutation's **output**, so a structural change to the round
//! function leaves them all green.
//!
//! That is not hypothetical. The backward half-round once applied `MDS_INV`,
//! which cancelled the forward half-round's `MDS` and collapsed the permutation
//! into twelve independent per-lane maps with zero cross-lane diffusion — fully
//! defeating the hiding property of the salted commitment (the amount was
//! recoverable from a published commitment). The entire suite passed throughout,
//! because every assertion was internally consistent with the broken
//! permutation.
//!
//! This file closes that class in two ways:
//!
//! 1. [`reference`] re-implements the permutation from its specification in the
//!    most naive way available — schoolbook `u128` modular arithmetic, no
//!    Montgomery form, no precomputed `Felt` matrices, no S-box addition chain.
//!    It shares only the published constants with the optimized code (those are
//!    pinned separately by `test_rescue_constants_hash`). A structural bug has
//!    to be made twice, in two different styles, to survive.
//!
//! 2. The `kat_*` tests pin actual permutation and hash **outputs**. Any change
//!    to the round function — ordering, matrix choice, S-box direction — breaks
//!    them loudly and on purpose.

use ves_stark_primitives::rescue::{
    rescue_hash, rescue_hash_pair, rescue_permutation, ALPHA, ALPHA_INV, MDS, NUM_ROUNDS,
    ROUND_CONSTANTS, STATE_WIDTH,
};
use ves_stark_primitives::{felt_from_u64, felt_to_u64};

/// An independent, deliberately naive implementation of the same permutation.
///
/// Written from the round structure rather than from the optimized code: plain
/// `u128` arithmetic modulo `p = 2^64 - 2^32 + 1`, square-and-multiply
/// exponentiation, and textbook matrix multiplication.
mod reference {
    use super::{ALPHA, ALPHA_INV, MDS, NUM_ROUNDS, ROUND_CONSTANTS, STATE_WIDTH};

    /// Goldilocks prime.
    pub const P: u128 = (1u128 << 64) - (1u128 << 32) + 1;

    fn mul(a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % P) as u64
    }

    fn add(a: u64, b: u64) -> u64 {
        ((a as u128 + b as u128) % P) as u64
    }

    /// Square-and-multiply; no addition chain.
    fn pow(mut base: u64, mut exp: u64) -> u64 {
        let mut acc: u64 = 1;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = mul(acc, base);
            }
            base = mul(base, base);
            exp >>= 1;
        }
        acc
    }

    fn sbox(x: u64) -> u64 {
        pow(x, ALPHA)
    }

    fn sbox_inv(x: u64) -> u64 {
        pow(x, ALPHA_INV)
    }

    /// Textbook matrix-vector product.
    fn mds(state: &[u64; STATE_WIDTH]) -> [u64; STATE_WIDTH] {
        let mut out = [0u64; STATE_WIDTH];
        for (i, row) in MDS.iter().enumerate() {
            let mut acc = 0u64;
            for (j, &c) in row.iter().enumerate() {
                acc = add(acc, mul(c, state[j]));
            }
            out[i] = acc;
        }
        out
    }

    fn add_constants(state: &mut [u64; STATE_WIDTH], c: &[u64; STATE_WIDTH]) {
        for (s, &k) in state.iter_mut().zip(c.iter()) {
            *s = add(*s, k);
        }
    }

    /// The permutation, as specified in `rescue.rs`:
    ///
    /// * forward half-round:  S-box -> MDS -> add constants
    /// * backward half-round: MDS -> inverse S-box -> add constants
    ///
    /// Note the backward half-round applies the **forward** MDS. Applying
    /// `MDS_INV` here is precisely the historical defect described at the top of
    /// this file: it cancels the forward MDS and destroys all diffusion.
    pub fn permutation(state: &mut [u64; STATE_WIDTH]) {
        for round in 0..NUM_ROUNDS {
            // Forward half-round.
            for s in state.iter_mut() {
                *s = sbox(*s);
            }
            *state = mds(state);
            add_constants(state, &ROUND_CONSTANTS[round * 2]);

            // Backward half-round.
            *state = mds(state);
            for s in state.iter_mut() {
                *s = sbox_inv(*s);
            }
            add_constants(state, &ROUND_CONSTANTS[round * 2 + 1]);
        }
    }
}

/// Deterministic, dependency-free test input generator.
fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn optimized(state_u64: [u64; STATE_WIDTH]) -> [u64; STATE_WIDTH] {
    let mut felts = [felt_from_u64(0); STATE_WIDTH];
    for (f, &v) in felts.iter_mut().zip(state_u64.iter()) {
        *f = felt_from_u64(v);
    }
    rescue_permutation(&mut felts);
    let mut out = [0u64; STATE_WIDTH];
    for (o, f) in out.iter_mut().zip(felts.iter()) {
        *o = felt_to_u64(*f);
    }
    out
}

/// The optimized permutation must agree with the naive from-spec reference on
/// every input. This is the check that would have caught the `MDS_INV`
/// diffusion defect on the commit that introduced it.
#[test]
fn optimized_permutation_matches_independent_reference() {
    let mut seed = 0x5645_535F_4B41_5430u64;
    for case in 0..64 {
        let mut input = [0u64; STATE_WIDTH];
        for lane in input.iter_mut() {
            *lane = splitmix64(&mut seed) % reference::P as u64;
        }

        let mut expected = input;
        reference::permutation(&mut expected);
        let actual = optimized(input);

        assert_eq!(
            actual, expected,
            "case {case}: optimized permutation diverges from the from-spec reference\n\
             input:    {input:?}\n\
             expected: {expected:?}\n\
             actual:   {actual:?}"
        );
    }
}

/// Structured edge cases the random generator is unlikely to produce.
#[test]
fn reference_agreement_on_edge_case_states() {
    let p = reference::P as u64;
    let cases: [[u64; STATE_WIDTH]; 5] = [
        [0; STATE_WIDTH],
        [1; STATE_WIDTH],
        [p - 1; STATE_WIDTH],
        {
            let mut s = [0u64; STATE_WIDTH];
            s[0] = 1;
            s
        },
        {
            let mut s = [0u64; STATE_WIDTH];
            for (i, lane) in s.iter_mut().enumerate() {
                *lane = i as u64;
            }
            s
        },
    ];

    for (i, input) in cases.iter().enumerate() {
        let mut expected = *input;
        reference::permutation(&mut expected);
        assert_eq!(
            optimized(*input),
            expected,
            "edge case {i} diverges from the from-spec reference"
        );
    }
}

/// Known-answer vector: the all-zero state.
///
/// These values were produced by a third implementation — a standalone Python
/// script reading `docs/rescue_constants.json` — not by copying this crate's
/// output, so they are an external check rather than a snapshot.
///
/// Pins the permutation's output, not merely its self-consistency. Regenerating
/// this constant is only correct alongside a deliberate, documented change to
/// the permutation — which invalidates every previously issued proof.
#[test]
fn kat_permutation_of_zero_state() {
    let out = optimized([0u64; STATE_WIDTH]);
    assert_eq!(
        out,
        [
            15691095162440443531,
            11696517312817358869,
            16589403534838266721,
            7818620398376714657,
            5858251014388559533,
            10593572620696613148,
            10935987167480697690,
            18416146214891307694,
            16021463253537430205,
            1663223200304625487,
            16974486608359342651,
            6063232593086177394,
        ],
        "Rescue permutation of the zero state changed"
    );
}

/// Known-answer vector for the 2-to-1 Merkle compression, which every Merkle
/// path in the batch AIR depends on.
#[test]
fn kat_hash_pair() {
    let l = [1u64, 2, 3, 4].map(felt_from_u64);
    let r = [5u64, 6, 7, 8].map(felt_from_u64);
    let out = rescue_hash_pair(&l, &r).map(felt_to_u64);
    assert_eq!(
        out,
        [
            6050666348225663397,
            15122080935361975838,
            14866887522145733026,
            17772681253107559530
        ],
        "rescue_hash_pair KAT changed"
    );
}

/// The sponge is what commitments are actually built from, so pin it across
/// several input lengths — including the empty input and inputs that straddle
/// the rate boundary, where absorption logic differs.
#[test]
fn kat_hash_across_input_lengths() {
    let expected: [[u64; 4]; 4] = [
        // len 0 — empty input still permutes once, for domain separation.
        [
            15691095162440443531,
            11696517312817358869,
            16589403534838266721,
            7818620398376714657,
        ],
        // len 1
        [
            6086219427820333800,
            10131663354037557569,
            9909117481061545051,
            9218093228081488245,
        ],
        // len 8 — exactly one full rate block.
        [
            601725881615837329,
            6475117230276662949,
            1592973480011305081,
            4795680691571265276,
        ],
        // len 9 — straddles the rate boundary into a second absorption.
        [
            4238461255610980358,
            5635194165348497145,
            12947016137719865402,
            4403262437302108570,
        ],
    ];
    for (i, len) in [0usize, 1, 8, 9].iter().enumerate() {
        let input: Vec<_> = (0..*len as u64).map(felt_from_u64).collect();
        let out = rescue_hash(&input).map(felt_to_u64);
        assert_eq!(out, expected[i], "rescue_hash KAT changed for length {len}");
    }
}

/// The two MDS layers inside one round are separated only by a constant
/// addition (`... -> MDS -> +c -> MDS -> ...`). Because MDS is linear, they
/// collapse: `MDS * (MDS * y + c) = MDS^2 * y + MDS * c`. The matrix that
/// actually mixes lanes between the two S-box layers is therefore `MDS^2`, not
/// `MDS`, and diffusion depends on `MDS^2` retaining the MDS property.
///
/// This is a real consequence of the round ordering used here (see the note on
/// `half_round_backward`), so it is asserted rather than assumed. Every square
/// submatrix of an MDS matrix must be non-singular; 1x1 and 2x2 are checked
/// exhaustively, which is what a degraded or sparse `MDS^2` would fail first.
#[test]
fn effective_linear_layer_between_sboxes_is_still_mds() {
    const P: u128 = (1u128 << 64) - (1u128 << 32) + 1;
    let mul = |a: u64, b: u64| ((a as u128 * b as u128) % P) as u64;
    let sub = |a: u64, b: u64| ((a as u128 + P - b as u128) % P) as u64;

    // MDS^2 over the Goldilocks field.
    let mut sq = [[0u64; STATE_WIDTH]; STATE_WIDTH];
    for (i, row) in sq.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            // sum_k MDS[i][k] * MDS[k][j]: zip row i's entries with the rows
            // they select, taking column j from each.
            let mut acc = 0u128;
            for (&a, row) in MDS[i].iter().zip(MDS.iter()) {
                acc = (acc + mul(a, row[j]) as u128) % P;
            }
            *cell = acc as u64;
        }
    }

    // 1x1: a zero entry means some output lane ignores some input lane.
    for (i, row) in sq.iter().enumerate() {
        for (j, &v) in row.iter().enumerate() {
            assert_ne!(v, 0, "MDS^2 has a zero entry at ({i}, {j})");
        }
    }

    // 2x2: ad - bc must be non-zero for every pair of rows and columns.
    for r0 in 0..STATE_WIDTH {
        for r1 in (r0 + 1)..STATE_WIDTH {
            for c0 in 0..STATE_WIDTH {
                for c1 in (c0 + 1)..STATE_WIDTH {
                    let d = sub(mul(sq[r0][c0], sq[r1][c1]), mul(sq[r0][c1], sq[r1][c0]));
                    assert_ne!(
                        d, 0,
                        "MDS^2 has a singular 2x2 minor at rows ({r0},{r1}) cols ({c0},{c1})"
                    );
                }
            }
        }
    }
}
