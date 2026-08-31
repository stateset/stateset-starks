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

    /// Canonical Rescue-Prime (Rescue-XLIX), as specified in `rescue.rs`:
    ///
    /// * forward half-round:  S-box     -> MDS -> add constants
    /// * backward half-round: S-box_inv -> MDS -> add constants
    ///
    /// Both half-rounds apply the MDS after the S-box, differing only in the
    /// S-box direction. (A previous revision applied the MDS before the inverse
    /// S-box in the backward half — a non-standard variant; see git history.)
    pub fn permutation(state: &mut [u64; STATE_WIDTH]) {
        for round in 0..NUM_ROUNDS {
            // Forward half-round.
            for s in state.iter_mut() {
                *s = sbox(*s);
            }
            *state = mds(state);
            add_constants(state, &ROUND_CONSTANTS[round * 2]);

            // Backward half-round.
            for s in state.iter_mut() {
                *s = sbox_inv(*s);
            }
            *state = mds(state);
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
            7302086185172163127,
            324119935465390126,
            9408200979193655089,
            12756153108341236813,
            11524840374123953959,
            9260672491682336923,
            10628638363629002351,
            16420726786778080814,
            9528334870624610684,
            14704162118618677651,
            12810540684803692553,
            5207264791674842092,
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
            12831364978266134225,
            16241203603470026125,
            10230682936923694459,
            11302295235110243981
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
            7302086185172163127,
            324119935465390126,
            9408200979193655089,
            12756153108341236813,
        ],
        // len 1
        [
            15941290208263087085,
            190741665808472941,
            15167401857387304042,
            6178951341861175305,
        ],
        // len 8 — exactly one full rate block.
        [
            13785543260249572362,
            4316480048539002392,
            2185924351882292215,
            18269957007639383427,
        ],
        // len 9 — straddles the rate boundary into a second absorption.
        [
            10898281362911132113,
            503695227604256536,
            4287510919172478109,
            7701387656612714439,
        ],
    ];
    for (i, len) in [0usize, 1, 8, 9].iter().enumerate() {
        let input: Vec<_> = (0..*len as u64).map(felt_from_u64).collect();
        let out = rescue_hash(&input).map(felt_to_u64);
        assert_eq!(out, expected[i], "rescue_hash KAT changed for length {len}");
    }
}

/// Canonical Rescue-Prime applies the MDS directly between each S-box layer
/// (`sbox -> MDS -> +c -> sbox_inv -> MDS -> +c`), so the lane-mixing layer is
/// `MDS` itself — no longer `MDS^2` as in the previous variant where the two MDS
/// layers were adjacent. Diffusion therefore depends on `MDS` being MDS. Every
/// square submatrix must be non-singular; 1x1 and 2x2 are checked exhaustively.
#[test]
#[allow(clippy::needless_range_loop)] // 2x2 minors need explicit row/col index pairs
fn mds_matrix_is_mds() {
    const P: u128 = (1u128 << 64) - (1u128 << 32) + 1;
    let mul = |a: u64, b: u64| ((a as u128 * b as u128) % P) as u64;
    let sub = |a: u64, b: u64| ((a as u128 + P - b as u128) % P) as u64;

    // 1x1: no zero entry — every output lane depends on every input lane.
    for (i, row) in MDS.iter().enumerate() {
        for (j, &v) in row.iter().enumerate() {
            assert_ne!(v, 0, "MDS has a zero entry at ({i}, {j})");
        }
    }

    // 2x2: ad - bc must be non-zero for every pair of rows and columns.
    for r0 in 0..STATE_WIDTH {
        for r1 in (r0 + 1)..STATE_WIDTH {
            for c0 in 0..STATE_WIDTH {
                for c1 in (c0 + 1)..STATE_WIDTH {
                    let d = sub(mul(MDS[r0][c0], MDS[r1][c1]), mul(MDS[r0][c1], MDS[r1][c0]));
                    assert_ne!(
                        d, 0,
                        "MDS has a singular 2x2 minor at rows ({r0},{r1}) cols ({c0},{c1})"
                    );
                }
            }
        }
    }
}

/// Interop: our permutation's cryptographic components are the audited Rp64_256
/// ones. After the v0.7.0 canonicalization the round *structure* matches
/// Winterfell's `Rp64_256` (sbox -> MDS -> +c ; sbox_inv -> MDS -> +c), and the
/// security-critical constants — MDS, its inverse, and the S-box exponents — are
/// byte-for-byte identical to that audited implementation. Only the round
/// constants differ (ours are pi-based nothing-up-my-sleeve values; Rp64_256
/// uses its own ARK1/ARK2) and the sponge rate/capacity split differs (which
/// affects hashing layout, not the permutation).
///
/// This ties the diffusion layer and S-box to a reviewed reference; a drift in
/// either side breaks the test.
mod rp64_256_interop {
    use ves_stark_primitives::rescue::{ALPHA, ALPHA_INV, MDS, MDS_INV, NUM_ROUNDS, STATE_WIDTH};
    use winter_crypto::hashers::Rp64_256;
    use winter_math::fields::f64::BaseElement;

    #[test]
    fn structural_params_match_rp64_256() {
        assert_eq!(STATE_WIDTH, Rp64_256::STATE_WIDTH);
        assert_eq!(NUM_ROUNDS, Rp64_256::NUM_ROUNDS);
        // Goldilocks S-box exponent and its inverse (Rp64_256's are private, so
        // pin the known values; `test_sbox_inv_addition_chain` checks ALPHA_INV
        // really inverts ALPHA in the field).
        assert_eq!(ALPHA, 7);
        assert_eq!(ALPHA_INV, 10540996611094048183);
    }

    #[test]
    fn mds_matrix_is_the_audited_rp64_256_mds() {
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                assert_eq!(
                    BaseElement::new(MDS[i][j]),
                    Rp64_256::MDS[i][j],
                    "MDS[{i}][{j}] differs from audited Rp64_256"
                );
                assert_eq!(
                    BaseElement::new(MDS_INV[i][j]),
                    Rp64_256::INV_MDS[i][j],
                    "MDS_INV[{i}][{j}] differs from audited Rp64_256"
                );
            }
        }
    }

    /// Records the one deliberate divergence so it stays a conscious choice: our
    /// round constants are NOT Rp64_256's (ours are pi-based nothing-up-my-sleeve).
    #[test]
    fn round_constants_are_our_own_not_rp64_256() {
        use ves_stark_primitives::rescue::ROUND_CONSTANTS;
        // Rp64_256's first ARK1 entry, for contrast.
        assert_ne!(
            BaseElement::new(ROUND_CONSTANTS[0][0]),
            Rp64_256::ARK1[0][0],
            "round constants unexpectedly equal Rp64_256's — update the docs if adopting them"
        );
        // Ours is the pi nothing-up-my-sleeve constant.
        assert_eq!(ROUND_CONSTANTS[0][0], 0x243f_6a88_85a3_08d3);
    }
}
