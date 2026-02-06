//! Rescue-Prime AIR Constraints
//!
//! This module defines the constraints for verifying Rescue-Prime hash
//! computations within the STARK. These are used to bind private witness
//! data to public input commitments.

use ves_stark_primitives::rescue::STATE_WIDTH;
use ves_stark_primitives::{felt_from_u64, Felt, FELT_ZERO};

/// Rescue-Prime constants are defined in ves-stark-primitives and re-exported here
pub use ves_stark_primitives::rescue::{MDS, MDS_INV, ROUND_CONSTANTS};

/// Get round constants as field elements
pub fn get_round_constants(round: usize, half: usize) -> [Felt; STATE_WIDTH] {
    let idx = round * 2 + half;
    let mut result = [FELT_ZERO; STATE_WIDTH];
    for (out, &c) in result.iter_mut().zip(ROUND_CONSTANTS[idx].iter()) {
        *out = felt_from_u64(c);
    }
    result
}

/// Compute S-box output (x^7)
pub fn sbox_output(x: Felt) -> Felt {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

/// Apply MDS matrix
pub fn apply_mds(state: &[Felt; STATE_WIDTH]) -> [Felt; STATE_WIDTH] {
    let mut result = [FELT_ZERO; STATE_WIDTH];
    for (i, row) in MDS.iter().enumerate() {
        let mut sum = FELT_ZERO;
        for (&coeff, &s) in row.iter().zip(state.iter()) {
            sum += felt_from_u64(coeff) * s;
        }
        result[i] = sum;
    }
    result
}

/// Constraint: verify S-box transformation
/// Returns the constraint evaluation: out - in^7
pub fn sbox_constraint(input: Felt, output: Felt) -> Felt {
    output - sbox_output(input)
}

/// Constraint: verify MDS transformation
/// Returns an array of constraint evaluations
pub fn mds_constraint(
    input: &[Felt; STATE_WIDTH],
    output: &[Felt; STATE_WIDTH],
) -> [Felt; STATE_WIDTH] {
    let expected = apply_mds(input);
    let mut result = [FELT_ZERO; STATE_WIDTH];
    for ((out, &actual), &exp) in result.iter_mut().zip(output.iter()).zip(expected.iter()) {
        *out = actual - exp;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_constraint() {
        let input = felt_from_u64(5);
        let output = sbox_output(input);
        let constraint = sbox_constraint(input, output);
        assert_eq!(constraint.as_int(), 0);
    }

    #[test]
    fn test_mds_constraint() {
        let input = [felt_from_u64(1); STATE_WIDTH];
        let output = apply_mds(&input);
        let constraints = mds_constraint(&input, &output);
        for c in constraints.iter() {
            assert_eq!(c.as_int(), 0);
        }
    }
}
