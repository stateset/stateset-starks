//! Rescue-Prime AIR Constraints
//!
//! This module defines the constraints for verifying Rescue-Prime hash
//! computations within the STARK. These are used to bind private witness
//! data to public input commitments.

use ves_stark_primitives::{Felt, felt_from_u64, FELT_ZERO};
use ves_stark_primitives::rescue::{NUM_ROUNDS, STATE_WIDTH};

/// MDS matrix constants (same as in rescue.rs)
pub const MDS: [[u64; STATE_WIDTH]; STATE_WIDTH] = [
    [7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8],
    [8, 7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21],
    [21, 8, 7, 23, 8, 26, 13, 10, 9, 7, 6, 22],
    [22, 21, 8, 7, 23, 8, 26, 13, 10, 9, 7, 6],
    [6, 22, 21, 8, 7, 23, 8, 26, 13, 10, 9, 7],
    [7, 6, 22, 21, 8, 7, 23, 8, 26, 13, 10, 9],
    [9, 7, 6, 22, 21, 8, 7, 23, 8, 26, 13, 10],
    [10, 9, 7, 6, 22, 21, 8, 7, 23, 8, 26, 13],
    [13, 10, 9, 7, 6, 22, 21, 8, 7, 23, 8, 26],
    [26, 13, 10, 9, 7, 6, 22, 21, 8, 7, 23, 8],
    [8, 26, 13, 10, 9, 7, 6, 22, 21, 8, 7, 23],
    [23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8, 7],
];

/// Inverse MDS matrix constants (same as in rescue.rs)
pub const MDS_INV: [[u64; STATE_WIDTH]; STATE_WIDTH] = [
    [14, 15, 2, 13, 6, 4, 12, 9, 8, 3, 7, 11],
    [11, 14, 15, 2, 13, 6, 4, 12, 9, 8, 3, 7],
    [7, 11, 14, 15, 2, 13, 6, 4, 12, 9, 8, 3],
    [3, 7, 11, 14, 15, 2, 13, 6, 4, 12, 9, 8],
    [8, 3, 7, 11, 14, 15, 2, 13, 6, 4, 12, 9],
    [9, 8, 3, 7, 11, 14, 15, 2, 13, 6, 4, 12],
    [12, 9, 8, 3, 7, 11, 14, 15, 2, 13, 6, 4],
    [4, 12, 9, 8, 3, 7, 11, 14, 15, 2, 13, 6],
    [6, 4, 12, 9, 8, 3, 7, 11, 14, 15, 2, 13],
    [13, 6, 4, 12, 9, 8, 3, 7, 11, 14, 15, 2],
    [2, 13, 6, 4, 12, 9, 8, 3, 7, 11, 14, 15],
    [15, 2, 13, 6, 4, 12, 9, 8, 3, 7, 11, 14],
];

/// Round constants for Rescue-Prime (simplified subset for constraint reference)
pub const ROUND_CONSTANTS: [[u64; STATE_WIDTH]; NUM_ROUNDS * 2] = [
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
     0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
     0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96],
    [0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
     0xa458fea3f4933d7e, 0x0d95748f728eb658, 0x718bcd5882154aee, 0x7b54a41dc25a59b5,
     0x9c30d5392af26013, 0xc5d1b023286085f0, 0xca417918b8db38ef, 0x8e79dcb0603a180e],
    [0x6c9e0e8bb01e8a3e, 0xd71577c1bd314b27, 0x78af2fda55605c60, 0xe65525f3aa55ab94,
     0x5748986263e81440, 0x55ca396a2aab10b6, 0xb4cc5c341141e8ce, 0xa15486af7c72e993,
     0xb3ee1411636fbc2a, 0x2ba9c55d741831f6, 0xce5c3e169b87931e, 0xafd6ba336c24cf5c],
    [0x7a325381289586af, 0x8117eeb1429d6f9a, 0x850df208e88ee37e, 0x2f7e151678f6e70e,
     0x3c7279b4b84ea2e7, 0xcca84dff6bdc8a32, 0xca8556ef42cc7994, 0xa3b6c6a9f7b7e347,
     0xd3b1a53f1a489de9, 0x5fb9a84c9c21d4f7, 0xb7c25a6e8b5d0e72, 0x62a0c4e9bd3a1f8c],
    [0x4e548b384f6db908, 0x6f420d03f60a04bf, 0x2cb81290a94a1a56, 0x5a0c82b5af18e7f1,
     0x7b4c1d2e5f3a8d96, 0x1e6d5a9c2b7f4e83, 0x9c8b7a6f5e4d3c2b, 0x3d2e1f0a9b8c7d6e,
     0xf1e2d3c4b5a69788, 0x8796a5b4c3d2e1f0, 0x0f1e2d3c4b5a6978, 0x78695a4b3c2d1e0f],
    [0x5e4d3c2b1a0f9e8d, 0x8d9e0f1a2b3c4d5e, 0x4d5e6f7a8b9c0d1e, 0x1e0d9c8b7a6f5e4d,
     0x6f5e4d3c2b1a0f9e, 0x9e0f1a2b3c4d5e6f, 0x2b1a0f9e8d7c6b5a, 0x5a6b7c8d9e0f1a2b,
     0x7c8d9e0f1a2b3c4d, 0x3c4d5e6f7a8b9c0d, 0x9c0d1e2f3a4b5c6d, 0x6d5c4b3a2f1e0d9c],
    [0xa1b2c3d4e5f60718, 0x18079f6e5d4c3b2a, 0xc3b2a1908f7e6d5c, 0x5c6d7e8f9a0b1c2d,
     0x2d1c0b9a8f7e6d5c, 0x5c6d7e8f90a1b2c3, 0xc3b2a190807f6e5d, 0x5d6e7f8091a2b3c4,
     0xc4b3a29180706f5e, 0x5e6f708192a3b4c5, 0xc5b4a39281706f5e, 0x5e6f7081a2b3c4d5],
    [0xd5c4b3a291807060, 0x60708192a3b4c5d6, 0xd6c5b4a392817060, 0x60718293a4b5c6d7,
     0xd7c6b5a493827160, 0x60718293b4c5d6e7, 0xe7d6c5b4a3928170, 0x70819203b4c5d6e7,
     0xe7d6c5b4a3928171, 0x71829304b5c6d7e8, 0xe8d7c6b5a4938271, 0x71829304c5d6e7f8],
    [0xf8e7d6c5b4a39281, 0x81920314c5d6e7f8, 0xf8e7d6c5b4a39382, 0x82930415d6e7f809,
     0x09f8e7d6c5b4a393, 0x93a40516e7f80918, 0x1809f8e7d6c5b4a4, 0xa4b50617f8091827,
     0x271809f8e7d6c5b5, 0xb5c60718f9182736, 0x3627180908e7d6c6, 0xc6d7081909283746],
    [0x46372819090807d7, 0xd7e8091a0a394857, 0x57463829091a0be8, 0xe8f90a1b0b4a5968,
     0x68574639092a1bf9, 0xf90a1b2c0c5b6a79, 0x79685749093b2c0a, 0x0a1b2c3d0d6c7b8a,
     0x8a796859094c3d1b, 0x1b2c3d4e0e7d8c9b, 0x9b8a7969095d4e2c, 0x2c3d4e5f0f8e9dac],
    [0xac9b8a7a096e5f3d, 0x3d4e5f600f9faeba, 0xbaac9b8b097f6040, 0x40506171a0b0c1d2,
     0xd2c1b0a190807061, 0x51617182a1b1c2d3, 0xd3c2b1a291817162, 0x62728393b2c2d3e4,
     0xe4d3c2b2a2928373, 0x73839404c3d3e4f5, 0xf5e4d3c3b3a39484, 0x8494a515d4e4f506],
    [0x06f5e4d4c4b4a595, 0x95a5b616e5f50617, 0x1706f5e5d5c5b6a6, 0xa6b6c717f6061828,
     0x281706f6e6d6c7b7, 0xb7c7d81807082939, 0x3928170707e7d8c8, 0xc8d8e91908193a4a,
     0x4a392818080808e9, 0xe9f90a2a091a4b5b, 0x5b4a3929090909fa, 0xfa0b1b3b0a2b5c6c],
    [0x6c5b4a3a0a0a0a0b, 0x0b1c2c4c0b3c6d7d, 0x7d6c5b4b0b0b0b1c, 0x1c2d3d5d0c4d7e8e,
     0x8e7d6c5c0c0c0c2d, 0x2d3e4e6e0d5e8f9f, 0x9f8e7d6d0d0d0d3e, 0x3e4f5f7f0e6f90a0,
     0xa09f8e7e0e0e0e4f, 0x4f506080f07fa1b1, 0xb1a09f8f0f0f0f50, 0x506171910081b2c2],
    [0xc2b1a09010101061, 0x61728292a192c3d3, 0xd3c2b1a111111172, 0x728393a3b2a3d4e4,
     0xe4d3c2b212121283, 0x8394a4b4c3b4e5f5, 0xf5e4d3c313131394, 0x94a5b5c5d4c5f606,
     0x06f5e4d41414149a, 0xa5b6c6d6e5d60717, 0x1706f5e5151515b6, 0xb6c7d7e7f6e71828],
];

/// Get round constants as field elements
pub fn get_round_constants(round: usize, half: usize) -> [Felt; STATE_WIDTH] {
    let idx = round * 2 + half;
    let mut result = [FELT_ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        result[i] = felt_from_u64(ROUND_CONSTANTS[idx][i]);
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
    for i in 0..STATE_WIDTH {
        let mut sum = FELT_ZERO;
        for j in 0..STATE_WIDTH {
            sum = sum + felt_from_u64(MDS[i][j]) * state[j];
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
pub fn mds_constraint(input: &[Felt; STATE_WIDTH], output: &[Felt; STATE_WIDTH]) -> [Felt; STATE_WIDTH] {
    let expected = apply_mds(input);
    let mut result = [FELT_ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        result[i] = output[i] - expected[i];
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
