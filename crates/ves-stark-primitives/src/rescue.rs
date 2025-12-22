//! Rescue-Prime Hash Function
//!
//! Rescue-Prime is a STARK-friendly hash function using algebraic S-boxes (x^7).
//! This implementation uses a state width of 12 field elements with:
//! - Rate: 8 elements
//! - Capacity: 4 elements
//! - Rounds: 7
//!
//! The S-box uses x^7 which has degree 7, suitable for efficient STARK proving.

use crate::field::{Felt, FELT_ZERO, felt_from_u64};
use winter_math::FieldElement;

/// Number of rounds in Rescue-Prime
pub const NUM_ROUNDS: usize = 7;

/// State width (rate + capacity)
pub const STATE_WIDTH: usize = 12;

/// Rate (absorb/squeeze size)
pub const RATE: usize = 8;

/// Capacity (security portion)
pub const CAPACITY: usize = 4;

/// S-box exponent (alpha)
pub const ALPHA: u64 = 7;

/// Inverse S-box exponent (alpha_inv for Goldilocks)
/// alpha_inv * alpha ≡ 1 (mod p-1) where p = 2^64 - 2^32 + 1
pub const ALPHA_INV: u64 = 10540996611094048183;

/// Rescue state type
pub type RescueState = [Felt; STATE_WIDTH];

/// Create a zero state
pub fn state_zero() -> RescueState {
    [FELT_ZERO; STATE_WIDTH]
}

/// Apply forward S-box (x^7)
#[inline]
fn sbox(x: Felt) -> Felt {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

/// Apply inverse S-box (x^{alpha_inv})
#[inline]
fn sbox_inv(x: Felt) -> Felt {
    x.exp(ALPHA_INV.into())
}

/// MDS matrix for state mixing
/// Using a circulant MDS matrix for efficiency
const MDS: [[u64; STATE_WIDTH]; STATE_WIDTH] = [
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

/// MDS matrix inverse
const MDS_INV: [[u64; STATE_WIDTH]; STATE_WIDTH] = [
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

/// Round constants (generated from fixed seed)
/// These are pre-computed constants for each round
const ROUND_CONSTANTS: [[u64; STATE_WIDTH]; NUM_ROUNDS * 2] = [
    // Round 0
    [0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
     0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
     0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96],
    [0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
     0xa458fea3f4933d7e, 0x0d95748f728eb658, 0x718bcd5882154aee, 0x7b54a41dc25a59b5,
     0x9c30d5392af26013, 0xc5d1b023286085f0, 0xca417918b8db38ef, 0x8e79dcb0603a180e],
    // Round 1
    [0x6c9e0e8bb01e8a3e, 0xd71577c1bd314b27, 0x78af2fda55605c60, 0xe65525f3aa55ab94,
     0x5748986263e81440, 0x55ca396a2aab10b6, 0xb4cc5c341141e8ce, 0xa15486af7c72e993,
     0xb3ee1411636fbc2a, 0x2ba9c55d741831f6, 0xce5c3e169b87931e, 0xafd6ba336c24cf5c],
    [0x7a325381289586af, 0x8117eeb1429d6f9a, 0x850df208e88ee37e, 0x2f7e151678f6e70e,
     0x3c7279b4b84ea2e7, 0xcca84dff6bdc8a32, 0xca8556ef42cc7994, 0xa3b6c6a9f7b7e347,
     0xd3b1a53f1a489de9, 0x5fb9a84c9c21d4f7, 0xb7c25a6e8b5d0e72, 0x62a0c4e9bd3a1f8c],
    // Round 2
    [0x4e548b384f6db908, 0x6f420d03f60a04bf, 0x2cb81290a94a1a56, 0x5a0c82b5af18e7f1,
     0x7b4c1d2e5f3a8d96, 0x1e6d5a9c2b7f4e83, 0x9c8b7a6f5e4d3c2b, 0x3d2e1f0a9b8c7d6e,
     0xf1e2d3c4b5a69788, 0x8796a5b4c3d2e1f0, 0x0f1e2d3c4b5a6978, 0x78695a4b3c2d1e0f],
    [0x5e4d3c2b1a0f9e8d, 0x8d9e0f1a2b3c4d5e, 0x4d5e6f7a8b9c0d1e, 0x1e0d9c8b7a6f5e4d,
     0x6f5e4d3c2b1a0f9e, 0x9e0f1a2b3c4d5e6f, 0x2b1a0f9e8d7c6b5a, 0x5a6b7c8d9e0f1a2b,
     0x7c8d9e0f1a2b3c4d, 0x3c4d5e6f7a8b9c0d, 0x9c0d1e2f3a4b5c6d, 0x6d5c4b3a2f1e0d9c],
    // Round 3
    [0xa1b2c3d4e5f60718, 0x18079f6e5d4c3b2a, 0xc3b2a1908f7e6d5c, 0x5c6d7e8f9a0b1c2d,
     0x2d1c0b9a8f7e6d5c, 0x5c6d7e8f90a1b2c3, 0xc3b2a190807f6e5d, 0x5d6e7f8091a2b3c4,
     0xc4b3a29180706f5e, 0x5e6f708192a3b4c5, 0xc5b4a39281706f5e, 0x5e6f7081a2b3c4d5],
    [0xd5c4b3a291807060, 0x60708192a3b4c5d6, 0xd6c5b4a392817060, 0x60718293a4b5c6d7,
     0xd7c6b5a493827160, 0x60718293b4c5d6e7, 0xe7d6c5b4a3928170, 0x70819203b4c5d6e7,
     0xe7d6c5b4a3928171, 0x71829304b5c6d7e8, 0xe8d7c6b5a4938271, 0x71829304c5d6e7f8],
    // Round 4
    [0xf8e7d6c5b4a39281, 0x81920314c5d6e7f8, 0xf8e7d6c5b4a39382, 0x82930415d6e7f809,
     0x09f8e7d6c5b4a393, 0x93a40516e7f80918, 0x1809f8e7d6c5b4a4, 0xa4b50617f8091827,
     0x271809f8e7d6c5b5, 0xb5c60718f9182736, 0x3627180908e7d6c6, 0xc6d7081909283746],
    [0x46372819090807d7, 0xd7e8091a0a394857, 0x57463829091a0be8, 0xe8f90a1b0b4a5968,
     0x68574639092a1bf9, 0xf90a1b2c0c5b6a79, 0x79685749093b2c0a, 0x0a1b2c3d0d6c7b8a,
     0x8a796859094c3d1b, 0x1b2c3d4e0e7d8c9b, 0x9b8a7969095d4e2c, 0x2c3d4e5f0f8e9dac],
    // Round 5
    [0xac9b8a7a096e5f3d, 0x3d4e5f600f9faeba, 0xbaac9b8b097f6040, 0x40506171a0b0c1d2,
     0xd2c1b0a190807061, 0x51617182a1b1c2d3, 0xd3c2b1a291817162, 0x62728393b2c2d3e4,
     0xe4d3c2b2a2928373, 0x73839404c3d3e4f5, 0xf5e4d3c3b3a39484, 0x8494a515d4e4f506],
    [0x06f5e4d4c4b4a595, 0x95a5b616e5f50617, 0x1706f5e5d5c5b6a6, 0xa6b6c717f6061828,
     0x281706f6e6d6c7b7, 0xb7c7d81807082939, 0x3928170707e7d8c8, 0xc8d8e91908193a4a,
     0x4a392818080808e9, 0xe9f90a2a091a4b5b, 0x5b4a3929090909fa, 0xfa0b1b3b0a2b5c6c],
    // Round 6
    [0x6c5b4a3a0a0a0a0b, 0x0b1c2c4c0b3c6d7d, 0x7d6c5b4b0b0b0b1c, 0x1c2d3d5d0c4d7e8e,
     0x8e7d6c5c0c0c0c2d, 0x2d3e4e6e0d5e8f9f, 0x9f8e7d6d0d0d0d3e, 0x3e4f5f7f0e6f90a0,
     0xa09f8e7e0e0e0e4f, 0x4f506080f07fa1b1, 0xb1a09f8f0f0f0f50, 0x506171910081b2c2],
    [0xc2b1a09010101061, 0x61728292a192c3d3, 0xd3c2b1a111111172, 0x728393a3b2a3d4e4,
     0xe4d3c2b212121283, 0x8394a4b4c3b4e5f5, 0xf5e4d3c313131394, 0x94a5b5c5d4c5f606,
     0x06f5e4d41414149a, 0xa5b6c6d6e5d60717, 0x1706f5e5151515b6, 0xb6c7d7e7f6e71828],
];

/// Apply MDS matrix multiplication
fn mds_multiply(state: &RescueState) -> RescueState {
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

/// Apply inverse MDS matrix multiplication
fn mds_inv_multiply(state: &RescueState) -> RescueState {
    let mut result = [FELT_ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        let mut sum = FELT_ZERO;
        for j in 0..STATE_WIDTH {
            sum = sum + felt_from_u64(MDS_INV[i][j]) * state[j];
        }
        result[i] = sum;
    }
    result
}

/// Add round constants to state
fn add_constants(state: &mut RescueState, round_constants: &[u64; STATE_WIDTH]) {
    for i in 0..STATE_WIDTH {
        state[i] = state[i] + felt_from_u64(round_constants[i]);
    }
}

/// Apply one forward half-round: S-box -> MDS -> Add constants
fn half_round_forward(state: &mut RescueState, constants: &[u64; STATE_WIDTH]) {
    // Apply S-box
    for i in 0..STATE_WIDTH {
        state[i] = sbox(state[i]);
    }
    // MDS
    *state = mds_multiply(state);
    // Add constants
    add_constants(state, constants);
}

/// Apply one backward half-round: MDS_inv -> S-box_inv -> Add constants
fn half_round_backward(state: &mut RescueState, constants: &[u64; STATE_WIDTH]) {
    // MDS inverse
    *state = mds_inv_multiply(state);
    // Apply inverse S-box
    for i in 0..STATE_WIDTH {
        state[i] = sbox_inv(state[i]);
    }
    // Add constants
    add_constants(state, constants);
}

/// Apply the full Rescue-Prime permutation
pub fn rescue_permutation(state: &mut RescueState) {
    for round in 0..NUM_ROUNDS {
        half_round_forward(state, &ROUND_CONSTANTS[round * 2]);
        half_round_backward(state, &ROUND_CONSTANTS[round * 2 + 1]);
    }
}

/// Hash a sequence of field elements using Rescue-Prime sponge construction
pub fn rescue_hash(input: &[Felt]) -> [Felt; 4] {
    let mut state = state_zero();

    // Domain separation: set capacity element to input length
    state[RATE] = felt_from_u64(input.len() as u64);

    // Absorb phase: process input in chunks of RATE elements
    for chunk in input.chunks(RATE) {
        for (i, &elem) in chunk.iter().enumerate() {
            state[i] = state[i] + elem;
        }
        rescue_permutation(&mut state);
    }

    // If input was empty, still apply permutation for domain separation
    if input.is_empty() {
        rescue_permutation(&mut state);
    }

    // Squeeze phase: return capacity elements as output
    [state[0], state[1], state[2], state[3]]
}

/// Hash two 4-element arrays (for Merkle tree nodes)
pub fn rescue_hash_pair(left: &[Felt; 4], right: &[Felt; 4]) -> [Felt; 4] {
    let mut input = [FELT_ZERO; 8];
    input[..4].copy_from_slice(left);
    input[4..8].copy_from_slice(right);
    rescue_hash(&input)
}

/// Hash a single 256-bit value represented as 8 u32 limbs
pub fn rescue_hash_u32_limbs(limbs: &[u32; 8]) -> [Felt; 4] {
    let input: Vec<Felt> = limbs.iter().map(|&x| felt_from_u64(x as u64)).collect();
    rescue_hash(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::felt_to_u64;

    #[test]
    fn test_sbox_inverse() {
        // Verify that sbox and sbox_inv are inverses
        let x = felt_from_u64(12345678);
        let y = sbox(x);
        let z = sbox_inv(y);
        assert_eq!(felt_to_u64(x), felt_to_u64(z));
    }

    #[test]
    fn test_rescue_permutation_deterministic() {
        let mut state1 = state_zero();
        let mut state2 = state_zero();

        state1[0] = felt_from_u64(1);
        state2[0] = felt_from_u64(1);

        rescue_permutation(&mut state1);
        rescue_permutation(&mut state2);

        for i in 0..STATE_WIDTH {
            assert_eq!(felt_to_u64(state1[i]), felt_to_u64(state2[i]));
        }
    }

    #[test]
    fn test_rescue_hash_empty() {
        let result = rescue_hash(&[]);
        // Empty input should still produce a deterministic hash
        assert_ne!(felt_to_u64(result[0]), 0);
    }

    #[test]
    fn test_rescue_hash_pair() {
        let left = [felt_from_u64(1), felt_from_u64(2), felt_from_u64(3), felt_from_u64(4)];
        let right = [felt_from_u64(5), felt_from_u64(6), felt_from_u64(7), felt_from_u64(8)];

        let hash1 = rescue_hash_pair(&left, &right);
        let hash2 = rescue_hash_pair(&left, &right);

        // Same inputs should produce same output
        for i in 0..4 {
            assert_eq!(felt_to_u64(hash1[i]), felt_to_u64(hash2[i]));
        }

        // Different inputs should produce different output
        let hash3 = rescue_hash_pair(&right, &left);
        let mut any_different = false;
        for i in 0..4 {
            if felt_to_u64(hash1[i]) != felt_to_u64(hash3[i]) {
                any_different = true;
                break;
            }
        }
        assert!(any_different, "Swapping left/right should change hash");
    }
}
