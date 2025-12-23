//! Fuzz target for Rescue-Prime hash function
//!
//! This target ensures the hash function:
//! 1. Never panics on any input
//! 2. Produces deterministic output
//! 3. Produces valid field elements

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ves_stark_primitives::rescue::{rescue_hash, rescue_hash_pair, rescue_hash_u32_limbs};
use ves_stark_primitives::{felt_from_u64, Felt};

/// Arbitrary input for rescue_hash
#[derive(Debug, Arbitrary)]
struct RescueHashInput {
    /// Field elements to hash (as u64 values)
    values: Vec<u64>,
}

/// Arbitrary input for rescue_hash_pair
#[derive(Debug, Arbitrary)]
struct RescueHashPairInput {
    left: [u64; 4],
    right: [u64; 4],
}

/// Arbitrary input for rescue_hash_u32_limbs
#[derive(Debug, Arbitrary)]
struct RescueHashLimbsInput {
    limbs: [u32; 8],
}

#[derive(Debug, Arbitrary)]
enum FuzzInput {
    Hash(RescueHashInput),
    HashPair(RescueHashPairInput),
    HashLimbs(RescueHashLimbsInput),
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::Hash(h) => {
            // Limit input size to avoid OOM
            let values: Vec<Felt> = h.values
                .iter()
                .take(100)
                .map(|&v| felt_from_u64(v))
                .collect();

            // Hash should never panic
            let hash1 = rescue_hash(&values);

            // Hash should be deterministic
            let hash2 = rescue_hash(&values);
            assert_eq!(hash1[0].as_int(), hash2[0].as_int());
            assert_eq!(hash1[1].as_int(), hash2[1].as_int());
            assert_eq!(hash1[2].as_int(), hash2[2].as_int());
            assert_eq!(hash1[3].as_int(), hash2[3].as_int());
        }
        FuzzInput::HashPair(p) => {
            let left: [Felt; 4] = p.left.map(felt_from_u64);
            let right: [Felt; 4] = p.right.map(felt_from_u64);

            // Hash should never panic
            let hash1 = rescue_hash_pair(&left, &right);

            // Hash should be deterministic
            let hash2 = rescue_hash_pair(&left, &right);
            assert_eq!(hash1[0].as_int(), hash2[0].as_int());
            assert_eq!(hash1[1].as_int(), hash2[1].as_int());
            assert_eq!(hash1[2].as_int(), hash2[2].as_int());
            assert_eq!(hash1[3].as_int(), hash2[3].as_int());
        }
        FuzzInput::HashLimbs(l) => {
            // Hash should never panic
            let hash1 = rescue_hash_u32_limbs(&l.limbs);

            // Hash should be deterministic
            let hash2 = rescue_hash_u32_limbs(&l.limbs);
            assert_eq!(hash1[0].as_int(), hash2[0].as_int());
            assert_eq!(hash1[1].as_int(), hash2[1].as_int());
            assert_eq!(hash1[2].as_int(), hash2[2].as_int());
            assert_eq!(hash1[3].as_int(), hash2[3].as_int());
        }
    }
});
