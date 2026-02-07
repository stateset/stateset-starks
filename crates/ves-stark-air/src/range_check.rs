//! Range Check Constraints for VES STARK
//!
//! This module provides range proof constraints to verify that field elements
//! represent valid unsigned integers within a specified range.
//!
//! # Overview
//!
//! Range proofs are essential for ensuring that limbs in the comparison gadget
//! are actually valid u32 values. Without range proofs, a malicious prover could
//! use field elements that "wrap around" and provide false comparison results.
//!
//! # Strategies
//!
//! ## 1. Binary Decomposition (Full Security)
//!
//! The most secure approach decomposes each limb into 32 bits:
//! - For each bit b_i: b_i * (1 - b_i) = 0 (ensures bit is 0 or 1)
//! - Limb = sum(b_i * 2^i) for i in 0..32
//!
//! This requires 32 additional columns per limb (256 total for 8 limbs).
//!
//! ## 2. Lookup Arguments (Efficient)
//!
//! For smaller ranges, lookup arguments can be used:
//! - Pre-compute a table of valid values
//! - Prove each limb exists in the table
//!
//! Winterfell supports this via the LogUp protocol.
//!
//! ## 3. Hybrid (Current Implementation)
//!
//! For Phase 1, the AIR enforces range validity for the active u64 limbs:
//! - Amount limbs 0-1 are bit-decomposed into 32 bits each in the trace and constrained in-AIR
//! - Diff limbs 0-1 (subtraction witness) are bit-decomposed similarly
//! - Limbs 2-7 are boundary-asserted to 0 (so the value is a u64)
//!
//! # Security Note
//!
//! Witness-time limb validation is still performed for early error reporting, but the verifier
//! does not rely on honest witness construction for the enforced u64 range.

use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};

/// Maximum value for a u32 limb
pub const U32_MAX: u64 = 0xFFFFFFFF;

/// Number of bits in a u32
pub const U32_BITS: usize = 32;

/// Binary decomposition of a u32 value
///
/// Returns 32 field elements, each 0 or 1, representing the binary form.
/// Index 0 is the LSB, index 31 is the MSB.
pub fn decompose_u32(value: u32) -> [Felt; U32_BITS] {
    let mut bits = [FELT_ZERO; U32_BITS];
    for (i, bit) in bits.iter_mut().enumerate() {
        if (value >> i) & 1 == 1 {
            *bit = FELT_ONE;
        }
    }
    bits
}

/// Recompose a u32 from its binary decomposition
///
/// Computes sum(bits[i] * 2^i) for i in 0..32
pub fn recompose_u32(bits: &[Felt; U32_BITS]) -> Felt {
    let mut result = FELT_ZERO;
    let mut power = FELT_ONE;
    let two = felt_from_u64(2);

    for &bit in bits.iter() {
        result += bit * power;
        power *= two;
    }
    result
}

/// Binary constraint: b * (1 - b) = 0
///
/// This constraint is satisfied iff b is 0 or 1.
/// Returns the constraint evaluation.
pub fn binary_constraint(b: Felt) -> Felt {
    b * (FELT_ONE - b)
}

/// Range check constraint for a u32 limb using binary decomposition
///
/// This constraint set ensures:
/// 1. Each bit is binary (0 or 1)
/// 2. The limb equals the sum of its bits
///
/// Returns (binary_constraints, recomposition_constraint)
pub fn u32_range_check(limb: Felt, bits: &[Felt; U32_BITS]) -> ([Felt; U32_BITS], Felt) {
    // Binary constraints
    let mut binary_constraints = [FELT_ZERO; U32_BITS];
    for (out, &bit) in binary_constraints.iter_mut().zip(bits.iter()) {
        *out = binary_constraint(bit);
    }

    // Recomposition constraint
    let recomposed = recompose_u32(bits);
    let recomposition_constraint = limb - recomposed;

    (binary_constraints, recomposition_constraint)
}

/// Check if a field element is a valid u32 (witness-time check)
///
/// This is used during witness construction to validate limbs.
pub fn is_valid_u32(value: Felt) -> bool {
    value.as_int() <= U32_MAX
}

/// Validate all limbs in an array are valid u32 values
pub fn validate_limbs(limbs: &[Felt; 8]) -> bool {
    limbs.iter().all(|l| is_valid_u32(*l))
}

/// Range check data for the trace
///
/// If binary decomposition is used, this holds the bit columns.
#[derive(Debug, Clone)]
pub struct RangeCheckData {
    /// Binary decomposition of each limb (8 limbs × 32 bits)
    pub bit_decomposition: [[Felt; U32_BITS]; 8],
}

impl RangeCheckData {
    /// Create range check data from limbs
    pub fn from_limbs(limbs: &[Felt; 8]) -> Option<Self> {
        let mut bit_decomposition = [[FELT_ZERO; U32_BITS]; 8];

        for (i, limb) in limbs.iter().enumerate() {
            let value = limb.as_int();
            if value > U32_MAX {
                return None; // Invalid limb
            }
            bit_decomposition[i] = decompose_u32(value as u32);
        }

        Some(Self { bit_decomposition })
    }

    /// Verify all constraints are satisfied
    pub fn verify(&self, limbs: &[Felt; 8]) -> bool {
        for (i, limb) in limbs.iter().enumerate() {
            let (binary_constraints, recomp) = u32_range_check(*limb, &self.bit_decomposition[i]);

            // Check all binary constraints
            for bc in binary_constraints.iter() {
                if bc.as_int() != 0 {
                    return false;
                }
            }

            // Check recomposition
            if recomp.as_int() != 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompose_recompose() {
        for value in [0u32, 1, 255, 65535, 0xFFFFFFFF, 12345678] {
            let bits = decompose_u32(value);
            let recomposed = recompose_u32(&bits);
            assert_eq!(recomposed.as_int(), value as u64);
        }
    }

    #[test]
    fn test_binary_constraint() {
        // 0 and 1 should satisfy the constraint
        assert_eq!(binary_constraint(FELT_ZERO).as_int(), 0);
        assert_eq!(binary_constraint(FELT_ONE).as_int(), 0);

        // Other values should not
        assert_ne!(binary_constraint(felt_from_u64(2)).as_int(), 0);
        assert_ne!(binary_constraint(felt_from_u64(3)).as_int(), 0);
    }

    #[test]
    fn test_u32_range_check() {
        let value = 12345u32;
        let limb = felt_from_u64(value as u64);
        let bits = decompose_u32(value);

        let (binary_constraints, recomp) = u32_range_check(limb, &bits);

        // All binary constraints should be zero
        for bc in binary_constraints.iter() {
            assert_eq!(bc.as_int(), 0);
        }

        // Recomposition should match
        assert_eq!(recomp.as_int(), 0);
    }

    #[test]
    fn test_is_valid_u32() {
        assert!(is_valid_u32(FELT_ZERO));
        assert!(is_valid_u32(FELT_ONE));
        assert!(is_valid_u32(felt_from_u64(U32_MAX)));
        assert!(!is_valid_u32(felt_from_u64(U32_MAX + 1)));
    }

    #[test]
    fn test_range_check_data() {
        let limbs = [
            felt_from_u64(100),
            felt_from_u64(200),
            felt_from_u64(300),
            felt_from_u64(400),
            FELT_ZERO,
            FELT_ZERO,
            FELT_ZERO,
            FELT_ZERO,
        ];

        let data = RangeCheckData::from_limbs(&limbs).unwrap();
        assert!(data.verify(&limbs));
    }

    #[test]
    fn test_range_check_data_invalid() {
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(U32_MAX + 1); // Invalid

        assert!(RangeCheckData::from_limbs(&limbs).is_none());
    }

    #[test]
    fn test_validate_limbs() {
        let valid = [felt_from_u64(1000); 8];
        assert!(validate_limbs(&valid));

        let mut invalid = [FELT_ZERO; 8];
        invalid[0] = felt_from_u64(U32_MAX + 1);
        assert!(!validate_limbs(&invalid));
    }
}
