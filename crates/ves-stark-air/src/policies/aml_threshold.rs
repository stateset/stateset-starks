//! AML Threshold Policy Constraints
//!
//! This policy proves that an amount (from the encrypted payload) is strictly
//! less than a given threshold, without revealing the actual amount.
//!
//! # Constraint Strategy
//!
//! To prove `amount < threshold` we use a comparison gadget that works on
//! u32 limbs (8 limbs = 256 bits, though we typically only use lower limbs).
//!
//! The comparison is done lexicographically from high limb to low limb:
//! - If high limbs are equal, compare next lower limbs
//! - If high limb of amount < high limb of threshold, amount < threshold
//! - We track a "less than" flag and an "equal" flag through the comparison
//!
//! # Range Check
//!
//! We also need to prove that each limb is a valid u32 (< 2^32).
//! This is done by decomposing each limb into bits and constraining
//! the bit decomposition.

use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};

/// AML Threshold Policy
#[derive(Debug, Clone)]
pub struct AmlThresholdPolicy {
    /// The threshold value (amount must be strictly less than this)
    pub threshold: u64,
}

impl AmlThresholdPolicy {
    /// Create a new AML threshold policy
    pub fn new(threshold: u64) -> Self {
        Self { threshold }
    }

    /// Convert threshold to field element limbs (low to high)
    /// For u64, we only need 2 limbs (2 x u32)
    pub fn threshold_limbs(&self) -> [Felt; 8] {
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(self.threshold & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(self.threshold >> 32);
        limbs
    }
}

/// Witness for the AML threshold policy
#[derive(Debug, Clone)]
pub struct AmlThresholdWitness {
    /// The actual amount (private)
    pub amount: u64,
}

impl AmlThresholdWitness {
    /// Create a new witness
    pub fn new(amount: u64) -> Self {
        Self { amount }
    }

    /// Convert amount to field element limbs (low to high)
    pub fn amount_limbs(&self) -> [Felt; 8] {
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(self.amount & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(self.amount >> 32);
        limbs
    }

    /// Validate that amount < threshold
    pub fn is_valid(&self, policy: &AmlThresholdPolicy) -> bool {
        self.amount < policy.threshold
    }
}

/// Comparison result for limb-by-limb comparison
#[derive(Debug, Clone, Copy)]
pub struct ComparisonState {
    /// True if we've determined amount < threshold
    pub is_less: bool,
    /// True if all compared limbs so far are equal
    pub is_equal: bool,
}

impl ComparisonState {
    /// Initial state: equal, not yet determined less
    pub fn initial() -> Self {
        Self {
            is_less: false,
            is_equal: true,
        }
    }

    /// Update state after comparing one limb pair (from high to low)
    pub fn update(&mut self, amount_limb: u64, threshold_limb: u64) {
        if self.is_less {
            // Already determined less, no change
            return;
        }

        if self.is_equal {
            if amount_limb < threshold_limb {
                self.is_less = true;
                self.is_equal = false;
            } else if amount_limb > threshold_limb {
                // amount > threshold at this limb, constraint will fail
                self.is_equal = false;
            }
            // If equal, continue to next limb
        }
    }

    /// Check if the final result is valid (amount < threshold)
    pub fn is_valid(&self) -> bool {
        self.is_less
    }
}

/// Compute comparison values for trace
///
/// Returns 8 field elements representing the comparison state at each step.
/// Element i represents whether amount < threshold considering limbs [7-i..7].
pub fn compute_comparison_values(
    amount_limbs: &[Felt; 8],
    threshold_limbs: &[Felt; 8],
) -> [Felt; 8] {
    let mut result = [FELT_ZERO; 8];
    let mut state = ComparisonState::initial();

    // Compare from high limb (7) to low limb (0)
    for i in (0..8).rev() {
        let a = amount_limbs[i].as_int();
        let t = threshold_limbs[i].as_int();
        state.update(a, t);

        // Store whether we've determined amount < threshold at this point
        result[7 - i] = if state.is_less { FELT_ONE } else { FELT_ZERO };
    }

    result
}

/// Range check constraint for a single limb
///
/// Verifies that a field element represents a valid u32 (< 2^32).
/// This is enforced by the field element being less than 2^32.
pub fn is_valid_u32_limb(limb: Felt) -> bool {
    limb.as_int() < (1u64 << 32)
}

/// Compute the "less than" witness for two limbs
///
/// Returns (is_less, is_equal, diff) where:
/// - is_less: 1 if a < t, 0 otherwise
/// - is_equal: 1 if a == t, 0 otherwise
/// - diff: t - a if a < t, else 0 (for range proof)
pub fn limb_comparison_witness(a: Felt, t: Felt) -> (Felt, Felt, Felt) {
    let a_val = a.as_int();
    let t_val = t.as_int();

    if a_val < t_val {
        (FELT_ONE, FELT_ZERO, felt_from_u64(t_val - a_val))
    } else if a_val == t_val {
        (FELT_ZERO, FELT_ONE, FELT_ZERO)
    } else {
        (FELT_ZERO, FELT_ZERO, FELT_ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_threshold_limbs() {
        let policy = AmlThresholdPolicy::new(10000);
        let limbs = policy.threshold_limbs();

        assert_eq!(limbs[0].as_int(), 10000);
        assert_eq!(limbs[1].as_int(), 0);
    }

    #[test]
    fn test_witness_validation() {
        let policy = AmlThresholdPolicy::new(10000);

        let valid_witness = AmlThresholdWitness::new(5000);
        assert!(valid_witness.is_valid(&policy));

        let invalid_witness = AmlThresholdWitness::new(15000);
        assert!(!invalid_witness.is_valid(&policy));

        let boundary_witness = AmlThresholdWitness::new(10000);
        assert!(!boundary_witness.is_valid(&policy)); // Must be strictly less
    }

    #[test]
    fn test_comparison_state() {
        let mut state = ComparisonState::initial();

        // Compare 100 < 200
        state.update(100, 200);
        assert!(state.is_valid());

        // Reset and compare 200 > 100
        let mut state = ComparisonState::initial();
        state.update(200, 100);
        assert!(!state.is_valid());

        // Equal then less
        let mut state = ComparisonState::initial();
        state.update(100, 100); // Equal
        assert!(!state.is_valid()); // Not yet determined
        state.update(50, 100); // Less
        assert!(state.is_valid());
    }

    #[test]
    fn test_compute_comparison_values() {
        let amount = [
            felt_from_u64(1000),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
        ];
        let threshold = [
            felt_from_u64(2000),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
        ];

        let comparison = compute_comparison_values(&amount, &threshold);

        // Last comparison value should indicate amount < threshold
        assert_eq!(comparison[7].as_int(), 1);
    }

    #[test]
    fn test_is_valid_u32_limb() {
        assert!(is_valid_u32_limb(felt_from_u64(0)));
        assert!(is_valid_u32_limb(felt_from_u64(0xFFFFFFFF)));
        assert!(!is_valid_u32_limb(felt_from_u64(0x100000000)));
    }
}
