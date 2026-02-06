//! Order Total Cap Policy Constraints
//!
//! This policy proves that an order total is at or below a cap value,
//! without revealing the actual total.
//!
//! # Constraint Strategy
//!
//! To prove `amount <= cap` we use the same comparison gadget as aml.threshold
//! but with a less-than-or-equal check instead of strict less-than.
//!
//! The comparison is done lexicographically from high limb to low limb:
//! - If high limbs are equal, compare next lower limbs
//! - If high limb of amount < high limb of cap, amount <= cap
//! - If all limbs are equal, amount <= cap (since amount == cap is allowed)

use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};

/// Order Total Cap Policy
///
/// Proves that an order total is at or below a specified cap.
/// This is commonly used for:
/// - Maximum order size limits
/// - Spending limits per transaction
/// - Credit limits
#[derive(Debug, Clone)]
pub struct OrderTotalCapPolicy {
    /// The cap value (amount must be <= this)
    pub cap: u64,
}

impl OrderTotalCapPolicy {
    /// Create a new order total cap policy
    pub fn new(cap: u64) -> Self {
        Self { cap }
    }

    /// Convert cap to field element limbs (low to high)
    /// For u64, we only need 2 limbs (2 x u32)
    pub fn cap_limbs(&self) -> [Felt; 8] {
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(self.cap & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(self.cap >> 32);
        limbs
    }

    /// Get policy identifier
    pub fn policy_id() -> &'static str {
        "order_total.cap"
    }
}

/// Witness for the order total cap policy
#[derive(Debug, Clone)]
pub struct OrderTotalCapWitness {
    /// The actual order total (private)
    pub amount: u64,
}

impl OrderTotalCapWitness {
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

    /// Validate that amount <= cap
    pub fn is_valid(&self, policy: &OrderTotalCapPolicy) -> bool {
        self.amount <= policy.cap
    }
}

/// Comparison result for limb-by-limb comparison (less-than-or-equal)
#[derive(Debug, Clone, Copy)]
pub struct ComparisonStateLte {
    /// True if we've determined amount < cap
    pub is_less: bool,
    /// True if all compared limbs so far are equal
    pub is_equal: bool,
}

impl ComparisonStateLte {
    /// Initial state: equal, not yet determined less
    pub fn initial() -> Self {
        Self {
            is_less: false,
            is_equal: true,
        }
    }

    /// Update state after comparing one limb pair (from high to low)
    pub fn update(&mut self, amount_limb: u64, cap_limb: u64) {
        if self.is_less {
            // Already determined less, no change
            return;
        }

        if self.is_equal {
            if amount_limb < cap_limb {
                self.is_less = true;
                self.is_equal = false;
            } else if amount_limb > cap_limb {
                // amount > cap at this limb, constraint will fail
                self.is_equal = false;
            }
            // If equal, continue to next limb
        }
    }

    /// Check if the final result is valid (amount <= cap)
    /// Note: This is true if amount < cap OR amount == cap
    pub fn is_valid(&self) -> bool {
        self.is_less || self.is_equal
    }
}

/// Compute comparison values for trace (less-than-or-equal)
///
/// Returns 8 field elements representing the comparison state at each step.
/// For LTE, the final result is valid if is_less OR is_equal.
pub fn compute_comparison_values_lte(amount_limbs: &[Felt; 8], cap_limbs: &[Felt; 8]) -> [Felt; 8] {
    let mut result = [FELT_ZERO; 8];
    let mut state = ComparisonStateLte::initial();

    // Compare from high limb (7) to low limb (0)
    for i in (0..8).rev() {
        let a = amount_limbs[i].as_int();
        let c = cap_limbs[i].as_int();
        state.update(a, c);

        // Store whether we've determined amount <= cap at this point
        // For LTE, valid if less OR still equal
        result[7 - i] = if state.is_valid() {
            FELT_ONE
        } else {
            FELT_ZERO
        };
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_cap_limbs() {
        let policy = OrderTotalCapPolicy::new(10000);
        let limbs = policy.cap_limbs();

        assert_eq!(limbs[0].as_int(), 10000);
        assert_eq!(limbs[1].as_int(), 0);
    }

    #[test]
    fn test_witness_validation() {
        let policy = OrderTotalCapPolicy::new(10000);

        // Valid: amount < cap
        let valid_witness = OrderTotalCapWitness::new(5000);
        assert!(valid_witness.is_valid(&policy));

        // Valid: amount == cap (this is the key difference from aml.threshold)
        let boundary_witness = OrderTotalCapWitness::new(10000);
        assert!(boundary_witness.is_valid(&policy));

        // Invalid: amount > cap
        let invalid_witness = OrderTotalCapWitness::new(15000);
        assert!(!invalid_witness.is_valid(&policy));
    }

    #[test]
    fn test_comparison_state_lte() {
        // Test less than
        let mut state = ComparisonStateLte::initial();
        state.update(100, 200);
        assert!(state.is_valid());

        // Test greater than
        let mut state = ComparisonStateLte::initial();
        state.update(200, 100);
        assert!(!state.is_valid());

        // Test equal - should be valid for LTE
        let mut state = ComparisonStateLte::initial();
        state.update(100, 100);
        assert!(state.is_valid()); // This is the key difference!

        // Equal then less
        let mut state = ComparisonStateLte::initial();
        state.update(100, 100); // Equal
        assert!(state.is_valid());
        state.update(50, 100); // Less
        assert!(state.is_valid());

        // Equal then equal (all equal)
        let mut state = ComparisonStateLte::initial();
        state.update(100, 100);
        state.update(100, 100);
        assert!(state.is_valid());
    }

    #[test]
    fn test_compute_comparison_values_lte() {
        // Test less than
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
        let cap = [
            felt_from_u64(2000),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
        ];

        let comparison = compute_comparison_values_lte(&amount, &cap);
        assert_eq!(comparison[7].as_int(), 1);

        // Test equal (should also be valid for LTE)
        let amount_eq = [
            felt_from_u64(2000),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
            felt_from_u64(0),
        ];

        let comparison_eq = compute_comparison_values_lte(&amount_eq, &cap);
        assert_eq!(comparison_eq[7].as_int(), 1); // Valid because amount == cap
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(OrderTotalCapPolicy::policy_id(), "order_total.cap");
    }

    #[test]
    fn test_large_values() {
        // Test with values that span multiple limbs
        let cap = u64::MAX - 1000;
        let policy = OrderTotalCapPolicy::new(cap);

        let valid = OrderTotalCapWitness::new(cap - 1);
        assert!(valid.is_valid(&policy));

        let equal = OrderTotalCapWitness::new(cap);
        assert!(equal.is_valid(&policy));

        let invalid = OrderTotalCapWitness::new(cap + 1);
        assert!(!invalid.is_valid(&policy));
    }
}
