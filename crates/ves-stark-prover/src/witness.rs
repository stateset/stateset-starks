//! Witness generation for VES compliance proofs
//!
//! The witness contains the private data that the prover uses to generate
//! the proof. For the `aml.threshold` policy, this includes the actual
//! amount value from the encrypted payload.

use ves_stark_primitives::public_inputs::CompliancePublicInputs;
use ves_stark_primitives::{Felt, felt_from_u64, FELT_ZERO};
use ves_stark_air::range_check::validate_limbs;
use crate::error::ProverError;

/// Witness for compliance proofs
#[derive(Debug, Clone)]
pub struct ComplianceWitness {
    /// The actual amount (private witness data)
    pub amount: u64,

    /// Public inputs for the proof
    pub public_inputs: CompliancePublicInputs,
}

impl ComplianceWitness {
    /// Create a new compliance witness
    pub fn new(amount: u64, public_inputs: CompliancePublicInputs) -> Self {
        Self {
            amount,
            public_inputs,
        }
    }

    /// Validate the witness against the policy
    pub fn validate(&self, threshold: u64) -> Result<(), ProverError> {
        if self.amount >= threshold {
            return Err(ProverError::policy_validation_failed(format!(
                "Amount {} is not less than threshold {}",
                self.amount, threshold
            )));
        }

        // Validate public inputs
        if !self.public_inputs.validate_policy_hash() {
            return Err(ProverError::InvalidPublicInputs(
                "Policy hash mismatch".to_string()
            ));
        }

        // Validate amount limbs are valid u32 values (range check)
        let amount_limbs = self.amount_limbs();
        if !validate_limbs(&amount_limbs) {
            return Err(ProverError::invalid_witness(
                "Amount limbs contain invalid u32 values"
            ));
        }

        Ok(())
    }

    /// Get amount as field element limbs (low to high, 8 x u32)
    pub fn amount_limbs(&self) -> [Felt; 8] {
        let mut limbs = [FELT_ZERO; 8];
        limbs[0] = felt_from_u64(self.amount & 0xFFFFFFFF);
        limbs[1] = felt_from_u64(self.amount >> 32);
        limbs
    }

    /// Get amount as u128 for extended precision
    pub fn amount_u128(&self) -> u128 {
        self.amount as u128
    }
}

/// Builder for creating witnesses
pub struct WitnessBuilder {
    amount: Option<u64>,
    public_inputs: Option<CompliancePublicInputs>,
}

impl WitnessBuilder {
    /// Create a new witness builder
    pub fn new() -> Self {
        Self {
            amount: None,
            public_inputs: None,
        }
    }

    /// Set the amount
    pub fn amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set the public inputs
    pub fn public_inputs(mut self, inputs: CompliancePublicInputs) -> Self {
        self.public_inputs = Some(inputs);
        self
    }

    /// Build the witness
    pub fn build(self) -> Result<ComplianceWitness, ProverError> {
        let amount = self.amount
            .ok_or_else(|| ProverError::invalid_witness("Amount is required"))?;
        let public_inputs = self.public_inputs
            .ok_or_else(|| ProverError::invalid_witness("Public inputs are required"))?;

        Ok(ComplianceWitness::new(amount, public_inputs))
    }
}

impl Default for WitnessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{PolicyParams, compute_policy_hash};
    use uuid::Uuid;

    fn sample_public_inputs(threshold: u64) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params);

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
        }
    }

    #[test]
    fn test_witness_validation_valid() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold);
        let witness = ComplianceWitness::new(5000, inputs);

        assert!(witness.validate(threshold).is_ok());
    }

    #[test]
    fn test_witness_validation_invalid() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold);
        let witness = ComplianceWitness::new(15000, inputs);

        assert!(witness.validate(threshold).is_err());
    }

    #[test]
    fn test_witness_builder() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold);

        let witness = WitnessBuilder::new()
            .amount(5000)
            .public_inputs(inputs)
            .build()
            .unwrap();

        assert_eq!(witness.amount, 5000);
    }

    #[test]
    fn test_amount_limbs() {
        let inputs = sample_public_inputs(10000);
        let witness = ComplianceWitness::new(0x1234567890ABCDEF, inputs);
        let limbs = witness.amount_limbs();

        assert_eq!(limbs[0].as_int(), 0x90ABCDEF);
        assert_eq!(limbs[1].as_int(), 0x12345678);
    }

    // =========================================================================
    // Additional Unit Tests
    // =========================================================================

    #[test]
    fn test_witness_builder_missing_amount() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold);

        let result = WitnessBuilder::new()
            .public_inputs(inputs)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_witness_builder_missing_public_inputs() {
        let result = WitnessBuilder::new()
            .amount(5000)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_witness_zero_amount() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold);
        let witness = ComplianceWitness::new(0, inputs);

        assert!(witness.validate(threshold).is_ok());
        let limbs = witness.amount_limbs();
        assert_eq!(limbs[0].as_int(), 0);
        assert_eq!(limbs[1].as_int(), 0);
    }

    #[test]
    fn test_witness_max_valid_amount() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold);
        let witness = ComplianceWitness::new(9999, inputs);

        assert!(witness.validate(threshold).is_ok());
    }

    #[test]
    fn test_witness_boundary_amount_fails() {
        let threshold = 10000u64;
        let inputs = sample_public_inputs(threshold);
        let witness = ComplianceWitness::new(10000, inputs);

        // Equal to threshold should fail (must be strictly less than)
        assert!(witness.validate(threshold).is_err());
    }

    #[test]
    fn test_amount_u128_conversion() {
        let inputs = sample_public_inputs(10000);
        let witness = ComplianceWitness::new(u64::MAX, inputs);

        assert_eq!(witness.amount_u128(), u64::MAX as u128);
    }

    #[test]
    fn test_amount_limbs_max_value() {
        let inputs = sample_public_inputs(u64::MAX);
        let witness = ComplianceWitness::new(u64::MAX, inputs);
        let limbs = witness.amount_limbs();

        assert_eq!(limbs[0].as_int(), 0xFFFFFFFF);
        assert_eq!(limbs[1].as_int(), 0xFFFFFFFF);
        // Upper limbs should be zero for u64
        for i in 2..8 {
            assert_eq!(limbs[i].as_int(), 0);
        }
    }

    #[test]
    fn test_witness_builder_default() {
        let builder = WitnessBuilder::default();
        // Should be same as new()
        assert!(builder.build().is_err()); // Missing both fields
    }
}

// =============================================================================
// Property-Based Tests
// =============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use ves_stark_primitives::public_inputs::{PolicyParams, compute_policy_hash};
    use proptest::prelude::*;
    use uuid::Uuid;

    fn sample_public_inputs(threshold: u64) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params);

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
        }
    }

    proptest! {
        /// Property: Any amount less than threshold should pass validation
        #[test]
        fn prop_amount_less_than_threshold_validates(
            threshold in 1u64..=u64::MAX,
            amount_offset in 1u64..=u64::MAX
        ) {
            // Ensure amount < threshold
            let amount = if amount_offset <= threshold {
                threshold.saturating_sub(amount_offset)
            } else {
                0
            };

            let inputs = sample_public_inputs(threshold);
            let witness = ComplianceWitness::new(amount, inputs);

            prop_assert!(witness.validate(threshold).is_ok());
        }

        /// Property: Any amount >= threshold should fail validation
        #[test]
        fn prop_amount_gte_threshold_fails(
            threshold in 1u64..u64::MAX,
            extra in 0u64..1000
        ) {
            let amount = threshold.saturating_add(extra);
            let inputs = sample_public_inputs(threshold);
            let witness = ComplianceWitness::new(amount, inputs);

            prop_assert!(witness.validate(threshold).is_err());
        }

        /// Property: Amount limb decomposition is correct (low limb)
        #[test]
        fn prop_amount_limb_decomposition_low(amount in any::<u64>()) {
            let inputs = sample_public_inputs(u64::MAX);
            let witness = ComplianceWitness::new(amount, inputs);
            let limbs = witness.amount_limbs();

            let expected_low = amount & 0xFFFFFFFF;
            prop_assert_eq!(limbs[0].as_int(), expected_low);
        }

        /// Property: Amount limb decomposition is correct (high limb)
        #[test]
        fn prop_amount_limb_decomposition_high(amount in any::<u64>()) {
            let inputs = sample_public_inputs(u64::MAX);
            let witness = ComplianceWitness::new(amount, inputs);
            let limbs = witness.amount_limbs();

            let expected_high = amount >> 32;
            prop_assert_eq!(limbs[1].as_int(), expected_high);
        }

        /// Property: Limbs can be recombined to original amount
        #[test]
        fn prop_limb_recombination(amount in any::<u64>()) {
            let inputs = sample_public_inputs(u64::MAX);
            let witness = ComplianceWitness::new(amount, inputs);
            let limbs = witness.amount_limbs();

            let recombined = limbs[0].as_int() | (limbs[1].as_int() << 32);
            prop_assert_eq!(recombined, amount);
        }

        /// Property: Upper limbs (2-7) are always zero for u64 amounts
        #[test]
        fn prop_upper_limbs_zero(amount in any::<u64>()) {
            let inputs = sample_public_inputs(u64::MAX);
            let witness = ComplianceWitness::new(amount, inputs);
            let limbs = witness.amount_limbs();

            for i in 2..8 {
                prop_assert_eq!(limbs[i].as_int(), 0, "Limb {} should be zero", i);
            }
        }

        /// Property: amount_u128 preserves value
        #[test]
        fn prop_amount_u128_preserves(amount in any::<u64>()) {
            let inputs = sample_public_inputs(u64::MAX);
            let witness = ComplianceWitness::new(amount, inputs);

            prop_assert_eq!(witness.amount_u128(), amount as u128);
        }

        /// Property: WitnessBuilder produces same result as direct construction
        #[test]
        fn prop_builder_equals_direct(amount in any::<u64>()) {
            let inputs = sample_public_inputs(u64::MAX);
            let direct = ComplianceWitness::new(amount, inputs.clone());
            let built = WitnessBuilder::new()
                .amount(amount)
                .public_inputs(inputs)
                .build()
                .unwrap();

            prop_assert_eq!(direct.amount, built.amount);
        }
    }
}
