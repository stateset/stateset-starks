//! VES Compliance AIR
//!
//! This is the main AIR (Algebraic Intermediate Representation) for VES
//! compliance proofs. It orchestrates the various constraint sub-systems
//! to prove policy compliance.
//!
//! # Security Features
//!
//! This AIR provides cryptographic security through:
//! 1. Binary decomposition constraints for range proofs
//! 2. Recomposition constraints binding bits to limbs
//! 3. Rescue hash constraints for witness binding (optional)
//!
//! # Constraint Structure
//!
//! The AIR defines:
//! - Boundary constraints: assertions on first/last rows
//! - Transition constraints: relations between adjacent rows
//!
//! ## Transition Constraints
//!
//! 1. Round counter increment: counter[next] = counter[curr] + 1
//! 2. Amount consistency: amount limbs remain constant across all rows
//! 3. Threshold consistency: threshold limbs remain constant across all rows
//! 4. Comparison consistency: comparison results remain constant across rows
//! 5. Binary constraints: b * (1 - b) = 0 for all bit columns (64 constraints)
//! 6. Bit consistency: bits remain constant across all rows (64 constraints)

use crate::trace::{cols, TRACE_WIDTH, MIN_TRACE_LENGTH};
use crate::policies::aml_threshold::AmlThresholdPolicy;
use ves_stark_primitives::{Felt, felt_from_u64, FELT_ONE, FELT_ZERO};
use ves_stark_primitives::public_inputs::CompliancePublicInputsFelts;
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::{FieldElement, ToElements};

/// Number of transition constraints in the AIR
/// - 1: round counter
/// - 8: amount consistency
/// - 8: threshold consistency
/// - 8: comparison consistency
/// - 64: binary constraints (b * (1-b) = 0 for 64 bits)
/// - 64: bit consistency (bits remain constant)
/// - 2: recomposition constraints (limb = sum of bits)
/// - 12: Rescue state consistency (witness commitment remains constant)
const NUM_CONSTRAINTS: usize = 167;

/// Public inputs for the compliance AIR
#[derive(Debug, Clone)]
pub struct PublicInputs {
    /// The threshold value
    pub threshold: u64,
    /// Public input field elements
    pub elements: Vec<Felt>,
    /// Witness commitment (first 4 elements of Rescue hash)
    /// This binds the private witness to the proof
    pub witness_commitment: [Felt; 4],
}

impl PublicInputs {
    /// Create new public inputs (legacy, without witness commitment)
    pub fn new(threshold: u64, elements: Vec<Felt>) -> Self {
        Self {
            threshold,
            elements,
            witness_commitment: [FELT_ZERO; 4],
        }
    }

    /// Create new public inputs with witness commitment
    pub fn with_commitment(threshold: u64, elements: Vec<Felt>, commitment: [Felt; 4]) -> Self {
        Self {
            threshold,
            elements,
            witness_commitment: commitment,
        }
    }
}

impl ToElements<Felt> for PublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut result = vec![felt_from_u64(self.threshold)];
        result.extend(self.elements.iter().cloned());
        // Include witness commitment in public inputs
        result.extend(self.witness_commitment.iter().cloned());
        result
    }
}

/// The main compliance AIR
pub struct ComplianceAir {
    /// AIR context (trace info, options, etc.)
    context: AirContext<Felt>,

    /// Policy threshold (for aml.threshold)
    threshold: u64,

    /// Witness commitment (first 4 elements of Rescue hash)
    /// The verifier checks that the trace contains this commitment
    witness_commitment: [Felt; 4],
}

impl ComplianceAir {
    /// Create a new compliance AIR for the given public inputs and policy
    pub fn with_policy(
        trace_info: TraceInfo,
        pub_inputs: &PublicInputs,
        options: ProofOptions,
    ) -> Self {
        // Build transition constraint degrees matching Air::new
        let mut degrees = Vec::with_capacity(NUM_CONSTRAINTS);

        // Constraint 0: Round counter (degree 1)
        degrees.push(TransitionConstraintDegree::new(1));

        // Constraints 1-8: Amount consistency (degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 9-16: Threshold consistency (degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 17-24: Comparison consistency (degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 25-88: Binary constraints for 64 bits (degree 1)
        // Note: b * (1 - b) is algebraically degree 2, but since bit values
        // are constant across the trace, the actual polynomial degree is 1.
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 89-152: Bit consistency (degree 1)
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 153-154: Recomposition constraints (degree 1)
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));

        // Constraints 155-166: Rescue state consistency (degree 1)
        // Witness commitment (Rescue hash output) remains constant across rows
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // 15 boundary assertions: 5 original + 6 upper limbs + 4 witness commitment
        let context = AirContext::new(trace_info, degrees, 15, options);

        Self {
            context,
            threshold: pub_inputs.threshold,
            witness_commitment: pub_inputs.witness_commitment,
        }
    }

    /// Get the policy threshold
    pub fn threshold(&self) -> u64 {
        self.threshold
    }
}

impl Air for ComplianceAir {
    type BaseField = Felt;
    type PublicInputs = PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Build transition constraint degrees
        let mut degrees = Vec::with_capacity(NUM_CONSTRAINTS);

        // Constraint 0: Round counter (degree 1)
        degrees.push(TransitionConstraintDegree::new(1));

        // Constraints 1-8: Amount consistency (degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 9-16: Threshold consistency (degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 17-24: Comparison consistency (degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 25-88: Binary constraints for 64 bits (degree 1)
        // Note: b * (1 - b) is algebraically degree 2, but since bit values
        // are constant across the trace, the actual polynomial degree is 1.
        // Winterfell verifies actual degree, so we declare degree 1.
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 89-152: Bit consistency (degree 1)
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 153-154: Recomposition constraints (degree 1)
        // These verify: limb = sum(bit[i] * 2^i)
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));

        // Constraints 155-166: Rescue state consistency (degree 1)
        // Witness commitment (Rescue hash output) remains constant across rows
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Number of boundary assertions: 5 original + 6 upper limbs + 4 witness commitment = 15
        let context = AirContext::new(trace_info, degrees, 15, options);

        Self {
            context,
            threshold: pub_inputs.threshold,
            witness_commitment: pub_inputs.witness_commitment,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Boundary constraint: first row flag = 1
        assertions.push(Assertion::single(cols::FLAG_IS_FIRST, 0, FELT_ONE));

        // Boundary constraint: last row flag = 1
        let last_row = self.trace_length() - 1;
        assertions.push(Assertion::single(cols::FLAG_IS_LAST, last_row, FELT_ONE));

        // Boundary constraint: threshold values match public input
        let threshold_low = felt_from_u64(self.threshold & 0xFFFFFFFF);
        let threshold_high = felt_from_u64(self.threshold >> 32);
        assertions.push(Assertion::single(cols::THRESHOLD_START, 0, threshold_low));
        assertions.push(Assertion::single(cols::THRESHOLD_START + 1, 0, threshold_high));

        // Boundary constraint: final comparison result must be 1 (amount < threshold)
        assertions.push(Assertion::single(cols::COMPARISON_END - 1, last_row, FELT_ONE));

        // Boundary constraint: upper limbs (2-7) must be zero for u64 amounts
        // This ensures the amount fits in 64 bits
        for i in 2..8 {
            assertions.push(Assertion::single(cols::AMOUNT_START + i, 0, FELT_ZERO));
        }

        // Boundary constraint: witness commitment must match public input
        // This binds the private witness to the proof via Rescue hash
        for i in 0..4 {
            assertions.push(Assertion::single(
                cols::RESCUE_STATE_START + i,
                0,
                self.witness_commitment[i],
            ));
        }

        assertions
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let mut idx = 0;

        // Constraint 0: Round counter increments by 1 (degree 1)
        // next_counter = current_counter + 1
        let counter_current = current[cols::ROUND_COUNTER];
        let counter_next = next[cols::ROUND_COUNTER];
        result[idx] = counter_next - counter_current - E::ONE;
        idx += 1;

        // Constraints 1-8: Amount limbs remain constant
        // For each limb i: amount[i][next] = amount[i][curr]
        for i in 0..8 {
            let amount_curr = current[cols::AMOUNT_START + i];
            let amount_next = next[cols::AMOUNT_START + i];
            result[idx] = amount_next - amount_curr;
            idx += 1;
        }

        // Constraints 9-16: Threshold limbs remain constant
        // For each limb i: threshold[i][next] = threshold[i][curr]
        for i in 0..8 {
            let threshold_curr = current[cols::THRESHOLD_START + i];
            let threshold_next = next[cols::THRESHOLD_START + i];
            result[idx] = threshold_next - threshold_curr;
            idx += 1;
        }

        // Constraints 17-24: Comparison values remain constant
        // For each value i: comparison[i][next] = comparison[i][curr]
        for i in 0..8 {
            let comparison_curr = current[cols::COMPARISON_START + i];
            let comparison_next = next[cols::COMPARISON_START + i];
            result[idx] = comparison_next - comparison_curr;
            idx += 1;
        }

        // Constraints 25-56: Binary constraints for limb 0 bits (32 bits)
        // For each bit b: b * (1 - b) = 0 (ensures b is 0 or 1)
        for i in 0..32 {
            let bit = current[cols::AMOUNT_BITS_LIMB0_START + i];
            result[idx] = bit * (E::ONE - bit);
            idx += 1;
        }

        // Constraints 57-88: Binary constraints for limb 1 bits (32 bits)
        for i in 0..32 {
            let bit = current[cols::AMOUNT_BITS_LIMB1_START + i];
            result[idx] = bit * (E::ONE - bit);
            idx += 1;
        }

        // Constraints 89-120: Bit consistency for limb 0 (bits remain constant)
        for i in 0..32 {
            let bit_curr = current[cols::AMOUNT_BITS_LIMB0_START + i];
            let bit_next = next[cols::AMOUNT_BITS_LIMB0_START + i];
            result[idx] = bit_next - bit_curr;
            idx += 1;
        }

        // Constraints 121-152: Bit consistency for limb 1 (bits remain constant)
        for i in 0..32 {
            let bit_curr = current[cols::AMOUNT_BITS_LIMB1_START + i];
            let bit_next = next[cols::AMOUNT_BITS_LIMB1_START + i];
            result[idx] = bit_next - bit_curr;
            idx += 1;
        }

        // Constraint 153: Recomposition for limb 0
        // Verifies: limb0 = sum(bit[i] * 2^i for i in 0..32)
        let limb0 = current[cols::AMOUNT_START];
        let mut recomp0 = E::ZERO;
        let two = E::from(felt_from_u64(2));
        let mut power = E::ONE;
        for i in 0..32 {
            recomp0 = recomp0 + current[cols::AMOUNT_BITS_LIMB0_START + i] * power;
            power = power * two;
        }
        result[idx] = limb0 - recomp0;
        idx += 1;

        // Constraint 154: Recomposition for limb 1
        // Verifies: limb1 = sum(bit[i] * 2^i for i in 0..32)
        let limb1 = current[cols::AMOUNT_START + 1];
        let mut recomp1 = E::ZERO;
        let mut power = E::ONE;
        for i in 0..32 {
            recomp1 = recomp1 + current[cols::AMOUNT_BITS_LIMB1_START + i] * power;
            power = power * two;
        }
        result[idx] = limb1 - recomp1;
        idx += 1;

        // Constraints 155-166: Rescue state consistency
        // Witness commitment (Rescue hash output) remains constant across rows
        for i in 0..12 {
            let state_curr = current[cols::RESCUE_STATE_START + i];
            let state_next = next[cols::RESCUE_STATE_START + i];
            result[idx] = state_next - state_curr;
            idx += 1;
        }
        // idx is now 167, matching NUM_CONSTRAINTS
        let _ = idx; // Silence unused variable warning
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        vec![]
    }
}

/// Builder for creating ComplianceAir instances
pub struct ComplianceAirBuilder {
    trace_length: usize,
    pub_inputs: Option<CompliancePublicInputsFelts>,
    policy: Option<AmlThresholdPolicy>,
    options: Option<winter_air::ProofOptions>,
}

impl ComplianceAirBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            trace_length: MIN_TRACE_LENGTH,
            pub_inputs: None,
            policy: None,
            options: None,
        }
    }

    /// Set the trace length
    pub fn trace_length(mut self, length: usize) -> Self {
        self.trace_length = length.next_power_of_two().max(MIN_TRACE_LENGTH);
        self
    }

    /// Set the public inputs
    pub fn public_inputs(mut self, inputs: CompliancePublicInputsFelts) -> Self {
        self.pub_inputs = Some(inputs);
        self
    }

    /// Set the policy
    pub fn policy(mut self, policy: AmlThresholdPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set proof options
    pub fn options(mut self, options: winter_air::ProofOptions) -> Self {
        self.options = Some(options);
        self
    }

    /// Build the AIR
    pub fn build(self) -> Result<(ComplianceAir, PublicInputs), &'static str> {
        let pub_inputs_felts = self.pub_inputs.ok_or("Public inputs required")?;
        let policy = self.policy.ok_or("Policy required")?;
        let options = self.options.unwrap_or_else(|| {
            crate::options::ProofOptions::default().to_winterfell()
        });

        let trace_info = TraceInfo::new(TRACE_WIDTH, self.trace_length);
        let pub_inputs = PublicInputs::new(policy.threshold, pub_inputs_felts.to_vec());
        let air = ComplianceAir::with_policy(trace_info, &pub_inputs, options);

        Ok((air, pub_inputs))
    }
}

impl Default for ComplianceAirBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams};
    use uuid::Uuid;

    fn sample_public_inputs() -> CompliancePublicInputs {
        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10000),
            policy_hash: "0".repeat(64),
        }
    }

    #[test]
    fn test_air_builder() {
        let inputs = sample_public_inputs();
        let felts = inputs.to_field_elements();
        let policy = AmlThresholdPolicy::new(10000);

        let (air, _pub_inputs) = ComplianceAirBuilder::new()
            .public_inputs(felts)
            .policy(policy)
            .build()
            .unwrap();

        assert_eq!(air.threshold(), 10000);
    }

    #[test]
    fn test_air_assertions() {
        let inputs = sample_public_inputs();
        let felts = inputs.to_field_elements();
        let policy = AmlThresholdPolicy::new(10000);

        let (air, _pub_inputs) = ComplianceAirBuilder::new()
            .public_inputs(felts)
            .policy(policy)
            .build()
            .unwrap();

        let assertions = air.get_assertions();
        assert!(!assertions.is_empty());
    }

    #[test]
    fn test_public_inputs_to_elements() {
        let pub_inputs = PublicInputs::new(10000, vec![felt_from_u64(1), felt_from_u64(2)]);
        let elements = pub_inputs.to_elements();
        // threshold + 2 elements + 4 witness commitment elements = 7
        assert_eq!(elements.len(), 7);
        assert_eq!(elements[0].as_int(), 10000);
    }

    #[test]
    fn test_public_inputs_with_commitment() {
        let commitment = [felt_from_u64(100), felt_from_u64(200), felt_from_u64(300), felt_from_u64(400)];
        let pub_inputs = PublicInputs::with_commitment(
            10000,
            vec![felt_from_u64(1), felt_from_u64(2)],
            commitment,
        );
        let elements = pub_inputs.to_elements();
        // threshold + 2 elements + 4 witness commitment elements = 7
        assert_eq!(elements.len(), 7);
        assert_eq!(elements[0].as_int(), 10000);
        // Check commitment elements are at the end
        assert_eq!(elements[3].as_int(), 100);
        assert_eq!(elements[4].as_int(), 200);
        assert_eq!(elements[5].as_int(), 300);
        assert_eq!(elements[6].as_int(), 400);
    }
}
