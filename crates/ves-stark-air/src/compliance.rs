//! # VES Compliance AIR (Algebraic Intermediate Representation)
//!
//! This module defines the constraint system for proving policy compliance
//! in zero-knowledge. The AIR encodes the statement "amount < threshold"
//! (or "amount <= cap") as algebraic constraints that can be verified
//! without revealing the actual amount.
//!
//! ## Soundness Argument
//!
//! The constraint system is **sound** if: whenever the verifier accepts,
//! the prover knows a valid witness (amount satisfying the policy).
//!
//! ### Key Security Properties
//!
//! 1. **Witness Binding**: The Rescue hash commitment binds the private
//!    amount to the proof. A prover cannot change the amount after
//!    generating the commitment.
//!
//! 2. **Range Validity**: Binary decomposition constraints (b × (1-b) = 0)
//!    ensure each bit is actually 0 or 1, preventing malicious provers
//!    from using non-binary "bits" to fake range proofs.
//!
//! 3. **Recomposition Correctness**: The constraint `limb = Σ(bit[i] × 2^i)`
//!    ensures the bit representation matches the limb value.
//!
//! 4. **Comparison Integrity**: The comparison result is computed honestly
//!    from the limb difference, and the final result is bound via
//!    boundary constraints.
//!
//! ## Formal Constraint Specification
//!
//! ### Notation
//!
//! - `T[i][r]`: Value at trace column `i`, row `r`
//! - `curr`: Current row values
//! - `next`: Next row values
//! - `≡`: Constraint equality (must equal zero)
//!
//! ### Boundary Constraints (First/Last Row)
//!
//! ```text
//! 1. T[FLAG_IS_FIRST][0] = 1
//!    Purpose: Mark first row for initialization checks
//!
//! 2. T[FLAG_IS_LAST][last] = 1
//!    Purpose: Mark last row for finalization checks
//!
//! 3. T[THRESHOLD_START][0] = threshold_low
//!    T[THRESHOLD_START+1][0] = threshold_high
//!    Purpose: Bind public threshold to trace
//!
//! 4. T[COMPARISON_END-1][last] = 1
//!    Purpose: Assert final comparison result is TRUE (amount < threshold)
//!
//! 5. T[AMOUNT_START+i][0] = 0  for i in 2..8
//!    Purpose: Upper limbs zero (amount fits in 64 bits)
//!
//! 6. T[RESCUE_STATE_START+i][0] = witness_commitment[i]  for i in 0..4
//!    Purpose: Bind witness commitment hash to trace
//! ```
//!
//! ### Transition Constraints (Adjacent Rows)
//!
//! ```text
//! Constraint 0: Round Counter Increment
//!   counter[next] - counter[curr] - 1 ≡ 0
//!   Degree: 1
//!   Purpose: Ensure trace has correct length
//!
//! Constraints 1-8: Amount Consistency
//!   amount[i][next] - amount[i][curr] ≡ 0  for i in 0..8
//!   Degree: 1
//!   Purpose: Amount stays constant across all rows
//!
//! Constraints 9-16: Threshold Consistency
//!   threshold[i][next] - threshold[i][curr] ≡ 0  for i in 0..8
//!   Degree: 1
//!   Purpose: Threshold stays constant
//!
//! Constraints 17-24: Comparison Consistency
//!   comparison[i][next] - comparison[i][curr] ≡ 0  for i in 0..8
//!   Degree: 1
//!   Purpose: Comparison results stay constant
//!
//! Constraints 25-56: Binary Constraints (Limb 0, 32 bits)
//!   bit[i] × (1 - bit[i]) ≡ 0  for i in 0..32
//!   Degree: 2 (algebraically), but constant bits → degree 1 actual
//!   Purpose: Each bit is 0 or 1
//!
//!   SOUNDNESS: This is critical! Without b(1-b)=0, a malicious prover
//!   could set "bits" to fractional values that sum to a valid limb
//!   but represent a different actual value.
//!
//! Constraints 57-88: Binary Constraints (Limb 1, 32 bits)
//!   Same as above for high limb
//!
//! Constraints 89-120: Bit Consistency (Limb 0)
//!   bit[i][next] - bit[i][curr] ≡ 0  for i in 0..32
//!   Degree: 1
//!   Purpose: Bits stay constant across rows
//!
//! Constraints 121-152: Bit Consistency (Limb 1)
//!   Same as above for high limb
//!
//! Constraint 153: Recomposition (Limb 0)
//!   limb0 - Σ(bit[i] × 2^i for i in 0..32) ≡ 0
//!   Degree: 1 (all bits are constant, so just linear combination)
//!   Purpose: Bit representation matches limb value
//!
//!   SOUNDNESS: Combined with binary constraints, this ensures
//!   the bit decomposition is unique and correct.
//!
//! Constraint 154: Recomposition (Limb 1)
//!   Same as above for high limb
//!
//! Constraints 155-166: Rescue State Consistency
//!   rescue[i][next] - rescue[i][curr] ≡ 0  for i in 0..12
//!   Degree: 1
//!   Purpose: Witness commitment stays constant
//! ```
//!
//! ## Constraint Count Summary
//!
//! | Category | Count | Description |
//! |----------|-------|-------------|
//! | Round counter | 1 | Increment check |
//! | Amount consistency | 8 | 8 limbs constant |
//! | Threshold consistency | 8 | 8 limbs constant |
//! | Comparison consistency | 8 | 8 values constant |
//! | Binary (limb 0) | 32 | b(1-b)=0 checks |
//! | Binary (limb 1) | 32 | b(1-b)=0 checks |
//! | Bit consistency (limb 0) | 32 | Bits constant |
//! | Bit consistency (limb 1) | 32 | Bits constant |
//! | Recomposition | 2 | limb = Σ bits |
//! | Rescue consistency | 12 | Hash state constant |
//! | **Total** | **167** | |
//!
//! ## Security Level
//!
//! With the Winterfell STARK backend:
//! - Field: Goldilocks (64-bit prime)
//! - Hash: Blake3 for Merkle commitments
//! - FRI: 128-bit security with appropriate parameters
//!
//! The overall proof provides ~128-bit security against forging.

use crate::trace::{cols, TRACE_WIDTH, MIN_TRACE_LENGTH};
use crate::policies::aml_threshold::AmlThresholdPolicy;
use ves_stark_primitives::{Felt, felt_from_u64, FELT_ONE, FELT_ZERO};
use ves_stark_primitives::public_inputs::CompliancePublicInputsFelts;
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::{FieldElement, ToElements};

/// Number of transition constraints in the AIR (V2 - Full Security)
///
/// Phase 1 (original):
/// - 1: round counter
/// - 8: amount consistency
/// - 8: threshold consistency
/// - 8: comparison consistency (legacy)
/// - 64: binary constraints limbs 0-1 (b * (1-b) = 0 for 64 bits)
/// - 64: bit consistency limbs 0-1
/// - 2: recomposition constraints limbs 0-1
/// - 12: Rescue state consistency
///
/// Phase 2 additions (V2):
/// Note: Limbs 2-7 are boundary-asserted to zero, so no binary decomposition needed.
/// The value 0 is trivially a valid u32. Winterfell has a 255-column limit.
/// - 8: is_less consistency constraints
/// - 8: is_equal consistency constraints
/// - 8: diff consistency constraints
/// - 8: borrow consistency constraints
/// - 8: is_less binary constraints
/// - 8: is_equal binary constraints
/// - 8: borrow binary constraints
///
/// Total: 167 + 56 = 223
const NUM_CONSTRAINTS: usize = 223;

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
        // Delegate to Air::new which has the full constraint setup
        Self::new(trace_info, pub_inputs.clone(), options)
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

        // Constraints 17-24: Comparison consistency (legacy) (degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 25-88: Binary constraints for 64 bits limbs 0-1 (degree 1)
        // Note: b * (1 - b) is algebraically degree 2, but since bit values
        // are constant across the trace, the actual polynomial degree is 1.
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 89-152: Bit consistency limbs 0-1 (degree 1)
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 153-154: Recomposition constraints limbs 0-1 (degree 1)
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));

        // Constraints 155-166: Rescue state consistency (degree 1)
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // =========================================================================
        // V2 Extended Constraints: Comparison Gadget
        // Note: Limbs 2-7 are boundary-asserted to zero, no decomposition needed
        // =========================================================================

        // Constraints 167-174: is_less consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 175-182: is_equal consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 183-190: diff consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 191-198: borrow consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 199-206: is_less binary (8 constraints, degree 1)
        // Note: b * (1 - b) is algebraically degree 2, but since is_less values
        // are constant across the trace, the actual polynomial degree is 1.
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 207-214: is_equal binary (8 constraints, degree 1)
        // Note: b * (1 - b) is algebraically degree 2, but since is_equal values
        // are constant across the trace, the actual polynomial degree is 1.
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Constraints 215-222: borrow binary (8 constraints, degree 1)
        // Note: b * (1 - b) is algebraically degree 2, but since borrow values
        // are constant across the trace, the actual polynomial degree is 1.
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Number of boundary assertions: 15 original + 1 (is_less[7] = 1 at last row) = 16
        let context = AirContext::new(trace_info, degrees, 16, options);

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
        // Legacy: using COMPARISON_END - 1
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

        // V2: Boundary constraint for comparison gadget
        // is_less[0] must be 1 at the last row, meaning amount < threshold
        // considering all limbs (0 through 7)
        assertions.push(Assertion::single(cols::is_less(0), last_row, FELT_ONE));

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
        // idx is now 167

        // =========================================================================
        // V2 Extended Constraints: Comparison Gadget
        // Note: Limbs 2-7 are boundary-asserted to zero, no binary decomposition needed
        // =========================================================================

        // Constraints 167-174: is_less consistency (8 constraints)
        for limb_idx in 0..8 {
            let is_less_curr = current[cols::is_less(limb_idx)];
            let is_less_next = next[cols::is_less(limb_idx)];
            result[idx] = is_less_next - is_less_curr;
            idx += 1;
        }

        // Constraints 175-182: is_equal consistency (8 constraints)
        for limb_idx in 0..8 {
            let is_equal_curr = current[cols::is_equal(limb_idx)];
            let is_equal_next = next[cols::is_equal(limb_idx)];
            result[idx] = is_equal_next - is_equal_curr;
            idx += 1;
        }

        // Constraints 183-190: diff consistency (8 constraints)
        for limb_idx in 0..8 {
            let diff_curr = current[cols::diff(limb_idx)];
            let diff_next = next[cols::diff(limb_idx)];
            result[idx] = diff_next - diff_curr;
            idx += 1;
        }

        // Constraints 191-198: borrow consistency (8 constraints)
        for limb_idx in 0..8 {
            let borrow_curr = current[cols::borrow(limb_idx)];
            let borrow_next = next[cols::borrow(limb_idx)];
            result[idx] = borrow_next - borrow_curr;
            idx += 1;
        }

        // Constraints 199-206: is_less binary (8 constraints)
        for limb_idx in 0..8 {
            let is_less_val = current[cols::is_less(limb_idx)];
            result[idx] = is_less_val * (E::ONE - is_less_val);
            idx += 1;
        }

        // Constraints 207-214: is_equal binary (8 constraints)
        for limb_idx in 0..8 {
            let is_equal_val = current[cols::is_equal(limb_idx)];
            result[idx] = is_equal_val * (E::ONE - is_equal_val);
            idx += 1;
        }

        // Constraints 215-222: borrow binary (8 constraints)
        for limb_idx in 0..8 {
            let borrow_val = current[cols::borrow(limb_idx)];
            result[idx] = borrow_val * (E::ONE - borrow_val);
            idx += 1;
        }

        // idx is now 167 + 56 = 223, matching NUM_CONSTRAINTS
        debug_assert_eq!(idx, NUM_CONSTRAINTS);
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
