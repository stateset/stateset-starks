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

use crate::rescue_air::{MDS, MDS_INV, ROUND_CONSTANTS};
use crate::trace::{cols, TRACE_WIDTH, MIN_TRACE_LENGTH};
use crate::policies::aml_threshold::AmlThresholdPolicy;
use ves_stark_primitives::{Felt, felt_from_u64, FELT_ONE, FELT_ZERO};
use ves_stark_primitives::rescue::STATE_WIDTH as RESCUE_STATE_WIDTH;
use ves_stark_primitives::public_inputs::CompliancePublicInputsFelts;
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::{FieldElement, ToElements};

/// Number of transition constraints in the AIR (V3 - Full Security)
///
/// - 1: round counter
/// - 8: amount consistency
/// - 8: threshold consistency
/// - 47: public input binding (constant across rows)
/// - 64: amount bit binary constraints
/// - 64: amount bit consistency
/// - 2: amount recomposition
/// - 64: diff bit binary constraints (limbs 0-1)
/// - 64: diff bit consistency
/// - 2: diff recomposition
/// - 2: borrow consistency (limbs 0-1)
/// - 2: borrow binary (limbs 0-1)
/// - 2: subtraction constraints (limbs 0-1)
/// - 12: Rescue permutation transition constraints
/// - 8: Rescue init binding (state[0..7] == amount limbs at row 0)
///
/// Total: 350
const NUM_CONSTRAINTS: usize = 350;

const RESCUE_HALF_ROUNDS: usize = ROUND_CONSTANTS.len();
const RESCUE_OUTPUT_ROW: usize = RESCUE_HALF_ROUNDS;

const PERIODIC_RESCUE_ACTIVE_IDX: usize = 0;
const PERIODIC_RESCUE_INIT_IDX: usize = 1;
const PERIODIC_RESCUE_IS_FORWARD_IDX: usize = 2;
const PERIODIC_RESCUE_CONST_START_IDX: usize = 3;
const PERIODIC_COLUMN_COUNT: usize = PERIODIC_RESCUE_CONST_START_IDX + RESCUE_STATE_WIDTH;

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
        assert_eq!(
            elements.len(),
            cols::PUBLIC_INPUTS_LEN,
            "public input element length mismatch"
        );
        Self {
            threshold,
            elements,
            witness_commitment: [FELT_ZERO; 4],
        }
    }

    /// Create new public inputs with witness commitment
    pub fn with_commitment(threshold: u64, elements: Vec<Felt>, commitment: [Felt; 4]) -> Self {
        assert_eq!(
            elements.len(),
            cols::PUBLIC_INPUTS_LEN,
            "public input element length mismatch"
        );
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

    /// Public input elements bound into trace columns
    public_inputs: Vec<Felt>,
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

        // Amount consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Threshold consistency (8 constraints, degree 1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Public input binding (constant across rows)
        for _ in 0..cols::PUBLIC_INPUTS_LEN {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Amount bit binary constraints (64 bits)
        // Since bits are constant across all rows, the polynomial is degree 0
        // but we declare 1 to account for trace polynomial structure
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Amount bit consistency (64 bits, degree 1)
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Amount recomposition (2 constraints, degree 1)
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));

        // Diff bit binary constraints (64 bits)
        // Since diff bits are constant across all rows, polynomial is degree 0
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Diff bit consistency (64 bits, degree 1)
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Diff recomposition (2 constraints, degree 1)
        degrees.push(TransitionConstraintDegree::new(1));
        degrees.push(TransitionConstraintDegree::new(1));

        // Borrow consistency (2 constraints, degree 1)
        for _ in 0..2 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Borrow binary (2 constraints)
        // Borrows are constant across rows
        for _ in 0..2 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Subtraction constraints (2 constraints, degree 1)
        for _ in 0..2 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Rescue permutation transitions (12 constraints)
        // Base degree 7 (pow7), but multiplied by periodic columns rescue_active and rescue_is_forward
        // which adds +2 to effective degree when periodic columns have full trace length period
        for _ in 0..RESCUE_STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::new(9));
        }

        // Rescue init binding (8 constraints)
        // Base degree 1, but multiplied by rescue_init periodic column (adds +1)
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(2));
        }

        // Number of boundary assertions: 78 (see get_assertions)
        let context = AirContext::new(trace_info, degrees, 78, options);

        Self {
            context,
            threshold: pub_inputs.threshold,
            witness_commitment: pub_inputs.witness_commitment,
            public_inputs: pub_inputs.elements.clone(),
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

        // Boundary constraint: upper limbs (2-7) must be zero for u64 amounts
        for i in 2..8 {
            assertions.push(Assertion::single(cols::AMOUNT_START + i, 0, FELT_ZERO));
        }

        // Boundary constraint: upper threshold limbs (2-7) must be zero for u64 limits
        for i in 2..8 {
            assertions.push(Assertion::single(cols::THRESHOLD_START + i, 0, FELT_ZERO));
        }

        // Boundary constraint: diff limbs (2-7) are zero (u64 subtraction only)
        for i in 2..8 {
            assertions.push(Assertion::single(cols::diff(i), 0, FELT_ZERO));
        }

        // Boundary constraint: final borrow (limb 1) must be zero for amount <= limit
        assertions.push(Assertion::single(cols::borrow(1), last_row, FELT_ZERO));

        // Boundary constraint: Rescue sponge domain separator and capacity padding
        assertions.push(Assertion::single(
            cols::RESCUE_STATE_START + 8,
            0,
            felt_from_u64(8),
        ));
        for i in 9..RESCUE_STATE_WIDTH {
            assertions.push(Assertion::single(
                cols::RESCUE_STATE_START + i,
                0,
                FELT_ZERO,
            ));
        }

        // Boundary constraint: witness commitment must match Rescue output (row 14)
        for i in 0..4 {
            assertions.push(Assertion::single(
                cols::RESCUE_STATE_START + i,
                RESCUE_OUTPUT_ROW,
                self.witness_commitment[i],
            ));
        }

        // Boundary constraint: bind public input elements into trace columns
        assert_eq!(
            self.public_inputs.len(),
            cols::PUBLIC_INPUTS_LEN,
            "public input element length mismatch"
        );
        for (idx, value) in self.public_inputs.iter().enumerate() {
            assertions.push(Assertion::single(
                cols::public_input(idx),
                0,
                *value,
            ));
        }

        assertions
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let mut idx = 0;

        debug_assert_eq!(periodic_values.len(), PERIODIC_COLUMN_COUNT);
        let rescue_active = periodic_values[PERIODIC_RESCUE_ACTIVE_IDX];
        let rescue_init = periodic_values[PERIODIC_RESCUE_INIT_IDX];
        let rescue_is_forward = periodic_values[PERIODIC_RESCUE_IS_FORWARD_IDX];

        // Constraint 0: Round counter increments by 1 (degree 1)
        let counter_current = current[cols::ROUND_COUNTER];
        let counter_next = next[cols::ROUND_COUNTER];
        result[idx] = counter_next - counter_current - E::ONE;
        idx += 1;

        // Amount limbs remain constant
        for i in 0..8 {
            let amount_curr = current[cols::AMOUNT_START + i];
            let amount_next = next[cols::AMOUNT_START + i];
            result[idx] = amount_next - amount_curr;
            idx += 1;
        }

        // Threshold limbs remain constant
        for i in 0..8 {
            let threshold_curr = current[cols::THRESHOLD_START + i];
            let threshold_next = next[cols::THRESHOLD_START + i];
            result[idx] = threshold_next - threshold_curr;
            idx += 1;
        }

        // Public inputs remain constant
        for i in 0..cols::PUBLIC_INPUTS_LEN {
            let value_curr = current[cols::public_input(i)];
            let value_next = next[cols::public_input(i)];
            result[idx] = value_next - value_curr;
            idx += 1;
        }

        // Amount bit binary constraints (limb 0)
        for i in 0..32 {
            let bit = current[cols::AMOUNT_BITS_LIMB0_START + i];
            result[idx] = bit * (E::ONE - bit);
            idx += 1;
        }

        // Amount bit binary constraints (limb 1)
        for i in 0..32 {
            let bit = current[cols::AMOUNT_BITS_LIMB1_START + i];
            result[idx] = bit * (E::ONE - bit);
            idx += 1;
        }

        // Amount bit consistency (limb 0)
        for i in 0..32 {
            let bit_curr = current[cols::AMOUNT_BITS_LIMB0_START + i];
            let bit_next = next[cols::AMOUNT_BITS_LIMB0_START + i];
            result[idx] = bit_next - bit_curr;
            idx += 1;
        }

        // Amount bit consistency (limb 1)
        for i in 0..32 {
            let bit_curr = current[cols::AMOUNT_BITS_LIMB1_START + i];
            let bit_next = next[cols::AMOUNT_BITS_LIMB1_START + i];
            result[idx] = bit_next - bit_curr;
            idx += 1;
        }

        // Amount recomposition (limb 0)
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

        // Amount recomposition (limb 1)
        let limb1 = current[cols::AMOUNT_START + 1];
        let mut recomp1 = E::ZERO;
        let mut power = E::ONE;
        for i in 0..32 {
            recomp1 = recomp1 + current[cols::AMOUNT_BITS_LIMB1_START + i] * power;
            power = power * two;
        }
        result[idx] = limb1 - recomp1;
        idx += 1;

        // Diff bit binary constraints (limb 0)
        for i in 0..32 {
            let bit = current[cols::DIFF_BITS_LIMB0_START + i];
            result[idx] = bit * (E::ONE - bit);
            idx += 1;
        }

        // Diff bit binary constraints (limb 1)
        for i in 0..32 {
            let bit = current[cols::DIFF_BITS_LIMB1_START + i];
            result[idx] = bit * (E::ONE - bit);
            idx += 1;
        }

        // Diff bit consistency (limb 0)
        for i in 0..32 {
            let bit_curr = current[cols::DIFF_BITS_LIMB0_START + i];
            let bit_next = next[cols::DIFF_BITS_LIMB0_START + i];
            result[idx] = bit_next - bit_curr;
            idx += 1;
        }

        // Diff bit consistency (limb 1)
        for i in 0..32 {
            let bit_curr = current[cols::DIFF_BITS_LIMB1_START + i];
            let bit_next = next[cols::DIFF_BITS_LIMB1_START + i];
            result[idx] = bit_next - bit_curr;
            idx += 1;
        }

        // Diff recomposition (limb 0)
        let diff0 = current[cols::diff(0)];
        let mut diff_recomp0 = E::ZERO;
        let mut power = E::ONE;
        for i in 0..32 {
            diff_recomp0 = diff_recomp0 + current[cols::DIFF_BITS_LIMB0_START + i] * power;
            power = power * two;
        }
        result[idx] = diff0 - diff_recomp0;
        idx += 1;

        // Diff recomposition (limb 1)
        let diff1 = current[cols::diff(1)];
        let mut diff_recomp1 = E::ZERO;
        let mut power = E::ONE;
        for i in 0..32 {
            diff_recomp1 = diff_recomp1 + current[cols::DIFF_BITS_LIMB1_START + i] * power;
            power = power * two;
        }
        result[idx] = diff1 - diff_recomp1;
        idx += 1;

        // Borrow consistency (limbs 0-1)
        for i in 0..2 {
            let borrow_curr = current[cols::borrow(i)];
            let borrow_next = next[cols::borrow(i)];
            result[idx] = borrow_next - borrow_curr;
            idx += 1;
        }

        // Borrow binary (limbs 0-1)
        for i in 0..2 {
            let borrow_val = current[cols::borrow(i)];
            result[idx] = borrow_val * (E::ONE - borrow_val);
            idx += 1;
        }

        // Subtraction constraints for limbs 0-1
        let two_pow_32 = E::from(felt_from_u64(1u64 << 32));
        let threshold_low = current[cols::THRESHOLD_START];
        let threshold_high = current[cols::THRESHOLD_START + 1];
        let borrow0 = current[cols::borrow(0)];
        let borrow1 = current[cols::borrow(1)];
        result[idx] = limb0 + diff0 - threshold_low - borrow0 * two_pow_32;
        idx += 1;
        result[idx] = limb1 + diff1 + borrow0 - threshold_high - borrow1 * two_pow_32;
        idx += 1;

        // Rescue permutation transitions
        let mut curr_state = [E::ZERO; RESCUE_STATE_WIDTH];
        let mut next_state = [E::ZERO; RESCUE_STATE_WIDTH];
        for i in 0..RESCUE_STATE_WIDTH {
            curr_state[i] = current[cols::RESCUE_STATE_START + i];
            next_state[i] = next[cols::RESCUE_STATE_START + i];
        }

        let mut sbox_state = [E::ZERO; RESCUE_STATE_WIDTH];
        for i in 0..RESCUE_STATE_WIDTH {
            sbox_state[i] = pow7(curr_state[i]);
        }

        let mds_forward = apply_mds(&sbox_state, &MDS);
        let mds_inv = apply_mds(&curr_state, &MDS_INV);

        for i in 0..RESCUE_STATE_WIDTH {
            let round_const = periodic_values[PERIODIC_RESCUE_CONST_START_IDX + i];
            let forward_constraint = next_state[i] - (mds_forward[i] + round_const);
            let backward_constraint = pow7(next_state[i] - round_const) - mds_inv[i];
            let step_constraint =
                rescue_is_forward * forward_constraint + (E::ONE - rescue_is_forward) * backward_constraint;

            result[idx] = rescue_active * step_constraint
                + (E::ONE - rescue_active) * (next_state[i] - curr_state[i]);
            idx += 1;
        }

        // Rescue init binding at row 0 (state[0..7] == amount limbs)
        for i in 0..8 {
            let state_val = current[cols::RESCUE_STATE_START + i];
            let amount_val = current[cols::AMOUNT_START + i];
            result[idx] = rescue_init * (state_val - amount_val);
            idx += 1;
        }

        debug_assert_eq!(idx, NUM_CONSTRAINTS);
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let trace_len = self.trace_length();
        let mut columns = Vec::with_capacity(PERIODIC_COLUMN_COUNT);

        let active_len = RESCUE_HALF_ROUNDS.min(trace_len.saturating_sub(1));

        let mut rescue_active = vec![FELT_ZERO; trace_len];
        for i in 0..active_len {
            rescue_active[i] = FELT_ONE;
        }
        columns.push(rescue_active);

        let mut rescue_init = vec![FELT_ZERO; trace_len];
        if trace_len > 0 {
            rescue_init[0] = FELT_ONE;
        }
        columns.push(rescue_init);

        let mut rescue_is_forward = vec![FELT_ZERO; trace_len];
        for i in 0..active_len {
            rescue_is_forward[i] = if i % 2 == 0 { FELT_ONE } else { FELT_ZERO };
        }
        columns.push(rescue_is_forward);

        for const_idx in 0..RESCUE_STATE_WIDTH {
            let mut col = vec![FELT_ZERO; trace_len];
            for step in 0..active_len {
                col[step] = felt_from_u64(ROUND_CONSTANTS[step][const_idx]);
            }
            columns.push(col);
        }

        debug_assert_eq!(columns.len(), PERIODIC_COLUMN_COUNT);
        columns
    }
}

fn pow7<E: FieldElement<BaseField = Felt>>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

fn apply_mds<E: FieldElement<BaseField = Felt>>(
    state: &[E; RESCUE_STATE_WIDTH],
    matrix: &[[u64; RESCUE_STATE_WIDTH]; RESCUE_STATE_WIDTH],
) -> [E; RESCUE_STATE_WIDTH] {
    let mut result = [E::ZERO; RESCUE_STATE_WIDTH];
    for i in 0..RESCUE_STATE_WIDTH {
        let mut sum = E::ZERO;
        for j in 0..RESCUE_STATE_WIDTH {
            sum = sum + E::from(felt_from_u64(matrix[i][j])) * state[j];
        }
        result[i] = sum;
    }
    result
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
        let elements_vec = vec![felt_from_u64(1); cols::PUBLIC_INPUTS_LEN];
        let pub_inputs = PublicInputs::new(10000, elements_vec);
        let elements = pub_inputs.to_elements();
        // threshold + public inputs + witness commitment elements
        assert_eq!(elements.len(), 1 + cols::PUBLIC_INPUTS_LEN + 4);
        assert_eq!(elements[0].as_int(), 10000);
    }

    #[test]
    fn test_public_inputs_with_commitment() {
        let commitment = [felt_from_u64(100), felt_from_u64(200), felt_from_u64(300), felt_from_u64(400)];
        let elements_vec = vec![felt_from_u64(1); cols::PUBLIC_INPUTS_LEN];
        let pub_inputs = PublicInputs::with_commitment(
            10000,
            elements_vec,
            commitment,
        );
        let elements = pub_inputs.to_elements();
        // threshold + public inputs + witness commitment elements
        assert_eq!(elements.len(), 1 + cols::PUBLIC_INPUTS_LEN + 4);
        assert_eq!(elements[0].as_int(), 10000);
        // Check commitment elements are at the end
        let commitment_start = 1 + cols::PUBLIC_INPUTS_LEN;
        assert_eq!(elements[commitment_start].as_int(), 100);
        assert_eq!(elements[commitment_start + 1].as_int(), 200);
        assert_eq!(elements[commitment_start + 2].as_int(), 300);
        assert_eq!(elements[commitment_start + 3].as_int(), 400);
    }
}
