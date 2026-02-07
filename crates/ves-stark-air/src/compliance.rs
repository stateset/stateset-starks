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
//! 4. **Inequality Integrity**: A 2-limb (u64) subtraction gadget enforces
//!    `amount <= effective_limit`, and the final borrow is bound via a
//!    boundary assertion.
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
//! 3. T[ROUND_COUNTER][0] = 0
//!    T[ROUND_COUNTER][last] = last
//!    Purpose: Bind the round counter to row index (and thus trace length).
//!
//! 4. T[THRESHOLD_START][0] = limit_low
//!    T[THRESHOLD_START+1][0] = limit_high
//!    Purpose: Bind public threshold to trace
//!
//! 5. T[AMOUNT_START+i][0] = 0  for i in 2..8
//!    Purpose: Upper limbs zero (amount fits in 64 bits)
//!
//! 6. T[THRESHOLD_START+i][0] = 0  for i in 2..8
//!    Purpose: Upper limbs zero (limit fits in 64 bits)
//!
//! 7. T[DIFF_START+i][0] = 0  for i in 2..8
//!    Purpose: Upper limbs zero (diff fits in 64 bits)
//!
//! 8. T[BORROW_START+1][0] = 0
//!    Purpose: Final borrow is zero, enforcing amount <= limit.
//!
//! 9. T[RESCUE_STATE_START+8][0] = 8
//!    T[RESCUE_STATE_START+9..12][0] = 0
//!    Purpose: Rescue sponge domain separator and capacity padding.
//!
//! 10. T[RESCUE_STATE_START+i][14] = witness_commitment[i]  for i in 0..4
//!     Purpose: Bind witness commitment hash to the Rescue output row.
//! ```
//!
//! ### Transition Constraints (Adjacent Rows)
//!
//! ```text
//! Constraint 0: Round Counter Increment
//!   counter[next] - counter[curr] - 1 ≡ 0
//!   Degree: 1
//!   Purpose: Together with boundary assertions, binds counter to row index.
//!
//! Comparison constraints are gated by the periodic column `rescue_init`
//! (1 only on row 0). This enforces correctness at row 0 while allowing
//! unconstrained padding rows.
//!
//! Constraints 1-64: Amount Bit Binary (Limb 0/1)
//!   rescue_init * bit[i] * (1 - bit[i]) ≡ 0
//!   Degree: 3 (binary + selector)
//!
//! Constraints 65-66: Amount Recomposition (Limbs 0-1)
//!   rescue_init * (limb - Σ(bit[i] × 2^i)) ≡ 0
//!   Degree: 2 (linear + selector)
//!
//! Constraints 67-130: Diff Bit Binary (Limb 0/1)
//!   rescue_init * bit[i] * (1 - bit[i]) ≡ 0
//!   Degree: 3 (binary + selector)
//!
//! Constraints 131-132: Diff Recomposition (Limbs 0-1)
//!   rescue_init * (diff - Σ(bit[i] × 2^i)) ≡ 0
//!   Degree: 2 (linear + selector)
//!
//! Constraints 133-134: Borrow Binary (Limbs 0-1)
//!   rescue_init * borrow[i] * (1 - borrow[i]) ≡ 0
//!   Degree: 3 (binary + selector)
//!
//! Constraints 135-136: Subtraction (Limbs 0-1)
//!   rescue_init * (a + diff - t - borrow * 2^32) ≡ 0
//!   Degree: 2 (linear + selector)
//!
//! Constraints 137-148: Rescue Permutation Transitions
//!   Rescue-Prime half-round transitions (forward/backward)
//!
//! Constraints 149-156: Rescue Init Binding
//!   rescue_init * (state[i] - amount[i]) ≡ 0  for i in 0..8
//! ```
//!
//! ## Constraint Count Summary
//!
//! | Category | Count | Description |
//! |----------|-------|-------------|
//! | Round counter | 1 | Increment check |
//! | Amount bit binary (gated) | 64 | b(1-b)=0 checks |
//! | Amount recomposition (gated) | 2 | limb = Σ bits |
//! | Diff bit binary (gated) | 64 | b(1-b)=0 checks |
//! | Diff recomposition (gated) | 2 | limb = Σ bits |
//! | Borrow binary (gated) | 2 | b(1-b)=0 checks |
//! | Subtraction constraints (gated) | 2 | limb subtraction |
//! | Rescue transitions | 12 | Rescue permutation steps |
//! | Rescue init binding | 8 | state[0..7] == amount limbs |
//! | **Total** | **157** | |
//!
//! ## Security Level
//!
//! Security depends on the chosen `ProofOptions` (FRI queries, blowup factor, grinding factor,
//! field extension degree, etc.). This crate exposes `ProofOptions::{default, fast, secure}` as
//! convenient presets, but callers should treat the included security estimate as approximate.

use crate::policies::aml_threshold::AmlThresholdPolicy;
use crate::rescue_air::{MDS, MDS_INV, ROUND_CONSTANTS};
use crate::trace::{cols, MIN_TRACE_LENGTH, TRACE_WIDTH};
use thiserror::Error;
use ves_stark_primitives::public_inputs::CompliancePublicInputsFelts;
use ves_stark_primitives::rescue::STATE_WIDTH as RESCUE_STATE_WIDTH;
use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::{FieldElement, ToElements};

/// Number of transition constraints in the AIR (V3 - Full Security)
///
/// - 1: round counter
/// - 64: amount bit binary constraints (gated)
/// - 2: amount recomposition (gated)
/// - 64: diff bit binary constraints (gated)
/// - 2: diff recomposition (gated)
/// - 2: borrow binary (gated)
/// - 2: subtraction constraints (gated)
/// - 12: Rescue permutation transition constraints
/// - 8: Rescue init binding (state[0..7] == amount limbs at row 0)
///
/// Total: 157
pub const NUM_CONSTRAINTS: usize = 157;

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
    /// The policy limit used by the AIR (effective limit for strict policies)
    pub policy_limit: u64,
    /// Public input field elements
    pub elements: Vec<Felt>,
    /// Witness commitment (first 4 elements of Rescue hash)
    /// This binds the private witness to the proof
    pub witness_commitment: [Felt; 4],
}

/// Errors that can occur when constructing AIR public inputs
#[derive(Debug, Error)]
pub enum PublicInputsError {
    /// Public input element length mismatch
    #[error("public input element length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}

impl PublicInputs {
    /// Create new public inputs (legacy, without witness commitment)
    pub fn new(policy_limit: u64, elements: Vec<Felt>) -> Self {
        Self::try_new(policy_limit, elements).expect("public input element length mismatch")
    }

    /// Create new public inputs with witness commitment
    pub fn with_commitment(policy_limit: u64, elements: Vec<Felt>, commitment: [Felt; 4]) -> Self {
        Self::try_with_commitment(policy_limit, elements, commitment)
            .expect("public input element length mismatch")
    }

    /// Create new public inputs (legacy, without witness commitment) without panicking
    pub fn try_new(policy_limit: u64, elements: Vec<Felt>) -> Result<Self, PublicInputsError> {
        if elements.len() != cols::PUBLIC_INPUTS_LEN {
            return Err(PublicInputsError::LengthMismatch {
                expected: cols::PUBLIC_INPUTS_LEN,
                actual: elements.len(),
            });
        }
        Ok(Self {
            policy_limit,
            elements,
            witness_commitment: [FELT_ZERO; 4],
        })
    }

    /// Create new public inputs with witness commitment without panicking
    pub fn try_with_commitment(
        policy_limit: u64,
        elements: Vec<Felt>,
        commitment: [Felt; 4],
    ) -> Result<Self, PublicInputsError> {
        if elements.len() != cols::PUBLIC_INPUTS_LEN {
            return Err(PublicInputsError::LengthMismatch {
                expected: cols::PUBLIC_INPUTS_LEN,
                actual: elements.len(),
            });
        }
        Ok(Self {
            policy_limit,
            elements,
            witness_commitment: commitment,
        })
    }
}

impl ToElements<Felt> for PublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut result = vec![felt_from_u64(self.policy_limit)];
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

    /// Policy limit used by the AIR (effective limit for strict policies)
    policy_limit: u64,

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
    pub fn policy_limit(&self) -> u64 {
        self.policy_limit
    }
}

impl Air for ComplianceAir {
    type BaseField = Felt;
    type PublicInputs = PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // We assert against the Rescue output row, so the trace must be long enough.
        assert!(
            trace_info.length() > RESCUE_OUTPUT_ROW,
            "trace length {} too short; must be > {}",
            trace_info.length(),
            RESCUE_OUTPUT_ROW
        );
        // Never allow constructing an AIR instance with missing public inputs. If this invariant is
        // violated, `get_assertions()` could silently bind fewer public inputs in release builds.
        assert_eq!(
            pub_inputs.elements.len(),
            cols::PUBLIC_INPUTS_LEN,
            "public input element length mismatch: expected {}, got {}",
            cols::PUBLIC_INPUTS_LEN,
            pub_inputs.elements.len()
        );

        // Build transition constraint degrees
        let mut degrees = Vec::with_capacity(NUM_CONSTRAINTS);

        // Constraint 0: Round counter (degree 1)
        degrees.push(TransitionConstraintDegree::new(1));

        // Comparison constraints are gated by rescue_init (row 0 selector).
        // Gating adds +1 to the base degree for constraints using the selector.

        // Amount bit binary constraints (64 bits) -> degree 3 (binary + selector)
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(3));
        }

        // Amount recomposition (2 constraints) -> degree 2 (linear + selector)
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));

        // Diff bit binary constraints (64 bits) -> degree 3 (binary + selector)
        for _ in 0..64 {
            degrees.push(TransitionConstraintDegree::new(3));
        }

        // Diff recomposition (2 constraints) -> degree 2 (linear + selector)
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));

        // Borrow binary (2 constraints) -> degree 3 (binary + selector)
        for _ in 0..2 {
            degrees.push(TransitionConstraintDegree::new(3));
        }

        // Subtraction constraints (2 constraints) -> degree 2 (linear + selector)
        for _ in 0..2 {
            degrees.push(TransitionConstraintDegree::new(2));
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

        // Number of boundary assertions: 80 (see get_assertions)
        let context = AirContext::new(trace_info, degrees, 80, options);

        Self {
            context,
            policy_limit: pub_inputs.policy_limit,
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

        // Bind the round counter to row index.
        assertions.push(Assertion::single(cols::ROUND_COUNTER, 0, FELT_ZERO));
        assertions.push(Assertion::single(
            cols::ROUND_COUNTER,
            last_row,
            felt_from_u64(last_row as u64),
        ));

        // Boundary constraint: policy limit values match public input
        let threshold_low = felt_from_u64(self.policy_limit & 0xFFFFFFFF);
        let threshold_high = felt_from_u64(self.policy_limit >> 32);
        assertions.push(Assertion::single(cols::THRESHOLD_START, 0, threshold_low));
        assertions.push(Assertion::single(
            cols::THRESHOLD_START + 1,
            0,
            threshold_high,
        ));

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

        // Boundary constraint: final borrow (limb 1) must be zero for amount <= limit.
        //
        // Note: the subtraction gadget is enforced at row 0 (gated by `rescue_init`), so we
        // must bind the final borrow on the same row.
        assertions.push(Assertion::single(cols::borrow(1), 0, FELT_ZERO));

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
            assertions.push(Assertion::single(cols::public_input(idx), 0, *value));
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

        // Amount bit binary constraints (limb 0), gated by rescue_init
        for i in 0..32 {
            let bit = current[cols::AMOUNT_BITS_LIMB0_START + i];
            result[idx] = rescue_init * bit * (E::ONE - bit);
            idx += 1;
        }

        // Amount bit binary constraints (limb 1), gated by rescue_init
        for i in 0..32 {
            let bit = current[cols::AMOUNT_BITS_LIMB1_START + i];
            result[idx] = rescue_init * bit * (E::ONE - bit);
            idx += 1;
        }

        // Amount recomposition (limb 0), gated by rescue_init
        let limb0 = current[cols::AMOUNT_START];
        let mut recomp0 = E::ZERO;
        let two = E::from(felt_from_u64(2));
        let mut power = E::ONE;
        for i in 0..32 {
            recomp0 += current[cols::AMOUNT_BITS_LIMB0_START + i] * power;
            power *= two;
        }
        result[idx] = rescue_init * (limb0 - recomp0);
        idx += 1;

        // Amount recomposition (limb 1), gated by rescue_init
        let limb1 = current[cols::AMOUNT_START + 1];
        let mut recomp1 = E::ZERO;
        let mut power = E::ONE;
        for i in 0..32 {
            recomp1 += current[cols::AMOUNT_BITS_LIMB1_START + i] * power;
            power *= two;
        }
        result[idx] = rescue_init * (limb1 - recomp1);
        idx += 1;

        // Diff bit binary constraints (limb 0), gated by rescue_init
        for i in 0..32 {
            let bit = current[cols::DIFF_BITS_LIMB0_START + i];
            result[idx] = rescue_init * bit * (E::ONE - bit);
            idx += 1;
        }

        // Diff bit binary constraints (limb 1), gated by rescue_init
        for i in 0..32 {
            let bit = current[cols::DIFF_BITS_LIMB1_START + i];
            result[idx] = rescue_init * bit * (E::ONE - bit);
            idx += 1;
        }

        // Diff recomposition (limb 0), gated by rescue_init
        let diff0 = current[cols::diff(0)];
        let mut diff_recomp0 = E::ZERO;
        let mut power = E::ONE;
        for i in 0..32 {
            diff_recomp0 += current[cols::DIFF_BITS_LIMB0_START + i] * power;
            power *= two;
        }
        result[idx] = rescue_init * (diff0 - diff_recomp0);
        idx += 1;

        // Diff recomposition (limb 1), gated by rescue_init
        let diff1 = current[cols::diff(1)];
        let mut diff_recomp1 = E::ZERO;
        let mut power = E::ONE;
        for i in 0..32 {
            diff_recomp1 += current[cols::DIFF_BITS_LIMB1_START + i] * power;
            power *= two;
        }
        result[idx] = rescue_init * (diff1 - diff_recomp1);
        idx += 1;

        // Borrow binary (limbs 0-1), gated by rescue_init
        for i in 0..2 {
            let borrow_val = current[cols::borrow(i)];
            result[idx] = rescue_init * borrow_val * (E::ONE - borrow_val);
            idx += 1;
        }

        // Subtraction constraints for limbs 0-1, gated by rescue_init
        let two_pow_32 = E::from(felt_from_u64(1u64 << 32));
        let threshold_low = current[cols::THRESHOLD_START];
        let threshold_high = current[cols::THRESHOLD_START + 1];
        let borrow0 = current[cols::borrow(0)];
        let borrow1 = current[cols::borrow(1)];
        result[idx] = rescue_init * (limb0 + diff0 - threshold_low - borrow0 * two_pow_32);
        idx += 1;
        result[idx] =
            rescue_init * (limb1 + diff1 + borrow0 - threshold_high - borrow1 * two_pow_32);
        idx += 1;

        // Rescue permutation transitions
        let mut curr_state = [E::ZERO; RESCUE_STATE_WIDTH];
        let mut next_state = [E::ZERO; RESCUE_STATE_WIDTH];
        let rescue_state_start = cols::RESCUE_STATE_START;
        let rescue_state_end = rescue_state_start + RESCUE_STATE_WIDTH;
        curr_state.copy_from_slice(&current[rescue_state_start..rescue_state_end]);
        next_state.copy_from_slice(&next[rescue_state_start..rescue_state_end]);

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
            let step_constraint = rescue_is_forward * forward_constraint
                + (E::ONE - rescue_is_forward) * backward_constraint;

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
        for v in rescue_active.iter_mut().take(active_len) {
            *v = FELT_ONE;
        }
        columns.push(rescue_active);

        let mut rescue_init = vec![FELT_ZERO; trace_len];
        if trace_len > 0 {
            rescue_init[0] = FELT_ONE;
        }
        columns.push(rescue_init);

        let mut rescue_is_forward = vec![FELT_ZERO; trace_len];
        for (i, v) in rescue_is_forward.iter_mut().enumerate().take(active_len) {
            *v = if i % 2 == 0 { FELT_ONE } else { FELT_ZERO };
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
    for (i, row) in matrix.iter().enumerate() {
        let mut sum = E::ZERO;
        for (&coeff, &s) in row.iter().zip(state.iter()) {
            sum += E::from(felt_from_u64(coeff)) * s;
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
    pub fn build(self) -> Result<(ComplianceAir, PublicInputs), String> {
        let pub_inputs_felts = self
            .pub_inputs
            .ok_or_else(|| "Public inputs required".to_string())?;
        let policy = self.policy.ok_or_else(|| "Policy required".to_string())?;
        let options = match self.options {
            Some(options) => options,
            None => crate::options::ProofOptions::default()
                .try_to_winterfell()
                .map_err(|e| e.to_string())?,
        };

        let trace_info = TraceInfo::new(TRACE_WIDTH, self.trace_length);
        let policy_limit = crate::policy::Policy::from(policy)
            .effective_limit()
            .map_err(|_| "Invalid AML threshold (must be > 0)".to_string())?;
        let pub_inputs = PublicInputs::try_new(policy_limit, pub_inputs_felts.to_vec())
            .map_err(|e| e.to_string())?;
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
    use uuid::Uuid;
    use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams};

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
            witness_commitment: None,
        }
    }

    #[test]
    fn test_air_builder() {
        let inputs = sample_public_inputs();
        let felts = inputs.to_field_elements().unwrap();
        let policy = AmlThresholdPolicy::new(10000);

        let (air, _pub_inputs) = ComplianceAirBuilder::new()
            .public_inputs(felts)
            .policy(policy)
            .build()
            .unwrap();

        assert_eq!(air.policy_limit(), 9999);
    }

    #[test]
    fn test_air_assertions() {
        let inputs = sample_public_inputs();
        let felts = inputs.to_field_elements().unwrap();
        let policy = AmlThresholdPolicy::new(10000);

        let (air, _pub_inputs) = ComplianceAirBuilder::new()
            .public_inputs(felts)
            .policy(policy)
            .build()
            .unwrap();

        let assertions = air.get_assertions();
        assert_eq!(assertions.len(), 80);
    }

    #[test]
    fn test_public_inputs_to_elements() {
        let elements_vec = vec![felt_from_u64(1); cols::PUBLIC_INPUTS_LEN];
        let pub_inputs = PublicInputs::try_new(10000, elements_vec).unwrap();
        let elements = pub_inputs.to_elements();
        // threshold + public inputs + witness commitment elements
        assert_eq!(elements.len(), 1 + cols::PUBLIC_INPUTS_LEN + 4);
        assert_eq!(elements[0].as_int(), 10000);
    }

    #[test]
    fn test_public_inputs_with_commitment() {
        let commitment = [
            felt_from_u64(100),
            felt_from_u64(200),
            felt_from_u64(300),
            felt_from_u64(400),
        ];
        let elements_vec = vec![felt_from_u64(1); cols::PUBLIC_INPUTS_LEN];
        let pub_inputs =
            PublicInputs::try_with_commitment(10000, elements_vec, commitment).unwrap();
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
