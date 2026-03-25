//! Budget witness construction for the `agent.budget.v1` policy.
//!
//! The budget policy proves that an agent's cumulative spending does not exceed
//! a budget limit, without revealing the running total or individual amounts.
//!
//! # How It Works
//!
//! The caller computes `new_total = prev_running_total + this_amount` and passes
//! it as the witness amount. The AIR proves `new_total <= budget_limit` using
//! the standard LTE comparison gadget. The witness commitment binds `new_total`
//! via a Rescue hash, creating a verifiable chain of accumulator commitments.
//!
//! # Sequencer Chaining
//!
//! The sequencer tracks the chain of witness commitments:
//! - Proof N commits `total_N` via `witness_commitment_N`
//! - Proof N+1's public inputs reference `witness_commitment_N` as the
//!   previous accumulator
//! - The sequencer verifies the chain is consistent

use crate::witness::ComplianceWitness;
use crate::Policy;
use ves_stark_primitives::public_inputs::{compute_policy_hash, CompliancePublicInputs, PolicyParams};

/// Construct a budget witness for the `agent.budget.v1` policy.
///
/// # Arguments
///
/// * `this_amount` - The amount for the current transaction
/// * `prev_running_total` - Cumulative spend before this transaction (private)
/// * `budget_limit` - The maximum allowed cumulative spend
/// * `public_inputs` - Event public inputs (must have policy_id = "agent.budget.v1")
///
/// # Returns
///
/// A tuple of `(ComplianceWitness, Policy)` ready for proving.
///
/// # Example
///
/// ```ignore
/// use ves_stark_prover::budget::build_budget_witness;
///
/// let (witness, policy) = build_budget_witness(
///     3_500,       // this purchase
///     12_200,      // spent so far
///     50_000,      // budget cap
///     public_inputs,
/// )?;
///
/// let prover = ComplianceProver::with_policy(policy);
/// let proof = prover.prove(&witness)?;
/// ```
pub fn build_budget_witness(
    this_amount: u64,
    prev_running_total: u64,
    budget_limit: u64,
    public_inputs: CompliancePublicInputs,
) -> Result<(ComplianceWitness, Policy), BudgetWitnessError> {
    let new_total = prev_running_total
        .checked_add(this_amount)
        .ok_or(BudgetWitnessError::Overflow)?;

    if new_total > budget_limit {
        return Err(BudgetWitnessError::ExceedsBudget {
            new_total,
            budget_limit,
        });
    }

    let policy = Policy::agent_budget(budget_limit);

    // The witness amount is the new cumulative total — the AIR proves new_total <= budget_limit
    let witness = ComplianceWitness::new(new_total, public_inputs);

    Ok((witness, policy))
}

/// Create policy params and hash for a budget policy.
///
/// Returns `(PolicyParams, policy_hash_hex)` for constructing `CompliancePublicInputs`.
pub fn budget_policy_params(
    budget_limit: u64,
) -> Result<(PolicyParams, String), BudgetWitnessError> {
    let params = PolicyParams::budget(budget_limit);
    let hash = compute_policy_hash("agent.budget.v1", &params)
        .map_err(|e| BudgetWitnessError::PolicyHash(format!("{e}")))?;
    Ok((params, hash.to_hex()))
}

/// Errors from budget witness construction.
#[derive(Debug, thiserror::Error)]
pub enum BudgetWitnessError {
    /// Cumulative total would overflow u64
    #[error("cumulative total overflows u64: prev_running_total + this_amount > u64::MAX")]
    Overflow,
    /// New total exceeds budget limit
    #[error("new cumulative total {new_total} exceeds budget limit {budget_limit}")]
    ExceedsBudget { new_total: u64, budget_limit: u64 },
    /// Policy hash computation failed
    #[error("policy hash error: {0}")]
    PolicyHash(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::ComplianceProver;
    use uuid::Uuid;

    fn sample_budget_inputs(budget_limit: u64) -> CompliancePublicInputs {
        let (params, hash) = budget_policy_params(budget_limit).unwrap();
        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "a".repeat(64),
            payload_cipher_hash: "b".repeat(64),
            event_signing_hash: "c".repeat(64),
            policy_id: "agent.budget.v1".to_string(),
            policy_params: params,
            policy_hash: hash,
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
    }

    #[test]
    fn test_budget_witness_valid() {
        let inputs = sample_budget_inputs(50_000);
        let (witness, policy) = build_budget_witness(3_500, 12_200, 50_000, inputs).unwrap();

        assert_eq!(policy.policy_id(), "agent.budget.v1");
        assert_eq!(policy.limit(), 50_000);

        // The witness amount should be new_total = 12200 + 3500 = 15700
        assert_eq!(witness.amount, 15_700);
    }

    #[test]
    fn test_budget_witness_at_limit() {
        let inputs = sample_budget_inputs(50_000);
        // 30000 + 20000 = 50000, exactly at budget limit (LTE, should succeed)
        let result = build_budget_witness(20_000, 30_000, 50_000, inputs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0.amount, 50_000);
    }

    #[test]
    fn test_budget_witness_exceeds_limit() {
        let inputs = sample_budget_inputs(50_000);
        let result = build_budget_witness(20_001, 30_000, 50_000, inputs);
        assert!(matches!(result, Err(BudgetWitnessError::ExceedsBudget { .. })));
    }

    #[test]
    fn test_budget_witness_overflow() {
        let inputs = sample_budget_inputs(u64::MAX);
        let result = build_budget_witness(1, u64::MAX, u64::MAX, inputs);
        assert!(matches!(result, Err(BudgetWitnessError::Overflow)));
    }

    #[test]
    fn test_budget_prove() {
        let budget_limit = 50_000u64;
        let this_amount = 3_500u64;
        let prev_total = 12_200u64;

        let inputs = sample_budget_inputs(budget_limit);
        let (witness, policy) = build_budget_witness(
            this_amount,
            prev_total,
            budget_limit,
            inputs,
        )
        .unwrap();

        let prover = ComplianceProver::with_policy(policy);
        let proof = prover.prove(&witness).expect("budget proof should succeed");

        assert!(!proof.proof_bytes.is_empty());
        assert!(proof.proof_bytes.len() < 100_000); // Should be ~42 KB
        println!("Budget proof size: {} bytes", proof.proof_bytes.len());
    }
}
