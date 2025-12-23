//! Main prover implementation for VES compliance proofs
//!
//! This module provides the high-level interface for generating STARK proofs
//! of compliance. It orchestrates trace generation and proof computation.
//!
//! # Multi-Policy Support
//!
//! The prover supports multiple policy types through the unified [`Policy`] enum:
//! - `aml.threshold`: Proves amount < threshold (strict less-than)
//! - `order_total.cap`: Proves amount <= cap (less-than-or-equal)
//!
//! ```ignore
//! use ves_stark_prover::{ComplianceProver, Policy};
//!
//! // AML threshold policy
//! let prover = ComplianceProver::with_policy(Policy::aml_threshold(10000));
//!
//! // Order total cap policy
//! let prover = ComplianceProver::with_policy(Policy::order_total_cap(50000));
//! ```

use ves_stark_air::compliance::{ComplianceAir, PublicInputs};
use ves_stark_air::policies::aml_threshold::AmlThresholdPolicy;
use ves_stark_air::options::ProofOptions;
use ves_stark_primitives::{Felt, Hash256};
use ves_stark_primitives::rescue::rescue_hash;
use crate::trace::TraceBuilder;
use crate::witness::ComplianceWitness;
use crate::policy::Policy;
use crate::error::ProverError;
use winter_prover::{Prover, Trace, TraceTable};
use winter_air::TraceInfo;
use winter_crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Type alias for the hash function used
pub type Hasher = Blake3_256<Felt>;

/// Type alias for the random coin
pub type RandCoin = DefaultRandomCoin<Hasher>;

/// Type alias for vector commitment
pub type VectorCommit = MerkleTree<Hasher>;

/// A generated compliance proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceProof {
    /// The raw proof bytes
    #[serde(with = "serde_bytes")]
    pub proof_bytes: Vec<u8>,

    /// Hash of the proof
    pub proof_hash: String,

    /// Proof metadata
    pub metadata: ProofMetadata,

    /// Witness commitment (Rescue hash of private amount)
    /// This binds the private witness to the proof
    pub witness_commitment: [u64; 4],
}

/// Metadata about the proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Time taken to generate the proof (milliseconds)
    pub proving_time_ms: u64,

    /// Number of constraints
    pub num_constraints: usize,

    /// Trace length
    pub trace_length: usize,

    /// Proof size in bytes
    pub proof_size: usize,

    /// Prover version
    pub prover_version: String,
}

impl ComplianceProof {
    /// Compute the proof hash using the domain separator
    pub fn compute_hash(proof_bytes: &[u8]) -> Hash256 {
        Hash256::sha256_with_domain(
            b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
            proof_bytes
        )
    }
}

/// The main compliance prover
pub struct ComplianceProver {
    /// The unified policy being proven
    policy: Policy,

    /// Proof options
    options: ProofOptions,
}

impl ComplianceProver {
    /// Create a new prover for the given AmlThresholdPolicy (legacy API)
    pub fn new(policy: AmlThresholdPolicy) -> Self {
        Self {
            policy: policy.into(),
            options: ProofOptions::default(),
        }
    }

    /// Create a new prover with a unified Policy
    pub fn with_policy(policy: Policy) -> Self {
        Self {
            policy,
            options: ProofOptions::default(),
        }
    }

    /// Set proof options
    pub fn with_options(mut self, options: ProofOptions) -> Self {
        self.options = options;
        self
    }

    /// Get the policy
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Generate a proof for the given witness
    pub fn prove(&self, witness: &ComplianceWitness) -> Result<ComplianceProof, ProverError> {
        let start = Instant::now();

        // Validate witness against unified policy
        if !self.policy.validate_amount(witness.amount) {
            return Err(ProverError::policy_validation_failed(format!(
                "Amount {} does not satisfy {} policy with limit {}",
                witness.amount,
                self.policy.policy_id(),
                self.policy.limit()
            )));
        }

        // Ensure public inputs policy matches the prover policy
        let inputs_policy = Policy::from_public_inputs(
            &witness.public_inputs.policy_id,
            &witness.public_inputs.policy_params,
        )
        .map_err(|e| ProverError::InvalidPublicInputs(format!("Invalid policy params: {e}")))?;
        if inputs_policy != self.policy {
            return Err(ProverError::InvalidPublicInputs(format!(
                "Policy mismatch: public inputs are for {}, prover configured for {}",
                inputs_policy.policy_id(),
                self.policy.policy_id()
            )));
        }

        // Build execution trace with unified policy
        let trace = TraceBuilder::new(witness.clone(), self.policy.clone())
            .build()?;

        let trace_length = trace.length();

        // Compute witness commitment using Rescue hash
        // This binds the private amount to the proof
        let amount_limbs = witness.amount_limbs();
        let hash_input: Vec<Felt> = amount_limbs.iter().cloned().collect();
        let hash_output = rescue_hash(&hash_input);
        let witness_commitment: [Felt; 4] = [
            hash_output[0],
            hash_output[1],
            hash_output[2],
            hash_output[3],
        ];

        // Build public inputs (use limit as threshold for AIR compatibility)
        let pub_inputs_felts = witness.public_inputs
            .to_field_elements()
            .map_err(|e| ProverError::InvalidPublicInputs(format!("{e}")))?;
        let policy_limit = self
            .policy
            .effective_limit()
            .map_err(|e| ProverError::PolicyValidationFailed(format!("{e}")))?;
        let pub_inputs = PublicInputs::with_commitment(
            policy_limit,
            pub_inputs_felts.to_vec(),
            witness_commitment,
        );

        // Create internal prover
        let prover = VesComplianceProver::new(
            self.policy.clone(),
            self.options.clone(),
            pub_inputs,
        );

        // Generate proof
        let proof = prover.prove(trace)
            .map_err(|e| ProverError::ProofGenerationFailed(format!("{:?}", e)))?;

        // Serialize proof
        let proof_bytes = proof.to_bytes();
        let proof_hash = ComplianceProof::compute_hash(&proof_bytes);

        let proving_time = start.elapsed();

        // Convert witness commitment to u64 array for serialization
        let commitment_u64: [u64; 4] = [
            witness_commitment[0].as_int(),
            witness_commitment[1].as_int(),
            witness_commitment[2].as_int(),
            witness_commitment[3].as_int(),
        ];

        Ok(ComplianceProof {
            proof_bytes: proof_bytes.clone(),
            proof_hash: proof_hash.to_hex(),
            metadata: ProofMetadata {
                proving_time_ms: proving_time.as_millis() as u64,
                num_constraints: ves_stark_air::compliance::NUM_CONSTRAINTS,
                trace_length,
                proof_size: proof_bytes.len(),
                prover_version: env!("CARGO_PKG_VERSION").to_string(),
            },
            witness_commitment: commitment_u64,
        })
    }

    /// Get the policy limit (threshold or cap)
    pub fn limit(&self) -> u64 {
        self.policy.limit()
    }

    /// Get the policy threshold (legacy API, same as limit)
    pub fn threshold(&self) -> u64 {
        self.policy.limit()
    }
}

/// Internal Winterfell prover implementation
struct VesComplianceProver {
    #[allow(dead_code)]
    policy: Policy,
    options: winter_air::ProofOptions,
    pub_inputs: PublicInputs,
}

impl VesComplianceProver {
    fn new(policy: Policy, options: ProofOptions, pub_inputs: PublicInputs) -> Self {
        Self {
            policy,
            options: options.to_winterfell(),
            pub_inputs,
        }
    }
}

impl Prover for VesComplianceProver {
    type BaseField = Felt;
    type Air = ComplianceAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Hasher;
    type RandomCoin = RandCoin;
    type VC = VectorCommit;
    type TraceLde<E: winter_math::FieldElement<BaseField = Felt>> =
        winter_prover::DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: winter_math::FieldElement<BaseField = Felt>> =
        winter_prover::DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &winter_air::ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: winter_math::FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winter_prover::matrix::ColMatrix<Felt>,
        domain: &winter_prover::StarkDomain<Felt>,
        partition_option: winter_air::PartitionOptions,
    ) -> (Self::TraceLde<E>, winter_prover::TracePolyTable<E>) {
        winter_prover::DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: winter_math::FieldElement<BaseField = Felt>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winter_air::AuxRandElements<E>>,
        composition_coefficients: winter_air::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        winter_prover::DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{CompliancePublicInputs, PolicyParams, compute_policy_hash};
    use uuid::Uuid;

    fn sample_inputs(threshold: u64) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();

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
    fn test_prover_creation() {
        let policy = AmlThresholdPolicy::new(10000);
        let prover = ComplianceProver::new(policy);
        assert_eq!(prover.threshold(), 10000);
    }
}
