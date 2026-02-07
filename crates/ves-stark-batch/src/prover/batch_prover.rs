//! Batch prover implementation
//!
//! This module provides the high-level interface for generating batch
//! state transition proofs.

use serde::{Deserialize, Serialize};
use std::time::Instant;
use winter_air::TraceInfo;
use winter_crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winter_prover::{Prover, Trace, TraceTable};

use ves_stark_air::options::ProofOptions;
use ves_stark_primitives::{Felt, Hash256};

use crate::air::batch_air::BatchComplianceAir;
use crate::error::{BatchError, BatchResult};
use crate::prover::batch_trace::BatchTraceBuilder;
use crate::prover::witness::BatchWitness;
use crate::public_inputs::BatchPublicInputs;
use crate::state::BatchStateRoot;

/// Type alias for the hash function used
pub type Hasher = Blake3_256<Felt>;

/// Type alias for the random coin
pub type RandCoin = DefaultRandomCoin<Hasher>;

/// Type alias for vector commitment
pub type VectorCommit = MerkleTree<Hasher>;

/// Configuration for the batch prover
#[derive(Debug, Clone)]
pub struct BatchProverConfig {
    /// Proof options (FRI parameters, etc.)
    pub options: ProofOptions,

    /// Maximum batch size
    pub max_batch_size: usize,
}

impl Default for BatchProverConfig {
    fn default() -> Self {
        Self {
            options: ProofOptions::default(),
            max_batch_size: 128,
        }
    }
}

impl BatchProverConfig {
    /// Create config for small batches (8-16 events)
    pub fn small_batch() -> Self {
        Self {
            options: ProofOptions::default(),
            max_batch_size: 16,
        }
    }

    /// Create config for large batches (up to 100 events)
    pub fn large_batch() -> Self {
        Self {
            options: ProofOptions::default(),
            max_batch_size: 128,
        }
    }

    /// Set custom proof options
    pub fn with_options(mut self, options: ProofOptions) -> Self {
        self.options = options;
        self
    }
}

/// A generated batch proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProof {
    /// The raw proof bytes
    #[serde(with = "serde_bytes")]
    pub proof_bytes: Vec<u8>,

    /// Hash of the proof
    pub proof_hash: String,

    /// Previous state root
    pub prev_state_root: [u64; 4],

    /// New state root
    pub new_state_root: [u64; 4],

    /// Batch metadata
    pub metadata: BatchProofMetadata,
}

/// Metadata about the batch proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProofMetadata {
    /// Batch ID (hex encoded)
    pub batch_id: String,

    /// Number of events in batch
    pub num_events: usize,

    /// Whether all events were compliant
    pub all_compliant: bool,

    /// Time taken to generate the proof (milliseconds)
    pub proving_time_ms: u64,

    /// Trace length
    pub trace_length: usize,

    /// Proof size in bytes
    pub proof_size: usize,

    /// Prover version
    pub prover_version: String,
}

impl BatchProof {
    /// Compute the proof hash using the domain separator
    pub fn compute_hash(proof_bytes: &[u8]) -> Hash256 {
        Hash256::sha256_with_domain(b"STATESET_VES_BATCH_PROOF_HASH_V1", proof_bytes)
    }

    /// Get previous state root as field elements
    pub fn prev_state_root_felts(&self) -> [Felt; 4] {
        [
            Felt::new(self.prev_state_root[0]),
            Felt::new(self.prev_state_root[1]),
            Felt::new(self.prev_state_root[2]),
            Felt::new(self.prev_state_root[3]),
        ]
    }

    /// Get new state root as field elements
    pub fn new_state_root_felts(&self) -> [Felt; 4] {
        [
            Felt::new(self.new_state_root[0]),
            Felt::new(self.new_state_root[1]),
            Felt::new(self.new_state_root[2]),
            Felt::new(self.new_state_root[3]),
        ]
    }
}

/// The main batch prover
pub struct BatchProver {
    /// Prover configuration
    config: BatchProverConfig,
}

impl BatchProver {
    /// Create a new batch prover with default configuration
    pub fn new() -> Self {
        Self {
            config: BatchProverConfig::default(),
        }
    }

    /// Create a new batch prover with the given configuration
    pub fn with_config(config: BatchProverConfig) -> Self {
        Self { config }
    }

    /// Generate a proof for the given batch witness
    pub fn prove(&self, witness: &BatchWitness) -> Result<BatchProof, BatchError> {
        let start = Instant::now();

        // Validate witness
        witness.validate()?;

        // Check batch size limit
        if witness.num_events() > self.config.max_batch_size {
            return Err(BatchError::BatchTooLarge {
                size: witness.num_events(),
                max: self.config.max_batch_size,
            });
        }

        // Compute state roots
        let prev_state_root = &witness.prev_state_root;
        let new_state_root = witness.compute_new_state_root();
        let all_compliant = witness.all_compliant();

        // Build execution trace
        let trace = BatchTraceBuilder::new(witness.clone()).build()?;

        let trace_length = trace.length();

        // Build public inputs
        let pub_inputs = BatchPublicInputs::new(
            prev_state_root.root,
            new_state_root.root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            witness.metadata.sequence_start,
            witness.metadata.sequence_end,
            witness.num_events(),
            all_compliant,
            witness.policy_hash,
            witness.policy_limit,
        );

        // Create internal prover
        let prover = VesBatchProver::try_new(self.config.options.clone(), pub_inputs.clone())?;

        // Generate proof
        let proof = prover
            .prove(trace)
            .map_err(|e| BatchError::ProofGenerationFailed(format!("{:?}", e)))?;

        // Serialize proof
        let proof_bytes = proof.to_bytes();
        let proof_hash = BatchProof::compute_hash(&proof_bytes);

        let proving_time = start.elapsed();

        // Convert state roots to u64 arrays
        let prev_root_u64: [u64; 4] = [
            prev_state_root.root[0].as_int(),
            prev_state_root.root[1].as_int(),
            prev_state_root.root[2].as_int(),
            prev_state_root.root[3].as_int(),
        ];

        let new_root_u64: [u64; 4] = [
            new_state_root.root[0].as_int(),
            new_state_root.root[1].as_int(),
            new_state_root.root[2].as_int(),
            new_state_root.root[3].as_int(),
        ];

        Ok(BatchProof {
            proof_bytes: proof_bytes.clone(),
            proof_hash: proof_hash.to_hex(),
            prev_state_root: prev_root_u64,
            new_state_root: new_root_u64,
            metadata: BatchProofMetadata {
                batch_id: witness.metadata.batch_id.to_string(),
                num_events: witness.num_events(),
                all_compliant,
                proving_time_ms: proving_time.as_millis() as u64,
                trace_length,
                proof_size: proof_bytes.len(),
                prover_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        })
    }

    /// Prove a batch and return the new state root
    ///
    /// This is a convenience method that generates the proof and returns
    /// the computed new state root for chaining batches.
    pub fn prove_and_get_root(
        &self,
        witness: &BatchWitness,
    ) -> Result<(BatchProof, BatchStateRoot), BatchError> {
        let new_root = witness.compute_new_state_root();
        let proof = self.prove(witness)?;
        Ok((proof, new_root))
    }

    /// Get the configuration
    pub fn config(&self) -> &BatchProverConfig {
        &self.config
    }
}

impl Default for BatchProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal Winterfell prover implementation for batch proofs
struct VesBatchProver {
    options: winter_air::ProofOptions,
    pub_inputs: BatchPublicInputs,
}

impl VesBatchProver {
    fn try_new(options: ProofOptions, pub_inputs: BatchPublicInputs) -> BatchResult<Self> {
        let options = options
            .try_to_winterfell()
            .map_err(|e| BatchError::InvalidPublicInputs(format!("Invalid proof options: {e}")))?;
        Ok(Self {
            options,
            pub_inputs,
        })
    }
}

impl Prover for VesBatchProver {
    type BaseField = Felt;
    type Air = BatchComplianceAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Hasher;
    type RandomCoin = RandCoin;
    type VC = VectorCommit;
    type TraceLde<E: winter_math::FieldElement<BaseField = Felt>> =
        winter_prover::DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: winter_math::FieldElement<BaseField = Felt>> =
        winter_prover::DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BatchPublicInputs {
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
        winter_prover::DefaultConstraintEvaluator::new(
            air,
            aux_rand_elements,
            composition_coefficients,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::witness::BatchWitnessBuilder;
    use crate::state::BatchMetadata;
    use crate::verifier::verify_batch_proof;
    use uuid::Uuid;
    use ves_stark_primitives::hash_to_felts;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, CompliancePublicInputs, PolicyParams,
    };

    #[test]
    fn test_prover_creation() {
        let prover = BatchProver::new();
        assert_eq!(prover.config().max_batch_size, 128);
    }

    #[test]
    fn test_prover_config() {
        let config = BatchProverConfig::small_batch();
        assert_eq!(config.max_batch_size, 16);

        let config = BatchProverConfig::large_batch();
        assert_eq!(config.max_batch_size, 128);
    }

    fn sample_public_inputs(threshold: u64, sequence_number: u64) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();

        CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: policy_id.to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
            witness_commitment: None,
        }
    }

    fn sample_policy_hash(threshold: u64) -> [Felt; 8] {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = compute_policy_hash(policy_id, &params).unwrap();
        hash_to_felts(&hash)
    }

    #[test]
    fn test_batch_prove_and_verify_all_compliant() {
        let threshold = 10_000u64;
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 1);

        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(sample_policy_hash(threshold))
            .policy_limit(threshold)
            .add_event(5_000, sample_public_inputs(threshold, 0))
            .add_event(9_999, sample_public_inputs(threshold, 1))
            .build()
            .unwrap();

        let prover = BatchProver::with_config(
            BatchProverConfig::default().with_options(ProofOptions::fast()),
        );
        let proof = prover.prove(&witness).unwrap();

        let pub_inputs = BatchPublicInputs::new(
            witness.prev_state_root.root,
            witness.compute_new_state_root().root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            witness.metadata.sequence_start,
            witness.metadata.sequence_end,
            witness.num_events(),
            witness.all_compliant(),
            witness.policy_hash,
            witness.policy_limit,
        );

        let result = verify_batch_proof(&proof.proof_bytes, &pub_inputs).unwrap();
        assert!(
            result.valid,
            "batch proof should verify: {:?}",
            result.error
        );
        assert!(result.all_compliant);
    }

    #[test]
    fn test_batch_verifier_rejects_tampered_public_inputs() {
        let threshold = 10_000u64;
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 1);

        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(sample_policy_hash(threshold))
            .policy_limit(threshold)
            .add_event(5_000, sample_public_inputs(threshold, 0))
            .add_event(9_999, sample_public_inputs(threshold, 1))
            .build()
            .unwrap();

        let prover = BatchProver::with_config(
            BatchProverConfig::default().with_options(ProofOptions::fast()),
        );
        let proof = prover.prove(&witness).unwrap();

        let pub_inputs = BatchPublicInputs::new(
            witness.prev_state_root.root,
            witness.compute_new_state_root().root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            witness.metadata.sequence_start,
            witness.metadata.sequence_end,
            witness.num_events(),
            witness.all_compliant(),
            witness.policy_hash,
            witness.policy_limit,
        );

        // Tamper with public inputs that are bound into the AIR via boundary assertions.
        for (label, tampered) in [
            ("policy_limit", {
                let mut t = pub_inputs.clone();
                t.policy_limit =
                    ves_stark_primitives::felt_from_u64(t.policy_limit.as_int().wrapping_add(1));
                t
            }),
            ("policy_hash", {
                let mut t = pub_inputs.clone();
                t.policy_hash[0] =
                    ves_stark_primitives::felt_from_u64(t.policy_hash[0].as_int().wrapping_add(1));
                t
            }),
            ("batch_id", {
                let mut t = pub_inputs.clone();
                t.batch_id[0] =
                    ves_stark_primitives::felt_from_u64(t.batch_id[0].as_int().wrapping_add(1));
                t
            }),
            ("sequence_end", {
                let mut t = pub_inputs.clone();
                t.sequence_end =
                    ves_stark_primitives::felt_from_u64(t.sequence_end.as_int().wrapping_add(1));
                t
            }),
            ("num_events", {
                let mut t = pub_inputs.clone();
                t.num_events =
                    ves_stark_primitives::felt_from_u64(t.num_events.as_int().wrapping_add(1));
                t
            }),
        ] {
            let result = verify_batch_proof(&proof.proof_bytes, &tampered).unwrap();
            assert!(
                !result.valid,
                "batch proof must not verify under different public inputs: tampered {label}"
            );
        }
    }

    #[test]
    fn test_batch_prove_and_verify_not_all_compliant() {
        let threshold = 10_000u64;
        let metadata =
            BatchMetadata::with_ids(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 1);

        let witness = BatchWitnessBuilder::new()
            .metadata(metadata)
            .policy_hash(sample_policy_hash(threshold))
            .policy_limit(threshold)
            .add_event(5_000, sample_public_inputs(threshold, 0))
            .add_event(15_000, sample_public_inputs(threshold, 1)) // non-compliant
            .build()
            .unwrap();

        let prover = BatchProver::with_config(
            BatchProverConfig::default().with_options(ProofOptions::fast()),
        );
        let proof = prover.prove(&witness).unwrap();

        let pub_inputs = BatchPublicInputs::new(
            witness.prev_state_root.root,
            witness.compute_new_state_root().root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            witness.metadata.sequence_start,
            witness.metadata.sequence_end,
            witness.num_events(),
            witness.all_compliant(),
            witness.policy_hash,
            witness.policy_limit,
        );

        let result = verify_batch_proof(&proof.proof_bytes, &pub_inputs).unwrap();
        assert!(
            result.valid,
            "batch proof should verify: {:?}",
            result.error
        );
        assert!(!result.all_compliant);
    }
}
