//! Node.js bindings for VES STARK proof system
//!
//! This crate provides Node.js bindings for generating and verifying
//! STARK compliance proofs using NAPI-RS.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use uuid::Uuid;

use ves_stark_air::Policy;
use ves_stark_primitives::{CompliancePublicInputs, PolicyParams};
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_verifier::verify_compliance_proof_auto;

/// Public inputs for compliance proof generation/verification
#[napi(object)]
pub struct JsCompliancePublicInputs {
    /// UUID of the event being proven
    pub event_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Store ID
    pub store_id: String,
    /// Sequence number of the event
    pub sequence_number: i64,
    /// Payload kind (event type discriminator)
    pub payload_kind: u32,
    /// SHA-256 hash of plaintext payload (hex64, lowercase)
    pub payload_plain_hash: String,
    /// SHA-256 hash of ciphertext payload (hex64, lowercase)
    pub payload_cipher_hash: String,
    /// Event signing hash (hex64, lowercase)
    pub event_signing_hash: String,
    /// Policy identifier (e.g., "aml.threshold")
    pub policy_id: String,
    /// Policy parameters as JSON object
    pub policy_params: serde_json::Value,
    /// Policy hash (hex64, lowercase)
    pub policy_hash: String,
}

/// Result of proof generation
#[napi(object)]
pub struct JsComplianceProof {
    /// Raw proof bytes
    pub proof_bytes: Buffer,
    /// SHA-256 hash of proof bytes (hex)
    pub proof_hash: String,
    /// Time taken to generate proof in milliseconds
    pub proving_time_ms: i64,
    /// Size of proof in bytes
    pub proof_size: i64,
    /// Witness commitment (4 x u64 as field elements)
    pub witness_commitment: Vec<i64>,
}

/// Result of proof verification
#[napi(object)]
pub struct JsVerificationResult {
    /// Whether the proof is valid
    pub valid: bool,
    /// Time taken to verify in milliseconds
    pub verification_time_ms: i64,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Policy ID that was verified
    pub policy_id: String,
    /// Policy limit that was verified against
    pub policy_limit: i64,
}

/// Convert JS public inputs to Rust struct
fn convert_public_inputs(js: &JsCompliancePublicInputs) -> Result<CompliancePublicInputs> {
    let event_id = Uuid::parse_str(&js.event_id)
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid event_id UUID: {}", e)))?;
    let tenant_id = Uuid::parse_str(&js.tenant_id)
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid tenant_id UUID: {}", e)))?;
    let store_id = Uuid::parse_str(&js.store_id)
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid store_id UUID: {}", e)))?;

    Ok(CompliancePublicInputs {
        event_id,
        tenant_id,
        store_id,
        sequence_number: js.sequence_number as u64,
        payload_kind: js.payload_kind,
        payload_plain_hash: js.payload_plain_hash.clone(),
        payload_cipher_hash: js.payload_cipher_hash.clone(),
        event_signing_hash: js.event_signing_hash.clone(),
        policy_id: js.policy_id.clone(),
        policy_params: PolicyParams(js.policy_params.clone()),
        policy_hash: js.policy_hash.clone(),
    })
}

/// Generate a STARK compliance proof
///
/// @param amount - The amount to prove compliance for (must be less than policy limit)
/// @param publicInputs - Public inputs including event metadata and policy info
/// @param policyType - Policy type: "aml.threshold" or "order_total.cap"
/// @param policyLimit - The policy limit (threshold or cap value)
/// @returns ComplianceProof containing proof bytes and metadata
#[napi]
pub fn prove(
    amount: i64,
    public_inputs: JsCompliancePublicInputs,
    policy_type: String,
    policy_limit: i64,
) -> Result<JsComplianceProof> {
    // Validate amount is non-negative
    if amount < 0 {
        return Err(Error::new(
            Status::InvalidArg,
            "Amount must be non-negative",
        ));
    }
    if policy_limit < 0 {
        return Err(Error::new(
            Status::InvalidArg,
            "Policy limit must be non-negative",
        ));
    }

    // Create policy based on type
    let policy = match policy_type.as_str() {
        "aml.threshold" => Policy::aml_threshold(policy_limit as u64),
        "order_total.cap" => Policy::order_total_cap(policy_limit as u64),
        _ => {
            return Err(Error::new(
                Status::InvalidArg,
                format!(
                    "Unknown policy type: {}. Supported: aml.threshold, order_total.cap",
                    policy_type
                ),
            ))
        }
    };

    // Convert public inputs
    let rust_inputs = convert_public_inputs(&public_inputs)?;

    // Create witness
    let witness = ComplianceWitness::new(amount as u64, rust_inputs);

    // Create prover and generate proof
    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Proof generation failed: {}", e),
        )
    })?;

    // Convert witness commitment to i64 vec (JS doesn't have native u64)
    let witness_commitment: Vec<i64> = proof.witness_commitment.iter().map(|&v| v as i64).collect();

    Ok(JsComplianceProof {
        proof_bytes: Buffer::from(proof.proof_bytes),
        proof_hash: proof.proof_hash,
        proving_time_ms: proof.metadata.proving_time_ms as i64,
        proof_size: proof.metadata.proof_size as i64,
        witness_commitment,
    })
}

/// Verify a STARK compliance proof
///
/// @param proofBytes - The raw proof bytes from prove()
/// @param publicInputs - Public inputs (must match those used for proving)
/// @param witnessCommitment - Witness commitment from the proof
/// @returns VerificationResult indicating if proof is valid
#[napi]
pub fn verify(
    proof_bytes: Buffer,
    public_inputs: JsCompliancePublicInputs,
    witness_commitment: Vec<i64>,
) -> Result<JsVerificationResult> {
    // Convert public inputs
    let rust_inputs = convert_public_inputs(&public_inputs)?;

    // Convert witness commitment to u64 array
    if witness_commitment.len() != 4 {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "Witness commitment must have exactly 4 elements, got {}",
                witness_commitment.len()
            ),
        ));
    }
    let commitment: [u64; 4] = [
        witness_commitment[0] as u64,
        witness_commitment[1] as u64,
        witness_commitment[2] as u64,
        witness_commitment[3] as u64,
    ];

    // Verify proof
    let result = verify_compliance_proof_auto(&proof_bytes, &rust_inputs, &commitment);

    match result {
        Ok(verification) => Ok(JsVerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms as i64,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: verification.policy_limit as i64,
        }),
        Err(e) => Ok(JsVerificationResult {
            valid: false,
            verification_time_ms: 0,
            error: Some(format!("Verification error: {}", e)),
            policy_id: public_inputs.policy_id,
            policy_limit: 0,
        }),
    }
}

/// Compute the policy hash for given policy ID and parameters
///
/// @param policyId - Policy identifier (e.g., "aml.threshold")
/// @param policyParams - Policy parameters as JSON object
/// @returns Policy hash as hex string (64 characters, lowercase)
#[napi]
pub fn compute_policy_hash(policy_id: String, policy_params: serde_json::Value) -> Result<String> {
    let params = PolicyParams(policy_params);
    let hash = ves_stark_primitives::compute_policy_hash(&policy_id, &params).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to compute policy hash: {}", e),
        )
    })?;
    Ok(hash.to_hex())
}

/// Create policy parameters for AML threshold policy
///
/// @param threshold - The AML threshold value
/// @returns Policy parameters JSON object
#[napi]
pub fn create_aml_threshold_params(threshold: i64) -> serde_json::Value {
    serde_json::json!({ "threshold": threshold })
}

/// Create policy parameters for order total cap policy
///
/// @param cap - The order total cap value
/// @returns Policy parameters JSON object
#[napi]
pub fn create_order_total_cap_params(cap: i64) -> serde_json::Value {
    serde_json::json!({ "cap": cap })
}
