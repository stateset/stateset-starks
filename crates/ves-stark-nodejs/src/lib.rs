//! Node.js bindings for VES STARK proof system
//!
//! This crate provides Node.js bindings for generating and verifying
//! STARK compliance proofs using NAPI-RS.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use uuid::Uuid;

use ves_stark_air::Policy;
use ves_stark_primitives::{
    witness_commitment_hex_to_u64, CommerceAuthorizationReceipt, CompliancePublicInputs,
    PayloadAmountBinding, PolicyParams,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_verifier::{
    verify_agent_authorization_proof_auto_with_amount_binding, verify_compliance_proof_auto_bound,
    verify_compliance_proof_auto_with_amount_binding, VerifierError,
};

fn bigint_to_u64(value: &BigInt, field_name: &str) -> Result<u64> {
    let (sign_bit, value, lossless) = value.get_u64();
    if sign_bit {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{} must be non-negative", field_name),
        ));
    }
    if !lossless {
        return Err(Error::new(
            Status::InvalidArg,
            format!("{} must fit in u64", field_name),
        ));
    }
    Ok(value)
}

fn parse_witness_commitment(witness_commitment: Vec<String>) -> Result<[u64; 4]> {
    if witness_commitment.len() != 4 {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "Witness commitment must have exactly 4 elements, got {}",
                witness_commitment.len()
            ),
        ));
    }

    let mut commitment = [0u64; 4];
    for (idx, value) in witness_commitment.iter().enumerate() {
        let parsed = value.parse::<u64>().map_err(|_| {
            Error::new(
                Status::InvalidArg,
                "Invalid witness commitment element".to_string(),
            )
        })?;
        commitment[idx] = parsed;
    }

    Ok(commitment)
}

fn verifier_error_to_napi(err: VerifierError) -> Error {
    let status = match err {
        VerifierError::PublicInputMismatch(_)
        | VerifierError::InvalidHexFormat { .. }
        | VerifierError::DeserializationError(_)
        | VerifierError::InvalidPolicyHash { .. }
        | VerifierError::PolicyMismatch { .. }
        | VerifierError::LimitMismatch { .. }
        | VerifierError::WitnessCommitmentMismatch
        | VerifierError::ProofTooLarge { .. }
        | VerifierError::UnsupportedProofVersion { .. } => Status::InvalidArg,
        VerifierError::InvalidProofStructure(_)
        | VerifierError::FriVerificationFailed(_)
        | VerifierError::ConstraintCheckFailed(_)
        | VerifierError::VerificationFailed(_) => Status::GenericFailure,
    };

    Error::new(status, format!("Verification error: {}", err))
}

fn bind_public_inputs_to_commitment(
    mut public_inputs: CompliancePublicInputs,
    witness_commitment: &[u64; 4],
) -> Result<CompliancePublicInputs> {
    public_inputs = public_inputs
        .bind_witness_commitment(witness_commitment)
        .map_err(|e| {
            Error::new(
                Status::InvalidArg,
                format!("Failed to bind witness commitment to public inputs: {}", e),
            )
        })?;
    Ok(public_inputs)
}

fn parse_authorization_receipt(receipt: serde_json::Value) -> Result<CommerceAuthorizationReceipt> {
    serde_json::from_value(receipt).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("Invalid authorization receipt object: {}", e),
        )
    })
}

fn parse_payload_amount_binding(binding: serde_json::Value) -> Result<PayloadAmountBinding> {
    serde_json::from_value(binding).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("Invalid payload amount binding object: {}", e),
        )
    })
}

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
    pub sequence_number: BigInt,
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
    /// Optional witness commitment (hex64, lowercase) to bind the proved witness to canonical inputs.
    pub witness_commitment: Option<String>,
    /// Optional authorization receipt hash (hex64, lowercase) committed into canonical public inputs.
    pub authorization_receipt_hash: Option<String>,
    /// Optional payload amount binding hash (hex64, lowercase) committed into canonical public inputs.
    pub amount_binding_hash: Option<String>,
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
    pub witness_commitment: Vec<String>,
    /// Witness commitment encoded as 32 bytes (4 x u64 big-endian) and hex-encoded (64 chars).
    pub witness_commitment_hex: String,
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
    pub policy_limit: BigInt,
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
        sequence_number: bigint_to_u64(&js.sequence_number, "sequence_number")?,
        payload_kind: js.payload_kind,
        payload_plain_hash: js.payload_plain_hash.clone(),
        payload_cipher_hash: js.payload_cipher_hash.clone(),
        event_signing_hash: js.event_signing_hash.clone(),
        policy_id: js.policy_id.clone(),
        policy_params: PolicyParams(js.policy_params.clone()),
        policy_hash: js.policy_hash.clone(),
        witness_commitment: js.witness_commitment.clone(),
        authorization_receipt_hash: js.authorization_receipt_hash.clone(),
        amount_binding_hash: js.amount_binding_hash.clone(),
    })
}

/// Generate a STARK compliance proof for the provided amount witness.
///
/// @param amount - The amount to prove compliance for (must satisfy the policy constraint)
/// @param publicInputs - Public inputs including event metadata and policy info
/// @param policyType - Policy type: "aml.threshold", "order_total.cap", or "agent.authorization.v1"
/// @param policyLimit - The policy limit (threshold, cap, or maxTotal value)
/// @returns ComplianceProof containing proof bytes and metadata
///
/// Note: this proves a statement about the supplied `amount` witness. Binding that
/// witness back to encrypted payload contents is the responsibility of the
/// surrounding pipeline, not this library.
#[napi]
pub fn prove(
    amount: BigInt,
    public_inputs: JsCompliancePublicInputs,
    policy_type: String,
    policy_limit: BigInt,
) -> Result<JsComplianceProof> {
    let amount = bigint_to_u64(&amount, "amount")?;
    let policy_limit = bigint_to_u64(&policy_limit, "policy_limit")?;

    // Convert public inputs
    let rust_inputs = convert_public_inputs(&public_inputs)?;
    if rust_inputs.policy_id != policy_type {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "policyType {} does not match publicInputs.policyId {}",
                policy_type, rust_inputs.policy_id
            ),
        ));
    }

    let policy = Policy::from_public_inputs(&rust_inputs.policy_id, &rust_inputs.policy_params)
        .map_err(|e| {
            Error::new(
                Status::InvalidArg,
                format!("Invalid policy parameters for {}: {}", policy_type, e),
            )
        })?;
    if policy.limit() != policy_limit {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "policyLimit {} does not match publicInputs policy limit {}",
                policy_limit,
                policy.limit()
            ),
        ));
    }
    if !policy.validate_amount(amount) {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "amount must be {} policy limit for {}",
                match policy_type.as_str() {
                    "aml.threshold" => "<",
                    _ => "<=",
                },
                policy_type
            ),
        ));
    }

    // Create witness
    let witness = ComplianceWitness::try_new(amount, rust_inputs).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("Invalid witness/public inputs: {}", e),
        )
    })?;

    // Create prover and generate proof
    let prover = ComplianceProver::with_policy(policy);
    let proof = prover.prove(&witness).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Proof generation failed: {}", e),
        )
    })?;

    let witness_commitment: Vec<String> = proof
        .witness_commitment
        .iter()
        .map(|value| value.to_string())
        .collect();
    let witness_commitment_hex = proof.witness_commitment_hex.clone().ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "Missing witness_commitment_hex in proof".to_string(),
        )
    })?;

    Ok(JsComplianceProof {
        proof_bytes: Buffer::from(proof.proof_bytes),
        proof_hash: proof.proof_hash,
        proving_time_ms: proof.metadata.proving_time_ms as i64,
        proof_size: proof.metadata.proof_size as i64,
        witness_commitment,
        witness_commitment_hex,
    })
}

/// Verify a STARK compliance proof
///
/// @param proofBytes - The raw proof bytes from prove()
/// @param publicInputs - Public inputs (must match those used for proving)
/// @param witnessCommitment - Witness commitment from the proof
/// @returns VerificationResult indicating if proof is valid
///
/// Malformed public inputs, malformed proof encodings, or witness-commitment binding
/// mismatches are reported as thrown errors rather than `valid = false`.
#[napi]
pub fn verify(
    proof_bytes: Buffer,
    public_inputs: JsCompliancePublicInputs,
    witness_commitment: Vec<String>,
) -> Result<JsVerificationResult> {
    // Convert public inputs
    let rust_inputs = convert_public_inputs(&public_inputs)?;

    let commitment = parse_witness_commitment(witness_commitment)?;
    let rust_inputs = bind_public_inputs_to_commitment(rust_inputs, &commitment)?;

    // Verify proof
    let result = verify_compliance_proof_auto_bound(&proof_bytes, &rust_inputs);

    match result {
        Ok(verification) => Ok(JsVerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms as i64,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: BigInt::from(verification.policy_limit),
        }),
        Err(e) => Err(verifier_error_to_napi(e)),
    }
}

/// Verify a STARK compliance proof using the witness commitment hex string.
///
/// This avoids `u64` round-trip issues in JavaScript.
/// Malformed public inputs, malformed proof encodings, or witness-commitment binding
/// mismatches are reported as thrown errors rather than `valid = false`.
#[napi]
pub fn verify_hex(
    proof_bytes: Buffer,
    public_inputs: JsCompliancePublicInputs,
    witness_commitment_hex: String,
) -> Result<JsVerificationResult> {
    // Convert public inputs
    let rust_inputs = convert_public_inputs(&public_inputs)?;

    let commitment = witness_commitment_hex_to_u64(&witness_commitment_hex).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("Invalid witnessCommitmentHex: {}", e),
        )
    })?;
    let rust_inputs = bind_public_inputs_to_commitment(rust_inputs, &commitment)?;

    // Verify proof
    let result = verify_compliance_proof_auto_bound(&proof_bytes, &rust_inputs);

    match result {
        Ok(verification) => Ok(JsVerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms as i64,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: BigInt::from(verification.policy_limit),
        }),
        Err(e) => Err(verifier_error_to_napi(e)),
    }
}

/// Verify a STARK compliance proof against a canonical payload amount binding.
#[napi]
pub fn verify_with_amount_binding(
    proof_bytes: Buffer,
    public_inputs: JsCompliancePublicInputs,
    amount_binding: serde_json::Value,
) -> Result<JsVerificationResult> {
    let rust_inputs = convert_public_inputs(&public_inputs)?;
    let binding = parse_payload_amount_binding(amount_binding)?;

    let result =
        verify_compliance_proof_auto_with_amount_binding(&proof_bytes, &rust_inputs, &binding);

    match result {
        Ok(verification) => Ok(JsVerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms as i64,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: BigInt::from(verification.policy_limit),
        }),
        Err(e) => Err(verifier_error_to_napi(e)),
    }
}

/// Verify an `agent.authorization.v1` proof against a canonical authorization receipt.
#[napi]
pub fn verify_agent_authorization(
    proof_bytes: Buffer,
    public_inputs: JsCompliancePublicInputs,
    witness_commitment: Vec<String>,
    receipt: serde_json::Value,
) -> Result<JsVerificationResult> {
    let rust_inputs = convert_public_inputs(&public_inputs)?;
    let commitment = parse_witness_commitment(witness_commitment)?;
    let rust_inputs = bind_public_inputs_to_commitment(rust_inputs, &commitment)?;
    let receipt = parse_authorization_receipt(receipt)?;
    let binding = rust_inputs
        .payload_amount_binding(receipt.amount)
        .map_err(|e| verifier_error_to_napi(VerifierError::PublicInputMismatch(format!("{e}"))))?;

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        &proof_bytes,
        &rust_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => Ok(JsVerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms as i64,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: BigInt::from(verification.policy_limit),
        }),
        Err(e) => Err(verifier_error_to_napi(e)),
    }
}

/// Verify an `agent.authorization.v1` proof using the witness commitment hex string.
#[napi]
pub fn verify_agent_authorization_hex(
    proof_bytes: Buffer,
    public_inputs: JsCompliancePublicInputs,
    witness_commitment_hex: String,
    receipt: serde_json::Value,
) -> Result<JsVerificationResult> {
    let rust_inputs = convert_public_inputs(&public_inputs)?;
    let commitment = witness_commitment_hex_to_u64(&witness_commitment_hex).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("Invalid witnessCommitmentHex: {}", e),
        )
    })?;
    let rust_inputs = bind_public_inputs_to_commitment(rust_inputs, &commitment)?;
    let receipt = parse_authorization_receipt(receipt)?;
    let binding = rust_inputs
        .payload_amount_binding(receipt.amount)
        .map_err(|e| verifier_error_to_napi(VerifierError::PublicInputMismatch(format!("{e}"))))?;

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        &proof_bytes,
        &rust_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => Ok(JsVerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms as i64,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: BigInt::from(verification.policy_limit),
        }),
        Err(e) => Err(verifier_error_to_napi(e)),
    }
}

/// Verify an `agent.authorization.v1` proof against both a canonical payload amount binding and a
/// canonical authorization receipt.
#[napi]
pub fn verify_agent_authorization_with_amount_binding(
    proof_bytes: Buffer,
    public_inputs: JsCompliancePublicInputs,
    amount_binding: serde_json::Value,
    receipt: serde_json::Value,
) -> Result<JsVerificationResult> {
    let rust_inputs = convert_public_inputs(&public_inputs)?;
    let binding = parse_payload_amount_binding(amount_binding)?;
    let receipt = parse_authorization_receipt(receipt)?;

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        &proof_bytes,
        &rust_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => Ok(JsVerificationResult {
            valid: verification.valid,
            verification_time_ms: verification.verification_time_ms as i64,
            error: verification.error,
            policy_id: verification.policy_id,
            policy_limit: BigInt::from(verification.policy_limit),
        }),
        Err(e) => Err(verifier_error_to_napi(e)),
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
pub fn create_aml_threshold_params(threshold: BigInt) -> Result<serde_json::Value> {
    let threshold = bigint_to_u64(&threshold, "threshold")?;
    Ok(serde_json::json!({ "threshold": threshold }))
}

/// Create policy parameters for order total cap policy
///
/// @param cap - The order total cap value
/// @returns Policy parameters JSON object
#[napi]
pub fn create_order_total_cap_params(cap: BigInt) -> Result<serde_json::Value> {
    let cap = bigint_to_u64(&cap, "cap")?;
    Ok(serde_json::json!({ "cap": cap }))
}

/// Create policy parameters for agent authorization policy.
///
/// @param maxTotal - The maximum delegated total
/// @param intentHash - The delegated commerce intent hash (hex64, lowercase recommended)
/// @returns Policy parameters JSON object
#[napi]
pub fn create_agent_authorization_params(
    max_total: BigInt,
    intent_hash: String,
) -> Result<serde_json::Value> {
    let max_total = bigint_to_u64(&max_total, "max_total")?;
    let params = PolicyParams::agent_authorization(max_total, &intent_hash).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("Invalid agent authorization params: {}", e),
        )
    })?;
    Ok(params.to_json_value())
}

/// Create a canonical payload amount binding for the supplied public inputs and extracted amount.
#[napi]
pub fn create_payload_amount_binding(
    public_inputs: JsCompliancePublicInputs,
    amount: BigInt,
) -> Result<serde_json::Value> {
    let rust_inputs = convert_public_inputs(&public_inputs)?;
    let amount = bigint_to_u64(&amount, "amount")?;

    let binding = rust_inputs.payload_amount_binding(amount).map_err(|e| {
        Error::new(
            Status::InvalidArg,
            format!("Invalid payload amount binding inputs: {}", e),
        )
    })?;

    serde_json::to_value(&binding).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to serialize payload amount binding: {}", e),
        )
    })
}
