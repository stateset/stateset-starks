//! Proof verification implementation
//!
//! This module provides the main verification logic for VES compliance proofs.

use crate::error::{validate_hex_string, VerifierError, MAX_PROOF_SIZE};
use serde::{Deserialize, Serialize};
use ves_stark_air::compliance::{ComplianceAir, PublicInputs};
use ves_stark_air::policy::Policy;
use ves_stark_primitives::public_inputs::CompliancePublicInputs;
use ves_stark_primitives::{
    felt_from_u64, CommerceAuthorizationReceipt, Felt, Hash256, PayloadAmountBinding,
};
use winter_crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winter_verifier::{verify, AcceptableOptions};

/// Type alias for the hash function
pub type Hasher = Blake3_256<Felt>;

/// Type alias for the random coin
pub type RandCoin = DefaultRandomCoin<Hasher>;

/// Type alias for vector commitment
pub type VectorCommit = MerkleTree<Hasher>;

#[cfg(not(target_arch = "wasm32"))]
type Timer = std::time::Instant;

#[cfg(target_arch = "wasm32")]
type Timer = u64;

#[cfg(not(target_arch = "wasm32"))]
fn start_timer() -> Timer {
    std::time::Instant::now()
}

#[cfg(target_arch = "wasm32")]
fn start_timer() -> Timer {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn elapsed_ms(start: Timer) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(target_arch = "wasm32")]
fn elapsed_ms(start: Timer) -> u64 {
    (js_sys::Date::now() as u64).saturating_sub(start)
}

/// Result of proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,

    /// Verification time in milliseconds
    pub verification_time_ms: u64,

    /// Error message if verification failed
    pub error: Option<String>,

    /// The policy that was verified
    pub policy_id: String,

    /// The policy limit that was verified against
    pub policy_limit: u64,
}

impl VerificationResult {
    /// Convert an invalid verification result into an error for callers that
    /// want a strict success boundary.
    pub fn ensure_valid(self) -> Result<Self, VerifierError> {
        if self.valid {
            Ok(self)
        } else {
            Err(VerifierError::verification_failed(
                self.error
                    .unwrap_or_else(|| "proof failed verification".to_string()),
            ))
        }
    }
}

fn default_acceptable_options() -> Result<AcceptableOptions, VerifierError> {
    Ok(AcceptableOptions::OptionSet(vec![
        ves_stark_air::options::ProofOptions::default()
            .try_to_winterfell()
            .map_err(|e| {
                VerifierError::VerificationFailed(format!("Invalid proof options: {e}"))
            })?,
        ves_stark_air::options::ProofOptions::secure()
            .try_to_winterfell()
            .map_err(|e| {
                VerifierError::VerificationFailed(format!("Invalid proof options: {e}"))
            })?,
    ]))
}

fn verify_compliance_proof_with_options(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
    acceptable_options: &AcceptableOptions,
) -> Result<VerificationResult, VerifierError> {
    let start = start_timer();

    // Size check: reject oversized proofs before attempting deserialization
    if proof_bytes.len() > MAX_PROOF_SIZE {
        return Err(VerifierError::ProofTooLarge {
            size: proof_bytes.len(),
            max_size: MAX_PROOF_SIZE,
        });
    }

    // Input hardening: validate hex string formats in public inputs
    validate_hex_string("payload_plain_hash", &public_inputs.payload_plain_hash, 64)?;
    validate_hex_string(
        "payload_cipher_hash",
        &public_inputs.payload_cipher_hash,
        64,
    )?;
    validate_hex_string("event_signing_hash", &public_inputs.event_signing_hash, 64)?;
    validate_hex_string("policy_hash", &public_inputs.policy_hash, 64)?;
    if let Some(receipt_hash) = public_inputs.authorization_receipt_hash.as_deref() {
        validate_hex_string("authorization_receipt_hash", receipt_hash, 64)?;
    }
    if let Some(amount_binding_hash) = public_inputs.amount_binding_hash.as_deref() {
        validate_hex_string("amount_binding_hash", amount_binding_hash, 64)?;
    }

    // Optional hardening: if the canonical public inputs include a witness commitment, enforce
    // that the caller-provided commitment matches it.
    if let Some(expected) = public_inputs
        .witness_commitment_u64()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?
    {
        if &expected != witness_commitment {
            return Err(VerifierError::WitnessCommitmentMismatch);
        }
    }

    // Validate policy hash
    let policy_hash_valid = public_inputs
        .validate_policy_hash()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;
    if !policy_hash_valid {
        let expected = CompliancePublicInputs::compute_policy_hash(
            &public_inputs.policy_id,
            &public_inputs.policy_params,
        )
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;
        return Err(VerifierError::InvalidPolicyHash {
            expected: expected.to_hex(),
            actual: public_inputs.policy_hash.clone(),
        });
    }

    // Policy must match public inputs
    let derived_policy =
        Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
            .map_err(|e| {
                VerifierError::PublicInputMismatch(format!("Invalid policy params: {e}"))
            })?;
    if policy.policy_id() != derived_policy.policy_id() {
        return Err(VerifierError::policy_mismatch(
            policy.policy_id(),
            derived_policy.policy_id(),
        ));
    }
    if policy.limit() != derived_policy.limit() {
        return Err(VerifierError::limit_mismatch(
            policy.limit(),
            derived_policy.limit(),
        ));
    }
    if policy != &derived_policy {
        return Err(VerifierError::PublicInputMismatch(format!(
            "policy parameters in public inputs do not match expected policy for {}",
            policy.policy_id()
        )));
    }

    // Validate policy semantics before touching proof bytes so callers get consistent
    // public-input errors even if the proof encoding is malformed.
    let policy_limit = policy
        .effective_limit()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;

    // Deserialize proof
    let proof = winter_verifier::Proof::from_bytes(proof_bytes)
        .map_err(|e| VerifierError::DeserializationError(format!("{:?}", e)))?;

    // Convert witness commitment to field elements
    let commitment_felts: [Felt; 4] = [
        felt_from_u64(witness_commitment[0]),
        felt_from_u64(witness_commitment[1]),
        felt_from_u64(witness_commitment[2]),
        felt_from_u64(witness_commitment[3]),
    ];

    // Convert public inputs to field elements and include witness commitment
    let pub_inputs_felts = public_inputs
        .to_field_elements()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;
    let pub_inputs = PublicInputs::try_with_commitment(
        policy_limit,
        pub_inputs_felts.to_vec(),
        commitment_felts,
    )
    .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;

    // Verify the proof
    let result = verify::<ComplianceAir, Hasher, RandCoin, VectorCommit>(
        proof,
        pub_inputs,
        acceptable_options,
    );

    match result {
        Ok(_) => Ok(VerificationResult {
            valid: true,
            verification_time_ms: elapsed_ms(start),
            error: None,
            policy_id: public_inputs.policy_id.clone(),
            policy_limit: policy.limit(),
        }),
        Err(e) => Ok(VerificationResult {
            valid: false,
            verification_time_ms: elapsed_ms(start),
            error: Some(format!("{:?}", e)),
            policy_id: public_inputs.policy_id.clone(),
            policy_limit: policy.limit(),
        }),
    }
}

fn bound_witness_commitment(
    public_inputs: &CompliancePublicInputs,
) -> Result<[u64; 4], VerifierError> {
    public_inputs
        .witness_commitment_u64()
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?
        .ok_or_else(|| {
            VerifierError::PublicInputMismatch(
                "missing witnessCommitment in public inputs".to_string(),
            )
        })
}

fn validate_agent_authorization_receipt_binding(
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
) -> Result<CommerceAuthorizationReceipt, VerifierError> {
    if policy.policy_id() != "agent.authorization.v1" {
        return Err(VerifierError::PublicInputMismatch(
            "authorization receipt binding requires agent.authorization.v1 policy".to_string(),
        ));
    }

    let normalized_receipt = receipt.normalized().map_err(|e| {
        VerifierError::PublicInputMismatch(format!("invalid authorization receipt: {e}"))
    })?;
    public_inputs
        .validate_authorization_receipt(&normalized_receipt)
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))?;

    let expected_commitment = normalized_receipt.witness_commitment_u64();
    if &expected_commitment != witness_commitment {
        return Err(VerifierError::WitnessCommitmentMismatch);
    }

    Ok(normalized_receipt)
}

fn bind_public_inputs_to_payload_amount_binding(
    public_inputs: &CompliancePublicInputs,
    binding: &PayloadAmountBinding,
) -> Result<CompliancePublicInputs, VerifierError> {
    public_inputs
        .bind_payload_amount_binding(binding)
        .map_err(|e| VerifierError::PublicInputMismatch(format!("{e}")))
}

fn strict_payload_binding_required(
    payload_complete_fn: &str,
    witness_only_fn: &str,
) -> VerifierError {
    VerifierError::PayloadAmountBindingRequired(format!(
        "strict verification requires a canonical payload amount binding; use {payload_complete_fn} for payload-complete verification or {witness_only_fn} for witness-only verification"
    ))
}

fn verify_agent_authorization_proof_with_options(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
    acceptable_options: &AcceptableOptions,
) -> Result<VerificationResult, VerifierError> {
    validate_agent_authorization_receipt_binding(
        public_inputs,
        policy,
        witness_commitment,
        receipt,
    )?;
    verify_compliance_proof_with_options(
        proof_bytes,
        public_inputs,
        policy,
        witness_commitment,
        acceptable_options,
    )
}

/// Verify a compliance proof
///
/// This is the main entry point for proof verification. It takes raw proof
/// bytes, public inputs, policy, and the witness commitment from the proof.
///
/// The witness commitment is a Rescue hash of the private amount, included
/// in the proof to bind the private witness to the public proof.
pub fn verify_compliance_proof(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    let acceptable_options = default_acceptable_options()?;
    verify_compliance_proof_with_options(
        proof_bytes,
        public_inputs,
        policy,
        witness_commitment,
        &acceptable_options,
    )
}

/// Strict-verification guard. **Always returns an error.**
///
/// This entry point intentionally refuses to verify because it is ambiguous about whether the
/// caller has a payload-derived amount binding artifact. Callers must instead pick:
///
/// - [`verify_compliance_proof_with_amount_binding_strict`] — payload-complete verification, OR
/// - [`verify_compliance_proof_witness_strict`] — explicit witness-only verification.
///
/// The guard exists so that strict callers cannot silently drop the payload binding check.
pub fn verify_compliance_proof_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    let _ = (proof_bytes, public_inputs, policy, witness_commitment);
    Err(strict_payload_binding_required(
        "verify_compliance_proof_with_amount_binding_strict",
        "verify_compliance_proof_witness_strict",
    ))
}

/// Verify a witness-bound compliance proof and return an error on invalid proofs.
///
/// This helper is explicit about the weaker statement it checks: the proof is bound to the
/// witness commitment, but no payload-derived amount binding artifact is validated.
pub fn verify_compliance_proof_witness_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    verify_compliance_proof(proof_bytes, public_inputs, policy, witness_commitment)?.ensure_valid()
}

/// Verify an `agent.authorization.v1` proof against a canonical authorization receipt.
pub fn verify_agent_authorization_proof(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let acceptable_options = default_acceptable_options()?;
    verify_agent_authorization_proof_with_options(
        proof_bytes,
        public_inputs,
        policy,
        witness_commitment,
        receipt,
        &acceptable_options,
    )
}

/// Strict-verification guard. **Always returns an error.**
///
/// Callers must pick either [`verify_agent_authorization_proof_with_amount_binding_strict`]
/// (payload-complete) or [`verify_agent_authorization_proof_witness_strict`] (witness-only).
pub fn verify_agent_authorization_proof_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let _ = (
        proof_bytes,
        public_inputs,
        policy,
        witness_commitment,
        receipt,
    );
    Err(strict_payload_binding_required(
        "verify_agent_authorization_proof_with_amount_binding_strict",
        "verify_agent_authorization_proof_witness_strict",
    ))
}

/// Verify a witness-bound `agent.authorization.v1` proof and return an error on invalid proofs.
///
/// This validates the authorization receipt and witness commitment, but does not validate a
/// payload-derived amount binding artifact.
pub fn verify_agent_authorization_proof_witness_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    verify_agent_authorization_proof(
        proof_bytes,
        public_inputs,
        policy,
        witness_commitment,
        receipt,
    )?
    .ensure_valid()
}

/// Verify a compliance proof against an explicit policy and a payload-derived amount binding.
pub fn verify_compliance_proof_with_amount_binding(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    binding: &PayloadAmountBinding,
) -> Result<VerificationResult, VerifierError> {
    let bound_public_inputs = bind_public_inputs_to_payload_amount_binding(public_inputs, binding)?;
    verify_compliance_proof(
        proof_bytes,
        &bound_public_inputs,
        policy,
        &binding.witness_commitment_u64(),
    )
}

/// Verify a compliance proof against an explicit policy and a payload-derived amount binding, and
/// return an error on invalid proofs.
pub fn verify_compliance_proof_with_amount_binding_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    binding: &PayloadAmountBinding,
) -> Result<VerificationResult, VerifierError> {
    verify_compliance_proof_with_amount_binding(proof_bytes, public_inputs, policy, binding)?
        .ensure_valid()
}

/// Verify an `agent.authorization.v1` proof against an explicit policy, payload-derived amount
/// binding artifact, and canonical authorization receipt.
pub fn verify_agent_authorization_proof_with_amount_binding(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    binding: &PayloadAmountBinding,
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let bound_public_inputs = bind_public_inputs_to_payload_amount_binding(public_inputs, binding)?;
    verify_agent_authorization_proof(
        proof_bytes,
        &bound_public_inputs,
        policy,
        &binding.witness_commitment_u64(),
        receipt,
    )
}

/// Verify an `agent.authorization.v1` proof against an explicit policy, payload-derived amount
/// binding artifact, and canonical authorization receipt, and return an error on invalid proofs.
pub fn verify_agent_authorization_proof_with_amount_binding_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    policy: &Policy,
    binding: &PayloadAmountBinding,
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    verify_agent_authorization_proof_with_amount_binding(
        proof_bytes,
        public_inputs,
        policy,
        binding,
        receipt,
    )?
    .ensure_valid()
}

/// Verify a compliance proof using policy parameters from the public inputs.
pub fn verify_compliance_proof_auto(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    let policy = Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
        .map_err(|e| VerifierError::PublicInputMismatch(format!("Invalid policy params: {e}")))?;
    verify_compliance_proof(proof_bytes, public_inputs, &policy, witness_commitment)
}

/// Verify an `agent.authorization.v1` proof using policy parameters from the public inputs
/// and an explicit witness commitment.
pub fn verify_agent_authorization_proof_auto(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let policy = Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
        .map_err(|e| VerifierError::PublicInputMismatch(format!("Invalid policy params: {e}")))?;
    verify_agent_authorization_proof(
        proof_bytes,
        public_inputs,
        &policy,
        witness_commitment,
        receipt,
    )
}

/// Strict-verification guard. **Always returns an error.**
///
/// Callers must pick either [`verify_agent_authorization_proof_auto_with_amount_binding_strict`]
/// (payload-complete) or [`verify_agent_authorization_proof_auto_witness_strict`] (witness-only).
pub fn verify_agent_authorization_proof_auto_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let _ = (proof_bytes, public_inputs, witness_commitment, receipt);
    Err(strict_payload_binding_required(
        "verify_agent_authorization_proof_auto_with_amount_binding_strict",
        "verify_agent_authorization_proof_auto_witness_strict",
    ))
}

/// Verify a witness-bound `agent.authorization.v1` proof using policy parameters from the public
/// inputs and return an error on invalid proofs.
pub fn verify_agent_authorization_proof_auto_witness_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    verify_agent_authorization_proof_auto(proof_bytes, public_inputs, witness_commitment, receipt)?
        .ensure_valid()
}

/// Strict-verification guard. **Always returns an error.**
///
/// Callers must pick either [`verify_compliance_proof_auto_with_amount_binding_strict`]
/// (payload-complete) or [`verify_compliance_proof_auto_witness_strict`] (witness-only).
pub fn verify_compliance_proof_auto_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    let _ = (proof_bytes, public_inputs, witness_commitment);
    Err(strict_payload_binding_required(
        "verify_compliance_proof_auto_with_amount_binding_strict",
        "verify_compliance_proof_auto_witness_strict",
    ))
}

/// Verify a witness-bound compliance proof using policy parameters from the public inputs and
/// return an error on invalid proofs.
pub fn verify_compliance_proof_auto_witness_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    witness_commitment: &[u64; 4],
) -> Result<VerificationResult, VerifierError> {
    verify_compliance_proof_auto(proof_bytes, public_inputs, witness_commitment)?.ensure_valid()
}

/// Verify a compliance proof using policy parameters from the public inputs and a payload-derived
/// amount binding artifact.
pub fn verify_compliance_proof_auto_with_amount_binding(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    binding: &PayloadAmountBinding,
) -> Result<VerificationResult, VerifierError> {
    let bound_public_inputs = bind_public_inputs_to_payload_amount_binding(public_inputs, binding)?;
    verify_compliance_proof_auto_bound(proof_bytes, &bound_public_inputs)
}

/// Verify a compliance proof using a payload-derived amount binding artifact and return an error
/// on invalid proofs.
pub fn verify_compliance_proof_auto_with_amount_binding_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    binding: &PayloadAmountBinding,
) -> Result<VerificationResult, VerifierError> {
    verify_compliance_proof_auto_with_amount_binding(proof_bytes, public_inputs, binding)?
        .ensure_valid()
}

/// Verify an `agent.authorization.v1` proof using policy parameters from the public inputs, a
/// payload-derived amount binding artifact, and a canonical authorization receipt.
pub fn verify_agent_authorization_proof_auto_with_amount_binding(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    binding: &PayloadAmountBinding,
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let bound_public_inputs = bind_public_inputs_to_payload_amount_binding(public_inputs, binding)?;
    verify_agent_authorization_proof_auto_bound(proof_bytes, &bound_public_inputs, receipt)
}

/// Verify an `agent.authorization.v1` proof using a payload-derived amount binding artifact and
/// return an error on invalid proofs.
pub fn verify_agent_authorization_proof_auto_with_amount_binding_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    binding: &PayloadAmountBinding,
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    verify_agent_authorization_proof_auto_with_amount_binding(
        proof_bytes,
        public_inputs,
        binding,
        receipt,
    )?
    .ensure_valid()
}

/// Verify a compliance proof using policy parameters and witness commitment from the public inputs.
///
/// This requires `public_inputs.witnessCommitment` to be present.
pub fn verify_compliance_proof_auto_bound(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
) -> Result<VerificationResult, VerifierError> {
    let witness_commitment = bound_witness_commitment(public_inputs)?;
    verify_compliance_proof_auto(proof_bytes, public_inputs, &witness_commitment)
}

/// Verify an `agent.authorization.v1` proof using policy parameters and witness commitment
/// from the public inputs.
pub fn verify_agent_authorization_proof_auto_bound(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let witness_commitment = bound_witness_commitment(public_inputs)?;
    verify_agent_authorization_proof_auto(proof_bytes, public_inputs, &witness_commitment, receipt)
}

/// Strict-verification guard. **Always returns an error.**
///
/// Callers must pick either [`verify_agent_authorization_proof_auto_with_amount_binding_strict`]
/// (payload-complete) or [`verify_agent_authorization_proof_auto_bound_witness_strict`]
/// (witness-only).
pub fn verify_agent_authorization_proof_auto_bound_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    let _ = (proof_bytes, public_inputs, receipt);
    Err(strict_payload_binding_required(
        "verify_agent_authorization_proof_auto_with_amount_binding_strict",
        "verify_agent_authorization_proof_auto_bound_witness_strict",
    ))
}

/// Verify a witness-bound `agent.authorization.v1` proof using policy parameters and witness
/// commitment from public inputs and return an error on invalid proofs.
pub fn verify_agent_authorization_proof_auto_bound_witness_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
    receipt: &CommerceAuthorizationReceipt,
) -> Result<VerificationResult, VerifierError> {
    verify_agent_authorization_proof_auto_bound(proof_bytes, public_inputs, receipt)?.ensure_valid()
}

/// Strict-verification guard. **Always returns an error.**
///
/// Callers must pick either [`verify_compliance_proof_auto_with_amount_binding_strict`]
/// (payload-complete) or [`verify_compliance_proof_auto_bound_witness_strict`] (witness-only).
pub fn verify_compliance_proof_auto_bound_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
) -> Result<VerificationResult, VerifierError> {
    let _ = (proof_bytes, public_inputs);
    Err(strict_payload_binding_required(
        "verify_compliance_proof_auto_with_amount_binding_strict",
        "verify_compliance_proof_auto_bound_witness_strict",
    ))
}

/// Verify a witness-bound compliance proof using policy parameters and witness commitment from
/// public inputs and return an error on invalid proofs.
pub fn verify_compliance_proof_auto_bound_witness_strict(
    proof_bytes: &[u8],
    public_inputs: &CompliancePublicInputs,
) -> Result<VerificationResult, VerifierError> {
    verify_compliance_proof_auto_bound(proof_bytes, public_inputs)?.ensure_valid()
}

/// Stateless compliance proof verifier
pub struct ComplianceVerifier {
    /// Acceptable proof options
    #[allow(dead_code)]
    acceptable_options: AcceptableOptions,
}

impl ComplianceVerifier {
    /// Create a new verifier with default options
    pub fn new() -> Self {
        Self::try_new().expect("built-in verifier proof options must remain valid")
    }

    /// Create a new verifier with default options without panicking
    pub fn try_new() -> Result<Self, VerifierError> {
        Ok(Self {
            acceptable_options: default_acceptable_options()?,
        })
    }

    /// Create a verifier with custom acceptable options
    pub fn with_options(options: AcceptableOptions) -> Self {
        Self {
            acceptable_options: options,
        }
    }

    /// Verify a proof
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        policy: &Policy,
        witness_commitment: &[u64; 4],
    ) -> Result<VerificationResult, VerifierError> {
        verify_compliance_proof_with_options(
            proof_bytes,
            public_inputs,
            policy,
            witness_commitment,
            &self.acceptable_options,
        )
    }

    /// Verify a proof using policy parameters from the public inputs.
    pub fn verify_auto(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        witness_commitment: &[u64; 4],
    ) -> Result<VerificationResult, VerifierError> {
        let policy =
            Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
                .map_err(|e| {
                    VerifierError::PublicInputMismatch(format!("Invalid policy params: {e}"))
                })?;
        verify_compliance_proof_with_options(
            proof_bytes,
            public_inputs,
            &policy,
            witness_commitment,
            &self.acceptable_options,
        )
    }

    /// Verify a proof using policy parameters and witness commitment from the public inputs.
    pub fn verify_auto_bound(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
    ) -> Result<VerificationResult, VerifierError> {
        let witness_commitment = bound_witness_commitment(public_inputs)?;
        self.verify_auto(proof_bytes, public_inputs, &witness_commitment)
    }

    /// Verify an `agent.authorization.v1` proof with an authorization receipt.
    pub fn verify_agent_authorization(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        policy: &Policy,
        witness_commitment: &[u64; 4],
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<VerificationResult, VerifierError> {
        verify_agent_authorization_proof_with_options(
            proof_bytes,
            public_inputs,
            policy,
            witness_commitment,
            receipt,
            &self.acceptable_options,
        )
    }

    /// Verify an `agent.authorization.v1` proof using policy parameters from the public inputs.
    pub fn verify_agent_authorization_auto(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        witness_commitment: &[u64; 4],
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<VerificationResult, VerifierError> {
        let policy =
            Policy::from_public_inputs(&public_inputs.policy_id, &public_inputs.policy_params)
                .map_err(|e| {
                    VerifierError::PublicInputMismatch(format!("Invalid policy params: {e}"))
                })?;
        self.verify_agent_authorization(
            proof_bytes,
            public_inputs,
            &policy,
            witness_commitment,
            receipt,
        )
    }

    /// Verify an `agent.authorization.v1` proof using policy parameters and witness commitment
    /// from the public inputs.
    pub fn verify_agent_authorization_auto_bound(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<VerificationResult, VerifierError> {
        let witness_commitment = bound_witness_commitment(public_inputs)?;
        self.verify_agent_authorization_auto(
            proof_bytes,
            public_inputs,
            &witness_commitment,
            receipt,
        )
    }

    /// Verify a proof and return an error on invalid proofs.
    pub fn verify_strict(
        &self,
        proof_bytes: &[u8],
        public_inputs: &CompliancePublicInputs,
        policy: &Policy,
        witness_commitment: &[u64; 4],
    ) -> Result<VerificationResult, VerifierError> {
        self.verify(proof_bytes, public_inputs, policy, witness_commitment)?
            .ensure_valid()
    }

    /// Verify proof hash matches
    pub fn verify_proof_hash(proof_bytes: &[u8], expected_hash: &str) -> bool {
        let computed =
            Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof_bytes);
        computed.to_hex() == expected_hash
    }
}

impl Default for ComplianceVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use ves_stark_primitives::public_inputs::{PayloadAmountBinding, PolicyParams};
    use ves_stark_primitives::{CommerceExecution, CommerceIntent};

    fn sample_inputs(threshold: u64) -> CompliancePublicInputs {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = CompliancePublicInputs::compute_policy_hash(policy_id, &params).unwrap();

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
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
    }

    fn sample_agent_authorization_context(
    ) -> (CommerceAuthorizationReceipt, CompliancePublicInputs, Policy) {
        let intent = CommerceIntent {
            intent_id: Uuid::parse_str("9f7f314e-80c3-45dc-af6d-11d6c1a68701").unwrap(),
            tenant_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            store_id: Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            agent_id: Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            delegation_id: Uuid::parse_str("d9428888-122b-11e1-b85c-61cd3cbb3210").unwrap(),
            currency: "USD".to_string(),
            max_total: 25_000,
            merchant: Some("Acme Market".to_string()),
            payee: Some("settlement@stateset.app".to_string()),
            allowed_skus: vec!["sku-a".to_string(), "sku-b".to_string()],
            allowed_categories: vec!["produce".to_string()],
            shipping_country: Some("US".to_string()),
            expires_at: 1_900_000_000,
            nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        };
        let execution = CommerceExecution {
            event_id: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            sequence_number: 42,
            currency: "USD".to_string(),
            amount: 12_500,
            merchant: "Acme Market".to_string(),
            payee: "settlement@stateset.app".to_string(),
            sku_ids: vec!["sku-a".to_string()],
            category_ids: vec!["produce".to_string()],
            shipping_country: Some("US".to_string()),
            executed_at: 1_800_000_000,
        };
        let receipt = intent.authorize_execution(&execution).unwrap();
        let policy = Policy::agent_authorization(intent.max_total, &receipt.intent_hash).unwrap();
        let params =
            PolicyParams::agent_authorization(intent.max_total, &receipt.intent_hash).unwrap();
        let policy_hash =
            CompliancePublicInputs::compute_policy_hash(policy.policy_id(), &params).unwrap();
        let inputs = CompliancePublicInputs {
            event_id: receipt.event_id,
            tenant_id: receipt.tenant_id,
            store_id: receipt.store_id,
            sequence_number: receipt.sequence_number,
            payload_kind: 7,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: policy.policy_id().to_string(),
            policy_params: params,
            policy_hash: policy_hash.to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        (receipt, inputs, policy)
    }

    fn sample_payload_amount_binding(
        inputs: &CompliancePublicInputs,
        amount: u64,
    ) -> PayloadAmountBinding {
        let mut binding = PayloadAmountBinding {
            event_id: inputs.event_id,
            tenant_id: inputs.tenant_id,
            store_id: inputs.store_id,
            sequence_number: inputs.sequence_number,
            payload_kind: inputs.payload_kind,
            payload_plain_hash: inputs.payload_plain_hash.clone(),
            payload_cipher_hash: inputs.payload_cipher_hash.clone(),
            event_signing_hash: inputs.event_signing_hash.clone(),
            amount,
            binding_hash: String::new(),
        };
        binding.binding_hash = binding.compute_hash_hex().unwrap();
        binding
    }

    // =========================================================================
    // Basic Verifier Tests
    // =========================================================================

    #[test]
    fn test_verifier_creation() {
        let _verifier = ComplianceVerifier::new();
    }

    #[test]
    fn test_verifier_default() {
        let verifier = ComplianceVerifier::default();
        // Ensure default creates same as new
        assert!(std::mem::size_of_val(&verifier) > 0);
    }

    #[test]
    fn test_verifier_with_custom_options() {
        use winter_verifier::AcceptableOptions;
        let options =
            AcceptableOptions::OptionSet(vec![ves_stark_air::options::ProofOptions::secure()
                .try_to_winterfell()
                .unwrap()]);
        let verifier = ComplianceVerifier::with_options(options);
        assert!(std::mem::size_of_val(&verifier) > 0);
    }

    #[test]
    fn test_verifier_with_custom_options_rejects_fast_proof() {
        use ves_stark_prover::{ComplianceProver, ComplianceWitness};
        use winter_verifier::AcceptableOptions;

        let threshold = 10000u64;
        let amount = 5000u64;
        let inputs = sample_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let policy = Policy::aml_threshold(threshold);

        let prover = ComplianceProver::with_policy(policy.clone())
            .with_options(ves_stark_air::options::ProofOptions::fast());
        let proof = prover.prove(&witness).unwrap();

        let verifier = ComplianceVerifier::with_options(AcceptableOptions::OptionSet(vec![
            ves_stark_air::options::ProofOptions::secure()
                .try_to_winterfell()
                .unwrap(),
        ]));

        let result = verifier
            .verify(
                &proof.proof_bytes,
                &inputs,
                &policy,
                &proof.witness_commitment,
            )
            .unwrap();
        assert!(!result.valid);
        assert!(verifier
            .verify_strict(
                &proof.proof_bytes,
                &inputs,
                &policy,
                &proof.witness_commitment
            )
            .is_err());
    }

    #[test]
    fn test_default_verifier_rejects_fast_proof() {
        use ves_stark_prover::{ComplianceProver, ComplianceWitness};

        let threshold = 10_000u64;
        let amount = 5_000u64;
        let inputs = sample_inputs(threshold);
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let policy = Policy::aml_threshold(threshold);

        let prover = ComplianceProver::with_policy(policy.clone())
            .with_options(ves_stark_air::options::ProofOptions::fast());
        let proof = prover.prove(&witness).unwrap();

        let result = verify_compliance_proof(
            &proof.proof_bytes,
            &inputs,
            &policy,
            &proof.witness_commitment,
        )
        .unwrap();
        assert!(!result.valid);
        assert!(verify_compliance_proof_witness_strict(
            &proof.proof_bytes,
            &inputs,
            &policy,
            &proof.witness_commitment
        )
        .is_err());
    }

    // =========================================================================
    // Policy Hash Validation Tests
    // =========================================================================

    #[test]
    fn test_invalid_policy_hash() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        // Keep a valid lowercase hex string (length 64) but force a mismatch.
        let mut chars: Vec<char> = inputs.policy_hash.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        inputs.policy_hash = chars.into_iter().collect();

        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        assert!(matches!(
            result,
            Err(VerifierError::InvalidPolicyHash { .. })
        ));
    }

    #[test]
    fn test_empty_policy_hash_fails() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        inputs.policy_hash = String::new();

        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        assert!(matches!(
            result,
            Err(VerifierError::InvalidHexFormat { .. })
        ));
    }

    #[test]
    fn test_policy_hash_case_sensitivity() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        // Make hash uppercase (should fail since we use lowercase hex)
        inputs.policy_hash = inputs.policy_hash.to_uppercase();

        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        assert!(matches!(
            result,
            Err(VerifierError::InvalidHexFormat { .. })
        ));
    }

    #[test]
    fn test_valid_policy_hash_passes_validation() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);

        // Just check that policy hash validation passes
        assert!(inputs.validate_policy_hash().unwrap());
    }

    // =========================================================================
    // Proof Hash Verification Tests
    // =========================================================================

    #[test]
    fn test_proof_hash_verification() {
        let proof_bytes = b"test proof data";
        let hash =
            Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof_bytes);

        assert!(ComplianceVerifier::verify_proof_hash(
            proof_bytes,
            &hash.to_hex()
        ));
        assert!(!ComplianceVerifier::verify_proof_hash(
            proof_bytes,
            "wrong_hash"
        ));
    }

    #[test]
    fn test_proof_hash_empty_bytes() {
        let proof_bytes: &[u8] = b"";
        let hash =
            Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof_bytes);

        assert!(ComplianceVerifier::verify_proof_hash(
            proof_bytes,
            &hash.to_hex()
        ));
    }

    #[test]
    fn test_proof_hash_large_input() {
        let proof_bytes: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let hash =
            Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", &proof_bytes);

        assert!(ComplianceVerifier::verify_proof_hash(
            &proof_bytes,
            &hash.to_hex()
        ));
    }

    #[test]
    fn test_proof_hash_deterministic() {
        let proof_bytes = b"deterministic test data";
        let hash1 =
            Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof_bytes);
        let hash2 =
            Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof_bytes);

        assert_eq!(hash1.to_hex(), hash2.to_hex());
    }

    #[test]
    fn test_proof_hash_different_inputs_differ() {
        let proof1 = b"proof data 1";
        let proof2 = b"proof data 2";

        let hash1 = Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof1);
        let hash2 = Hash256::sha256_with_domain(b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof2);

        assert_ne!(hash1.to_hex(), hash2.to_hex());
    }

    // =========================================================================
    // Proof Deserialization Error Tests
    // =========================================================================

    #[test]
    fn test_empty_proof_bytes_fails() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);

        // Should fail with deserialization error (empty proof can't be parsed)
        assert!(matches!(
            result,
            Err(VerifierError::DeserializationError(_))
        ));
    }

    #[test]
    fn test_garbage_proof_bytes_fails() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let garbage_bytes = vec![0xFF; 100];

        let result = verify_compliance_proof(&garbage_bytes, &inputs, &policy, &witness_commitment);

        assert!(matches!(
            result,
            Err(VerifierError::DeserializationError(_))
        ));
    }

    #[test]
    fn test_truncated_proof_bytes_fails() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        // Some bytes that look like they could be a proof header but are truncated
        let truncated_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let result =
            verify_compliance_proof(&truncated_bytes, &inputs, &policy, &witness_commitment);

        assert!(matches!(
            result,
            Err(VerifierError::DeserializationError(_))
        ));
    }

    // =========================================================================
    // Verification Result Serialization Tests
    // =========================================================================

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            valid: true,
            verification_time_ms: 150,
            error: None,
            policy_id: "aml.threshold".to_string(),
            policy_limit: 10000,
        };

        let json = serde_json::to_string(&result).unwrap();
        let recovered: VerificationResult = serde_json::from_str(&json).unwrap();

        assert!(recovered.valid);
        assert_eq!(recovered.verification_time_ms, 150);
        assert!(recovered.error.is_none());
        assert_eq!(recovered.policy_id, "aml.threshold");
        assert_eq!(recovered.policy_limit, 10000);
    }

    #[test]
    fn test_verification_result_with_error_serialization() {
        let result = VerificationResult {
            valid: false,
            verification_time_ms: 50,
            error: Some("Constraint check failed".to_string()),
            policy_id: "aml.threshold".to_string(),
            policy_limit: 5000,
        };

        let json = serde_json::to_string(&result).unwrap();
        let recovered: VerificationResult = serde_json::from_str(&json).unwrap();

        assert!(!recovered.valid);
        assert!(recovered.error.is_some());
        assert_eq!(recovered.error.unwrap(), "Constraint check failed");
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_zero_threshold() {
        let threshold = 0u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        // With threshold 0, no amount can satisfy amount < 0 for unsigned
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        assert!(matches!(result, Err(VerifierError::PublicInputMismatch(_))));
    }

    #[test]
    fn test_max_threshold() {
        let threshold = u64::MAX;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        // Should fail at deserialization
        assert!(matches!(
            result,
            Err(VerifierError::DeserializationError(_))
        ));
    }

    #[test]
    fn test_witness_commitment_zeros() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        // Zero commitment with empty proof should fail at deserialization
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_commitment_max_values() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [u64::MAX; 4];

        // Max commitment with empty proof should fail at deserialization
        let result = verify_compliance_proof(&[], &inputs, &policy, &witness_commitment);
        assert!(result.is_err());
    }

    // =========================================================================
    // Public Input Field Tests
    // =========================================================================

    #[test]
    fn test_public_inputs_various_uuids() {
        let threshold = 10000u64;

        // Create multiple inputs with different UUIDs
        for _ in 0..5 {
            let inputs = sample_inputs(threshold);
            assert!(inputs.validate_policy_hash().unwrap());
        }
    }

    #[test]
    fn test_public_inputs_different_sequence_numbers() {
        let threshold = 10000u64;
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(threshold);
        let hash = CompliancePublicInputs::compute_policy_hash(policy_id, &params).unwrap();

        for seq in [0u64, 1, 100, u64::MAX] {
            let inputs = CompliancePublicInputs {
                event_id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                store_id: Uuid::new_v4(),
                sequence_number: seq,
                payload_kind: 1,
                payload_plain_hash: "0".repeat(64),
                payload_cipher_hash: "0".repeat(64),
                event_signing_hash: "0".repeat(64),
                policy_id: policy_id.to_string(),
                policy_params: params.clone(),
                policy_hash: hash.to_hex(),
                witness_commitment: None,
                authorization_receipt_hash: None,
                amount_binding_hash: None,
            };
            assert!(inputs.validate_policy_hash().unwrap());
        }
    }

    #[test]
    fn test_public_inputs_witness_commitment_mismatch_fails_fast() {
        let threshold = 10000u64;
        let mut inputs = sample_inputs(threshold);
        let expected = [1u64, 2, 3, 4];
        inputs.witness_commitment = Some(ves_stark_primitives::witness_commitment_u64_to_hex(
            &expected,
        ));

        let policy = Policy::aml_threshold(threshold);
        let wrong = [0u64; 4];
        let err = verify_compliance_proof(&[], &inputs, &policy, &wrong).unwrap_err();
        assert!(matches!(err, VerifierError::WitnessCommitmentMismatch));
    }

    #[test]
    fn test_verify_auto_bound_requires_witness_commitment() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let err = verify_compliance_proof_auto_bound(&[], &inputs).unwrap_err();
        assert!(matches!(err, VerifierError::PublicInputMismatch(_)));
    }

    #[test]
    fn test_verify_with_amount_binding_accepts_valid_binding() {
        let threshold = 10_000u64;
        let amount = 5_000u64;
        let inputs = sample_inputs(threshold);
        let binding = sample_payload_amount_binding(&inputs, amount);
        let witness = ves_stark_prover::ComplianceWitness::new(amount, inputs.clone());
        let proof =
            ves_stark_prover::ComplianceProver::with_policy(Policy::aml_threshold(threshold))
                .prove(&witness)
                .unwrap();

        let result =
            verify_compliance_proof_auto_with_amount_binding(&proof.proof_bytes, &inputs, &binding)
                .unwrap();
        assert!(result.valid, "{:?}", result.error);
    }

    #[test]
    fn test_verify_with_amount_binding_rejects_payload_mismatch() {
        let threshold = 10_000u64;
        let amount = 5_000u64;
        let inputs = sample_inputs(threshold);
        let mut binding = sample_payload_amount_binding(&inputs, amount);
        binding.payload_plain_hash = "f".repeat(64);
        binding.binding_hash = binding.compute_hash_hex().unwrap();

        let witness = ves_stark_prover::ComplianceWitness::new(amount, inputs.clone());
        let proof =
            ves_stark_prover::ComplianceProver::with_policy(Policy::aml_threshold(threshold))
                .prove(&witness)
                .unwrap();

        let err =
            verify_compliance_proof_auto_with_amount_binding(&proof.proof_bytes, &inputs, &binding)
                .unwrap_err();
        assert!(matches!(err, VerifierError::PublicInputMismatch(_)));
    }

    #[test]
    fn test_strict_verification_requires_payload_binding_artifact() {
        let threshold = 10_000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];

        assert!(matches!(
            verify_compliance_proof_strict(&[], &inputs, &policy, &witness_commitment),
            Err(VerifierError::PayloadAmountBindingRequired(_))
        ));
        assert!(matches!(
            verify_compliance_proof_auto_strict(&[], &inputs, &witness_commitment),
            Err(VerifierError::PayloadAmountBindingRequired(_))
        ));
        assert!(matches!(
            verify_compliance_proof_auto_bound_strict(&[], &inputs),
            Err(VerifierError::PayloadAmountBindingRequired(_))
        ));
    }

    #[test]
    fn test_agent_authorization_receipt_requires_agent_policy() {
        let (receipt, inputs, _) = sample_agent_authorization_context();
        let witness_commitment = receipt.witness_commitment_u64();
        let err = verify_agent_authorization_proof(
            &[],
            &inputs,
            &Policy::aml_threshold(10_000),
            &witness_commitment,
            &receipt,
        )
        .unwrap_err();
        assert!(matches!(err, VerifierError::PublicInputMismatch(_)));
    }

    #[test]
    fn test_agent_authorization_receipt_rejects_invalid_hash_before_deserialization() {
        let (mut receipt, inputs, policy) = sample_agent_authorization_context();
        let witness_commitment = receipt.witness_commitment_u64();
        receipt.receipt_hash = "0".repeat(64);

        let err =
            verify_agent_authorization_proof(&[], &inputs, &policy, &witness_commitment, &receipt)
                .unwrap_err();
        assert!(matches!(err, VerifierError::PublicInputMismatch(_)));
    }

    #[test]
    fn test_agent_authorization_receipt_rejects_public_input_receipt_hash_mismatch() {
        let (receipt, mut inputs, policy) = sample_agent_authorization_context();
        let witness_commitment = receipt.witness_commitment_u64();
        inputs.authorization_receipt_hash = Some("0".repeat(64));

        let err =
            verify_agent_authorization_proof(&[], &inputs, &policy, &witness_commitment, &receipt)
                .unwrap_err();
        assert!(matches!(err, VerifierError::PublicInputMismatch(_)));
    }

    #[test]
    fn test_agent_authorization_receipt_rejects_amount_commitment_mismatch() {
        let (mut receipt, inputs, policy) = sample_agent_authorization_context();
        let witness_commitment = receipt.witness_commitment_u64();
        receipt.amount += 1;
        receipt.receipt_hash = receipt.compute_hash_hex().unwrap();

        let err =
            verify_agent_authorization_proof(&[], &inputs, &policy, &witness_commitment, &receipt)
                .unwrap_err();
        assert!(matches!(err, VerifierError::WitnessCommitmentMismatch));
    }

    // =========================================================================
    // Error Type Tests
    // =========================================================================

    #[test]
    fn test_verifier_error_display() {
        let err = VerifierError::InvalidPolicyHash {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("abc123"));
        assert!(display.contains("def456"));
    }

    // =========================================================================
    // Proof Size Limit Tests
    // =========================================================================

    #[test]
    fn test_proof_at_max_size_is_not_rejected_for_size() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let big_proof = vec![0xAB; MAX_PROOF_SIZE];

        // Should fail with deserialization (invalid proof content), NOT ProofTooLarge
        let result = verify_compliance_proof(&big_proof, &inputs, &policy, &witness_commitment);
        assert!(
            !matches!(result, Err(VerifierError::ProofTooLarge { .. })),
            "proof at exactly MAX_PROOF_SIZE should not be rejected for size"
        );
    }

    #[test]
    fn test_proof_over_max_size_is_rejected() {
        let threshold = 10000u64;
        let inputs = sample_inputs(threshold);
        let policy = Policy::aml_threshold(threshold);
        let witness_commitment = [0u64; 4];
        let oversized_proof = vec![0xAB; MAX_PROOF_SIZE + 1];

        let result =
            verify_compliance_proof(&oversized_proof, &inputs, &policy, &witness_commitment);
        assert!(
            matches!(
                result,
                Err(VerifierError::ProofTooLarge {
                    size,
                    max_size,
                }) if size == MAX_PROOF_SIZE + 1 && max_size == MAX_PROOF_SIZE
            ),
            "proof 1 byte over MAX_PROOF_SIZE must be rejected: {result:?}"
        );
    }

    #[test]
    fn test_verifier_error_deserialization_display() {
        let err = VerifierError::DeserializationError("invalid format".to_string());
        let display = format!("{}", err);
        assert!(display.contains("invalid format"));
    }

    #[test]
    fn test_verifier_error_helper_methods() {
        let err1 = VerifierError::invalid_structure("bad structure");
        assert!(matches!(err1, VerifierError::InvalidProofStructure(_)));

        let err2 = VerifierError::verification_failed("verification issue");
        assert!(matches!(err2, VerifierError::VerificationFailed(_)));
    }
}
