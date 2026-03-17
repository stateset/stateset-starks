//! Type definitions for the sequencer API

use crate::error::{ClientError, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ves_stark_primitives::public_inputs::{
    canonical_json, witness_commitment_hex_to_u64, witness_commitment_u64_to_hex,
    CompliancePublicInputs, PayloadAmountBinding, PolicyParams,
};
use ves_stark_primitives::{CommerceAuthorizationReceipt, Hash256};
use ves_stark_prover::{ComplianceProof, ProofMetadata};
use ves_stark_verifier::VerificationResult;

/// Request to get public inputs for an event
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicInputsRequest {
    pub policy_id: String,
    #[serde(default)]
    pub policy_params: serde_json::Value,
}

/// Response containing public inputs
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicInputsResponse {
    pub event_id: Uuid,
    pub public_inputs: serde_json::Value,
    pub public_inputs_hash: String,
}

impl PublicInputsResponse {
    /// Parse the sequencer-provided `public_inputs` into canonical inputs and validate that
    /// its hash matches `public_inputs_hash`.
    pub fn validate_and_parse_public_inputs(
        &self,
    ) -> Result<ves_stark_primitives::public_inputs::CompliancePublicInputs> {
        let inputs: ves_stark_primitives::public_inputs::CompliancePublicInputs =
            serde_json::from_value(self.public_inputs.clone()).map_err(|e| {
                ClientError::InvalidPublicInputs(format!("failed to parse public_inputs: {e}"))
            })?;

        if inputs.event_id != self.event_id {
            return Err(ClientError::PublicInputsEventIdMismatch {
                expected: self.event_id,
                actual: inputs.event_id,
            });
        }

        let expected = ves_stark_primitives::public_inputs::compute_public_inputs_hash(&inputs)
            .map_err(|e| {
                ClientError::InvalidPublicInputs(format!(
                    "failed to compute public inputs hash: {e}"
                ))
            })?
            .to_hex();

        if expected != self.public_inputs_hash {
            return Err(ClientError::PublicInputsHashMismatch {
                expected,
                actual: self.public_inputs_hash.clone(),
            });
        }

        Ok(inputs)
    }
}

// Note: For canonical `CompliancePublicInputs`, use `ves_stark_primitives::public_inputs::CompliancePublicInputs`.

/// Witness commitment for STARK compliance proofs.
///
/// Prefer `Hex` across JSON APIs to avoid JavaScript `u64` precision issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WitnessCommitment {
    Hex(String),
    U64([u64; 4]),
}

/// Request to submit a compliance proof
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitProofRequest {
    pub proof_type: String,
    pub proof_version: u32,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub proof_b64: String,
    pub witness_commitment: WitnessCommitment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_inputs: Option<serde_json::Value>,
}

/// Response after submitting a proof
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitProofResponse {
    pub proof_id: Uuid,
    pub event_id: Uuid,
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub proof_type: String,
    pub proof_version: u32,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub policy_hash: String,
    pub proof_hash: String,
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    pub witness_commitment_hex: Option<String>,
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: String,
}

/// Proof summary (when listing proofs)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofSummary {
    pub proof_id: Uuid,
    pub event_id: Uuid,
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub proof_type: String,
    pub proof_version: u32,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub policy_hash: String,
    pub proof_hash: String,
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    pub witness_commitment_hex: Option<String>,
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: String,
}

/// Response when listing proofs for an event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProofsResponse {
    pub event_id: Uuid,
    pub proofs: Vec<ProofSummary>,
    pub count: usize,
}

/// Full proof details including the proof bytes
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofDetails {
    pub proof_id: Uuid,
    pub event_id: Uuid,
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub proof_type: String,
    pub proof_version: u32,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub policy_hash: String,
    pub proof_hash: String,
    pub proof_b64: String,
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    pub witness_commitment_hex: Option<String>,
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: String,
}

impl SubmitProofResponse {
    /// Parse and validate optional canonical public inputs returned by the sequencer.
    pub fn validate_and_parse_public_inputs(&self) -> Result<Option<CompliancePublicInputs>> {
        let witness_commitment = normalized_optional_witness_commitment(
            self.witness_commitment,
            self.witness_commitment_hex.as_deref(),
            "submit proof response",
        )?;
        let public_inputs =
            parse_optional_public_inputs_value(&self.public_inputs, "submit proof response")?;
        if let Some(public_inputs) = public_inputs.as_ref() {
            validate_response_public_inputs(
                "submit proof response",
                self.event_id,
                self.tenant_id,
                self.store_id,
                &self.policy_id,
                &self.policy_params,
                &self.policy_hash,
                witness_commitment,
                public_inputs,
            )?;
        }
        Ok(public_inputs)
    }

    /// Validate the structural consistency of the sequencer response.
    pub fn validate(&self) -> Result<()> {
        self.validate_and_parse_public_inputs()?;
        Ok(())
    }
}

impl ProofSummary {
    /// Parse and validate optional canonical public inputs returned by the sequencer.
    pub fn validate_and_parse_public_inputs(&self) -> Result<Option<CompliancePublicInputs>> {
        let witness_commitment = normalized_optional_witness_commitment(
            self.witness_commitment,
            self.witness_commitment_hex.as_deref(),
            "proof summary",
        )?;
        let public_inputs =
            parse_optional_public_inputs_value(&self.public_inputs, "proof summary")?;
        if let Some(public_inputs) = public_inputs.as_ref() {
            validate_response_public_inputs(
                "proof summary",
                self.event_id,
                self.tenant_id,
                self.store_id,
                &self.policy_id,
                &self.policy_params,
                &self.policy_hash,
                witness_commitment,
                public_inputs,
            )?;
        }
        Ok(public_inputs)
    }

    /// Validate the structural consistency of the proof summary.
    pub fn validate(&self) -> Result<()> {
        self.validate_and_parse_public_inputs()?;
        Ok(())
    }
}

impl ProofDetails {
    /// Decode the raw proof bytes from the sequencer response.
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid proof_b64: {e}")))
    }

    /// Parse and validate optional canonical public inputs returned by the sequencer.
    pub fn validate_and_parse_public_inputs(&self) -> Result<Option<CompliancePublicInputs>> {
        let witness_commitment = normalized_optional_witness_commitment(
            self.witness_commitment,
            self.witness_commitment_hex.as_deref(),
            "proof details",
        )?;
        let public_inputs =
            parse_optional_public_inputs_value(&self.public_inputs, "proof details")?;
        if let Some(public_inputs) = public_inputs.as_ref() {
            validate_response_public_inputs(
                "proof details",
                self.event_id,
                self.tenant_id,
                self.store_id,
                &self.policy_id,
                &self.policy_params,
                &self.policy_hash,
                witness_commitment,
                public_inputs,
            )?;
        }
        Ok(public_inputs)
    }

    /// Validate the structural consistency of the fetched proof details.
    pub fn validate(&self) -> Result<()> {
        if self.proof_type != "stark" {
            return Err(ClientError::InvalidProofBundle(format!(
                "proof details has unsupported proof type {}",
                self.proof_type
            )));
        }

        let proof_bytes = self.proof_bytes()?;
        let expected_proof_hash = ComplianceProof::compute_hash(&proof_bytes).to_hex();
        if self.proof_hash != expected_proof_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "proof details proof_hash mismatch: expected {}, got {}",
                expected_proof_hash, self.proof_hash
            )));
        }

        self.validate_and_parse_public_inputs()?;
        Ok(())
    }
}

/// Verification result
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub proof_id: Uuid,
    pub event_id: Uuid,
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub proof_type: String,
    pub proof_version: u32,
    pub policy_id: String,
    pub policy_hash: String,
    pub proof_hash: String,
    pub public_inputs_hash: Option<String>,
    pub canonical_public_inputs_hash: String,
    pub public_inputs_match: bool,
    #[serde(default)]
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    pub witness_commitment_hex: Option<String>,
    #[serde(default)]
    pub stark_valid: Option<bool>,
    #[serde(default)]
    pub stark_error: Option<String>,
    #[serde(default)]
    pub stark_verification_time_ms: Option<u64>,
    pub valid: bool,
    pub reason: Option<String>,
}

/// Parameters for AML threshold policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlThresholdParams {
    pub threshold: u64,
}

impl AmlThresholdParams {
    pub fn new(threshold: u64) -> Self {
        Self { threshold }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "threshold": self.threshold })
    }
}

/// Parameters for order total cap policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderTotalCapParams {
    pub cap: u64,
}

impl OrderTotalCapParams {
    pub fn new(cap: u64) -> Self {
        Self { cap }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "cap": self.cap })
    }
}

/// Parameters for agent.authorization.v1 policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuthorizationParams {
    pub max_total: u64,
    pub intent_hash: String,
}

impl AgentAuthorizationParams {
    pub fn new(max_total: u64, intent_hash: &str) -> Result<Self> {
        let params = PolicyParams::agent_authorization(max_total, intent_hash)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        Ok(Self {
            max_total: params
                .get_max_total()
                .expect("agent authorization params should include maxTotal"),
            intent_hash: params
                .get_intent_hash()
                .expect("agent authorization params should include intentHash")
                .to_string(),
        })
    }

    pub fn from_receipt(max_total: u64, receipt: &CommerceAuthorizationReceipt) -> Result<Self> {
        Self::new(max_total, &receipt.intent_hash)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "maxTotal": self.max_total,
            "intentHash": self.intent_hash,
        })
    }
}

/// Version of the canonical compliance proof bundle format.
pub const COMPLIANCE_PROOF_BUNDLE_VERSION: u32 = 1;
/// Domain separator for canonical compliance bundle hashing.
pub const DOMAIN_COMPLIANCE_PROOF_BUNDLE_HASH: &[u8] =
    b"STATESET_VES_COMPLIANCE_PROOF_BUNDLE_HASH_V1";

/// Canonical transport artifact for a payload-bound compliance proof.
///
/// This bundles proof bytes, proof metadata, payload amount-bound public inputs, and the canonical
/// payload amount binding into a single locally verifiable artifact for any supported policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceProofBundle {
    /// Bundle format version.
    pub version: u32,
    /// Proof system type.
    pub proof_type: String,
    /// Wire-format proof version.
    pub proof_version: u32,
    /// Base64-encoded proof bytes.
    pub proof_b64: String,
    /// Domain-separated proof hash.
    pub proof_hash: String,
    /// Proof metadata captured at proving time.
    pub metadata: ProofMetadata,
    /// Witness commitment binding the private amount to the proof.
    pub witness_commitment: [u64; 4],
    /// Hex form of the witness commitment for JSON-safe transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_commitment_hex: Option<String>,
    /// Canonical amount-bound public inputs.
    pub public_inputs: CompliancePublicInputs,
    /// Canonical sequencer public-input hash for `public_inputs`.
    pub public_inputs_hash: String,
    /// Full local public-input hash for `public_inputs`, including `witnessCommitment`.
    pub bound_public_inputs_hash: String,
    /// Canonical payload-derived amount binding.
    pub amount_binding: PayloadAmountBinding,
    /// Domain-separated canonical bundle hash.
    pub bundle_hash: String,
}

impl ComplianceProofBundle {
    /// Create a canonical compliance proof bundle from a generated proof, public inputs, and a
    /// canonical payload amount binding.
    pub fn new(
        proof: &ComplianceProof,
        public_inputs: &CompliancePublicInputs,
        amount_binding: &PayloadAmountBinding,
    ) -> Result<Self> {
        validate_bundle_proof_artifact(
            &proof.proof_bytes,
            &proof.proof_hash,
            &proof.metadata,
            &proof.witness_commitment,
            proof.witness_commitment_hex.as_deref(),
        )?;

        let normalized_binding = amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        let bound_public_inputs = public_inputs
            .bind_payload_amount_binding(&normalized_binding)
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        let public_inputs_hash = bound_public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        let bound_public_inputs_hash = bound_public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();

        let mut bundle = Self {
            version: COMPLIANCE_PROOF_BUNDLE_VERSION,
            proof_type: "stark".to_string(),
            proof_version: ves_stark_verifier::PROOF_VERSION,
            proof_b64: base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
            proof_hash: proof.proof_hash.clone(),
            metadata: proof.metadata.clone(),
            witness_commitment: proof.witness_commitment,
            witness_commitment_hex: Some(witness_commitment_u64_to_hex(&proof.witness_commitment)),
            public_inputs: bound_public_inputs,
            public_inputs_hash,
            bound_public_inputs_hash,
            amount_binding: normalized_binding,
            bundle_hash: String::new(),
        };
        bundle.bundle_hash = bundle.compute_hash_hex()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Decode the raw proof bytes from the bundle.
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid proof_b64: {e}")))
    }

    /// Canonical JSON representation of the bundle payload excluding `bundle_hash`.
    pub fn canonical_json(&self) -> Result<String> {
        canonical_json(&serde_json::json!({
            "amountBinding": self.amount_binding,
            "metadata": self.metadata,
            "proofB64": self.proof_b64,
            "proofHash": self.proof_hash,
            "proofType": self.proof_type,
            "proofVersion": self.proof_version,
            "publicInputs": self.public_inputs,
            "publicInputsHash": self.public_inputs_hash,
            "boundPublicInputsHash": self.bound_public_inputs_hash,
            "version": self.version,
            "witnessCommitment": self.witness_commitment,
            "witnessCommitmentHex": self.witness_commitment_hex,
        }))
        .map_err(|e| ClientError::InvalidProofBundle(format!("failed to canonicalize bundle: {e}")))
    }

    /// Domain-separated canonical bundle hash.
    pub fn compute_hash(&self) -> Result<Hash256> {
        let canonical = self.canonical_json()?;
        Ok(Hash256::sha256_with_domain(
            DOMAIN_COMPLIANCE_PROOF_BUNDLE_HASH,
            canonical.as_bytes(),
        ))
    }

    /// Domain-separated canonical bundle hash as lowercase hex.
    pub fn compute_hash_hex(&self) -> Result<String> {
        Ok(self.compute_hash()?.to_hex())
    }

    /// Validate the bundle invariants without running STARK verification.
    pub fn validate(&self) -> Result<()> {
        if self.version != COMPLIANCE_PROOF_BUNDLE_VERSION {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported bundle version {}",
                self.version
            )));
        }
        if self.proof_type != "stark" {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported proof type {}",
                self.proof_type
            )));
        }
        if self.proof_version == 0 {
            return Err(ClientError::InvalidProofBundle(
                "proof_version must be greater than zero".to_string(),
            ));
        }

        let proof_bytes = self.proof_bytes()?;
        validate_bundle_proof_artifact(
            &proof_bytes,
            &self.proof_hash,
            &self.metadata,
            &self.witness_commitment,
            self.witness_commitment_hex.as_deref(),
        )?;

        let normalized_binding = self
            .amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        self.public_inputs
            .to_field_elements()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let policy_hash_valid = self
            .public_inputs
            .validate_policy_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        if !policy_hash_valid {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs policyHash does not match canonical policy params".to_string(),
            ));
        }

        let bound_commitment = self
            .public_inputs
            .witness_commitment_u64()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing witnessCommitment".to_string(),
                )
            })?;
        if bound_commitment != self.witness_commitment {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs witnessCommitment does not match bundle witness commitment"
                    .to_string(),
            ));
        }

        let amount_binding_hash = self
            .public_inputs
            .amount_binding_hash
            .as_deref()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing amountBindingHash".to_string(),
                )
            })?;
        if amount_binding_hash != normalized_binding.binding_hash {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs amountBindingHash does not match amount binding".to_string(),
            ));
        }

        self.public_inputs
            .validate_payload_amount_binding(&normalized_binding)
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let expected_public_inputs_hash = self
            .public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.public_inputs_hash != expected_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "public_inputs_hash mismatch: expected {}, got {}",
                expected_public_inputs_hash, self.public_inputs_hash
            )));
        }
        let expected_bound_public_inputs_hash = self
            .public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.bound_public_inputs_hash != expected_bound_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bound_public_inputs_hash mismatch: expected {}, got {}",
                expected_bound_public_inputs_hash, self.bound_public_inputs_hash
            )));
        }

        let expected_bundle_hash = self.compute_hash_hex()?;
        if self.bundle_hash != expected_bundle_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bundle_hash mismatch: expected {}, got {}",
                expected_bundle_hash, self.bundle_hash
            )));
        }

        Ok(())
    }

    /// Serialize the bundle to JSON after validating it.
    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let bundle: Self = serde_json::from_str(json)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Serialize the bundle to JSON bytes after validating it.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(bytes)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Convert this bundle back into a submit-ready proof submission.
    pub fn to_submission(&self) -> Result<ProofSubmission> {
        self.validate()?;

        let submission = ProofSubmission {
            event_id: self.public_inputs.event_id,
            policy_id: self.public_inputs.policy_id.clone(),
            policy_params: self.public_inputs.policy_params.to_json_value(),
            proof_bytes: self.proof_bytes()?,
            witness_commitment: self.witness_commitment,
            public_inputs: Some(self.public_inputs.clone()),
        };
        submission.validate()?;
        Ok(submission)
    }

    /// Run local STARK verification using the bound public inputs.
    pub fn verify(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_compliance_proof_auto_with_amount_binding(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Run strict local STARK verification and return an error for invalid proofs.
    pub fn verify_strict(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_compliance_proof_auto_with_amount_binding_strict(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Validate that a submit response still matches this canonical bundle.
    pub fn validate_submit_response(&self, response: &SubmitProofResponse) -> Result<()> {
        self.validate()?;
        response.validate()?;
        validate_compliance_bundle_response_common(
            "submit proof response",
            self,
            response.event_id,
            response.tenant_id,
            response.store_id,
            &response.proof_type,
            response.proof_version,
            &response.policy_id,
            &response.policy_params,
            &response.policy_hash,
            &response.proof_hash,
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
        )?;

        if let Some(public_inputs) = response.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(
                &self.public_inputs,
                &public_inputs,
                "submit proof response",
            )?;
        }

        Ok(())
    }

    /// Validate that fetched proof details still match this canonical bundle.
    pub fn validate_proof_details(&self, details: &ProofDetails) -> Result<()> {
        self.validate()?;
        details.validate()?;
        validate_compliance_bundle_response_common(
            "proof details",
            self,
            details.event_id,
            details.tenant_id,
            details.store_id,
            &details.proof_type,
            details.proof_version,
            &details.policy_id,
            &details.policy_params,
            &details.policy_hash,
            &details.proof_hash,
            details.witness_commitment,
            details.witness_commitment_hex.as_deref(),
        )?;

        if details.proof_bytes()? != self.proof_bytes()? {
            return Err(ClientError::InvalidProofBundle(
                "proof details proof bytes do not match bundle proof bytes".to_string(),
            ));
        }

        if let Some(public_inputs) = details.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(&self.public_inputs, &public_inputs, "proof details")?;
        }

        Ok(())
    }

    /// Validate that a sequencer verification response still matches this canonical bundle.
    pub fn validate_verify_response(&self, response: &VerifyResponse) -> Result<()> {
        self.validate()?;
        let witness_commitment = normalized_optional_witness_commitment(
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
            "verify response",
        )?;

        if response.event_id != self.public_inputs.event_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response event_id mismatch: expected {}, got {}",
                self.public_inputs.event_id, response.event_id
            )));
        }
        if response.tenant_id != self.public_inputs.tenant_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response tenant_id mismatch: expected {}, got {}",
                self.public_inputs.tenant_id, response.tenant_id
            )));
        }
        if response.store_id != self.public_inputs.store_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response store_id mismatch: expected {}, got {}",
                self.public_inputs.store_id, response.store_id
            )));
        }
        if response.proof_type != self.proof_type {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_type mismatch: expected {}, got {}",
                self.proof_type, response.proof_type
            )));
        }
        if response.proof_version != self.proof_version {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_version mismatch: expected {}, got {}",
                self.proof_version, response.proof_version
            )));
        }
        if response.policy_id != self.public_inputs.policy_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_id mismatch: expected {}, got {}",
                self.public_inputs.policy_id, response.policy_id
            )));
        }
        if response.policy_hash != self.public_inputs.policy_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_hash mismatch: expected {}, got {}",
                self.public_inputs.policy_hash, response.policy_hash
            )));
        }
        if response.proof_hash != self.proof_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_hash mismatch: expected {}, got {}",
                self.proof_hash, response.proof_hash
            )));
        }
        if response.canonical_public_inputs_hash != self.public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response canonical_public_inputs_hash mismatch: expected {}, got {}",
                self.public_inputs_hash, response.canonical_public_inputs_hash
            )));
        }
        if let Some(public_inputs_hash) = response.public_inputs_hash.as_deref() {
            if public_inputs_hash != self.public_inputs_hash {
                return Err(ClientError::InvalidProofBundle(format!(
                    "verify response public_inputs_hash mismatch: expected {}, got {}",
                    self.public_inputs_hash, public_inputs_hash
                )));
            }
        }
        if !response.public_inputs_match {
            return Err(ClientError::InvalidProofBundle(
                "verify response reports public_inputs_match = false".to_string(),
            ));
        }
        if let Some(witness_commitment) = witness_commitment {
            if witness_commitment != self.witness_commitment {
                return Err(ClientError::InvalidProofBundle(
                    "verify response witness commitment does not match bundle".to_string(),
                ));
            }
        }
        if response.stark_valid == Some(false) {
            return Err(ClientError::InvalidProofBundle(
                response
                    .stark_error
                    .clone()
                    .unwrap_or_else(|| "verify response reports stark_valid = false".to_string()),
            ));
        }
        if !response.valid {
            return Err(ClientError::InvalidProofBundle(
                response
                    .reason
                    .clone()
                    .unwrap_or_else(|| "verify response reports valid = false".to_string()),
            ));
        }

        Ok(())
    }
}

/// Version of the canonical agent authorization proof bundle format.
pub const AGENT_AUTHORIZATION_PROOF_BUNDLE_VERSION: u32 = 2;
/// Domain separator for canonical bundle hashing.
pub const DOMAIN_AGENT_AUTHORIZATION_PROOF_BUNDLE_HASH: &[u8] =
    b"STATESET_VES_AGENT_AUTHORIZATION_PROOF_BUNDLE_HASH_V1";

/// Canonical transport artifact for an `agent.authorization.v1` proof.
///
/// This bundles proof bytes, proof metadata, payload amount and receipt-bound public inputs,
/// the canonical payload-derived amount binding, and the delegated commerce receipt into a
/// single locally verifiable artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAuthorizationProofBundle {
    /// Bundle format version.
    pub version: u32,
    /// Proof system type.
    pub proof_type: String,
    /// Wire-format proof version.
    pub proof_version: u32,
    /// Base64-encoded proof bytes.
    pub proof_b64: String,
    /// Domain-separated proof hash.
    pub proof_hash: String,
    /// Proof metadata captured at proving time.
    pub metadata: ProofMetadata,
    /// Witness commitment binding the private amount to the proof.
    pub witness_commitment: [u64; 4],
    /// Hex form of the witness commitment for JSON-safe transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_commitment_hex: Option<String>,
    /// Canonical payload amount and receipt-bound public inputs.
    pub public_inputs: CompliancePublicInputs,
    /// Canonical sequencer public-input hash for `public_inputs`.
    pub public_inputs_hash: String,
    /// Full local public-input hash for `public_inputs`, including `witnessCommitment`.
    pub bound_public_inputs_hash: String,
    /// Canonical payload-derived amount binding.
    pub amount_binding: PayloadAmountBinding,
    /// Canonical authorization receipt bound to the proof.
    pub receipt: CommerceAuthorizationReceipt,
    /// Domain-separated canonical bundle hash.
    pub bundle_hash: String,
}

impl AgentAuthorizationProofBundle {
    /// Create a canonical authorization proof bundle from a generated proof, public inputs,
    /// payload amount binding, and delegated execution receipt.
    pub fn new(
        proof: &ComplianceProof,
        public_inputs: &CompliancePublicInputs,
        amount_binding: &PayloadAmountBinding,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        validate_bundle_proof_artifact(
            &proof.proof_bytes,
            &proof.proof_hash,
            &proof.metadata,
            &proof.witness_commitment,
            proof.witness_commitment_hex.as_deref(),
        )?;

        let normalized_receipt = receipt
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        normalized_receipt
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        let normalized_binding = amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        let bound_public_inputs = public_inputs
            .bind_payload_amount_binding_and_authorization_receipt(
                &normalized_binding,
                &normalized_receipt,
            )
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        let public_inputs_hash = bound_public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        let bound_public_inputs_hash = bound_public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();

        let mut bundle = Self {
            version: AGENT_AUTHORIZATION_PROOF_BUNDLE_VERSION,
            proof_type: "stark".to_string(),
            proof_version: ves_stark_verifier::PROOF_VERSION,
            proof_b64: base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
            proof_hash: proof.proof_hash.clone(),
            metadata: proof.metadata.clone(),
            witness_commitment: proof.witness_commitment,
            witness_commitment_hex: Some(witness_commitment_u64_to_hex(&proof.witness_commitment)),
            public_inputs: bound_public_inputs,
            public_inputs_hash,
            bound_public_inputs_hash,
            amount_binding: normalized_binding,
            receipt: normalized_receipt,
            bundle_hash: String::new(),
        };
        bundle.bundle_hash = bundle.compute_hash_hex()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Decode the raw proof bytes from the bundle.
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid proof_b64: {e}")))
    }

    /// Canonical JSON representation of the bundle payload excluding `bundle_hash`.
    pub fn canonical_json(&self) -> Result<String> {
        canonical_json(&serde_json::json!({
            "amountBinding": self.amount_binding,
            "metadata": self.metadata,
            "proofB64": self.proof_b64,
            "proofHash": self.proof_hash,
            "proofType": self.proof_type,
            "proofVersion": self.proof_version,
            "publicInputs": self.public_inputs,
            "publicInputsHash": self.public_inputs_hash,
            "boundPublicInputsHash": self.bound_public_inputs_hash,
            "receipt": self.receipt,
            "version": self.version,
            "witnessCommitment": self.witness_commitment,
            "witnessCommitmentHex": self.witness_commitment_hex,
        }))
        .map_err(|e| ClientError::InvalidProofBundle(format!("failed to canonicalize bundle: {e}")))
    }

    /// Domain-separated canonical bundle hash.
    pub fn compute_hash(&self) -> Result<Hash256> {
        let canonical = self.canonical_json()?;
        Ok(Hash256::sha256_with_domain(
            DOMAIN_AGENT_AUTHORIZATION_PROOF_BUNDLE_HASH,
            canonical.as_bytes(),
        ))
    }

    /// Domain-separated canonical bundle hash as lowercase hex.
    pub fn compute_hash_hex(&self) -> Result<String> {
        Ok(self.compute_hash()?.to_hex())
    }

    /// Validate the bundle invariants without running STARK verification.
    pub fn validate(&self) -> Result<()> {
        if self.version != AGENT_AUTHORIZATION_PROOF_BUNDLE_VERSION {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported bundle version {}",
                self.version
            )));
        }
        if self.proof_type != "stark" {
            return Err(ClientError::InvalidProofBundle(format!(
                "unsupported proof type {}",
                self.proof_type
            )));
        }
        if self.proof_version == 0 {
            return Err(ClientError::InvalidProofBundle(
                "proof_version must be greater than zero".to_string(),
            ));
        }

        let proof_bytes = self.proof_bytes()?;
        validate_bundle_proof_artifact(
            &proof_bytes,
            &self.proof_hash,
            &self.metadata,
            &self.witness_commitment,
            self.witness_commitment_hex.as_deref(),
        )?;

        let normalized_receipt = self
            .receipt
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        normalized_receipt
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid receipt: {e}")))?;
        let normalized_binding = self
            .amount_binding
            .normalized()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;
        normalized_binding
            .validate()
            .map_err(|e| ClientError::InvalidProofBundle(format!("invalid amount binding: {e}")))?;

        self.public_inputs
            .to_field_elements()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let policy_hash_valid = self
            .public_inputs
            .validate_policy_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;
        if !policy_hash_valid {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs policyHash does not match canonical policy params".to_string(),
            ));
        }

        let bound_commitment = self
            .public_inputs
            .witness_commitment_u64()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing witnessCommitment".to_string(),
                )
            })?;
        if bound_commitment != self.witness_commitment {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs witnessCommitment does not match bundle witness commitment"
                    .to_string(),
            ));
        }

        let receipt_hash = self
            .public_inputs
            .authorization_receipt_hash
            .as_deref()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing authorizationReceiptHash".to_string(),
                )
            })?;
        if receipt_hash != normalized_receipt.receipt_hash {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs authorizationReceiptHash does not match receipt".to_string(),
            ));
        }

        let amount_binding_hash = self
            .public_inputs
            .amount_binding_hash
            .as_deref()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "public_inputs is missing amountBindingHash".to_string(),
                )
            })?;
        if amount_binding_hash != normalized_binding.binding_hash {
            return Err(ClientError::InvalidProofBundle(
                "public_inputs amountBindingHash does not match amount binding".to_string(),
            ));
        }

        self.public_inputs
            .validate_payload_amount_binding_and_authorization_receipt(
                &normalized_binding,
                &normalized_receipt,
            )
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?;

        let expected_public_inputs_hash = self
            .public_inputs
            .compute_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.public_inputs_hash != expected_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "public_inputs_hash mismatch: expected {}, got {}",
                expected_public_inputs_hash, self.public_inputs_hash
            )));
        }
        let expected_bound_public_inputs_hash = self
            .public_inputs
            .compute_bound_hash()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{e}")))?
            .to_hex();
        if self.bound_public_inputs_hash != expected_bound_public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bound_public_inputs_hash mismatch: expected {}, got {}",
                expected_bound_public_inputs_hash, self.bound_public_inputs_hash
            )));
        }

        let expected_bundle_hash = self.compute_hash_hex()?;
        if self.bundle_hash != expected_bundle_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "bundle_hash mismatch: expected {}, got {}",
                expected_bundle_hash, self.bundle_hash
            )));
        }

        Ok(())
    }

    /// Serialize the bundle to JSON after validating it.
    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let bundle: Self = serde_json::from_str(json)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Serialize the bundle to JSON bytes after validating it.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(Into::into)
    }

    /// Deserialize and validate a bundle from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(bytes)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Convert this bundle back into a submit-ready proof submission.
    pub fn to_submission(&self) -> Result<ProofSubmission> {
        self.validate()?;

        let max_total = self
            .public_inputs
            .policy_params
            .get_max_total()
            .ok_or_else(|| {
                ClientError::InvalidProofBundle(
                    "missing maxTotal in agent authorization policy params".to_string(),
                )
            })?;

        ProofSubmission::agent_authorization_for_receipt(
            max_total,
            &self.receipt,
            self.proof_bytes()?,
            self.witness_commitment,
        )?
        .with_public_inputs(self.public_inputs.clone())
    }

    /// Run local STARK verification using the bound public inputs and receipt.
    pub fn verify(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_agent_authorization_proof_auto_with_amount_binding(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
            &self.receipt,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Run strict local STARK verification and return an error for invalid proofs.
    pub fn verify_strict(&self) -> Result<VerificationResult> {
        self.validate()?;
        let proof_bytes = self.proof_bytes()?;
        ves_stark_verifier::verify_agent_authorization_proof_auto_with_amount_binding_strict(
            &proof_bytes,
            &self.public_inputs,
            &self.amount_binding,
            &self.receipt,
        )
        .map_err(|e| ClientError::InvalidProofBundle(format!("bundle verification failed: {e}")))
    }

    /// Validate that a submit response still matches this canonical bundle.
    pub fn validate_submit_response(&self, response: &SubmitProofResponse) -> Result<()> {
        self.validate()?;
        response.validate()?;
        validate_bundle_response_common(
            "submit proof response",
            self,
            response.event_id,
            response.tenant_id,
            response.store_id,
            &response.proof_type,
            response.proof_version,
            &response.policy_id,
            &response.policy_params,
            &response.policy_hash,
            &response.proof_hash,
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
        )?;

        if let Some(public_inputs) = response.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(
                &self.public_inputs,
                &public_inputs,
                "submit proof response",
            )?;
        }

        Ok(())
    }

    /// Validate that fetched proof details still match this canonical bundle.
    pub fn validate_proof_details(&self, details: &ProofDetails) -> Result<()> {
        self.validate()?;
        details.validate()?;
        validate_bundle_response_common(
            "proof details",
            self,
            details.event_id,
            details.tenant_id,
            details.store_id,
            &details.proof_type,
            details.proof_version,
            &details.policy_id,
            &details.policy_params,
            &details.policy_hash,
            &details.proof_hash,
            details.witness_commitment,
            details.witness_commitment_hex.as_deref(),
        )?;

        if details.proof_bytes()? != self.proof_bytes()? {
            return Err(ClientError::InvalidProofBundle(
                "proof details proof bytes do not match bundle proof bytes".to_string(),
            ));
        }

        if let Some(public_inputs) = details.validate_and_parse_public_inputs()? {
            validate_public_inputs_equal(&self.public_inputs, &public_inputs, "proof details")?;
        }

        Ok(())
    }

    /// Validate that a sequencer verification response still matches this canonical bundle.
    pub fn validate_verify_response(&self, response: &VerifyResponse) -> Result<()> {
        self.validate()?;
        let witness_commitment = normalized_optional_witness_commitment(
            response.witness_commitment,
            response.witness_commitment_hex.as_deref(),
            "verify response",
        )?;

        if response.event_id != self.receipt.event_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response event_id mismatch: expected {}, got {}",
                self.receipt.event_id, response.event_id
            )));
        }
        if response.tenant_id != self.receipt.tenant_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response tenant_id mismatch: expected {}, got {}",
                self.receipt.tenant_id, response.tenant_id
            )));
        }
        if response.store_id != self.receipt.store_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response store_id mismatch: expected {}, got {}",
                self.receipt.store_id, response.store_id
            )));
        }
        if response.proof_type != self.proof_type {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_type mismatch: expected {}, got {}",
                self.proof_type, response.proof_type
            )));
        }
        if response.proof_version != self.proof_version {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_version mismatch: expected {}, got {}",
                self.proof_version, response.proof_version
            )));
        }
        if response.policy_id != self.public_inputs.policy_id {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_id mismatch: expected {}, got {}",
                self.public_inputs.policy_id, response.policy_id
            )));
        }
        if response.policy_hash != self.public_inputs.policy_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response policy_hash mismatch: expected {}, got {}",
                self.public_inputs.policy_hash, response.policy_hash
            )));
        }
        if response.proof_hash != self.proof_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response proof_hash mismatch: expected {}, got {}",
                self.proof_hash, response.proof_hash
            )));
        }
        if response.canonical_public_inputs_hash != self.public_inputs_hash {
            return Err(ClientError::InvalidProofBundle(format!(
                "verify response canonical_public_inputs_hash mismatch: expected {}, got {}",
                self.public_inputs_hash, response.canonical_public_inputs_hash
            )));
        }
        if let Some(public_inputs_hash) = response.public_inputs_hash.as_deref() {
            if public_inputs_hash != self.public_inputs_hash {
                return Err(ClientError::InvalidProofBundle(format!(
                    "verify response public_inputs_hash mismatch: expected {}, got {}",
                    self.public_inputs_hash, public_inputs_hash
                )));
            }
        }
        if !response.public_inputs_match {
            return Err(ClientError::InvalidProofBundle(
                "verify response reports public_inputs_match = false".to_string(),
            ));
        }
        if let Some(witness_commitment) = witness_commitment {
            if witness_commitment != self.witness_commitment {
                return Err(ClientError::InvalidProofBundle(
                    "verify response witness commitment does not match bundle".to_string(),
                ));
            }
        }
        if response.stark_valid == Some(false) {
            return Err(ClientError::InvalidProofBundle(
                response
                    .stark_error
                    .clone()
                    .unwrap_or_else(|| "verify response reports stark_valid = false".to_string()),
            ));
        }
        if !response.valid {
            return Err(ClientError::InvalidProofBundle(
                response
                    .reason
                    .clone()
                    .unwrap_or_else(|| "verify response reports valid = false".to_string()),
            ));
        }

        Ok(())
    }
}

/// Proof submission helper
#[derive(Debug, Clone)]
pub struct ProofSubmission {
    pub event_id: Uuid,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub proof_bytes: Vec<u8>,
    pub witness_commitment: [u64; 4],
    pub public_inputs: Option<CompliancePublicInputs>,
}

impl ProofSubmission {
    /// Create a new proof submission for the aml.threshold policy
    pub fn aml_threshold(
        event_id: Uuid,
        threshold: u64,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Self {
        Self {
            event_id,
            policy_id: "aml.threshold".to_string(),
            policy_params: AmlThresholdParams::new(threshold).to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        }
    }

    /// Create a new proof submission for the order_total.cap policy
    pub fn order_total_cap(
        event_id: Uuid,
        cap: u64,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Self {
        Self {
            event_id,
            policy_id: "order_total.cap".to_string(),
            policy_params: OrderTotalCapParams::new(cap).to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        }
    }

    /// Create a new proof submission for the agent.authorization.v1 policy
    pub fn agent_authorization(
        event_id: Uuid,
        max_total: u64,
        intent_hash: &str,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Result<Self> {
        let params = AgentAuthorizationParams::new(max_total, intent_hash)?;
        Ok(Self {
            event_id,
            policy_id: "agent.authorization.v1".to_string(),
            policy_params: params.to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        })
    }

    /// Create a new proof submission for the agent.authorization.v1 policy from a receipt.
    pub fn agent_authorization_for_receipt(
        max_total: u64,
        receipt: &CommerceAuthorizationReceipt,
        proof_bytes: Vec<u8>,
        witness_commitment: [u64; 4],
    ) -> Result<Self> {
        let params = AgentAuthorizationParams::from_receipt(max_total, receipt)?;
        Ok(Self {
            event_id: receipt.event_id,
            policy_id: "agent.authorization.v1".to_string(),
            policy_params: params.to_json(),
            proof_bytes,
            witness_commitment,
            public_inputs: None,
        })
    }

    /// Attach canonical public inputs to the submission after validating they match.
    pub fn with_public_inputs(mut self, public_inputs: CompliancePublicInputs) -> Result<Self> {
        validate_submission_public_inputs(
            self.event_id,
            &self.policy_id,
            &self.policy_params,
            &self.witness_commitment,
            &public_inputs,
        )?;
        self.public_inputs = Some(public_inputs);
        Ok(self)
    }

    /// Attach canonical public inputs bound to an authorization receipt and its implied payload
    /// amount binding.
    pub fn with_bound_authorization_receipt(
        self,
        public_inputs: &CompliancePublicInputs,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        let bound = public_inputs
            .bind_amount_and_authorization_receipt(receipt)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        self.with_public_inputs(bound)
    }

    /// Attach canonical public inputs bound to both the authorization receipt hash and the
    /// canonical payload amount binding implied by `receipt.amount`.
    pub fn with_amount_and_authorization_receipt(
        self,
        public_inputs: &CompliancePublicInputs,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        self.with_bound_authorization_receipt(public_inputs, receipt)
    }

    /// Attach canonical public inputs bound to both a payload amount binding and an
    /// authorization receipt.
    pub fn with_payload_amount_binding_and_authorization_receipt(
        self,
        public_inputs: &CompliancePublicInputs,
        binding: &PayloadAmountBinding,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self> {
        let bound = public_inputs
            .bind_payload_amount_binding_and_authorization_receipt(binding, receipt)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        self.with_public_inputs(bound)
    }

    /// Attach payload amount-bound canonical public inputs to the submission.
    pub fn with_payload_amount_binding(
        self,
        public_inputs: &CompliancePublicInputs,
        binding: &PayloadAmountBinding,
    ) -> Result<Self> {
        let bound = public_inputs
            .bind_payload_amount_binding(binding)
            .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
        self.with_public_inputs(bound)
    }

    /// Validate the submission before sending it over the wire.
    pub fn validate(&self) -> Result<()> {
        if let Some(public_inputs) = self.public_inputs.as_ref() {
            validate_submission_public_inputs(
                self.event_id,
                &self.policy_id,
                &self.policy_params,
                &self.witness_commitment,
                public_inputs,
            )?;
        }
        Ok(())
    }
}

fn validate_bundle_proof_artifact(
    proof_bytes: &[u8],
    proof_hash: &str,
    metadata: &ProofMetadata,
    witness_commitment: &[u64; 4],
    witness_commitment_hex: Option<&str>,
) -> Result<()> {
    if proof_bytes.is_empty() {
        return Err(ClientError::InvalidProofBundle(
            "proof_bytes must not be empty".to_string(),
        ));
    }

    let expected_proof_hash = ComplianceProof::compute_hash(proof_bytes).to_hex();
    if proof_hash != expected_proof_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "proof_hash mismatch: expected {}, got {}",
            expected_proof_hash, proof_hash
        )));
    }

    if metadata.proof_size != proof_bytes.len() {
        return Err(ClientError::InvalidProofBundle(format!(
            "metadata.proof_size mismatch: expected {}, got {}",
            proof_bytes.len(),
            metadata.proof_size
        )));
    }

    let expected_commitment_hex = witness_commitment_u64_to_hex(witness_commitment);
    match witness_commitment_hex {
        Some(actual) if actual == expected_commitment_hex => {}
        Some(actual) => {
            return Err(ClientError::InvalidProofBundle(format!(
                "witness_commitment_hex mismatch: expected {}, got {}",
                expected_commitment_hex, actual
            )));
        }
        None => {
            return Err(ClientError::InvalidProofBundle(
                "missing witness_commitment_hex".to_string(),
            ));
        }
    }

    Ok(())
}

fn normalized_optional_witness_commitment(
    witness_commitment: Option<[u64; 4]>,
    witness_commitment_hex: Option<&str>,
    context: &str,
) -> Result<Option<[u64; 4]>> {
    let parsed_hex = witness_commitment_hex
        .map(|hex| {
            witness_commitment_hex_to_u64(hex).map_err(|e| {
                ClientError::InvalidProofBundle(format!(
                    "{context} has invalid witnessCommitmentHex: {e}"
                ))
            })
        })
        .transpose()?;

    match (witness_commitment, parsed_hex) {
        (Some(commitment), Some(parsed)) => {
            if commitment != parsed {
                return Err(ClientError::InvalidProofBundle(format!(
                    "{context} witness commitment array does not match witnessCommitmentHex"
                )));
            }
            Ok(Some(commitment))
        }
        (Some(commitment), None) => Ok(Some(commitment)),
        (None, Some(parsed)) => Ok(Some(parsed)),
        (None, None) => Ok(None),
    }
}

fn parse_optional_public_inputs_value(
    value: &Option<serde_json::Value>,
    context: &str,
) -> Result<Option<CompliancePublicInputs>> {
    value
        .as_ref()
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|e| {
                ClientError::InvalidPublicInputs(format!(
                    "failed to parse {context} public_inputs: {e}"
                ))
            })
        })
        .transpose()
}

#[allow(clippy::too_many_arguments)]
fn validate_response_public_inputs(
    context: &str,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &str,
    witness_commitment: Option<[u64; 4]>,
    public_inputs: &CompliancePublicInputs,
) -> Result<()> {
    if public_inputs.event_id != event_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs event_id mismatch: expected {}, got {}",
            event_id, public_inputs.event_id
        )));
    }
    if public_inputs.tenant_id != tenant_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs tenant_id mismatch: expected {}, got {}",
            tenant_id, public_inputs.tenant_id
        )));
    }
    if public_inputs.store_id != store_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs store_id mismatch: expected {}, got {}",
            store_id, public_inputs.store_id
        )));
    }
    if public_inputs.policy_id != policy_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policy_id mismatch: expected {}, got {}",
            policy_id, public_inputs.policy_id
        )));
    }
    if public_inputs.policy_params.to_json_value() != *policy_params {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policy_params mismatch"
        )));
    }
    if public_inputs.policy_hash != policy_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policy_hash mismatch: expected {}, got {}",
            policy_hash, public_inputs.policy_hash
        )));
    }

    let policy_hash_valid = public_inputs
        .validate_policy_hash()
        .map_err(|e| ClientError::InvalidProofBundle(format!("{context} public_inputs: {e}")))?;
    if !policy_hash_valid {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policyHash does not match canonical policy params"
        )));
    }

    if let Some(expected_witness_commitment) = witness_commitment {
        if let Some(actual_witness_commitment) = public_inputs
            .witness_commitment_u64()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{context} public_inputs: {e}")))?
        {
            if actual_witness_commitment != expected_witness_commitment {
                return Err(ClientError::InvalidProofBundle(format!(
                    "{context} public_inputs witnessCommitment does not match response witness commitment"
                )));
            }
        }
    }

    Ok(())
}

fn validate_public_inputs_equal(
    expected: &CompliancePublicInputs,
    actual: &CompliancePublicInputs,
    context: &str,
) -> Result<()> {
    let expected_hash = expected
        .compute_full_hash()
        .map_err(|e| ClientError::InvalidProofBundle(format!("{context}: {e}")))?
        .to_hex();
    let actual_hash = actual
        .compute_full_hash()
        .map_err(|e| ClientError::InvalidProofBundle(format!("{context}: {e}")))?
        .to_hex();

    if expected_hash != actual_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs do not match bundle public_inputs"
        )));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_compliance_bundle_response_common(
    context: &str,
    bundle: &ComplianceProofBundle,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: &str,
    proof_version: u32,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &str,
    proof_hash: &str,
    witness_commitment: Option<[u64; 4]>,
    witness_commitment_hex: Option<&str>,
) -> Result<()> {
    let normalized_witness_commitment = normalized_optional_witness_commitment(
        witness_commitment,
        witness_commitment_hex,
        context,
    )?;

    if event_id != bundle.public_inputs.event_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} event_id mismatch: expected {}, got {}",
            bundle.public_inputs.event_id, event_id
        )));
    }
    if tenant_id != bundle.public_inputs.tenant_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} tenant_id mismatch: expected {}, got {}",
            bundle.public_inputs.tenant_id, tenant_id
        )));
    }
    if store_id != bundle.public_inputs.store_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} store_id mismatch: expected {}, got {}",
            bundle.public_inputs.store_id, store_id
        )));
    }
    if proof_type != bundle.proof_type {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_type mismatch: expected {}, got {}",
            bundle.proof_type, proof_type
        )));
    }
    if proof_version != bundle.proof_version {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_version mismatch: expected {}, got {}",
            bundle.proof_version, proof_version
        )));
    }
    if policy_id != bundle.public_inputs.policy_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_id mismatch: expected {}, got {}",
            bundle.public_inputs.policy_id, policy_id
        )));
    }
    if *policy_params != bundle.public_inputs.policy_params.to_json_value() {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_params do not match bundle policy params"
        )));
    }
    if policy_hash != bundle.public_inputs.policy_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_hash mismatch: expected {}, got {}",
            bundle.public_inputs.policy_hash, policy_hash
        )));
    }
    if proof_hash != bundle.proof_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_hash mismatch: expected {}, got {}",
            bundle.proof_hash, proof_hash
        )));
    }
    if let Some(witness_commitment) = normalized_witness_commitment {
        if witness_commitment != bundle.witness_commitment {
            return Err(ClientError::InvalidProofBundle(format!(
                "{context} witness commitment does not match bundle witness commitment"
            )));
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_bundle_response_common(
    context: &str,
    bundle: &AgentAuthorizationProofBundle,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: &str,
    proof_version: u32,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &str,
    proof_hash: &str,
    witness_commitment: Option<[u64; 4]>,
    witness_commitment_hex: Option<&str>,
) -> Result<()> {
    let normalized_witness_commitment = normalized_optional_witness_commitment(
        witness_commitment,
        witness_commitment_hex,
        context,
    )?;

    if event_id != bundle.receipt.event_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} event_id mismatch: expected {}, got {}",
            bundle.receipt.event_id, event_id
        )));
    }
    if tenant_id != bundle.receipt.tenant_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} tenant_id mismatch: expected {}, got {}",
            bundle.receipt.tenant_id, tenant_id
        )));
    }
    if store_id != bundle.receipt.store_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} store_id mismatch: expected {}, got {}",
            bundle.receipt.store_id, store_id
        )));
    }
    if proof_type != bundle.proof_type {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_type mismatch: expected {}, got {}",
            bundle.proof_type, proof_type
        )));
    }
    if proof_version != bundle.proof_version {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_version mismatch: expected {}, got {}",
            bundle.proof_version, proof_version
        )));
    }
    if policy_id != bundle.public_inputs.policy_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_id mismatch: expected {}, got {}",
            bundle.public_inputs.policy_id, policy_id
        )));
    }
    if *policy_params != bundle.public_inputs.policy_params.to_json_value() {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_params do not match bundle policy params"
        )));
    }
    if policy_hash != bundle.public_inputs.policy_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_hash mismatch: expected {}, got {}",
            bundle.public_inputs.policy_hash, policy_hash
        )));
    }
    if proof_hash != bundle.proof_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_hash mismatch: expected {}, got {}",
            bundle.proof_hash, proof_hash
        )));
    }
    if let Some(witness_commitment) = normalized_witness_commitment {
        if witness_commitment != bundle.witness_commitment {
            return Err(ClientError::InvalidProofBundle(format!(
                "{context} witness commitment does not match bundle witness commitment"
            )));
        }
    }

    Ok(())
}

fn validate_submission_public_inputs(
    event_id: Uuid,
    policy_id: &str,
    policy_params: &serde_json::Value,
    witness_commitment: &[u64; 4],
    public_inputs: &CompliancePublicInputs,
) -> Result<()> {
    if public_inputs.event_id != event_id {
        return Err(ClientError::InvalidPublicInputs(format!(
            "event_id mismatch: submission targets {}, but public inputs are for {}",
            event_id, public_inputs.event_id
        )));
    }
    if public_inputs.policy_id != policy_id {
        return Err(ClientError::InvalidPublicInputs(format!(
            "policy_id mismatch: submission targets {}, but public inputs are for {}",
            policy_id, public_inputs.policy_id
        )));
    }
    if public_inputs.policy_params.to_json_value() != *policy_params {
        return Err(ClientError::InvalidPublicInputs(format!(
            "policy_params mismatch for policy {}",
            policy_id
        )));
    }
    let policy_hash_valid = public_inputs
        .validate_policy_hash()
        .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
    if !policy_hash_valid {
        return Err(ClientError::InvalidPublicInputs(
            "policyHash does not match canonical policy params".to_string(),
        ));
    }
    if let Some(expected) = public_inputs
        .witness_commitment_u64()
        .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?
    {
        if &expected != witness_commitment {
            return Err(ClientError::InvalidPublicInputs(
                "witnessCommitment in public inputs does not match submission witness commitment"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, CompliancePublicInputs, PayloadAmountBinding,
    };
    use ves_stark_primitives::{CommerceExecution, CommerceIntent};
    use ves_stark_prover::{ComplianceProver, ComplianceWitness};

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
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
    }

    fn sample_authorization_bundle(max_total: u64) -> AgentAuthorizationProofBundle {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(max_total, &receipt);
        let binding = sample_payload_amount_binding(&inputs, receipt.amount);
        let bound_inputs = inputs
            .bind_payload_amount_binding_and_authorization_receipt(&binding, &receipt)
            .unwrap();
        let policy = ves_stark_air::policy::Policy::from_public_inputs(
            &inputs.policy_id,
            &inputs.policy_params,
        )
        .unwrap();
        let witness = ComplianceWitness::new(receipt.amount, bound_inputs);
        let proof = ComplianceProver::with_policy(policy)
            .prove(&witness)
            .unwrap();
        AgentAuthorizationProofBundle::new(&proof, &inputs, &binding, &receipt).unwrap()
    }

    fn sample_compliance_bundle(threshold: u64, amount: u64) -> ComplianceProofBundle {
        let inputs = sample_inputs(threshold);
        let binding = sample_payload_amount_binding(&inputs, amount);
        let bound_inputs = inputs.bind_payload_amount_binding(&binding).unwrap();
        let witness = ComplianceWitness::new(amount, bound_inputs);
        let proof =
            ComplianceProver::with_policy(ves_stark_air::policy::Policy::aml_threshold(threshold))
                .prove(&witness)
                .unwrap();
        ComplianceProofBundle::new(&proof, &inputs, &binding).unwrap()
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

    fn sample_authorization_receipt() -> CommerceAuthorizationReceipt {
        let intent = CommerceIntent {
            intent_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            currency: "USD".to_string(),
            max_total: 25_000,
            merchant: Some("Acme Market".to_string()),
            payee: Some("settlement@stateset.app".to_string()),
            allowed_skus: vec!["sku-a".to_string()],
            allowed_categories: vec!["grocery".to_string()],
            shipping_country: Some("US".to_string()),
            expires_at: 1_900_000_000,
            nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        };
        let execution = CommerceExecution {
            event_id: Uuid::new_v4(),
            sequence_number: 42,
            currency: "USD".to_string(),
            amount: 12_500,
            merchant: "Acme Market".to_string(),
            payee: "settlement@stateset.app".to_string(),
            sku_ids: vec!["sku-a".to_string()],
            category_ids: vec!["grocery".to_string()],
            shipping_country: Some("US".to_string()),
            executed_at: 1_800_000_000,
        };
        intent.authorize_execution(&execution).unwrap()
    }

    fn sample_authorization_inputs(
        max_total: u64,
        receipt: &CommerceAuthorizationReceipt,
    ) -> CompliancePublicInputs {
        let params = PolicyParams::agent_authorization(max_total, &receipt.intent_hash).unwrap();
        let hash = compute_policy_hash("agent.authorization.v1", &params).unwrap();
        CompliancePublicInputs {
            event_id: receipt.event_id,
            tenant_id: receipt.tenant_id,
            store_id: receipt.store_id,
            sequence_number: receipt.sequence_number,
            payload_kind: 7,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "agent.authorization.v1".to_string(),
            policy_params: params,
            policy_hash: hash.to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
    }

    #[test]
    fn test_public_inputs_response_validation_ok() {
        let inputs = sample_inputs(10_000);
        let inputs_hash = inputs.compute_hash().unwrap();

        let resp = PublicInputsResponse {
            event_id: inputs.event_id,
            public_inputs: serde_json::to_value(&inputs).unwrap(),
            public_inputs_hash: inputs_hash.to_hex(),
        };

        let recovered = resp.validate_and_parse_public_inputs().unwrap();
        assert_eq!(recovered.event_id, inputs.event_id);
        assert_eq!(recovered.policy_id, inputs.policy_id);
    }

    #[test]
    fn test_public_inputs_response_hash_mismatch() {
        let inputs = sample_inputs(10_000);

        let resp = PublicInputsResponse {
            event_id: inputs.event_id,
            public_inputs: serde_json::to_value(&inputs).unwrap(),
            public_inputs_hash: "0".repeat(64),
        };

        let err = resp.validate_and_parse_public_inputs().unwrap_err();
        assert!(matches!(err, ClientError::PublicInputsHashMismatch { .. }));
    }

    #[test]
    fn test_public_inputs_response_event_id_mismatch() {
        let inputs = sample_inputs(10_000);
        let inputs_hash = inputs.compute_hash().unwrap();

        let resp = PublicInputsResponse {
            event_id: Uuid::new_v4(),
            public_inputs: serde_json::to_value(&inputs).unwrap(),
            public_inputs_hash: inputs_hash.to_hex(),
        };

        let err = resp.validate_and_parse_public_inputs().unwrap_err();
        assert!(matches!(
            err,
            ClientError::PublicInputsEventIdMismatch { .. }
        ));
    }

    #[test]
    fn test_public_inputs_response_parse_error() {
        let resp = PublicInputsResponse {
            event_id: Uuid::new_v4(),
            public_inputs: serde_json::json!({ "not": "inputs" }),
            public_inputs_hash: "0".repeat(64),
        };

        let err = resp.validate_and_parse_public_inputs().unwrap_err();
        assert!(matches!(err, ClientError::InvalidPublicInputs(_)));
    }

    #[test]
    fn test_response_structs_deserialize_camel_case() {
        let proof_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let submit: SubmitProofResponse = serde_json::from_value(serde_json::json!({
            "proofId": proof_id,
            "eventId": event_id,
            "tenantId": tenant_id,
            "storeId": store_id,
            "proofType": "stark",
            "proofVersion": 1,
            "policyId": "aml.threshold",
            "policyParams": { "threshold": 10000 },
            "policyHash": "ab".repeat(32),
            "proofHash": "cd".repeat(32),
            "witnessCommitmentHex": "ef".repeat(32),
            "publicInputs": serde_json::Value::Null,
            "submittedAt": "2026-03-10T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(submit.proof_id, proof_id);
        assert_eq!(submit.event_id, event_id);
        assert_eq!(submit.submitted_at, "2026-03-10T00:00:00Z");

        let verify: VerifyResponse = serde_json::from_value(serde_json::json!({
            "proofId": proof_id,
            "eventId": event_id,
            "tenantId": tenant_id,
            "storeId": store_id,
            "proofType": "stark",
            "proofVersion": 1,
            "policyId": "aml.threshold",
            "policyHash": "ab".repeat(32),
            "proofHash": "cd".repeat(32),
            "publicInputsHash": "01".repeat(32),
            "canonicalPublicInputsHash": "02".repeat(32),
            "publicInputsMatch": true,
            "witnessCommitmentHex": "ef".repeat(32),
            "starkValid": true,
            "starkVerificationTimeMs": 42,
            "valid": true,
            "reason": null
        }))
        .unwrap();
        assert_eq!(verify.proof_id, proof_id);
        assert!(verify.public_inputs_match);
        assert_eq!(verify.stark_verification_time_ms, Some(42));
    }

    #[test]
    fn test_agent_authorization_params() {
        let params = AgentAuthorizationParams::new(
            25_000,
            "0X0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        )
        .unwrap();
        let json = params.to_json();
        assert_eq!(json["maxTotal"], 25_000);
        assert_eq!(
            json["intentHash"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_agent_authorization_params_from_receipt() {
        let receipt = CommerceAuthorizationReceipt {
            intent_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            nonce: "0".repeat(64),
            expires_at: 1_900_000_000,
            event_id: Uuid::new_v4(),
            sequence_number: 42,
            currency: "USD".to_string(),
            amount: 12_500,
            merchant: "Acme Market".to_string(),
            payee: "settlement@stateset.app".to_string(),
            sku_ids: vec!["sku-a".to_string()],
            category_ids: vec!["produce".to_string()],
            shipping_country: Some("US".to_string()),
            executed_at: 1_800_000_000,
            intent_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            receipt_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
        };
        let params = AgentAuthorizationParams::from_receipt(25_000, &receipt).unwrap();
        assert_eq!(params.max_total, 25_000);
        assert_eq!(params.intent_hash, receipt.intent_hash);
    }

    #[test]
    fn test_agent_authorization_proof_submission() {
        let event_id = Uuid::new_v4();
        let submission = ProofSubmission::agent_authorization(
            event_id,
            25_000,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            vec![1, 2, 3, 4],
            [0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(submission.policy_id, "agent.authorization.v1");
        assert_eq!(submission.event_id, event_id);
        assert_eq!(submission.policy_params["maxTotal"], 25_000);
    }

    #[test]
    fn test_agent_authorization_proof_submission_from_receipt() {
        let receipt = CommerceAuthorizationReceipt {
            intent_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            delegation_id: Uuid::new_v4(),
            nonce: "0".repeat(64),
            expires_at: 1_900_000_000,
            event_id: Uuid::new_v4(),
            sequence_number: 42,
            currency: "USD".to_string(),
            amount: 12_500,
            merchant: "Acme Market".to_string(),
            payee: "settlement@stateset.app".to_string(),
            sku_ids: vec!["sku-a".to_string()],
            category_ids: vec!["produce".to_string()],
            shipping_country: Some("US".to_string()),
            executed_at: 1_800_000_000,
            intent_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            receipt_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
        };
        let submission = ProofSubmission::agent_authorization_for_receipt(
            25_000,
            &receipt,
            vec![1, 2, 3, 4],
            [0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(submission.policy_id, "agent.authorization.v1");
        assert_eq!(submission.event_id, receipt.event_id);
        assert_eq!(submission.policy_params["intentHash"], receipt.intent_hash);
    }

    #[test]
    fn test_proof_submission_with_public_inputs() {
        let inputs = sample_inputs(10_000);
        let submission =
            ProofSubmission::aml_threshold(inputs.event_id, 10_000, vec![1, 2, 3], [0, 0, 0, 0])
                .with_public_inputs(inputs.clone())
                .unwrap();
        assert_eq!(submission.public_inputs.unwrap().event_id, inputs.event_id);
    }

    #[test]
    fn test_proof_submission_with_payload_amount_binding() {
        let inputs = sample_inputs(10_000);
        let binding = sample_payload_amount_binding(&inputs, 5_000);
        let submission = ProofSubmission::aml_threshold(
            inputs.event_id,
            10_000,
            vec![1, 2, 3],
            binding.witness_commitment_u64(),
        )
        .with_payload_amount_binding(&inputs, &binding)
        .unwrap();

        let bound_inputs = submission.public_inputs.unwrap();
        assert_eq!(
            bound_inputs.amount_binding_hash,
            Some(binding.binding_hash.clone())
        );
        assert_eq!(
            bound_inputs.witness_commitment,
            Some(witness_commitment_u64_to_hex(
                &binding.witness_commitment_u64()
            ))
        );
    }

    #[test]
    fn test_proof_submission_with_public_inputs_rejects_witness_commitment_mismatch() {
        let mut inputs = sample_inputs(10_000);
        inputs.witness_commitment =
            Some(ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(&[1, 2, 3, 4]));

        let err =
            ProofSubmission::aml_threshold(inputs.event_id, 10_000, vec![1, 2, 3], [0, 0, 0, 0])
                .with_public_inputs(inputs)
                .unwrap_err();
        assert!(matches!(err, ClientError::InvalidPublicInputs(_)));
    }

    #[test]
    fn test_agent_authorization_submission_with_bound_receipt_public_inputs() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(25_000, &receipt);
        let binding = inputs.payload_amount_binding(receipt.amount).unwrap();
        let submission = ProofSubmission::agent_authorization_for_receipt(
            25_000,
            &receipt,
            vec![1, 2, 3, 4],
            receipt.witness_commitment_u64(),
        )
        .unwrap()
        .with_bound_authorization_receipt(&inputs, &receipt)
        .unwrap();

        let bound_inputs = submission.public_inputs.unwrap();
        assert_eq!(
            bound_inputs.authorization_receipt_hash,
            Some(receipt.receipt_hash.clone())
        );
        assert_eq!(
            bound_inputs.amount_binding_hash,
            Some(binding.binding_hash.clone())
        );
        assert_eq!(
            bound_inputs.witness_commitment,
            Some(
                ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(
                    &receipt.witness_commitment_u64()
                )
            )
        );
    }

    #[test]
    fn test_agent_authorization_submission_with_amount_and_receipt_derives_payload_binding() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(25_000, &receipt);
        let submission = ProofSubmission::agent_authorization_for_receipt(
            25_000,
            &receipt,
            vec![1, 2, 3, 4],
            receipt.witness_commitment_u64(),
        )
        .unwrap()
        .with_amount_and_authorization_receipt(&inputs, &receipt)
        .unwrap();

        let bound_inputs = submission.public_inputs.unwrap();
        let binding = inputs.payload_amount_binding(receipt.amount).unwrap();
        assert_eq!(
            bound_inputs.amount_binding_hash,
            Some(binding.binding_hash.clone())
        );
        assert_eq!(
            bound_inputs.authorization_receipt_hash,
            Some(receipt.receipt_hash.clone())
        );
        assert_eq!(
            bound_inputs.witness_commitment,
            Some(
                ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(
                    &receipt.witness_commitment_u64()
                )
            )
        );
    }

    #[test]
    fn test_agent_authorization_submission_with_payload_amount_binding_and_receipt() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(25_000, &receipt);
        let binding = sample_payload_amount_binding(&inputs, receipt.amount);
        let submission = ProofSubmission::agent_authorization_for_receipt(
            25_000,
            &receipt,
            vec![1, 2, 3, 4],
            receipt.witness_commitment_u64(),
        )
        .unwrap()
        .with_payload_amount_binding_and_authorization_receipt(&inputs, &binding, &receipt)
        .unwrap();

        let bound_inputs = submission.public_inputs.unwrap();
        assert_eq!(
            bound_inputs.amount_binding_hash,
            Some(binding.binding_hash.clone())
        );
        assert_eq!(
            bound_inputs.authorization_receipt_hash,
            Some(receipt.receipt_hash.clone())
        );
        assert_eq!(
            bound_inputs.witness_commitment,
            Some(
                ves_stark_primitives::public_inputs::witness_commitment_u64_to_hex(
                    &receipt.witness_commitment_u64()
                )
            )
        );
    }

    #[test]
    fn test_compliance_proof_bundle_roundtrip_and_submission() {
        let bundle = sample_compliance_bundle(10_000, 5_000);

        let json = bundle.to_json().unwrap();
        let decoded = ComplianceProofBundle::from_json(&json).unwrap();
        let bytes = bundle.to_bytes().unwrap();
        let decoded_from_bytes = ComplianceProofBundle::from_bytes(&bytes).unwrap();

        assert_eq!(
            decoded.public_inputs.amount_binding_hash,
            Some(decoded.amount_binding.binding_hash.clone())
        );
        assert_eq!(
            decoded.public_inputs.witness_commitment,
            decoded.witness_commitment_hex.clone()
        );
        assert_eq!(
            decoded.public_inputs_hash,
            decoded.public_inputs.compute_hash().unwrap().to_hex()
        );
        assert_eq!(
            decoded.bound_public_inputs_hash,
            decoded.public_inputs.compute_bound_hash().unwrap().to_hex()
        );
        assert_eq!(decoded.bundle_hash, decoded.compute_hash_hex().unwrap());
        assert_eq!(decoded.bundle_hash, bundle.bundle_hash);

        let verification = decoded.verify_strict().unwrap();
        assert!(verification.valid);

        let submission = decoded_from_bytes.to_submission().unwrap();
        assert_eq!(
            submission.event_id,
            decoded_from_bytes.public_inputs.event_id
        );
        assert_eq!(submission.policy_id, "aml.threshold");
        assert_eq!(
            submission.public_inputs.unwrap().amount_binding_hash,
            Some(decoded_from_bytes.amount_binding.binding_hash.clone())
        );
    }

    #[test]
    fn test_compliance_proof_bundle_validates_submit_and_verify_responses() {
        let bundle = sample_compliance_bundle(10_000, 5_000);

        let submit_response = SubmitProofResponse {
            proof_id: Uuid::new_v4(),
            event_id: bundle.public_inputs.event_id,
            tenant_id: bundle.public_inputs.tenant_id,
            store_id: bundle.public_inputs.store_id,
            proof_type: bundle.proof_type.clone(),
            proof_version: bundle.proof_version,
            policy_id: bundle.public_inputs.policy_id.clone(),
            policy_params: bundle.public_inputs.policy_params.to_json_value(),
            policy_hash: bundle.public_inputs.policy_hash.clone(),
            proof_hash: bundle.proof_hash.clone(),
            witness_commitment: Some(bundle.witness_commitment),
            witness_commitment_hex: bundle.witness_commitment_hex.clone(),
            public_inputs: Some(serde_json::to_value(&bundle.public_inputs).unwrap()),
            submitted_at: "2026-03-17T00:00:00Z".to_string(),
        };
        bundle.validate_submit_response(&submit_response).unwrap();

        let verify_response = VerifyResponse {
            proof_id: Uuid::new_v4(),
            event_id: bundle.public_inputs.event_id,
            tenant_id: bundle.public_inputs.tenant_id,
            store_id: bundle.public_inputs.store_id,
            proof_type: bundle.proof_type.clone(),
            proof_version: bundle.proof_version,
            policy_id: bundle.public_inputs.policy_id.clone(),
            policy_hash: bundle.public_inputs.policy_hash.clone(),
            proof_hash: bundle.proof_hash.clone(),
            public_inputs_hash: Some(bundle.public_inputs_hash.clone()),
            canonical_public_inputs_hash: bundle.public_inputs_hash.clone(),
            public_inputs_match: true,
            witness_commitment: Some(bundle.witness_commitment),
            witness_commitment_hex: bundle.witness_commitment_hex.clone(),
            stark_valid: Some(true),
            stark_error: None,
            stark_verification_time_ms: Some(1),
            valid: true,
            reason: None,
        };
        bundle.validate_verify_response(&verify_response).unwrap();
    }

    #[test]
    fn test_compliance_proof_bundle_rejects_tampered_amount_binding() {
        let mut bundle = sample_compliance_bundle(10_000, 5_000);
        bundle.amount_binding.amount += 1;
        bundle.amount_binding.binding_hash = bundle.amount_binding.compute_hash_hex().unwrap();

        let err = bundle.validate().unwrap_err();
        assert!(matches!(err, ClientError::InvalidProofBundle(_)));
    }

    #[test]
    fn test_agent_authorization_proof_bundle_roundtrip_and_submission() {
        let bundle = sample_authorization_bundle(25_000);

        let json = bundle.to_json().unwrap();
        let decoded = AgentAuthorizationProofBundle::from_json(&json).unwrap();
        let bytes = bundle.to_bytes().unwrap();
        let decoded_from_bytes = AgentAuthorizationProofBundle::from_bytes(&bytes).unwrap();

        assert_eq!(
            decoded.public_inputs.authorization_receipt_hash,
            Some(decoded.receipt.receipt_hash.clone())
        );
        assert_eq!(
            decoded.public_inputs.amount_binding_hash,
            Some(decoded.amount_binding.binding_hash.clone())
        );
        assert_eq!(
            decoded.public_inputs.witness_commitment,
            decoded.witness_commitment_hex.clone()
        );
        assert_eq!(
            decoded.public_inputs_hash,
            decoded.public_inputs.compute_hash().unwrap().to_hex()
        );
        assert_eq!(
            decoded.bound_public_inputs_hash,
            decoded.public_inputs.compute_bound_hash().unwrap().to_hex()
        );
        assert_eq!(decoded.bundle_hash, decoded.compute_hash_hex().unwrap());
        assert_eq!(decoded.bundle_hash, bundle.bundle_hash);

        let verification = decoded.verify_strict().unwrap();
        assert!(verification.valid);

        let submission = decoded_from_bytes.to_submission().unwrap();
        assert_eq!(submission.event_id, decoded_from_bytes.receipt.event_id);
        assert_eq!(submission.policy_id, "agent.authorization.v1");
        let submission_inputs = submission.public_inputs.unwrap();
        assert_eq!(
            submission_inputs.authorization_receipt_hash,
            Some(decoded_from_bytes.receipt.receipt_hash.clone())
        );
        assert_eq!(
            submission_inputs.amount_binding_hash,
            Some(decoded_from_bytes.amount_binding.binding_hash.clone())
        );
    }

    #[test]
    fn test_agent_authorization_proof_bundle_validates_submit_and_verify_responses() {
        let bundle = sample_authorization_bundle(25_000);

        let submit_response = SubmitProofResponse {
            proof_id: Uuid::new_v4(),
            event_id: bundle.receipt.event_id,
            tenant_id: bundle.receipt.tenant_id,
            store_id: bundle.receipt.store_id,
            proof_type: bundle.proof_type.clone(),
            proof_version: bundle.proof_version,
            policy_id: bundle.public_inputs.policy_id.clone(),
            policy_params: bundle.public_inputs.policy_params.to_json_value(),
            policy_hash: bundle.public_inputs.policy_hash.clone(),
            proof_hash: bundle.proof_hash.clone(),
            witness_commitment: Some(bundle.witness_commitment),
            witness_commitment_hex: bundle.witness_commitment_hex.clone(),
            public_inputs: Some(serde_json::to_value(&bundle.public_inputs).unwrap()),
            submitted_at: "2026-03-16T00:00:00Z".to_string(),
        };
        bundle.validate_submit_response(&submit_response).unwrap();

        let verify_response = VerifyResponse {
            proof_id: Uuid::new_v4(),
            event_id: bundle.receipt.event_id,
            tenant_id: bundle.receipt.tenant_id,
            store_id: bundle.receipt.store_id,
            proof_type: bundle.proof_type.clone(),
            proof_version: bundle.proof_version,
            policy_id: bundle.public_inputs.policy_id.clone(),
            policy_hash: bundle.public_inputs.policy_hash.clone(),
            proof_hash: bundle.proof_hash.clone(),
            public_inputs_hash: Some(bundle.public_inputs_hash.clone()),
            canonical_public_inputs_hash: bundle.public_inputs_hash.clone(),
            public_inputs_match: true,
            witness_commitment: Some(bundle.witness_commitment),
            witness_commitment_hex: bundle.witness_commitment_hex.clone(),
            stark_valid: Some(true),
            stark_error: None,
            stark_verification_time_ms: Some(1),
            valid: true,
            reason: None,
        };
        bundle.validate_verify_response(&verify_response).unwrap();
    }

    #[test]
    fn test_agent_authorization_proof_bundle_validates_proof_details() {
        let bundle = sample_authorization_bundle(25_000);
        let details = ProofDetails {
            proof_id: Uuid::new_v4(),
            event_id: bundle.receipt.event_id,
            tenant_id: bundle.receipt.tenant_id,
            store_id: bundle.receipt.store_id,
            proof_type: bundle.proof_type.clone(),
            proof_version: bundle.proof_version,
            policy_id: bundle.public_inputs.policy_id.clone(),
            policy_params: bundle.public_inputs.policy_params.to_json_value(),
            policy_hash: bundle.public_inputs.policy_hash.clone(),
            proof_hash: bundle.proof_hash.clone(),
            proof_b64: bundle.proof_b64.clone(),
            witness_commitment: Some(bundle.witness_commitment),
            witness_commitment_hex: bundle.witness_commitment_hex.clone(),
            public_inputs: Some(serde_json::to_value(&bundle.public_inputs).unwrap()),
            submitted_at: "2026-03-16T00:00:00Z".to_string(),
        };

        bundle.validate_proof_details(&details).unwrap();
        assert_eq!(
            details.proof_bytes().unwrap(),
            bundle.proof_bytes().unwrap()
        );
        assert_eq!(
            details
                .validate_and_parse_public_inputs()
                .unwrap()
                .unwrap()
                .compute_full_hash()
                .unwrap()
                .to_hex(),
            bundle.public_inputs.compute_full_hash().unwrap().to_hex()
        );
    }

    #[test]
    fn test_agent_authorization_proof_bundle_rejects_tampered_proof_hash() {
        let mut bundle = sample_authorization_bundle(25_000);
        bundle.proof_hash = "0".repeat(64);

        let err = bundle.validate().unwrap_err();
        assert!(matches!(err, ClientError::InvalidProofBundle(_)));
    }

    #[test]
    fn test_agent_authorization_proof_bundle_rejects_tampered_receipt_binding() {
        let mut bundle = sample_authorization_bundle(25_000);
        bundle.public_inputs.authorization_receipt_hash = Some("f".repeat(64));
        bundle.public_inputs_hash = bundle.public_inputs.compute_hash().unwrap().to_hex();
        bundle.bound_public_inputs_hash =
            bundle.public_inputs.compute_bound_hash().unwrap().to_hex();

        let err = bundle.validate().unwrap_err();
        assert!(matches!(err, ClientError::InvalidProofBundle(_)));
    }

    #[test]
    fn test_agent_authorization_proof_bundle_rejects_tampered_amount_binding() {
        let mut bundle = sample_authorization_bundle(25_000);
        bundle.amount_binding.amount += 1;
        bundle.amount_binding.binding_hash = bundle.amount_binding.compute_hash_hex().unwrap();

        let err = bundle.validate().unwrap_err();
        assert!(matches!(err, ClientError::InvalidProofBundle(_)));
    }

    #[test]
    fn test_agent_authorization_proof_bundle_rejects_tampered_bundle_hash() {
        let mut bundle = sample_authorization_bundle(25_000);
        bundle.bundle_hash = "0".repeat(64);

        let err = bundle.validate().unwrap_err();
        assert!(matches!(err, ClientError::InvalidProofBundle(_)));
    }

    #[test]
    fn test_agent_authorization_proof_bundle_rejects_verify_response_mismatch() {
        let bundle = sample_authorization_bundle(25_000);
        let verify_response = VerifyResponse {
            proof_id: Uuid::new_v4(),
            event_id: bundle.receipt.event_id,
            tenant_id: bundle.receipt.tenant_id,
            store_id: bundle.receipt.store_id,
            proof_type: bundle.proof_type.clone(),
            proof_version: bundle.proof_version,
            policy_id: bundle.public_inputs.policy_id.clone(),
            policy_hash: bundle.public_inputs.policy_hash.clone(),
            proof_hash: bundle.proof_hash.clone(),
            public_inputs_hash: Some("0".repeat(64)),
            canonical_public_inputs_hash: bundle.public_inputs_hash.clone(),
            public_inputs_match: true,
            witness_commitment: Some(bundle.witness_commitment),
            witness_commitment_hex: bundle.witness_commitment_hex.clone(),
            stark_valid: Some(true),
            stark_error: None,
            stark_verification_time_ms: Some(1),
            valid: true,
            reason: None,
        };

        let err = bundle
            .validate_verify_response(&verify_response)
            .unwrap_err();
        assert!(matches!(err, ClientError::InvalidProofBundle(_)));
    }
}
