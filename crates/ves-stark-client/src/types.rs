//! Type definitions for the sequencer API

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
pub struct PublicInputsResponse {
    pub event_id: Uuid,
    pub public_inputs: serde_json::Value,
    pub public_inputs_hash: String,
}

/// Structured public inputs from the sequencer
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePublicInputs {
    pub event_id: Uuid,
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub sequence_number: u64,
    pub payload_kind: u32,
    pub payload_plain_hash: String,
    pub payload_cipher_hash: String,
    pub event_signing_hash: String,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub policy_hash: String,
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
    pub witness_commitment: [u64; 4],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_inputs: Option<serde_json::Value>,
}

/// Response after submitting a proof
#[derive(Debug, Clone, Deserialize)]
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
    pub witness_commitment: [u64; 4],
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: String,
}

/// Proof summary (when listing proofs)
#[derive(Debug, Clone, Deserialize)]
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
    pub witness_commitment: [u64; 4],
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: String,
}

/// Response when listing proofs for an event
#[derive(Debug, Clone, Deserialize)]
pub struct ListProofsResponse {
    pub event_id: Uuid,
    pub proofs: Vec<ProofSummary>,
    pub count: usize,
}

/// Full proof details including the proof bytes
#[derive(Debug, Clone, Deserialize)]
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
    pub witness_commitment: [u64; 4],
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: String,
}

/// Verification result
#[derive(Debug, Clone, Deserialize)]
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

/// Proof submission helper
#[derive(Debug, Clone)]
pub struct ProofSubmission {
    pub event_id: Uuid,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub proof_bytes: Vec<u8>,
    pub witness_commitment: [u64; 4],
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
        }
    }
}
