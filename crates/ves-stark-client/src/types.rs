//! Type definitions for the sequencer API

use crate::error::{ClientError, Result};
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

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{
        compute_policy_hash, CompliancePublicInputs, PolicyParams,
    };

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
}
