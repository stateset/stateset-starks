//! Type definitions for the sequencer API.
//!
//! These are transport DTOs: each struct mirrors, field for field, a JSON
//! request or response body of the sequencer REST API, with `serde(rename_all =
//! "camelCase")` supplying the wire names. The authoritative description of each
//! field is the API reference, not this crate.
//!
//! Fields are documented with what the wire contract actually requires —
//! encodings (base64, hex), which hash is reported versus recomputed, and where
//! a `u64` form is unsafe for JavaScript consumers — rather than restating the
//! field name.

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
    /// Policy identifier, e.g. `aml.threshold`.
    pub policy_id: String,
    #[serde(default)]
    /// Policy parameters as canonical JSON; the shape depends on `policy_id`.
    pub policy_params: serde_json::Value,
}

/// Response containing public inputs
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicInputsResponse {
    /// VES event the proof attests to.
    pub event_id: Uuid,
    /// Canonical public inputs, when the sequencer stored them.
    pub public_inputs: serde_json::Value,
    /// Hash the sequencer reports for the returned public inputs.
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
    /// Hex-encoded commitment (64 characters). Preferred on JSON APIs.
    Hex(String),
    /// Four raw field elements. Loses precision through JavaScript JSON parsers.
    U64([u64; 4]),
}

/// Request to submit a compliance proof
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitProofRequest {
    /// Statement kind, e.g. `compliance` or `agent.authorization.v1`.
    pub proof_type: String,
    /// Proof format version; the verifier accepts only `PROOF_VERSION`.
    pub proof_version: u32,
    /// Policy identifier, e.g. `aml.threshold`.
    pub policy_id: String,
    /// Policy parameters as canonical JSON; the shape depends on `policy_id`.
    pub policy_params: serde_json::Value,
    /// Base64-encoded serialized STARK proof.
    pub proof_b64: String,
    /// Rescue commitment to the salted witness, as four field elements.
    pub witness_commitment: WitnessCommitment,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Canonical public inputs, when the sequencer stored them.
    pub public_inputs: Option<serde_json::Value>,
}

/// Response after submitting a proof
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitProofResponse {
    /// Sequencer-assigned identifier for this stored proof.
    pub proof_id: Uuid,
    /// VES event the proof attests to.
    pub event_id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Owning store.
    pub store_id: Uuid,
    /// Statement kind, e.g. `compliance` or `agent.authorization.v1`.
    pub proof_type: String,
    /// Proof format version; the verifier accepts only `PROOF_VERSION`.
    pub proof_version: u32,
    /// Policy identifier, e.g. `aml.threshold`.
    pub policy_id: String,
    /// Policy parameters as canonical JSON; the shape depends on `policy_id`.
    pub policy_params: serde_json::Value,
    /// Hex digest binding `policy_id` to `policy_params`.
    pub policy_hash: String,
    /// Hex digest of the serialized proof bytes.
    pub proof_hash: String,
    /// Rescue commitment to the salted witness, as four field elements.
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    /// The same commitment, hex-encoded. Prefer this form on JSON APIs:
    /// JavaScript numbers cannot represent a `u64` exactly.
    pub witness_commitment_hex: Option<String>,
    /// Canonical public inputs, when the sequencer stored them.
    pub public_inputs: Option<serde_json::Value>,
    /// RFC 3339 timestamp of submission.
    pub submitted_at: String,
}

/// Proof summary (when listing proofs)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofSummary {
    /// Sequencer-assigned identifier for this stored proof.
    pub proof_id: Uuid,
    /// VES event the proof attests to.
    pub event_id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Owning store.
    pub store_id: Uuid,
    /// Statement kind, e.g. `compliance` or `agent.authorization.v1`.
    pub proof_type: String,
    /// Proof format version; the verifier accepts only `PROOF_VERSION`.
    pub proof_version: u32,
    /// Policy identifier, e.g. `aml.threshold`.
    pub policy_id: String,
    /// Policy parameters as canonical JSON; the shape depends on `policy_id`.
    pub policy_params: serde_json::Value,
    /// Hex digest binding `policy_id` to `policy_params`.
    pub policy_hash: String,
    /// Hex digest of the serialized proof bytes.
    pub proof_hash: String,
    /// Rescue commitment to the salted witness, as four field elements.
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    /// The same commitment, hex-encoded. Prefer this form on JSON APIs:
    /// JavaScript numbers cannot represent a `u64` exactly.
    pub witness_commitment_hex: Option<String>,
    /// Canonical public inputs, when the sequencer stored them.
    pub public_inputs: Option<serde_json::Value>,
    /// RFC 3339 timestamp of submission.
    pub submitted_at: String,
}

/// Response when listing proofs for an event
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListProofsResponse {
    /// VES event the proof attests to.
    pub event_id: Uuid,
    /// Proofs recorded for the event.
    pub proofs: Vec<ProofSummary>,
    /// Number of entries in `proofs`.
    pub count: usize,
}

/// Full proof details including the proof bytes
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofDetails {
    /// Sequencer-assigned identifier for this stored proof.
    pub proof_id: Uuid,
    /// VES event the proof attests to.
    pub event_id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Owning store.
    pub store_id: Uuid,
    /// Statement kind, e.g. `compliance` or `agent.authorization.v1`.
    pub proof_type: String,
    /// Proof format version; the verifier accepts only `PROOF_VERSION`.
    pub proof_version: u32,
    /// Policy identifier, e.g. `aml.threshold`.
    pub policy_id: String,
    /// Policy parameters as canonical JSON; the shape depends on `policy_id`.
    pub policy_params: serde_json::Value,
    /// Hex digest binding `policy_id` to `policy_params`.
    pub policy_hash: String,
    /// Hex digest of the serialized proof bytes.
    pub proof_hash: String,
    /// Base64-encoded serialized STARK proof.
    pub proof_b64: String,
    /// Rescue commitment to the salted witness, as four field elements.
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    /// The same commitment, hex-encoded. Prefer this form on JSON APIs:
    /// JavaScript numbers cannot represent a `u64` exactly.
    pub witness_commitment_hex: Option<String>,
    /// Canonical public inputs, when the sequencer stored them.
    pub public_inputs: Option<serde_json::Value>,
    /// RFC 3339 timestamp of submission.
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
    /// Sequencer-assigned identifier for this stored proof.
    pub proof_id: Uuid,
    /// VES event the proof attests to.
    pub event_id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Owning store.
    pub store_id: Uuid,
    /// Statement kind, e.g. `compliance` or `agent.authorization.v1`.
    pub proof_type: String,
    /// Proof format version; the verifier accepts only `PROOF_VERSION`.
    pub proof_version: u32,
    /// Policy identifier, e.g. `aml.threshold`.
    pub policy_id: String,
    /// Hex digest binding `policy_id` to `policy_params`.
    pub policy_hash: String,
    /// Hex digest of the serialized proof bytes.
    pub proof_hash: String,
    /// Hash the sequencer reports for the returned public inputs.
    pub public_inputs_hash: Option<String>,
    /// Hash the verifier recomputed from the canonical inputs.
    pub canonical_public_inputs_hash: String,
    /// Whether the reported and recomputed public-input hashes agree.
    pub public_inputs_match: bool,
    #[serde(default)]
    /// Rescue commitment to the salted witness, as four field elements.
    pub witness_commitment: Option<[u64; 4]>,
    #[serde(default)]
    /// The same commitment, hex-encoded. Prefer this form on JSON APIs:
    /// JavaScript numbers cannot represent a `u64` exactly.
    pub witness_commitment_hex: Option<String>,
    #[serde(default)]
    /// Whether the STARK itself verified, when verification ran.
    pub stark_valid: Option<bool>,
    #[serde(default)]
    /// Verifier error message, when verification failed.
    pub stark_error: Option<String>,
    #[serde(default)]
    /// Wall-clock verification time, in milliseconds.
    pub stark_verification_time_ms: Option<u64>,
    /// Overall verdict: the STARK verified and every binding check passed.
    pub valid: bool,
    /// Why `valid` is false.
    pub reason: Option<String>,
}

/// Parameters for AML threshold policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlThresholdParams {
    /// Exclusive upper bound the amount must stay under.
    pub threshold: u64,
}

impl AmlThresholdParams {
    /// Build AML-threshold parameters for the given exclusive bound.
    pub fn new(threshold: u64) -> Self {
        Self { threshold }
    }

    /// Serialize to the canonical JSON shape the sequencer expects for `policyParams`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "threshold": self.threshold })
    }
}

/// Parameters for order total cap policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderTotalCapParams {
    /// Inclusive upper bound on the order total.
    pub cap: u64,
}

impl OrderTotalCapParams {
    /// Build order-total-cap parameters for the given inclusive bound.
    pub fn new(cap: u64) -> Self {
        Self { cap }
    }

    /// Serialize to the canonical JSON shape the sequencer expects for `policyParams`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "cap": self.cap })
    }
}

/// Parameters for agent.authorization.v1 policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuthorizationParams {
    /// Inclusive spend cap authorized by the intent.
    pub max_total: u64,
    /// Hex hash of the `CommerceIntent` this authorization binds to.
    pub intent_hash: String,
}

impl AgentAuthorizationParams {
    /// Build agent-authorization parameters, validating `intent_hash` as 64 hex characters.
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

    /// Build agent-authorization parameters from a signed authorization receipt.
    pub fn from_receipt(max_total: u64, receipt: &CommerceAuthorizationReceipt) -> Result<Self> {
        Self::new(max_total, &receipt.intent_hash)
    }

    /// Serialize to the canonical JSON shape the sequencer expects for `policyParams`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "maxTotal": self.max_total,
            "intentHash": self.intent_hash,
        })
    }
}

// Split by concern; each file is one slice of the sequencer wire contract.
// Everything public is re-exported here so `ves_stark_client::types::*` is
// unchanged for callers.
mod bundles;
mod submission;
mod validation;

pub use bundles::*;
pub use submission::*;
pub(crate) use validation::*;

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
            rest_hash: None,
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
            rest_hash: None,
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
