//! Canonical Public Inputs for VES Compliance Proofs
//!
//! These structures define the public inputs for Phase 1 per-event compliance proofs.
//! They MUST match the canonical format used by the sequencer (RFC 8785 JCS canonicalization).

use crate::commerce_intent::CommerceAuthorizationReceipt;
use crate::field::{felt_from_u64, Felt, FeltArray8};
use crate::hash::{hash_to_felts, u64_to_felt_pair, Hash256};
use crate::rescue::rescue_hash;
use crate::FELT_ZERO;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Domain separator for policy hash computation
pub const DOMAIN_POLICY_HASH: &[u8] = b"STATESET_VES_COMPLIANCE_POLICY_HASH_V1";
/// Domain separator for payload amount-binding hashes.
pub const DOMAIN_PAYLOAD_AMOUNT_BINDING_HASH: &[u8] =
    b"STATESET_VES_PAYLOAD_AMOUNT_BINDING_HASH_V1";

/// Errors that can occur when handling public inputs
#[derive(Debug, Error)]
pub enum PublicInputsError {
    /// Invalid hex string in a public input field
    #[error("Invalid hex in {field}: {source}")]
    InvalidHex {
        field: &'static str,
        source: hex::FromHexError,
    },
    /// Invalid hex format (length or casing)
    #[error("Invalid hex format in {field}: {reason}")]
    InvalidHexFormat { field: &'static str, reason: String },
    /// JSON serialization failed
    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// JCS canonicalization failed
    #[error("JCS canonicalization failed: {0}")]
    Canonicalization(String),
    /// Authorization receipt binding failed
    #[error("Invalid authorization receipt binding: {0}")]
    AuthorizationReceiptBinding(String),
    /// Payload amount binding failed
    #[error("Invalid payload amount binding: {0}")]
    AmountBinding(String),
    /// Witness commitment binding failed
    #[error("Invalid witness commitment binding: {0}")]
    WitnessCommitmentBinding(String),
}

/// Policy parameters (JSON object)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(transparent)]
pub struct PolicyParams(pub serde_json::Value);

impl PolicyParams {
    /// Create empty policy params
    pub fn empty() -> Self {
        Self(serde_json::json!({}))
    }

    /// Create from a threshold value (for aml.threshold policy)
    pub fn threshold(value: u64) -> Self {
        Self(serde_json::json!({ "threshold": value }))
    }

    /// Create from a cap value (for order_total.cap policy)
    pub fn cap(value: u64) -> Self {
        Self(serde_json::json!({ "cap": value }))
    }

    /// Create from a budget limit (for agent.budget.v1 policy)
    pub fn budget(budget_limit: u64) -> Self {
        Self(serde_json::json!({ "budgetLimit": budget_limit }))
    }

    /// Create from agent authorization parameters.
    ///
    /// The `intent_hash` is normalized to lowercase hex without a `0x` prefix.
    pub fn agent_authorization(
        max_total: u64,
        intent_hash: &str,
    ) -> Result<Self, PublicInputsError> {
        let intent_hash = normalize_hex_input("intentHash", intent_hash, 64)?;
        Ok(Self(serde_json::json!({
            "intentHash": intent_hash,
            "maxTotal": max_total
        })))
    }

    /// Get the threshold value if this is an aml.threshold policy
    pub fn get_threshold(&self) -> Option<u64> {
        self.0.get("threshold")?.as_u64()
    }

    /// Get the cap value if this is an order_total.cap policy
    pub fn get_cap(&self) -> Option<u64> {
        self.0.get("cap")?.as_u64()
    }

    /// Get the maximum authorized total if this is an agent.authorization.v1 policy.
    pub fn get_max_total(&self) -> Option<u64> {
        self.0.get("maxTotal")?.as_u64()
    }

    /// Get the budget limit if this is an agent.budget.v1 policy.
    pub fn get_budget_limit(&self) -> Option<u64> {
        self.0.get("budgetLimit")?.as_u64()
    }

    /// Get the delegated commerce intent hash if this is an agent.authorization.v1 policy.
    pub fn get_intent_hash(&self) -> Option<&str> {
        self.0.get("intentHash")?.as_str()
    }

    /// Get the inner JSON value.
    pub fn to_json_value(&self) -> serde_json::Value {
        self.0.clone()
    }
}

/// Canonical payload-derived amount binding.
///
/// This artifact is intended to be derived by the surrounding sequencer or parser layer after it
/// has extracted an amount from the canonical event payload referenced by the public inputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAmountBinding {
    /// UUID of the event being proven.
    pub event_id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Store ID.
    pub store_id: Uuid,
    /// Sequence number of the event.
    pub sequence_number: u64,
    /// Payload kind (event type discriminator).
    pub payload_kind: u32,
    /// SHA-256 hash of plaintext payload (hex64, lowercase).
    pub payload_plain_hash: String,
    /// SHA-256 hash of ciphertext payload (hex64, lowercase).
    pub payload_cipher_hash: String,
    /// Event signing hash (hex64, lowercase).
    pub event_signing_hash: String,
    /// Amount extracted from the payload by the surrounding protocol.
    pub amount: u64,
    /// Domain-separated canonical hash of the binding payload.
    pub binding_hash: String,
}

impl PayloadAmountBinding {
    /// Construct a canonical binding from event public inputs and a private amount.
    pub fn from_public_inputs(
        inputs: &CompliancePublicInputs,
        amount: u64,
    ) -> Result<Self, PublicInputsError> {
        let mut binding = Self {
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
        binding.binding_hash = binding.compute_hash_hex()?;
        Ok(binding)
    }

    fn normalized_payload_value(&self) -> Result<serde_json::Value, PublicInputsError> {
        Ok(serde_json::json!({
            "amount": self.amount,
            "eventId": self.event_id,
            "eventSigningHash": normalize_hex_input(
                "eventSigningHash",
                &self.event_signing_hash,
                64,
            )?,
            "payloadCipherHash": normalize_hex_input(
                "payloadCipherHash",
                &self.payload_cipher_hash,
                64,
            )?,
            "payloadKind": self.payload_kind,
            "payloadPlainHash": normalize_hex_input(
                "payloadPlainHash",
                &self.payload_plain_hash,
                64,
            )?,
            "sequenceNumber": self.sequence_number,
            "storeId": self.store_id,
            "tenantId": self.tenant_id,
        }))
    }

    /// Return a normalized form suitable for stable transport and equality checks.
    pub fn normalized(&self) -> Result<Self, PublicInputsError> {
        Ok(Self {
            event_id: self.event_id,
            tenant_id: self.tenant_id,
            store_id: self.store_id,
            sequence_number: self.sequence_number,
            payload_kind: self.payload_kind,
            payload_plain_hash: normalize_hex_input(
                "payloadPlainHash",
                &self.payload_plain_hash,
                64,
            )?,
            payload_cipher_hash: normalize_hex_input(
                "payloadCipherHash",
                &self.payload_cipher_hash,
                64,
            )?,
            event_signing_hash: normalize_hex_input(
                "eventSigningHash",
                &self.event_signing_hash,
                64,
            )?,
            amount: self.amount,
            binding_hash: normalize_hex_input("bindingHash", &self.binding_hash, 64)?,
        })
    }

    /// Canonical JSON representation of the binding payload used for hashing.
    pub fn canonical_json(&self) -> Result<String, PublicInputsError> {
        canonical_json(&self.normalized_payload_value()?)
    }

    /// Recompute the domain-separated binding hash.
    pub fn compute_hash(&self) -> Result<Hash256, PublicInputsError> {
        let canonical = self.canonical_json()?;
        Ok(Hash256::sha256_with_domain(
            DOMAIN_PAYLOAD_AMOUNT_BINDING_HASH,
            canonical.as_bytes(),
        ))
    }

    /// Recompute the domain-separated binding hash as lowercase hex.
    pub fn compute_hash_hex(&self) -> Result<String, PublicInputsError> {
        Ok(self.compute_hash()?.to_hex())
    }

    /// Validate that `binding_hash` matches the canonical payload.
    pub fn validate_hash(&self) -> Result<bool, PublicInputsError> {
        Ok(self.compute_hash_hex()? == normalize_hex_input("bindingHash", &self.binding_hash, 64)?)
    }

    /// Validate the binding payload and embedded hash.
    pub fn validate(&self) -> Result<(), PublicInputsError> {
        let normalized = self.normalized()?;
        if !normalized.validate_hash()? {
            return Err(PublicInputsError::AmountBinding(
                "bindingHash does not match canonical payload amount binding".to_string(),
            ));
        }
        Ok(())
    }

    /// Compute the Rescue witness commitment for the bound amount.
    pub fn witness_commitment_u64(&self) -> [u64; 4] {
        let mut amount_limbs = [FELT_ZERO; 8];
        amount_limbs[0] = felt_from_u64(self.amount & 0xFFFF_FFFF);
        amount_limbs[1] = felt_from_u64(self.amount >> 32);

        let hash_output = rescue_hash(&amount_limbs);
        [
            hash_output[0].as_int(),
            hash_output[1].as_int(),
            hash_output[2].as_int(),
            hash_output[3].as_int(),
        ]
    }
}

/// Canonical Public Inputs for VES Compliance Proofs
///
/// This structure matches the sequencer's canonical public inputs format.
/// Field names use camelCase for JSON compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompliancePublicInputs {
    /// UUID of the event being proven
    pub event_id: Uuid,

    /// Tenant ID
    pub tenant_id: Uuid,

    /// Store ID
    pub store_id: Uuid,

    /// Sequence number of the event
    pub sequence_number: u64,

    /// Payload kind (event type discriminator)
    pub payload_kind: u32,

    /// SHA-256 hash of plaintext payload (hex32, lowercase, no 0x)
    pub payload_plain_hash: String,

    /// SHA-256 hash of ciphertext payload (hex32, lowercase, no 0x)
    pub payload_cipher_hash: String,

    /// Event signing hash (hex32, lowercase, no 0x)
    pub event_signing_hash: String,

    /// Policy identifier (e.g., "aml.threshold")
    pub policy_id: String,

    /// Policy parameters (e.g., {"threshold": 10000})
    pub policy_params: PolicyParams,

    /// Policy hash (hex32, lowercase, no 0x)
    pub policy_hash: String,

    /// Witness commitment to the private witness amount, encoded as 32 bytes hex (lowercase, no 0x).
    ///
    /// When present, verifiers SHOULD require the proof's witness commitment matches this value
    /// to bind the proven witness to the canonical public inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_commitment: Option<String>,

    /// Optional authorization receipt hash (hex32, lowercase, no 0x).
    ///
    /// When present, canonical public-input hashes commit to a specific delegated execution
    /// receipt for `agent.authorization.v1` flows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_receipt_hash: Option<String>,

    /// Optional payload-derived amount binding hash (hex32, lowercase, no 0x).
    ///
    /// When present, canonical public-input hashes commit to a specific payload-to-amount
    /// binding artifact derived by the surrounding protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_binding_hash: Option<String>,
}

impl CompliancePublicInputs {
    /// Compute the policy hash for a given policy ID and params
    pub fn compute_policy_hash(
        policy_id: &str,
        policy_params: &PolicyParams,
    ) -> Result<Hash256, PublicInputsError> {
        compute_policy_hash(policy_id, policy_params)
    }

    /// Compute the sequencer-canonical hash of these public inputs.
    ///
    /// The canonical sequencer hash excludes `witnessCommitment`, which is submitted
    /// out-of-band alongside the proof. When present, `authorizationReceiptHash`
    /// remains part of the canonical hash.
    pub fn compute_hash(&self) -> Result<Hash256, PublicInputsError> {
        compute_public_inputs_hash(self)
    }

    /// Compute the hash of the full local public-input object, including
    /// `witnessCommitment` when present.
    pub fn compute_full_hash(&self) -> Result<Hash256, PublicInputsError> {
        compute_full_public_inputs_hash(self)
    }

    /// Compute the hash of a witness-bound public-input object.
    ///
    /// Unlike `compute_hash()`, this requires `witnessCommitment` to be present and
    /// includes it in the hashed object.
    pub fn compute_bound_hash(&self) -> Result<Hash256, PublicInputsError> {
        compute_bound_public_inputs_hash(self)
    }

    /// Convert to field elements for use in the AIR
    pub fn to_field_elements(&self) -> Result<CompliancePublicInputsFelts, PublicInputsError> {
        CompliancePublicInputsFelts::from_public_inputs(self)
    }

    /// Validate that the policy_hash field matches the computed hash
    pub fn validate_policy_hash(&self) -> Result<bool, PublicInputsError> {
        let computed = Self::compute_policy_hash(&self.policy_id, &self.policy_params)?;
        Ok(computed.to_hex() == self.policy_hash)
    }

    /// Parse the optional `witnessCommitment` field into the u64 array form used by the prover/verifier.
    ///
    /// Encoding: 32 bytes represented as 64 lowercase hex characters, interpreted as 4 big-endian u64s.
    pub fn witness_commitment_u64(&self) -> Result<Option<[u64; 4]>, PublicInputsError> {
        let Some(hex_str) = self.witness_commitment.as_deref() else {
            return Ok(None);
        };
        Ok(Some(witness_commitment_hex_to_u64(hex_str)?))
    }

    /// Validate that this public-input object is consistent with an authorization receipt.
    pub fn validate_authorization_receipt(
        &self,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<(), PublicInputsError> {
        let receipt = receipt
            .normalized()
            .map_err(|e| PublicInputsError::AuthorizationReceiptBinding(e.to_string()))?;
        receipt
            .validate()
            .map_err(|e| PublicInputsError::AuthorizationReceiptBinding(e.to_string()))?;

        if self.policy_id != "agent.authorization.v1" {
            return Err(PublicInputsError::AuthorizationReceiptBinding(
                "authorization receipts require agent.authorization.v1 policy".to_string(),
            ));
        }

        let max_total = self.policy_params.get_max_total().ok_or_else(|| {
            PublicInputsError::AuthorizationReceiptBinding(
                "missing maxTotal in agent authorization policy params".to_string(),
            )
        })?;
        let intent_hash = self.policy_params.get_intent_hash().ok_or_else(|| {
            PublicInputsError::AuthorizationReceiptBinding(
                "missing intentHash in agent authorization policy params".to_string(),
            )
        })?;
        if receipt.intent_hash != intent_hash {
            return Err(PublicInputsError::AuthorizationReceiptBinding(
                "authorization receipt intent hash does not match policy params".to_string(),
            ));
        }
        if receipt.amount > max_total {
            return Err(PublicInputsError::AuthorizationReceiptBinding(format!(
                "authorization receipt amount {} exceeds policy maxTotal {}",
                receipt.amount, max_total
            )));
        }
        if receipt.event_id != self.event_id {
            return Err(PublicInputsError::AuthorizationReceiptBinding(
                "authorization receipt event_id does not match public inputs".to_string(),
            ));
        }
        if receipt.tenant_id != self.tenant_id {
            return Err(PublicInputsError::AuthorizationReceiptBinding(
                "authorization receipt tenant_id does not match public inputs".to_string(),
            ));
        }
        if receipt.store_id != self.store_id {
            return Err(PublicInputsError::AuthorizationReceiptBinding(
                "authorization receipt store_id does not match public inputs".to_string(),
            ));
        }
        if receipt.sequence_number != self.sequence_number {
            return Err(PublicInputsError::AuthorizationReceiptBinding(
                "authorization receipt sequence_number does not match public inputs".to_string(),
            ));
        }
        if let Some(expected_commitment) = self.witness_commitment_u64()? {
            let receipt_commitment = receipt.witness_commitment_u64();
            if expected_commitment != receipt_commitment {
                return Err(PublicInputsError::AuthorizationReceiptBinding(
                    "authorization receipt amount does not match witnessCommitment".to_string(),
                ));
            }
        }
        if let Some(expected_receipt_hash) = self.authorization_receipt_hash.as_deref() {
            validate_hex_string("authorizationReceiptHash", expected_receipt_hash, 64)?;
            if expected_receipt_hash != receipt.receipt_hash {
                return Err(PublicInputsError::AuthorizationReceiptBinding(
                    "authorizationReceiptHash does not match authorization receipt".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate that this public-input object is consistent with a payload amount binding.
    pub fn validate_payload_amount_binding(
        &self,
        binding: &PayloadAmountBinding,
    ) -> Result<(), PublicInputsError> {
        let normalized = binding.normalized()?;
        normalized.validate()?;

        validate_hex_string("payloadPlainHash", &self.payload_plain_hash, 64)?;
        validate_hex_string("payloadCipherHash", &self.payload_cipher_hash, 64)?;
        validate_hex_string("eventSigningHash", &self.event_signing_hash, 64)?;

        if normalized.event_id != self.event_id {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding event_id does not match public inputs".to_string(),
            ));
        }
        if normalized.tenant_id != self.tenant_id {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding tenant_id does not match public inputs".to_string(),
            ));
        }
        if normalized.store_id != self.store_id {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding store_id does not match public inputs".to_string(),
            ));
        }
        if normalized.sequence_number != self.sequence_number {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding sequence_number does not match public inputs".to_string(),
            ));
        }
        if normalized.payload_kind != self.payload_kind {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding payload_kind does not match public inputs".to_string(),
            ));
        }
        if normalized.payload_plain_hash != self.payload_plain_hash {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding payload_plain_hash does not match public inputs"
                    .to_string(),
            ));
        }
        if normalized.payload_cipher_hash != self.payload_cipher_hash {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding payload_cipher_hash does not match public inputs"
                    .to_string(),
            ));
        }
        if normalized.event_signing_hash != self.event_signing_hash {
            return Err(PublicInputsError::AmountBinding(
                "payload amount binding event_signing_hash does not match public inputs"
                    .to_string(),
            ));
        }

        if let Some(expected_commitment) = self.witness_commitment_u64()? {
            let binding_commitment = normalized.witness_commitment_u64();
            if expected_commitment != binding_commitment {
                return Err(PublicInputsError::AmountBinding(
                    "payload amount binding amount does not match witnessCommitment".to_string(),
                ));
            }
        }
        if let Some(expected_hash) = self.amount_binding_hash.as_deref() {
            validate_hex_string("amountBindingHash", expected_hash, 64)?;
            if expected_hash != normalized.binding_hash {
                return Err(PublicInputsError::AmountBinding(
                    "amountBindingHash does not match payload amount binding".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Construct the canonical payload amount binding for these public inputs and a private amount.
    pub fn payload_amount_binding(
        &self,
        amount: u64,
    ) -> Result<PayloadAmountBinding, PublicInputsError> {
        PayloadAmountBinding::from_public_inputs(self, amount)
    }

    /// Validate that this public-input object is consistent with both a payload amount binding
    /// and an authorization receipt, and that the two artifacts agree on the witness commitment.
    pub fn validate_payload_amount_binding_and_authorization_receipt(
        &self,
        binding: &PayloadAmountBinding,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<(), PublicInputsError> {
        let normalized_binding = binding.normalized()?;
        let normalized_receipt = receipt
            .normalized()
            .map_err(|e| PublicInputsError::AuthorizationReceiptBinding(e.to_string()))?;

        self.validate_payload_amount_binding(&normalized_binding)?;
        self.validate_authorization_receipt(&normalized_receipt)?;

        if normalized_binding.witness_commitment_u64()
            != normalized_receipt.witness_commitment_u64()
        {
            return Err(PublicInputsError::WitnessCommitmentBinding(
                "payload amount binding does not match authorization receipt amount".to_string(),
            ));
        }

        Ok(())
    }

    /// Return a copy of these public inputs bound to a witness commitment.
    pub fn bind_witness_commitment(
        &self,
        witness_commitment: &[u64; 4],
    ) -> Result<Self, PublicInputsError> {
        let witness_commitment_hex = witness_commitment_u64_to_hex(witness_commitment);
        if let Some(expected) = self.witness_commitment.as_deref() {
            if expected != witness_commitment_hex {
                return Err(PublicInputsError::WitnessCommitmentBinding(
                    "witnessCommitment does not match the requested witness commitment".to_string(),
                ));
            }
        }

        let mut bound = self.clone();
        bound.witness_commitment = Some(witness_commitment_hex);
        Ok(bound)
    }

    /// Return a copy of these public inputs bound to a canonical payload amount binding.
    pub fn bind_payload_amount_binding(
        &self,
        binding: &PayloadAmountBinding,
    ) -> Result<Self, PublicInputsError> {
        self.validate_payload_amount_binding(binding)?;

        let normalized = binding.normalized()?;
        let mut bound = self.clone();
        bound.witness_commitment = Some(witness_commitment_u64_to_hex(
            &normalized.witness_commitment_u64(),
        ));
        bound.amount_binding_hash = Some(normalized.binding_hash);
        Ok(bound)
    }

    /// Return a copy of these public inputs canonically bound to a private amount.
    pub fn bind_amount(&self, amount: u64) -> Result<Self, PublicInputsError> {
        let binding = self.payload_amount_binding(amount)?;
        self.bind_payload_amount_binding(&binding)
    }

    /// Return a copy of these public inputs bound to both a canonical payload amount binding and
    /// a canonical authorization receipt.
    pub fn bind_payload_amount_binding_and_authorization_receipt(
        &self,
        binding: &PayloadAmountBinding,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self, PublicInputsError> {
        self.validate_payload_amount_binding_and_authorization_receipt(binding, receipt)?;

        let normalized_binding = binding.normalized()?;
        let normalized_receipt = receipt
            .normalized()
            .map_err(|e| PublicInputsError::AuthorizationReceiptBinding(e.to_string()))?;

        let mut bound = self.clone();
        bound.witness_commitment = Some(witness_commitment_u64_to_hex(
            &normalized_binding.witness_commitment_u64(),
        ));
        bound.amount_binding_hash = Some(normalized_binding.binding_hash);
        bound.authorization_receipt_hash = Some(normalized_receipt.receipt_hash);
        Ok(bound)
    }

    /// Return a copy of these public inputs bound to the canonical payload amount binding derived
    /// from an authorization receipt and to the canonical authorization receipt hash.
    pub fn bind_amount_and_authorization_receipt(
        &self,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self, PublicInputsError> {
        let normalized_receipt = receipt
            .normalized()
            .map_err(|e| PublicInputsError::AuthorizationReceiptBinding(e.to_string()))?;
        let binding = self.payload_amount_binding(normalized_receipt.amount)?;
        self.bind_payload_amount_binding_and_authorization_receipt(&binding, &normalized_receipt)
    }

    /// Return a copy of these public inputs bound to a canonical authorization receipt.
    pub fn bind_authorization_receipt(
        &self,
        receipt: &CommerceAuthorizationReceipt,
    ) -> Result<Self, PublicInputsError> {
        self.validate_authorization_receipt(receipt)?;

        let mut bound = self.clone();
        bound.witness_commitment = Some(witness_commitment_u64_to_hex(
            &receipt.witness_commitment_u64(),
        ));
        bound.authorization_receipt_hash = Some(receipt.receipt_hash.clone());
        Ok(bound)
    }
}

/// Public inputs represented as field elements (for AIR constraints)
#[derive(Debug, Clone)]
pub struct CompliancePublicInputsFelts {
    /// Event ID as field elements (UUID bytes -> 4 felts)
    pub event_id: [Felt; 4],

    /// Tenant ID as field elements
    pub tenant_id: [Felt; 4],

    /// Store ID as field elements
    pub store_id: [Felt; 4],

    /// Sequence number (low, high u32)
    pub sequence_number: (Felt, Felt),

    /// Payload kind
    pub payload_kind: Felt,

    /// Payload plain hash as 8 field elements
    pub payload_plain_hash: FeltArray8,

    /// Payload cipher hash as 8 field elements
    pub payload_cipher_hash: FeltArray8,

    /// Event signing hash as 8 field elements
    pub event_signing_hash: FeltArray8,

    /// Policy hash as 8 field elements
    pub policy_hash: FeltArray8,
}

impl CompliancePublicInputsFelts {
    /// Convert from CompliancePublicInputs
    pub fn from_public_inputs(inputs: &CompliancePublicInputs) -> Result<Self, PublicInputsError> {
        validate_hex_string("payloadPlainHash", &inputs.payload_plain_hash, 64)?;
        validate_hex_string("payloadCipherHash", &inputs.payload_cipher_hash, 64)?;
        validate_hex_string("eventSigningHash", &inputs.event_signing_hash, 64)?;
        validate_hex_string("policyHash", &inputs.policy_hash, 64)?;
        if let Some(commitment) = inputs.witness_commitment.as_deref() {
            validate_hex_string("witnessCommitment", commitment, 64)?;
        }
        if let Some(receipt_hash) = inputs.authorization_receipt_hash.as_deref() {
            validate_hex_string("authorizationReceiptHash", receipt_hash, 64)?;
        }
        if let Some(amount_binding_hash) = inputs.amount_binding_hash.as_deref() {
            validate_hex_string("amountBindingHash", amount_binding_hash, 64)?;
        }

        Ok(Self {
            event_id: uuid_to_felts(&inputs.event_id),
            tenant_id: uuid_to_felts(&inputs.tenant_id),
            store_id: uuid_to_felts(&inputs.store_id),
            sequence_number: u64_to_felt_pair(inputs.sequence_number),
            payload_kind: felt_from_u64(inputs.payload_kind as u64),
            payload_plain_hash: hash_to_felts(
                &Hash256::from_hex(&inputs.payload_plain_hash).map_err(|e| {
                    PublicInputsError::InvalidHex {
                        field: "payloadPlainHash",
                        source: e,
                    }
                })?,
            ),
            payload_cipher_hash: hash_to_felts(
                &Hash256::from_hex(&inputs.payload_cipher_hash).map_err(|e| {
                    PublicInputsError::InvalidHex {
                        field: "payloadCipherHash",
                        source: e,
                    }
                })?,
            ),
            event_signing_hash: hash_to_felts(
                &Hash256::from_hex(&inputs.event_signing_hash).map_err(|e| {
                    PublicInputsError::InvalidHex {
                        field: "eventSigningHash",
                        source: e,
                    }
                })?,
            ),
            policy_hash: hash_to_felts(&Hash256::from_hex(&inputs.policy_hash).map_err(|e| {
                PublicInputsError::InvalidHex {
                    field: "policyHash",
                    source: e,
                }
            })?),
        })
    }

    /// Flatten all public inputs into a vector for proof verification
    pub fn to_vec(&self) -> Vec<Felt> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.event_id);
        result.extend_from_slice(&self.tenant_id);
        result.extend_from_slice(&self.store_id);
        result.push(self.sequence_number.0);
        result.push(self.sequence_number.1);
        result.push(self.payload_kind);
        result.extend_from_slice(&self.payload_plain_hash);
        result.extend_from_slice(&self.payload_cipher_hash);
        result.extend_from_slice(&self.event_signing_hash);
        result.extend_from_slice(&self.policy_hash);
        result
    }
}

/// Encode a witness commitment (4 u64s) as a 32-byte big-endian hex string.
pub fn witness_commitment_u64_to_hex(commitment: &[u64; 4]) -> String {
    let mut bytes = [0u8; 32];
    for (i, v) in commitment.iter().enumerate() {
        let offset = i * 8;
        bytes[offset..offset + 8].copy_from_slice(&v.to_be_bytes());
    }
    hex::encode(bytes)
}

/// Decode a witness commitment from a 32-byte big-endian hex string into 4 u64 limbs.
pub fn witness_commitment_hex_to_u64(hex_str: &str) -> Result<[u64; 4], PublicInputsError> {
    validate_hex_string("witnessCommitment", hex_str, 64)?;

    let bytes = hex::decode(hex_str).map_err(|e| PublicInputsError::InvalidHex {
        field: "witnessCommitment",
        source: e,
    })?;

    if bytes.len() != 32 {
        return Err(PublicInputsError::InvalidHexFormat {
            field: "witnessCommitment",
            reason: format!("expected 32 bytes, got {}", bytes.len()),
        });
    }

    let mut out = [0u64; 4];
    for (i, v) in out.iter_mut().enumerate() {
        let offset = i * 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[offset..offset + 8]);
        *v = u64::from_be_bytes(limb);
    }

    Ok(out)
}

/// Convert a UUID to 4 field elements (each u32 limb)
fn uuid_to_felts(uuid: &Uuid) -> [Felt; 4] {
    let bytes = uuid.as_bytes();
    let mut result = [felt_from_u64(0); 4];
    for (i, out) in result.iter_mut().enumerate() {
        let offset = i * 4;
        let limb = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        *out = felt_from_u64(limb as u64);
    }
    result
}

/// Compute policy hash: SHA256(domain || JCS({policyId, policyParams}))
pub fn compute_policy_hash(
    policy_id: &str,
    policy_params: &PolicyParams,
) -> Result<Hash256, PublicInputsError> {
    let policy_obj = serde_json::json!({
        "policyId": policy_id,
        "policyParams": policy_params.0
    });
    let canonical = canonical_json(&policy_obj)?;
    Ok(Hash256::sha256_with_domain(
        DOMAIN_POLICY_HASH,
        canonical.as_bytes(),
    ))
}

/// Compute public inputs hash: SHA256(JCS(public_inputs))
pub fn compute_public_inputs_hash(
    inputs: &CompliancePublicInputs,
) -> Result<Hash256, PublicInputsError> {
    let mut canonical_inputs = inputs.clone();
    canonical_inputs.witness_commitment = None;
    let canonical = canonical_json(&serde_json::to_value(&canonical_inputs)?)?;
    Ok(Hash256::sha256(canonical.as_bytes()))
}

/// Compute the hash of the full local public-input object, including
/// `witnessCommitment` when present.
pub fn compute_full_public_inputs_hash(
    inputs: &CompliancePublicInputs,
) -> Result<Hash256, PublicInputsError> {
    let canonical = canonical_json(&serde_json::to_value(inputs)?)?;
    Ok(Hash256::sha256(canonical.as_bytes()))
}

/// Compute the hash of a witness-bound public-input object.
///
/// This requires `witnessCommitment` to be present and includes it in the hashed object.
pub fn compute_bound_public_inputs_hash(
    inputs: &CompliancePublicInputs,
) -> Result<Hash256, PublicInputsError> {
    if inputs.witness_commitment.is_none() {
        return Err(PublicInputsError::WitnessCommitmentBinding(
            "missing witnessCommitment".to_string(),
        ));
    }
    compute_full_public_inputs_hash(inputs)
}

fn normalize_hex_input(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<String, PublicInputsError> {
    let normalized = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim())
        .to_ascii_lowercase();

    if normalized.len() != expected_len {
        return Err(PublicInputsError::InvalidHexFormat {
            field,
            reason: format!(
                "expected {} characters, got {}",
                expected_len,
                normalized.len()
            ),
        });
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(PublicInputsError::InvalidHexFormat {
            field,
            reason: "must contain only hexadecimal characters".to_string(),
        });
    }

    Ok(normalized)
}

fn validate_hex_string(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<(), PublicInputsError> {
    if value.len() != expected_len {
        return Err(PublicInputsError::InvalidHexFormat {
            field,
            reason: format!("expected {} characters, got {}", expected_len, value.len()),
        });
    }

    for (i, c) in value.chars().enumerate() {
        if !c.is_ascii_hexdigit() {
            return Err(PublicInputsError::InvalidHexFormat {
                field,
                reason: format!("invalid character '{}' at position {}", c, i),
            });
        }
        if c.is_ascii_uppercase() {
            return Err(PublicInputsError::InvalidHexFormat {
                field,
                reason: format!(
                    "uppercase character '{}' at position {} (must be lowercase)",
                    c, i
                ),
            });
        }
    }

    Ok(())
}

/// Canonicalize JSON according to RFC 8785 (JCS)
pub fn canonical_json(value: &serde_json::Value) -> Result<String, PublicInputsError> {
    serde_jcs::to_string(value).map_err(|e| PublicInputsError::Canonicalization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommerceExecution, CommerceIntent};

    fn sample_authorization_receipt() -> CommerceAuthorizationReceipt {
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
            allowed_skus: vec!["sku-a".to_string()],
            allowed_categories: vec!["grocery".to_string()],
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
            category_ids: vec!["grocery".to_string()],
            shipping_country: Some("US".to_string()),
            executed_at: 1_800_000_000,
        };
        intent.authorize_execution(&execution).unwrap()
    }

    fn sample_authorization_inputs(
        receipt: &CommerceAuthorizationReceipt,
    ) -> CompliancePublicInputs {
        let params = PolicyParams::agent_authorization(25_000, &receipt.intent_hash).unwrap();
        let policy_hash = compute_policy_hash("agent.authorization.v1", &params).unwrap();
        CompliancePublicInputs {
            event_id: receipt.event_id,
            tenant_id: receipt.tenant_id,
            store_id: receipt.store_id,
            sequence_number: receipt.sequence_number,
            payload_kind: 7,
            payload_plain_hash: "a".repeat(64),
            payload_cipher_hash: "b".repeat(64),
            event_signing_hash: "c".repeat(64),
            policy_id: "agent.authorization.v1".to_string(),
            policy_params: params,
            policy_hash: policy_hash.to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
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

    #[test]
    fn test_canonical_json_simple() {
        let obj = serde_json::json!({"b": 2, "a": 1});
        let canonical = canonical_json(&obj).unwrap();
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_canonical_json_nested() {
        let obj = serde_json::json!({"outer": {"b": 2, "a": 1}});
        let canonical = canonical_json(&obj).unwrap();
        assert_eq!(canonical, r#"{"outer":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(10000);

        let hash1 = compute_policy_hash(policy_id, &params).unwrap();
        let hash2 = compute_policy_hash(policy_id, &params).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_policy_hash_different_params() {
        let policy_id = "aml.threshold";
        let params1 = PolicyParams::threshold(10000);
        let params2 = PolicyParams::threshold(20000);

        let hash1 = compute_policy_hash(policy_id, &params1).unwrap();
        let hash2 = compute_policy_hash(policy_id, &params2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_agent_authorization_params_normalize_intent_hash() {
        let params = PolicyParams::agent_authorization(
            25_000,
            "0X0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        )
        .unwrap();

        assert_eq!(params.get_max_total(), Some(25_000));
        assert_eq!(
            params.get_intent_hash(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn test_agent_authorization_params_reject_invalid_intent_hash() {
        let err = PolicyParams::agent_authorization(25_000, "xyz").unwrap_err();
        assert!(matches!(err, PublicInputsError::InvalidHexFormat { .. }));
    }

    #[test]
    fn test_public_inputs_felts_roundtrip() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 12345,
            payload_kind: 1,
            payload_plain_hash: "a".repeat(64),
            payload_cipher_hash: "b".repeat(64),
            event_signing_hash: "c".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10000),
            policy_hash: "d".repeat(64),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let felts = inputs.to_field_elements().unwrap();
        let vec = felts.to_vec();

        // Should have the expected number of elements
        // 4 (event_id) + 4 (tenant_id) + 4 (store_id) + 2 (seq) + 1 (kind)
        // + 8 (plain) + 8 (cipher) + 8 (signing) + 8 (policy) = 47
        assert_eq!(vec.len(), 47);
    }

    #[test]
    fn test_validate_policy_hash() {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(10000);
        let hash = compute_policy_hash(policy_id, &params).unwrap();

        let inputs = CompliancePublicInputs {
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
        };

        assert!(inputs.validate_policy_hash().unwrap());
    }

    #[test]
    fn test_uppercase_hex_rejected() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "A".repeat(64),
            payload_cipher_hash: "b".repeat(64),
            event_signing_hash: "c".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10000),
            policy_hash: "d".repeat(64),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let result = inputs.to_field_elements();
        assert!(result.is_err());
    }

    #[test]
    fn test_canonical_hash_ignores_witness_commitment() {
        let witness_commitment = witness_commitment_u64_to_hex(&[1, 2, 3, 4]);
        let inputs_without_commitment = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };
        let mut inputs_with_commitment = inputs_without_commitment.clone();
        inputs_with_commitment.witness_commitment = Some(witness_commitment);

        assert_eq!(
            inputs_without_commitment.compute_hash().unwrap(),
            inputs_with_commitment.compute_hash().unwrap()
        );
        assert_ne!(
            inputs_without_commitment.compute_full_hash().unwrap(),
            inputs_with_commitment.compute_full_hash().unwrap()
        );
    }

    #[test]
    fn test_witness_commitment_hex_roundtrip() {
        let commitment = [1u64, 2, 3, 4];
        let commitment_hex = witness_commitment_u64_to_hex(&commitment);

        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10000),
            policy_hash: "0".repeat(64),
            witness_commitment: Some(commitment_hex),
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let recovered = inputs.witness_commitment_u64().unwrap().unwrap();
        assert_eq!(recovered, commitment);
    }

    #[test]
    fn test_witness_commitment_hex_uppercase_rejected() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10000),
            policy_hash: "0".repeat(64),
            witness_commitment: Some("A".repeat(64)),
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let err = inputs.witness_commitment_u64().unwrap_err();
        assert!(matches!(
            err,
            PublicInputsError::InvalidHexFormat {
                field: "witnessCommitment",
                ..
            }
        ));
    }

    #[test]
    fn test_compute_bound_hash_requires_witness_commitment() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let err = inputs.compute_bound_hash().unwrap_err();
        assert!(matches!(
            err,
            PublicInputsError::WitnessCommitmentBinding(_)
        ));
    }

    #[test]
    fn test_bind_witness_commitment_sets_bound_hash() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let bound = inputs.bind_witness_commitment(&[1, 2, 3, 4]).unwrap();
        assert_eq!(
            bound.witness_commitment,
            Some(witness_commitment_u64_to_hex(&[1, 2, 3, 4]))
        );
        assert_eq!(
            inputs.compute_hash().unwrap(),
            bound.compute_hash().unwrap()
        );
        assert_ne!(
            inputs.compute_full_hash().unwrap(),
            bound.compute_full_hash().unwrap()
        );
        assert_eq!(
            bound.compute_bound_hash().unwrap(),
            bound.compute_full_hash().unwrap()
        );
    }

    #[test]
    fn test_payload_amount_binding_hash_roundtrip() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };
        let binding = sample_payload_amount_binding(&inputs, 5_000);

        assert!(binding.validate().is_ok());
        assert_eq!(binding.compute_hash_hex().unwrap(), binding.binding_hash);
    }

    #[test]
    fn test_payload_amount_binding_from_public_inputs_matches_method() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let binding = PayloadAmountBinding::from_public_inputs(&inputs, 5_000).unwrap();
        assert!(binding.validate().is_ok());
        assert_eq!(binding, inputs.payload_amount_binding(5_000).unwrap());
    }

    #[test]
    fn test_bind_payload_amount_binding_sets_witness_commitment_and_hash() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };
        let binding = sample_payload_amount_binding(&inputs, 5_000);

        let bound = inputs.bind_payload_amount_binding(&binding).unwrap();

        assert_eq!(
            bound.witness_commitment,
            Some(witness_commitment_u64_to_hex(
                &binding.witness_commitment_u64()
            ))
        );
        assert_eq!(
            bound.amount_binding_hash,
            Some(binding.binding_hash.clone())
        );
        assert_ne!(
            inputs.compute_hash().unwrap(),
            bound.compute_hash().unwrap()
        );
    }

    #[test]
    fn test_bind_amount_sets_witness_commitment_and_hash() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };

        let bound = inputs.bind_amount(5_000).unwrap();
        let binding = inputs.payload_amount_binding(5_000).unwrap();
        assert_eq!(
            bound.witness_commitment,
            Some(witness_commitment_u64_to_hex(
                &binding.witness_commitment_u64()
            ))
        );
        assert_eq!(bound.amount_binding_hash, Some(binding.binding_hash));
    }

    #[test]
    fn test_validate_payload_amount_binding_rejects_hash_mismatch() {
        let inputs = CompliancePublicInputs {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            store_id: Uuid::new_v4(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "1".repeat(64),
            event_signing_hash: "2".repeat(64),
            policy_id: "aml.threshold".to_string(),
            policy_params: PolicyParams::threshold(10_000),
            policy_hash: compute_policy_hash("aml.threshold", &PolicyParams::threshold(10_000))
                .unwrap()
                .to_hex(),
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        };
        let mut binding = sample_payload_amount_binding(&inputs, 5_000);
        binding.binding_hash = "f".repeat(64);

        let err = inputs
            .validate_payload_amount_binding(&binding)
            .unwrap_err();
        assert!(matches!(err, PublicInputsError::AmountBinding(_)));
    }

    #[test]
    fn test_bind_authorization_receipt_sets_witness_commitment_and_hash() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(&receipt);

        let bound = inputs.bind_authorization_receipt(&receipt).unwrap();

        assert_eq!(
            bound.witness_commitment,
            Some(witness_commitment_u64_to_hex(
                &receipt.witness_commitment_u64()
            ))
        );
        assert_eq!(
            bound.authorization_receipt_hash,
            Some(receipt.receipt_hash.clone())
        );
        assert_ne!(
            inputs.compute_hash().unwrap(),
            bound.compute_hash().unwrap()
        );
    }

    #[test]
    fn test_bind_payload_amount_binding_and_authorization_receipt_sets_all_hashes() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(&receipt);
        let binding = sample_payload_amount_binding(&inputs, receipt.amount);

        let bound = inputs
            .bind_payload_amount_binding_and_authorization_receipt(&binding, &receipt)
            .unwrap();

        assert_eq!(
            bound.witness_commitment,
            Some(witness_commitment_u64_to_hex(
                &receipt.witness_commitment_u64()
            ))
        );
        assert_eq!(
            bound.amount_binding_hash,
            Some(binding.binding_hash.clone())
        );
        assert_eq!(
            bound.authorization_receipt_hash,
            Some(receipt.receipt_hash.clone())
        );
        assert_ne!(
            inputs.compute_hash().unwrap(),
            bound.compute_hash().unwrap()
        );
    }

    #[test]
    fn test_bind_amount_and_authorization_receipt_derives_payload_binding() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(&receipt);
        let binding = inputs.payload_amount_binding(receipt.amount).unwrap();

        let bound = inputs
            .bind_amount_and_authorization_receipt(&receipt)
            .unwrap();

        assert_eq!(
            bound.witness_commitment,
            Some(witness_commitment_u64_to_hex(
                &receipt.witness_commitment_u64()
            ))
        );
        assert_eq!(bound.amount_binding_hash, Some(binding.binding_hash));
        assert_eq!(
            bound.authorization_receipt_hash,
            Some(receipt.receipt_hash.clone())
        );
    }

    #[test]
    fn test_validate_authorization_receipt_rejects_context_mismatch() {
        let receipt = sample_authorization_receipt();
        let mut inputs = sample_authorization_inputs(&receipt);
        inputs.event_id = Uuid::new_v4();

        let err = inputs.validate_authorization_receipt(&receipt).unwrap_err();
        assert!(matches!(
            err,
            PublicInputsError::AuthorizationReceiptBinding(_)
        ));
    }

    #[test]
    fn test_validate_authorization_receipt_rejects_mismatched_receipt_hash_binding() {
        let receipt = sample_authorization_receipt();
        let mut inputs = sample_authorization_inputs(&receipt);
        inputs.authorization_receipt_hash = Some("0".repeat(64));

        let err = inputs.validate_authorization_receipt(&receipt).unwrap_err();
        assert!(matches!(
            err,
            PublicInputsError::AuthorizationReceiptBinding(_)
        ));
    }

    #[test]
    fn test_validate_payload_amount_binding_and_authorization_receipt_rejects_amount_mismatch() {
        let receipt = sample_authorization_receipt();
        let inputs = sample_authorization_inputs(&receipt);
        let binding = sample_payload_amount_binding(&inputs, receipt.amount + 1);

        let err = inputs
            .validate_payload_amount_binding_and_authorization_receipt(&binding, &receipt)
            .unwrap_err();
        assert!(matches!(
            err,
            PublicInputsError::WitnessCommitmentBinding(_)
        ));
    }
}
