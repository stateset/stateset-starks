//! Canonical Public Inputs for VES Compliance Proofs
//!
//! These structures define the public inputs for Phase 1 per-event compliance proofs.
//! They MUST match the canonical format used by the sequencer (RFC 8785 JCS canonicalization).

use crate::field::{felt_from_u64, Felt, FeltArray8};
use crate::hash::{hash_to_felts, u64_to_felt_pair, Hash256};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Domain separator for policy hash computation
pub const DOMAIN_POLICY_HASH: &[u8] = b"STATESET_VES_COMPLIANCE_POLICY_HASH_V1";

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

    /// Get the threshold value if this is an aml.threshold policy
    pub fn get_threshold(&self) -> Option<u64> {
        self.0.get("threshold")?.as_u64()
    }

    /// Get the cap value if this is an order_total.cap policy
    pub fn get_cap(&self) -> Option<u64> {
        self.0.get("cap")?.as_u64()
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
}

impl CompliancePublicInputs {
    /// Compute the policy hash for a given policy ID and params
    pub fn compute_policy_hash(
        policy_id: &str,
        policy_params: &PolicyParams,
    ) -> Result<Hash256, PublicInputsError> {
        compute_policy_hash(policy_id, policy_params)
    }

    /// Compute the hash of these public inputs
    pub fn compute_hash(&self) -> Result<Hash256, PublicInputsError> {
        compute_public_inputs_hash(self)
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
    let canonical = canonical_json(&serde_json::to_value(inputs)?)?;
    Ok(Hash256::sha256(canonical.as_bytes()))
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
        };

        let result = inputs.to_field_elements();
        assert!(result.is_err());
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
}
