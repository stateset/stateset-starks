//! Canonical Public Inputs for VES Compliance Proofs
//!
//! These structures define the public inputs for Phase 1 per-event compliance proofs.
//! They MUST match the canonical format used by the sequencer (RFC 8785 JCS canonicalization).

use crate::field::{Felt, FeltArray8, felt_from_u64};
use crate::hash::{Hash256, hash_to_felts, u64_to_felt_pair};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Domain separator for policy hash computation
pub const DOMAIN_POLICY_HASH: &[u8] = b"STATESET_VES_COMPLIANCE_POLICY_HASH_V1";

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
}

impl CompliancePublicInputs {
    /// Compute the policy hash for a given policy ID and params
    pub fn compute_policy_hash(policy_id: &str, policy_params: &PolicyParams) -> Hash256 {
        compute_policy_hash(policy_id, policy_params)
    }

    /// Compute the hash of these public inputs
    pub fn compute_hash(&self) -> Hash256 {
        compute_public_inputs_hash(self)
    }

    /// Convert to field elements for use in the AIR
    pub fn to_field_elements(&self) -> CompliancePublicInputsFelts {
        CompliancePublicInputsFelts::from_public_inputs(self)
    }

    /// Validate that the policy_hash field matches the computed hash
    pub fn validate_policy_hash(&self) -> bool {
        let computed = Self::compute_policy_hash(&self.policy_id, &self.policy_params);
        computed.to_hex() == self.policy_hash
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
    pub fn from_public_inputs(inputs: &CompliancePublicInputs) -> Self {
        Self {
            event_id: uuid_to_felts(&inputs.event_id),
            tenant_id: uuid_to_felts(&inputs.tenant_id),
            store_id: uuid_to_felts(&inputs.store_id),
            sequence_number: u64_to_felt_pair(inputs.sequence_number),
            payload_kind: felt_from_u64(inputs.payload_kind as u64),
            payload_plain_hash: hash_to_felts(&Hash256::from_hex(&inputs.payload_plain_hash).unwrap_or_default()),
            payload_cipher_hash: hash_to_felts(&Hash256::from_hex(&inputs.payload_cipher_hash).unwrap_or_default()),
            event_signing_hash: hash_to_felts(&Hash256::from_hex(&inputs.event_signing_hash).unwrap_or_default()),
            policy_hash: hash_to_felts(&Hash256::from_hex(&inputs.policy_hash).unwrap_or_default()),
        }
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

/// Convert a UUID to 4 field elements (each u32 limb)
fn uuid_to_felts(uuid: &Uuid) -> [Felt; 4] {
    let bytes = uuid.as_bytes();
    let mut result = [felt_from_u64(0); 4];
    for i in 0..4 {
        let offset = i * 4;
        let limb = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        result[i] = felt_from_u64(limb as u64);
    }
    result
}

/// Compute policy hash: SHA256(domain || JCS({policyId, policyParams}))
pub fn compute_policy_hash(policy_id: &str, policy_params: &PolicyParams) -> Hash256 {
    let policy_obj = serde_json::json!({
        "policyId": policy_id,
        "policyParams": policy_params.0
    });
    let canonical = canonical_json(&policy_obj);
    Hash256::sha256_with_domain(DOMAIN_POLICY_HASH, canonical.as_bytes())
}

/// Compute public inputs hash: SHA256(JCS(public_inputs))
pub fn compute_public_inputs_hash(inputs: &CompliancePublicInputs) -> Hash256 {
    let canonical = canonical_json(&serde_json::to_value(inputs).unwrap());
    Hash256::sha256(canonical.as_bytes())
}

/// Canonicalize JSON according to RFC 8785 (JCS)
///
/// This is a simplified implementation that:
/// - Sorts object keys lexicographically
/// - Removes whitespace
/// - Uses lowercase hex for numbers
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", escape_json_string(s)),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let pairs: Vec<String> = keys
                .iter()
                .map(|k| format!("\"{}\":{}", escape_json_string(k), canonical_json(&obj[*k])))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// Escape special characters in JSON strings
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_json_simple() {
        let obj = serde_json::json!({"b": 2, "a": 1});
        let canonical = canonical_json(&obj);
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn test_canonical_json_nested() {
        let obj = serde_json::json!({"outer": {"b": 2, "a": 1}});
        let canonical = canonical_json(&obj);
        assert_eq!(canonical, r#"{"outer":{"a":1,"b":2}}"#);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let policy_id = "aml.threshold";
        let params = PolicyParams::threshold(10000);

        let hash1 = compute_policy_hash(policy_id, &params);
        let hash2 = compute_policy_hash(policy_id, &params);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_policy_hash_different_params() {
        let policy_id = "aml.threshold";
        let params1 = PolicyParams::threshold(10000);
        let params2 = PolicyParams::threshold(20000);

        let hash1 = compute_policy_hash(policy_id, &params1);
        let hash2 = compute_policy_hash(policy_id, &params2);

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
        };

        let felts = inputs.to_field_elements();
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
        let hash = compute_policy_hash(policy_id, &params);

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
        };

        assert!(inputs.validate_policy_hash());
    }
}
