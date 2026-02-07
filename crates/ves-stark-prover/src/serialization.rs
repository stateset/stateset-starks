//! Proof Serialization Utilities
//!
//! This module provides utilities for serializing and deserializing compliance proofs
//! in various formats suitable for storage, transmission, and inspection.

use crate::error::ProverError;
use crate::policy::Policy;
use crate::prover::{ComplianceProof, ProofMetadata};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Proof format for serialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofFormat {
    /// Raw binary format (most compact)
    Binary,
    /// Base64-encoded string
    Base64,
    /// JSON with metadata
    Json,
    /// JSON with metadata and public inputs
    JsonFull,
}

/// JSON representation of a proof (for JSON format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofJson {
    /// Base64-encoded proof bytes
    pub proof_b64: String,
    /// Proof hash (hex)
    pub proof_hash: String,
    /// Proof metadata
    pub metadata: ProofMetadata,
    /// Witness commitment (4 field elements as u64)
    pub witness_commitment: [u64; 4],
    /// Witness commitment encoded as 32 bytes (4 x u64 big-endian) and hex-encoded (64 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_commitment_hex: Option<String>,
    /// Policy information (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyInfo>,
}

/// Policy information for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    /// Policy type (e.g., "aml.threshold", "order_total.cap")
    #[serde(rename = "type")]
    pub policy_type: String,
    /// Policy limit value
    pub limit: u64,
}

impl From<&Policy> for PolicyInfo {
    fn from(policy: &Policy) -> Self {
        Self {
            policy_type: policy.policy_id().to_string(),
            limit: policy.limit(),
        }
    }
}

impl ProofJson {
    /// Create from a ComplianceProof
    pub fn from_proof(proof: &ComplianceProof) -> Self {
        Self {
            proof_b64: base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
            proof_hash: proof.proof_hash.clone(),
            metadata: proof.metadata.clone(),
            witness_commitment: proof.witness_commitment,
            witness_commitment_hex: proof.witness_commitment_hex.clone(),
            policy: None,
        }
    }

    /// Create from a ComplianceProof with policy information
    pub fn from_proof_with_policy(proof: &ComplianceProof, policy: &Policy) -> Self {
        Self {
            proof_b64: base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
            proof_hash: proof.proof_hash.clone(),
            metadata: proof.metadata.clone(),
            witness_commitment: proof.witness_commitment,
            witness_commitment_hex: proof.witness_commitment_hex.clone(),
            policy: Some(PolicyInfo::from(policy)),
        }
    }

    /// Extract raw proof bytes
    pub fn to_proof_bytes(&self) -> Result<Vec<u8>, ProverError> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.proof_b64)
            .map_err(|e| ProverError::SerializationError(format!("Base64 decode error: {}", e)))
    }
}

/// Serialize a proof to the specified format
pub fn serialize_proof(
    proof: &ComplianceProof,
    format: ProofFormat,
) -> Result<Vec<u8>, ProverError> {
    match format {
        ProofFormat::Binary => Ok(proof.proof_bytes.clone()),
        ProofFormat::Base64 => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes);
            Ok(b64.into_bytes())
        }
        ProofFormat::Json | ProofFormat::JsonFull => {
            let json = ProofJson::from_proof(proof);
            serde_json::to_vec_pretty(&json).map_err(|e| {
                ProverError::SerializationError(format!("JSON serialization error: {}", e))
            })
        }
    }
}

/// Serialize a proof with policy information
pub fn serialize_proof_with_policy(
    proof: &ComplianceProof,
    policy: &Policy,
    format: ProofFormat,
) -> Result<Vec<u8>, ProverError> {
    match format {
        ProofFormat::Binary => Ok(proof.proof_bytes.clone()),
        ProofFormat::Base64 => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes);
            Ok(b64.into_bytes())
        }
        ProofFormat::Json | ProofFormat::JsonFull => {
            let json = ProofJson::from_proof_with_policy(proof, policy);
            serde_json::to_vec_pretty(&json).map_err(|e| {
                ProverError::SerializationError(format!("JSON serialization error: {}", e))
            })
        }
    }
}

/// Deserialize proof bytes from a given format
pub fn deserialize_proof_bytes(data: &[u8], format: ProofFormat) -> Result<Vec<u8>, ProverError> {
    match format {
        ProofFormat::Binary => Ok(data.to_vec()),
        ProofFormat::Base64 => {
            let b64_str = std::str::from_utf8(data)
                .map_err(|e| ProverError::SerializationError(format!("Invalid UTF-8: {}", e)))?;
            base64::engine::general_purpose::STANDARD
                .decode(b64_str.trim())
                .map_err(|e| ProverError::SerializationError(format!("Base64 decode error: {}", e)))
        }
        ProofFormat::Json | ProofFormat::JsonFull => {
            let json: ProofJson = serde_json::from_slice(data)
                .map_err(|e| ProverError::SerializationError(format!("JSON parse error: {}", e)))?;
            json.to_proof_bytes()
        }
    }
}

/// Auto-detect format and deserialize proof bytes
pub fn deserialize_proof_bytes_auto(data: &[u8]) -> Result<Vec<u8>, ProverError> {
    // Try to detect format based on content
    if let Ok(s) = std::str::from_utf8(data) {
        let trimmed = s.trim();
        if trimmed.starts_with('{') {
            // Looks like JSON
            return deserialize_proof_bytes(data, ProofFormat::Json);
        } else if trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            // Looks like Base64
            return deserialize_proof_bytes(data, ProofFormat::Base64);
        }
    }
    // Default to binary
    Ok(data.to_vec())
}

/// Write proof to a writer
pub fn write_proof<W: Write>(
    writer: &mut W,
    proof: &ComplianceProof,
    format: ProofFormat,
) -> Result<(), ProverError> {
    let data = serialize_proof(proof, format)?;
    writer
        .write_all(&data)
        .map_err(|e| ProverError::SerializationError(format!("Write error: {}", e)))
}

/// Read proof bytes from a reader
pub fn read_proof_bytes<R: Read>(
    reader: &mut R,
    format: ProofFormat,
) -> Result<Vec<u8>, ProverError> {
    let mut data = Vec::new();
    reader
        .read_to_end(&mut data)
        .map_err(|e| ProverError::SerializationError(format!("Read error: {}", e)))?;
    deserialize_proof_bytes(&data, format)
}

/// Parse proof JSON to extract metadata and policy info
pub fn parse_proof_json(data: &[u8]) -> Result<ProofJson, ProverError> {
    serde_json::from_slice(data)
        .map_err(|e| ProverError::SerializationError(format!("JSON parse error: {}", e)))
}

/// Compact proof representation for storage (binary + metadata JSON)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactProof {
    /// Version of the compact format
    pub version: u8,
    /// Proof bytes (binary)
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    /// Proof hash
    pub hash: String,
    /// Policy type identifier
    pub policy_id: String,
    /// Policy limit
    pub limit: u64,
    /// Proving time in ms
    pub proving_time_ms: u64,
    /// Witness commitment (4 field elements as u64)
    pub witness_commitment: [u64; 4],
}

impl CompactProof {
    /// Create from a ComplianceProof and Policy
    pub fn new(proof: &ComplianceProof, policy: &Policy) -> Self {
        Self {
            version: 1,
            proof: proof.proof_bytes.clone(),
            hash: proof.proof_hash.clone(),
            policy_id: policy.policy_id().to_string(),
            limit: policy.limit(),
            proving_time_ms: proof.metadata.proving_time_ms,
            witness_commitment: proof.witness_commitment,
        }
    }

    /// Serialize to binary format (using bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProverError> {
        // Use JSON as a portable format for now
        serde_json::to_vec(self).map_err(|e| {
            ProverError::SerializationError(format!("Compact serialization error: {}", e))
        })
    }

    /// Deserialize from binary format
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProverError> {
        serde_json::from_slice(data).map_err(|e| {
            ProverError::SerializationError(format!("Compact deserialization error: {}", e))
        })
    }

    /// Get the raw proof bytes
    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::ProofMetadata;

    fn sample_proof() -> ComplianceProof {
        let witness_commitment = [1234567890, 9876543210, 1111111111, 2222222222];
        ComplianceProof {
            proof_bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
            proof_hash: "abcd1234".to_string(),
            metadata: ProofMetadata {
                proving_time_ms: 100,
                num_constraints: 167,
                trace_length: 128,
                proof_size: 8,
                prover_version: "0.1.0".to_string(),
            },
            witness_commitment,
            witness_commitment_hex: Some(hex::encode(
                witness_commitment
                    .iter()
                    .flat_map(|v| v.to_be_bytes())
                    .collect::<Vec<u8>>(),
            )),
        }
    }

    #[test]
    fn test_serialize_binary() {
        let proof = sample_proof();
        let data = serialize_proof(&proof, ProofFormat::Binary).unwrap();
        assert_eq!(data, proof.proof_bytes);
    }

    #[test]
    fn test_serialize_base64() {
        let proof = sample_proof();
        let data = serialize_proof(&proof, ProofFormat::Base64).unwrap();
        let b64_str = String::from_utf8(data).unwrap();
        assert_eq!(b64_str, "AQIDBAUGBwg=");
    }

    #[test]
    fn test_serialize_json() {
        let proof = sample_proof();
        let data = serialize_proof(&proof, ProofFormat::Json).unwrap();
        let json: ProofJson = serde_json::from_slice(&data).unwrap();
        assert_eq!(json.proof_hash, "abcd1234");
        assert_eq!(json.metadata.num_constraints, 167);
        assert_eq!(json.witness_commitment, proof.witness_commitment);
        assert_eq!(json.witness_commitment_hex, proof.witness_commitment_hex);
    }

    #[test]
    fn test_deserialize_base64() {
        let proof = sample_proof();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes);
        let data = deserialize_proof_bytes(b64.as_bytes(), ProofFormat::Base64).unwrap();
        assert_eq!(data, proof.proof_bytes);
    }

    #[test]
    fn test_deserialize_json() {
        let proof = sample_proof();
        let serialized = serialize_proof(&proof, ProofFormat::Json).unwrap();
        let data = deserialize_proof_bytes(&serialized, ProofFormat::Json).unwrap();
        assert_eq!(data, proof.proof_bytes);
    }

    #[test]
    fn test_auto_detect_base64() {
        let proof = sample_proof();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes);
        let data = deserialize_proof_bytes_auto(b64.as_bytes()).unwrap();
        assert_eq!(data, proof.proof_bytes);
    }

    #[test]
    fn test_auto_detect_json() {
        let proof = sample_proof();
        let json = serialize_proof(&proof, ProofFormat::Json).unwrap();
        let data = deserialize_proof_bytes_auto(&json).unwrap();
        assert_eq!(data, proof.proof_bytes);
    }

    #[test]
    fn test_proof_json_with_policy() {
        let proof = sample_proof();
        let policy = Policy::aml_threshold(10000);
        let json = ProofJson::from_proof_with_policy(&proof, &policy);

        assert!(json.policy.is_some());
        let policy_info = json.policy.unwrap();
        assert_eq!(policy_info.policy_type, "aml.threshold");
        assert_eq!(policy_info.limit, 10000);
        assert_eq!(json.witness_commitment, proof.witness_commitment);
        assert_eq!(json.witness_commitment_hex, proof.witness_commitment_hex);
    }

    #[test]
    fn test_compact_proof() {
        let proof = sample_proof();
        let policy = Policy::order_total_cap(50000);
        let compact = CompactProof::new(&proof, &policy);

        assert_eq!(compact.version, 1);
        assert_eq!(compact.policy_id, "order_total.cap");
        assert_eq!(compact.limit, 50000);
        assert_eq!(compact.witness_commitment, proof.witness_commitment);

        let bytes = compact.to_bytes().unwrap();
        let recovered = CompactProof::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.proof, proof.proof_bytes);
        assert_eq!(recovered.hash, proof.proof_hash);
        assert_eq!(recovered.policy_id, "order_total.cap");
        assert_eq!(recovered.witness_commitment, proof.witness_commitment);
    }
}
