//! Batch proof serialization
//!
//! This module provides serialization formats for batch proofs,
//! optimized for both human inspection (JSON) and efficient transport (binary).

use serde::{Deserialize, Serialize};

use crate::error::BatchError;
use crate::prover::BatchProof;
use crate::public_inputs::BatchPublicInputs;

/// Serializable batch proof with public inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableBatchProof {
    /// Protocol version
    pub version: u8,

    /// The proof
    pub proof: BatchProof,

    /// Public inputs
    pub public_inputs: SerializableBatchPublicInputs,
}

/// Serializable batch public inputs (all values as u64 for JSON compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableBatchPublicInputs {
    /// Previous batch state root (4 x u64)
    pub prev_state_root: [u64; 4],

    /// New batch state root (4 x u64)
    pub new_state_root: [u64; 4],

    /// Batch ID (4 x u64)
    pub batch_id: [u64; 4],

    /// Tenant ID (4 x u64)
    pub tenant_id: [u64; 4],

    /// Store ID (4 x u64)
    pub store_id: [u64; 4],

    /// First sequence number in batch
    pub sequence_start: u64,

    /// Last sequence number in batch
    pub sequence_end: u64,

    /// Number of events in batch
    pub num_events: u64,

    /// All events compliant flag (1 if all pass, 0 otherwise)
    pub all_compliant: u64,

    /// Policy hash (8 x u64)
    pub policy_hash: [u64; 8],

    /// Policy limit (threshold or cap)
    pub policy_limit: u64,
}

impl SerializableBatchProof {
    /// Current protocol version
    pub const VERSION: u8 = 1;

    /// Create a new serializable batch proof
    pub fn new(proof: BatchProof, public_inputs: BatchPublicInputs) -> Self {
        Self {
            version: Self::VERSION,
            proof,
            public_inputs: SerializableBatchPublicInputs::from(public_inputs),
        }
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, BatchError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| BatchError::SerializationFailed(format!("JSON error: {}", e)))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, BatchError> {
        serde_json::from_str(json)
            .map_err(|e| BatchError::DeserializationFailed(format!("JSON error: {}", e)))
    }

    /// Serialize to compact binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>, BatchError> {
        let mut bytes = Vec::new();

        // Version byte
        bytes.push(self.version);

        // Proof length (4 bytes, big-endian)
        let proof_len = self.proof.proof_bytes.len() as u32;
        bytes.extend_from_slice(&proof_len.to_be_bytes());

        // Proof bytes
        bytes.extend_from_slice(&self.proof.proof_bytes);

        // Public inputs (fixed layout)
        // prev_state_root (32 bytes)
        for val in &self.public_inputs.prev_state_root {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // new_state_root (32 bytes)
        for val in &self.public_inputs.new_state_root {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // batch_id (32 bytes)
        for val in &self.public_inputs.batch_id {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // tenant_id (32 bytes)
        for val in &self.public_inputs.tenant_id {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // store_id (32 bytes)
        for val in &self.public_inputs.store_id {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // sequence_start (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.sequence_start.to_le_bytes());

        // sequence_end (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.sequence_end.to_le_bytes());

        // num_events (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.num_events.to_le_bytes());

        // all_compliant (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.all_compliant.to_le_bytes());

        // policy_hash (64 bytes)
        for val in &self.public_inputs.policy_hash {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // policy_limit (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.policy_limit.to_le_bytes());

        Ok(bytes)
    }

    /// Deserialize from compact binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() < 5 {
            return Err(BatchError::DeserializationFailed(
                "Input too short".to_string(),
            ));
        }

        let mut pos = 0;

        // Version
        let version = bytes[pos];
        if version != Self::VERSION {
            return Err(BatchError::DeserializationFailed(format!(
                "Unsupported version: {}",
                version
            )));
        }
        pos += 1;

        // Proof length
        let proof_len =
            u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;

        if bytes.len() < pos + proof_len + 256 {
            return Err(BatchError::DeserializationFailed(
                "Input too short for proof".to_string(),
            ));
        }

        // Proof bytes
        let proof_bytes = bytes[pos..pos + proof_len].to_vec();
        pos += proof_len;

        // Helper to read u64
        let read_u64 = |pos: &mut usize| -> u64 {
            let val = u64::from_le_bytes([
                bytes[*pos],
                bytes[*pos + 1],
                bytes[*pos + 2],
                bytes[*pos + 3],
                bytes[*pos + 4],
                bytes[*pos + 5],
                bytes[*pos + 6],
                bytes[*pos + 7],
            ]);
            *pos += 8;
            val
        };

        // Read public inputs
        let mut prev_state_root = [0u64; 4];
        for val in &mut prev_state_root {
            *val = read_u64(&mut pos);
        }

        let mut new_state_root = [0u64; 4];
        for val in &mut new_state_root {
            *val = read_u64(&mut pos);
        }

        let mut batch_id = [0u64; 4];
        for val in &mut batch_id {
            *val = read_u64(&mut pos);
        }

        let mut tenant_id = [0u64; 4];
        for val in &mut tenant_id {
            *val = read_u64(&mut pos);
        }

        let mut store_id = [0u64; 4];
        for val in &mut store_id {
            *val = read_u64(&mut pos);
        }

        let sequence_start = read_u64(&mut pos);
        let sequence_end = read_u64(&mut pos);
        let num_events = read_u64(&mut pos);
        let all_compliant = read_u64(&mut pos);

        let mut policy_hash = [0u64; 8];
        for val in &mut policy_hash {
            *val = read_u64(&mut pos);
        }

        let policy_limit = read_u64(&mut pos);

        // Construct the proof struct (partial - hash will be recomputed on verification)
        let proof = BatchProof {
            proof_bytes,
            proof_hash: String::new(), // Will be verified separately
            prev_state_root,
            new_state_root,
            metadata: crate::prover::BatchProofMetadata {
                batch_id: format!(
                    "{:016x}{:016x}{:016x}{:016x}",
                    batch_id[0], batch_id[1], batch_id[2], batch_id[3]
                ),
                num_events: num_events as usize,
                all_compliant: all_compliant == 1,
                proving_time_ms: 0,
                trace_length: 0,
                proof_size: 0,
                prover_version: String::new(),
            },
        };

        Ok(Self {
            version,
            proof,
            public_inputs: SerializableBatchPublicInputs {
                prev_state_root,
                new_state_root,
                batch_id,
                tenant_id,
                store_id,
                sequence_start,
                sequence_end,
                num_events,
                all_compliant,
                policy_hash,
                policy_limit,
            },
        })
    }

    /// Convert public inputs back to BatchPublicInputs
    pub fn to_batch_public_inputs(&self) -> BatchPublicInputs {
        self.public_inputs.clone().into()
    }
}

impl From<BatchPublicInputs> for SerializableBatchPublicInputs {
    fn from(inputs: BatchPublicInputs) -> Self {
        Self {
            prev_state_root: [
                inputs.prev_state_root[0].as_int(),
                inputs.prev_state_root[1].as_int(),
                inputs.prev_state_root[2].as_int(),
                inputs.prev_state_root[3].as_int(),
            ],
            new_state_root: [
                inputs.new_state_root[0].as_int(),
                inputs.new_state_root[1].as_int(),
                inputs.new_state_root[2].as_int(),
                inputs.new_state_root[3].as_int(),
            ],
            batch_id: [
                inputs.batch_id[0].as_int(),
                inputs.batch_id[1].as_int(),
                inputs.batch_id[2].as_int(),
                inputs.batch_id[3].as_int(),
            ],
            tenant_id: [
                inputs.tenant_id[0].as_int(),
                inputs.tenant_id[1].as_int(),
                inputs.tenant_id[2].as_int(),
                inputs.tenant_id[3].as_int(),
            ],
            store_id: [
                inputs.store_id[0].as_int(),
                inputs.store_id[1].as_int(),
                inputs.store_id[2].as_int(),
                inputs.store_id[3].as_int(),
            ],
            sequence_start: inputs.sequence_start.as_int(),
            sequence_end: inputs.sequence_end.as_int(),
            num_events: inputs.num_events.as_int(),
            all_compliant: inputs.all_compliant.as_int(),
            policy_hash: [
                inputs.policy_hash[0].as_int(),
                inputs.policy_hash[1].as_int(),
                inputs.policy_hash[2].as_int(),
                inputs.policy_hash[3].as_int(),
                inputs.policy_hash[4].as_int(),
                inputs.policy_hash[5].as_int(),
                inputs.policy_hash[6].as_int(),
                inputs.policy_hash[7].as_int(),
            ],
            policy_limit: inputs.policy_limit.as_int(),
        }
    }
}

impl From<SerializableBatchPublicInputs> for BatchPublicInputs {
    fn from(inputs: SerializableBatchPublicInputs) -> Self {
        use ves_stark_primitives::felt_from_u64;

        Self {
            prev_state_root: [
                felt_from_u64(inputs.prev_state_root[0]),
                felt_from_u64(inputs.prev_state_root[1]),
                felt_from_u64(inputs.prev_state_root[2]),
                felt_from_u64(inputs.prev_state_root[3]),
            ],
            new_state_root: [
                felt_from_u64(inputs.new_state_root[0]),
                felt_from_u64(inputs.new_state_root[1]),
                felt_from_u64(inputs.new_state_root[2]),
                felt_from_u64(inputs.new_state_root[3]),
            ],
            batch_id: [
                felt_from_u64(inputs.batch_id[0]),
                felt_from_u64(inputs.batch_id[1]),
                felt_from_u64(inputs.batch_id[2]),
                felt_from_u64(inputs.batch_id[3]),
            ],
            tenant_id: [
                felt_from_u64(inputs.tenant_id[0]),
                felt_from_u64(inputs.tenant_id[1]),
                felt_from_u64(inputs.tenant_id[2]),
                felt_from_u64(inputs.tenant_id[3]),
            ],
            store_id: [
                felt_from_u64(inputs.store_id[0]),
                felt_from_u64(inputs.store_id[1]),
                felt_from_u64(inputs.store_id[2]),
                felt_from_u64(inputs.store_id[3]),
            ],
            sequence_start: felt_from_u64(inputs.sequence_start),
            sequence_end: felt_from_u64(inputs.sequence_end),
            num_events: felt_from_u64(inputs.num_events),
            all_compliant: felt_from_u64(inputs.all_compliant),
            policy_hash: [
                felt_from_u64(inputs.policy_hash[0]),
                felt_from_u64(inputs.policy_hash[1]),
                felt_from_u64(inputs.policy_hash[2]),
                felt_from_u64(inputs.policy_hash[3]),
                felt_from_u64(inputs.policy_hash[4]),
                felt_from_u64(inputs.policy_hash[5]),
                felt_from_u64(inputs.policy_hash[6]),
                felt_from_u64(inputs.policy_hash[7]),
            ],
            policy_limit: felt_from_u64(inputs.policy_limit),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::BatchProofMetadata;

    fn sample_proof() -> BatchProof {
        BatchProof {
            proof_bytes: vec![1, 2, 3, 4, 5],
            proof_hash: "abc123".to_string(),
            prev_state_root: [1, 2, 3, 4],
            new_state_root: [5, 6, 7, 8],
            metadata: BatchProofMetadata {
                batch_id: "test-batch".to_string(),
                num_events: 10,
                all_compliant: true,
                proving_time_ms: 100,
                trace_length: 256,
                proof_size: 5,
                prover_version: "0.1.0".to_string(),
            },
        }
    }

    fn sample_public_inputs() -> BatchPublicInputs {
        BatchPublicInputs::default()
    }

    #[test]
    fn test_json_serialization() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchProof::new(proof, inputs);

        let json = serializable.to_json().unwrap();
        let deserialized = SerializableBatchProof::from_json(&json).unwrap();

        assert_eq!(deserialized.version, SerializableBatchProof::VERSION);
        assert_eq!(deserialized.proof.proof_bytes, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_binary_round_trip() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchProof::new(proof.clone(), inputs.clone());

        let bytes = serializable.to_bytes().unwrap();
        let deserialized = SerializableBatchProof::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.version, SerializableBatchProof::VERSION);
        assert_eq!(deserialized.proof.proof_bytes, proof.proof_bytes);
        assert_eq!(
            deserialized.public_inputs.prev_state_root,
            serializable.public_inputs.prev_state_root
        );
        assert_eq!(
            deserialized.public_inputs.new_state_root,
            serializable.public_inputs.new_state_root
        );
    }

    #[test]
    fn test_public_inputs_conversion() {
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchPublicInputs::from(inputs.clone());
        let recovered: BatchPublicInputs = serializable.into();

        for i in 0..4 {
            assert_eq!(recovered.prev_state_root[i], inputs.prev_state_root[i]);
            assert_eq!(recovered.new_state_root[i], inputs.new_state_root[i]);
        }
    }
}
