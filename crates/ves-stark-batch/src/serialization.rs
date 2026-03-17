//! Batch proof serialization
//!
//! This module provides serialization formats for batch proofs,
//! optimized for both human inspection (JSON) and efficient transport (binary).

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ves_stark_primitives::felt_from_u64;

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

/// Serializable batch public inputs.
///
/// Integer values are string-encoded in JSON to preserve full 64-bit precision
/// across JavaScript and other IEEE-754-based consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableBatchPublicInputs {
    /// Previous batch state root (4 x u64)
    #[serde(with = "crate::json_num::u64_array_4_strings")]
    pub prev_state_root: [u64; 4],

    /// New batch state root (4 x u64)
    #[serde(with = "crate::json_num::u64_array_4_strings")]
    pub new_state_root: [u64; 4],

    /// Batch ID (4 x u64)
    #[serde(with = "crate::json_num::u64_array_4_strings")]
    pub batch_id: [u64; 4],

    /// Tenant ID (4 x u64)
    #[serde(with = "crate::json_num::u64_array_4_strings")]
    pub tenant_id: [u64; 4],

    /// Store ID (4 x u64)
    #[serde(with = "crate::json_num::u64_array_4_strings")]
    pub store_id: [u64; 4],

    /// First sequence number in batch
    #[serde(with = "crate::json_num::u64_string")]
    pub sequence_start: u64,

    /// Last sequence number in batch
    #[serde(with = "crate::json_num::u64_string")]
    pub sequence_end: u64,

    /// Batch timestamp (Unix epoch seconds)
    #[serde(with = "crate::json_num::u64_string")]
    pub timestamp: u64,

    /// Number of events in batch
    #[serde(with = "crate::json_num::u64_string")]
    pub num_events: u64,

    /// All events compliant flag (1 if all pass, 0 otherwise)
    #[serde(with = "crate::json_num::u64_string")]
    pub all_compliant: u64,

    /// Policy hash (8 x u64)
    #[serde(with = "crate::json_num::u64_array_8_strings")]
    pub policy_hash: [u64; 8],

    /// Policy kind encoding
    #[serde(with = "crate::json_num::u64_string")]
    pub policy_kind: u64,

    /// Policy limit (threshold or cap)
    #[serde(with = "crate::json_num::u64_string")]
    pub policy_limit: u64,

    /// Ordered accumulator over canonical per-event public-input hashes (8 x u64)
    #[serde(with = "crate::json_num::u64_array_8_strings")]
    pub public_inputs_accumulator: [u64; 8],
}

impl SerializableBatchProof {
    /// Current protocol version
    pub const VERSION: u8 = 4;
    const LEGACY_VERSION: u8 = 3;

    /// Fixed-size public input payload in bytes for compact binary serialization.
    ///
    /// 43 u64 elements × 8 bytes.
    const PUBLIC_INPUT_BYTES: usize = 43 * 8;

    /// Create a new serializable batch proof
    pub fn new(proof: BatchProof, public_inputs: BatchPublicInputs) -> Result<Self, BatchError> {
        let expected_batch_id = batch_id_to_uuid_string(
            public_inputs.batch_id.map(|lane| lane.as_int()),
        )
        .map_err(|err| match err {
            BatchError::DeserializationFailed(message) => BatchError::SerializationFailed(message),
            other => other,
        })?;
        validate_proof_consistency_with_error(
            &proof,
            &public_inputs,
            &expected_batch_id,
            BatchError::SerializationFailed,
        )?;

        Ok(Self {
            version: Self::VERSION,
            proof,
            public_inputs: SerializableBatchPublicInputs::try_from(public_inputs)?,
        })
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, BatchError> {
        self.validate_for_serialization()?;
        serde_json::to_string_pretty(self)
            .map_err(|e| BatchError::SerializationFailed(format!("JSON error: {}", e)))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, BatchError> {
        let proof: Self = serde_json::from_str(json)
            .map_err(|e| BatchError::DeserializationFailed(format!("JSON error: {}", e)))?;
        proof.validate_for_deserialization()?;
        Ok(proof)
    }

    /// Serialize to compact binary format
    pub fn to_bytes(&self) -> Result<Vec<u8>, BatchError> {
        self.validate_for_serialization()?;
        let mut bytes = Vec::new();

        // Version byte
        bytes.push(self.version);

        // Proof length (4 bytes, big-endian)
        let proof_len = u32::try_from(self.proof.proof_bytes.len()).map_err(|_| {
            BatchError::SerializationFailed("Proof payload is too large to serialize".to_string())
        })?;
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

        // timestamp (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.timestamp.to_le_bytes());

        // num_events (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.num_events.to_le_bytes());

        // all_compliant (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.all_compliant.to_le_bytes());

        // policy_hash (64 bytes)
        for val in &self.public_inputs.policy_hash {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        // policy_kind (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.policy_kind.to_le_bytes());

        // policy_limit (8 bytes)
        bytes.extend_from_slice(&self.public_inputs.policy_limit.to_le_bytes());

        // public_inputs_accumulator (64 bytes)
        for val in &self.public_inputs.public_inputs_accumulator {
            bytes.extend_from_slice(&val.to_le_bytes());
        }

        let metadata_json = serde_json::to_vec(&self.proof.metadata)
            .map_err(|e| BatchError::SerializationFailed(format!("Metadata JSON error: {e}")))?;
        let metadata_len = u32::try_from(metadata_json.len()).map_err(|_| {
            BatchError::SerializationFailed(
                "Metadata payload is too large to serialize".to_string(),
            )
        })?;
        bytes.extend_from_slice(&metadata_len.to_be_bytes());
        bytes.extend_from_slice(&metadata_json);

        Ok(bytes)
    }

    /// Maximum allowed serialized proof size in bytes (10 MB)
    pub const MAX_SERIALIZED_SIZE: usize = 10 * 1024 * 1024;

    /// Deserialize from compact binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BatchError> {
        if bytes.len() > Self::MAX_SERIALIZED_SIZE {
            return Err(BatchError::ProofTooLarge {
                size: bytes.len(),
                max_size: Self::MAX_SERIALIZED_SIZE,
            });
        }

        if bytes.len() < 5 {
            return Err(BatchError::DeserializationFailed(
                "Input too short".to_string(),
            ));
        }

        let mut pos = 0;

        // Version
        let version = bytes[pos];
        if version != Self::VERSION && version != Self::LEGACY_VERSION {
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

        let proof_len_end = pos.checked_add(proof_len).ok_or_else(|| {
            BatchError::DeserializationFailed("proof length overflows platform usize".to_string())
        })?;
        let public_inputs_end = proof_len_end
            .checked_add(Self::PUBLIC_INPUT_BYTES)
            .ok_or_else(|| {
                BatchError::DeserializationFailed(
                    "public input length overflows platform usize".to_string(),
                )
            })?;

        if proof_len_end > bytes.len() || public_inputs_end > bytes.len() {
            return Err(BatchError::DeserializationFailed(
                "Input too short for proof and public inputs".to_string(),
            ));
        }

        // Proof bytes
        let proof_bytes = bytes[pos..proof_len_end].to_vec();
        pos = proof_len_end;

        // Helper to read u64
        let read_u64 = |bytes: &[u8], pos: &mut usize| -> Result<u64, BatchError> {
            if *pos + 8 > bytes.len() {
                return Err(BatchError::DeserializationFailed(
                    "Input too short while reading public inputs".to_string(),
                ));
            }

            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[*pos..*pos + 8]);
            *pos += 8;
            Ok(u64::from_le_bytes(raw))
        };

        // Read public inputs
        let mut prev_state_root = [0u64; 4];
        for val in &mut prev_state_root {
            *val = read_u64(bytes, &mut pos)?;
        }

        let mut new_state_root = [0u64; 4];
        for val in &mut new_state_root {
            *val = read_u64(bytes, &mut pos)?;
        }

        let mut batch_id = [0u64; 4];
        for val in &mut batch_id {
            *val = read_u64(bytes, &mut pos)?;
        }

        let mut tenant_id = [0u64; 4];
        for val in &mut tenant_id {
            *val = read_u64(bytes, &mut pos)?;
        }

        let mut store_id = [0u64; 4];
        for val in &mut store_id {
            *val = read_u64(bytes, &mut pos)?;
        }

        let sequence_start = read_u64(bytes, &mut pos)?;
        let sequence_end = read_u64(bytes, &mut pos)?;
        let timestamp = read_u64(bytes, &mut pos)?;
        let num_events = read_u64(bytes, &mut pos)?;
        let all_compliant = read_u64(bytes, &mut pos)?;

        let mut policy_hash = [0u64; 8];
        for val in &mut policy_hash {
            *val = read_u64(bytes, &mut pos)?;
        }

        let policy_kind = read_u64(bytes, &mut pos)?;
        let policy_limit = read_u64(bytes, &mut pos)?;
        let mut public_inputs_accumulator = [0u64; 8];
        for val in &mut public_inputs_accumulator {
            *val = read_u64(bytes, &mut pos)?;
        }

        debug_assert_eq!(pos, public_inputs_end);

        let public_inputs = SerializableBatchPublicInputs {
            prev_state_root,
            new_state_root,
            batch_id,
            tenant_id,
            store_id,
            sequence_start,
            sequence_end,
            timestamp,
            num_events,
            all_compliant,
            policy_hash,
            policy_kind,
            policy_limit,
            public_inputs_accumulator,
        };
        let validated_public_inputs = BatchPublicInputs::try_from(public_inputs.clone())?;
        let batch_id_uuid = batch_id_to_uuid_string(public_inputs.batch_id)?;

        // Compute hash and size before moving proof_bytes
        let proof_hash = BatchProof::compute_hash(&proof_bytes).to_hex();
        let proof_size = proof_bytes.len();

        let metadata = if version == Self::LEGACY_VERSION {
            if public_inputs_end != bytes.len() {
                return Err(BatchError::DeserializationFailed(
                    "Input contains unexpected trailing bytes".to_string(),
                ));
            }
            crate::prover::BatchProofMetadata {
                batch_id: batch_id_uuid.clone(),
                num_events: validated_public_inputs.num_events_usize(),
                all_compliant: validated_public_inputs.is_all_compliant(),
                proving_time_ms: 0,
                trace_length: 0,
                proof_size,
                prover_version: String::new(),
            }
        } else {
            let metadata_len_end = public_inputs_end.checked_add(4).ok_or_else(|| {
                BatchError::DeserializationFailed(
                    "metadata length overflows platform usize".to_string(),
                )
            })?;
            if metadata_len_end > bytes.len() {
                return Err(BatchError::DeserializationFailed(
                    "Input too short for metadata length".to_string(),
                ));
            }

            let metadata_len = u32::from_be_bytes([
                bytes[public_inputs_end],
                bytes[public_inputs_end + 1],
                bytes[public_inputs_end + 2],
                bytes[public_inputs_end + 3],
            ]) as usize;
            let metadata_end = metadata_len_end.checked_add(metadata_len).ok_or_else(|| {
                BatchError::DeserializationFailed(
                    "metadata length overflows platform usize".to_string(),
                )
            })?;
            if metadata_end > bytes.len() {
                return Err(BatchError::DeserializationFailed(
                    "Input too short for metadata".to_string(),
                ));
            }
            if metadata_end != bytes.len() {
                return Err(BatchError::DeserializationFailed(
                    "Input contains unexpected trailing bytes".to_string(),
                ));
            }

            let metadata: crate::prover::BatchProofMetadata =
                serde_json::from_slice(&bytes[metadata_len_end..metadata_end]).map_err(|e| {
                    BatchError::DeserializationFailed(format!("Metadata JSON error: {e}"))
                })?;

            if metadata.batch_id != batch_id_uuid {
                return Err(BatchError::DeserializationFailed(
                    "metadata batch_id does not match public inputs".to_string(),
                ));
            }
            if metadata.num_events != validated_public_inputs.num_events_usize() {
                return Err(BatchError::DeserializationFailed(
                    "metadata num_events does not match public inputs".to_string(),
                ));
            }
            if metadata.all_compliant != validated_public_inputs.is_all_compliant() {
                return Err(BatchError::DeserializationFailed(
                    "metadata all_compliant does not match public inputs".to_string(),
                ));
            }
            if metadata.proof_size != proof_size {
                return Err(BatchError::DeserializationFailed(
                    "metadata proof_size does not match proof byte length".to_string(),
                ));
            }

            metadata
        };

        // Construct the proof struct with a recomputed proof hash so transport
        // corruption cannot spoof the digest.
        let proof = BatchProof {
            proof_bytes,
            proof_hash,
            prev_state_root,
            new_state_root,
            metadata,
        };

        validate_proof_consistency_with_error(
            &proof,
            &validated_public_inputs,
            &batch_id_uuid,
            BatchError::DeserializationFailed,
        )?;

        Ok(Self {
            version,
            proof,
            public_inputs,
        })
    }

    /// Convert public inputs back to BatchPublicInputs
    pub fn to_batch_public_inputs(&self) -> Result<BatchPublicInputs, BatchError> {
        self.public_inputs.clone().try_into()
    }

    fn validate_for_deserialization(&self) -> Result<(), BatchError> {
        let public_inputs = self.to_batch_public_inputs()?;
        let expected_batch_id = batch_id_to_uuid_string(self.public_inputs.batch_id)?;
        validate_proof_consistency_with_error(
            &self.proof,
            &public_inputs,
            &expected_batch_id,
            BatchError::DeserializationFailed,
        )
    }

    fn validate_for_serialization(&self) -> Result<(), BatchError> {
        let public_inputs = self.to_batch_public_inputs().map_err(|err| match err {
            BatchError::DeserializationFailed(message) => {
                BatchError::SerializationFailed(format!("invalid public inputs: {message}"))
            }
            other => other,
        })?;
        let expected_batch_id =
            batch_id_to_uuid_string(self.public_inputs.batch_id).map_err(|err| match err {
                BatchError::DeserializationFailed(message) => {
                    BatchError::SerializationFailed(message)
                }
                other => other,
            })?;
        validate_proof_consistency_with_error(
            &self.proof,
            &public_inputs,
            &expected_batch_id,
            BatchError::SerializationFailed,
        )
    }
}

impl TryFrom<BatchPublicInputs> for SerializableBatchPublicInputs {
    type Error = BatchError;

    fn try_from(inputs: BatchPublicInputs) -> Result<Self, Self::Error> {
        inputs.validate()?;
        let policy_hash = inputs.try_policy_hash()?;

        Ok(Self {
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
            timestamp: inputs.timestamp.as_int(),
            num_events: inputs.num_events.as_int(),
            all_compliant: inputs.all_compliant.as_int(),
            policy_hash: [
                policy_hash[0].as_int(),
                policy_hash[1].as_int(),
                policy_hash[2].as_int(),
                policy_hash[3].as_int(),
                policy_hash[4].as_int(),
                policy_hash[5].as_int(),
                policy_hash[6].as_int(),
                policy_hash[7].as_int(),
            ],
            policy_kind: inputs.policy_kind.as_int(),
            policy_limit: inputs.policy_limit.as_int(),
            public_inputs_accumulator: inputs.public_inputs_accumulator.map(|lane| lane.as_int()),
        })
    }
}

fn batch_id_to_uuid_string(batch_id: [u64; 4]) -> Result<String, BatchError> {
    let mut batch_id_bytes = [0u8; 16];

    for (index, limb) in batch_id.iter().enumerate() {
        let limb = u32::try_from(*limb).map_err(|_| {
            BatchError::DeserializationFailed(
                "batch_id values must fit in u32 for UUID reconstruction".to_string(),
            )
        })?;
        batch_id_bytes[index * 4..index * 4 + 4].copy_from_slice(&limb.to_le_bytes());
    }

    Ok(Uuid::from_bytes(batch_id_bytes).to_string())
}

fn validate_proof_consistency_with_error<F>(
    proof: &BatchProof,
    public_inputs: &BatchPublicInputs,
    expected_batch_id: &str,
    error: F,
) -> Result<(), BatchError>
where
    F: Fn(String) -> BatchError,
{
    let expected_proof_hash = BatchProof::compute_hash(&proof.proof_bytes).to_hex();
    if proof.proof_hash != expected_proof_hash {
        return Err(error(
            "proof_hash does not match the serialized proof bytes".to_string(),
        ));
    }

    let expected_prev_state_root = public_inputs.prev_state_root.map(|lane| lane.as_int());
    if proof.prev_state_root != expected_prev_state_root {
        return Err(error(
            "proof prev_state_root does not match public inputs".to_string(),
        ));
    }

    let expected_new_state_root = public_inputs.new_state_root.map(|lane| lane.as_int());
    if proof.new_state_root != expected_new_state_root {
        return Err(error(
            "proof new_state_root does not match public inputs".to_string(),
        ));
    }

    if proof.metadata.batch_id != expected_batch_id {
        return Err(error(
            "metadata batch_id does not match public inputs".to_string(),
        ));
    }
    if proof.metadata.num_events != public_inputs.num_events_usize() {
        return Err(error(
            "metadata num_events does not match public inputs".to_string(),
        ));
    }
    if proof.metadata.all_compliant != public_inputs.is_all_compliant() {
        return Err(error(
            "metadata all_compliant does not match public inputs".to_string(),
        ));
    }
    if proof.metadata.proof_size != proof.proof_bytes.len() {
        return Err(error(
            "metadata proof_size does not match proof byte length".to_string(),
        ));
    }

    Ok(())
}

impl TryFrom<SerializableBatchPublicInputs> for BatchPublicInputs {
    type Error = BatchError;

    fn try_from(inputs: SerializableBatchPublicInputs) -> Result<Self, Self::Error> {
        let public_inputs = BatchPublicInputs {
            prev_state_root: inputs.prev_state_root.map(felt_from_u64),
            new_state_root: inputs.new_state_root.map(felt_from_u64),
            batch_id: inputs.batch_id.map(felt_from_u64),
            tenant_id: inputs.tenant_id.map(felt_from_u64),
            store_id: inputs.store_id.map(felt_from_u64),
            sequence_start: felt_from_u64(inputs.sequence_start),
            sequence_end: felt_from_u64(inputs.sequence_end),
            timestamp: felt_from_u64(inputs.timestamp),
            num_events: felt_from_u64(inputs.num_events),
            all_compliant: felt_from_u64(inputs.all_compliant),
            policy_kind: felt_from_u64(inputs.policy_kind),
            policy_limit: felt_from_u64(inputs.policy_limit),
            public_inputs_accumulator: inputs.public_inputs_accumulator.map(felt_from_u64),
        };

        public_inputs.validate_for_deserialization()?;

        let expected_policy_hash = public_inputs
            .try_policy_hash()
            .map_err(|err| match err {
                BatchError::InvalidPublicInputs(message) => {
                    BatchError::DeserializationFailed(message)
                }
                other => other,
            })?
            .map(|lane| lane.as_int());
        if inputs.policy_hash != expected_policy_hash {
            return Err(BatchError::DeserializationFailed(
                "policy_hash does not match policy_kind + policy_limit".to_string(),
            ));
        }

        Ok(public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::BatchProofMetadata;
    use crate::public_inputs::BatchPolicyKind;
    use ves_stark_primitives::felt_from_u64;

    fn uuid_from_batch_id_fields(batch_id: [u64; 4]) -> Uuid {
        let mut bytes = [0u8; 16];

        for (index, limb) in batch_id.iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&limb.to_le_bytes()[..4]);
        }

        Uuid::from_bytes(bytes)
    }

    fn sample_proof() -> BatchProof {
        BatchProof {
            proof_bytes: vec![1, 2, 3, 4, 5],
            proof_hash: BatchProof::compute_hash(&[1, 2, 3, 4, 5]).to_hex(),
            prev_state_root: [1, 2, 3, 4],
            new_state_root: [5, 6, 7, 8],
            metadata: BatchProofMetadata {
                batch_id: uuid_from_batch_id_fields([9, 10, 11, 12]).to_string(),
                num_events: 4,
                all_compliant: true,
                proving_time_ms: 100,
                trace_length: 256,
                proof_size: 5,
                prover_version: "0.1.0".to_string(),
            },
        }
    }

    fn sample_public_inputs() -> BatchPublicInputs {
        BatchPublicInputs::new(
            [1, 2, 3, 4].map(felt_from_u64),
            [5, 6, 7, 8].map(felt_from_u64),
            [9, 10, 11, 12].map(felt_from_u64),
            [13, 14, 15, 16].map(felt_from_u64),
            [17, 18, 19, 20].map(felt_from_u64),
            0,
            3,
            1234567890,
            4,
            true,
            BatchPolicyKind::AmlThreshold,
            10_000,
            [21, 22, 23, 24, 25, 26, 27, 28].map(felt_from_u64),
        )
    }

    #[test]
    fn test_json_serialization() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchProof::new(proof, inputs).unwrap();

        let json = serializable.to_json().unwrap();
        let deserialized = SerializableBatchProof::from_json(&json).unwrap();

        assert_eq!(deserialized.version, SerializableBatchProof::VERSION);
        assert_eq!(deserialized.proof.proof_bytes, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_binary_round_trip() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchProof::new(proof.clone(), inputs.clone()).unwrap();

        let bytes = serializable.to_bytes().unwrap();
        let deserialized = SerializableBatchProof::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.version, SerializableBatchProof::VERSION);
        assert_eq!(deserialized.proof.proof_bytes, proof.proof_bytes);
        assert_eq!(deserialized.proof.metadata, proof.metadata);
        assert_eq!(
            deserialized.public_inputs.prev_state_root,
            serializable.public_inputs.prev_state_root
        );
        assert_eq!(
            deserialized.public_inputs.new_state_root,
            serializable.public_inputs.new_state_root
        );
        assert_eq!(
            deserialized.public_inputs.timestamp,
            serializable.public_inputs.timestamp
        );
        assert_eq!(
            deserialized.public_inputs.policy_kind,
            serializable.public_inputs.policy_kind
        );
        assert_eq!(
            deserialized.public_inputs.public_inputs_accumulator,
            serializable.public_inputs.public_inputs_accumulator
        );
    }

    #[test]
    fn test_binary_round_trip_preserves_batch_id_as_uuid() {
        let mut proof = sample_proof();
        let mut inputs = sample_public_inputs();
        inputs.batch_id = [11, 22, 33, 44].map(felt_from_u64);

        let expected_batch_id = uuid_from_batch_id_fields([11, 22, 33, 44]).to_string();
        proof.metadata.batch_id = expected_batch_id.clone();

        let serializable = SerializableBatchProof::new(proof, inputs).unwrap();

        let bytes = serializable.to_bytes().unwrap();
        let deserialized = SerializableBatchProof::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.proof.metadata.batch_id, expected_batch_id);
    }

    #[test]
    fn test_binary_deserialization_rejects_short_payload() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let bytes = SerializableBatchProof::new(proof, inputs)
            .unwrap()
            .to_bytes()
            .unwrap();

        let short = &bytes[..bytes.len() - 1];
        assert!(matches!(
            SerializableBatchProof::from_bytes(short),
            Err(BatchError::DeserializationFailed(_))
        ));
    }

    #[test]
    fn test_binary_deserialization_rejects_invalid_all_compliant_flag() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let mut bytes = SerializableBatchProof::new(proof, inputs)
            .unwrap()
            .to_bytes()
            .unwrap();

        // all_compliant is the 4th u64 inside the fixed public input block.
        let all_compliant_offset = bytes.len() - SerializableBatchProof::PUBLIC_INPUT_BYTES + 184;
        bytes[all_compliant_offset..all_compliant_offset + 8].copy_from_slice(&2u64.to_le_bytes());

        assert!(matches!(
            SerializableBatchProof::from_bytes(&bytes),
            Err(BatchError::DeserializationFailed(_))
        ));
    }

    #[test]
    fn test_binary_deserialization_rejects_invalid_batch_id_limb() {
        let proof = sample_proof();
        let proof_len = proof.proof_bytes.len();
        let inputs = sample_public_inputs();
        let mut bytes = SerializableBatchProof::new(proof, inputs)
            .unwrap()
            .to_bytes()
            .unwrap();
        let batch_id_offset = 1 + 4 + proof_len + 32 + 32;
        bytes[batch_id_offset..batch_id_offset + 8]
            .copy_from_slice(&(u32::MAX as u64 + 1).to_le_bytes());

        assert!(matches!(
            SerializableBatchProof::from_bytes(&bytes),
            Err(BatchError::DeserializationFailed(_))
        ));
    }

    #[test]
    fn test_binary_deserialization_rejects_trailing_bytes() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let mut bytes = SerializableBatchProof::new(proof, inputs)
            .unwrap()
            .to_bytes()
            .unwrap();
        bytes.extend_from_slice(&[9, 9, 9]);

        assert!(matches!(
            SerializableBatchProof::from_bytes(&bytes),
            Err(BatchError::DeserializationFailed(_))
        ));
    }

    #[test]
    fn test_binary_round_trip_recomputes_proof_hash() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchProof::new(proof.clone(), inputs).unwrap();
        let bytes = serializable.to_bytes().unwrap();

        let deserialized = SerializableBatchProof::from_bytes(&bytes).unwrap();
        assert_eq!(
            deserialized.proof.proof_hash,
            BatchProof::compute_hash(&proof.proof_bytes).to_hex()
        );
    }

    #[test]
    fn test_binary_deserialization_accepts_legacy_v3_payload() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchProof::new(proof, inputs).unwrap();
        let mut bytes = serializable.to_bytes().unwrap();
        let metadata_json = serde_json::to_vec(&serializable.proof.metadata).unwrap();
        let metadata_bytes = 4 + metadata_json.len();

        bytes.truncate(bytes.len() - metadata_bytes);
        bytes[0] = SerializableBatchProof::LEGACY_VERSION;

        let deserialized = SerializableBatchProof::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.version, SerializableBatchProof::LEGACY_VERSION);
        assert_eq!(deserialized.proof.metadata.proving_time_ms, 0);
        assert_eq!(deserialized.proof.metadata.trace_length, 0);
        assert!(deserialized.proof.metadata.prover_version.is_empty());
        assert_eq!(
            deserialized.proof.metadata.batch_id,
            uuid_from_batch_id_fields([9, 10, 11, 12]).to_string()
        );
    }

    #[test]
    fn test_public_inputs_conversion() {
        let inputs = sample_public_inputs();
        let serializable = SerializableBatchPublicInputs::try_from(inputs.clone()).unwrap();
        let recovered = BatchPublicInputs::try_from(serializable).unwrap();

        for i in 0..4 {
            assert_eq!(recovered.prev_state_root[i], inputs.prev_state_root[i]);
            assert_eq!(recovered.new_state_root[i], inputs.new_state_root[i]);
        }
        assert_eq!(recovered.timestamp, inputs.timestamp);
        assert_eq!(recovered.policy_kind, inputs.policy_kind);
        assert_eq!(
            recovered.public_inputs_accumulator,
            inputs.public_inputs_accumulator
        );
    }

    #[test]
    fn test_public_inputs_conversion_rejects_mismatched_policy_hash() {
        let inputs = sample_public_inputs();
        let mut serializable = SerializableBatchPublicInputs::try_from(inputs).unwrap();
        serializable.policy_hash[0] = serializable.policy_hash[0].wrapping_add(1);

        assert!(BatchPublicInputs::try_from(serializable).is_err());
    }

    #[test]
    fn test_serializable_proof_new_rejects_invalid_public_inputs() {
        let proof = sample_proof();
        let inputs = BatchPublicInputs {
            policy_kind: felt_from_u64(99),
            ..sample_public_inputs()
        };

        assert!(matches!(
            SerializableBatchProof::new(proof, inputs),
            Err(BatchError::InvalidPublicInputs(_))
        ));
    }

    #[test]
    fn test_serializable_proof_new_rejects_inconsistent_proof_metadata() {
        let mut proof = sample_proof();
        proof.metadata.num_events += 1;
        let inputs = sample_public_inputs();

        assert!(matches!(
            SerializableBatchProof::new(proof, inputs),
            Err(BatchError::SerializationFailed(_))
        ));
    }

    #[test]
    fn test_json_deserialization_rejects_invalid_policy_kind() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let mut serializable = SerializableBatchProof::new(proof, inputs).unwrap();
        serializable.public_inputs.policy_kind = 99;

        let json = serde_json::to_string(&serializable).unwrap();
        assert!(matches!(
            SerializableBatchProof::from_json(&json),
            Err(BatchError::DeserializationFailed(_))
        ));
    }

    #[test]
    fn test_json_deserialization_rejects_mismatched_proof_hash() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let mut serializable = SerializableBatchProof::new(proof, inputs).unwrap();
        serializable.proof.proof_hash = "deadbeef".to_string();

        let json = serde_json::to_string(&serializable).unwrap();
        assert!(matches!(
            SerializableBatchProof::from_json(&json),
            Err(BatchError::DeserializationFailed(_))
        ));
    }

    #[test]
    fn test_json_serialization_rejects_tampered_proof_hash() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let mut serializable = SerializableBatchProof::new(proof, inputs).unwrap();
        serializable.proof.proof_hash = "deadbeef".to_string();

        assert!(matches!(
            serializable.to_json(),
            Err(BatchError::SerializationFailed(_))
        ));
    }

    #[test]
    fn test_binary_serialization_rejects_tampered_state_root() {
        let proof = sample_proof();
        let inputs = sample_public_inputs();
        let mut serializable = SerializableBatchProof::new(proof, inputs).unwrap();
        serializable.proof.new_state_root[0] ^= 1;

        assert!(matches!(
            serializable.to_bytes(),
            Err(BatchError::SerializationFailed(_))
        ));
    }

    #[test]
    fn test_json_serialization_stringifies_u64_fields() {
        let large_field_value = 9_007_199_254_740_993u64;
        let mut proof = sample_proof();
        proof.prev_state_root = [large_field_value, 2, 3, 4];
        proof.new_state_root = [5, 6, 7, large_field_value];
        proof.metadata.proving_time_ms = u64::MAX;

        let mut inputs = sample_public_inputs();
        inputs.prev_state_root = proof.prev_state_root.map(felt_from_u64);
        inputs.new_state_root = proof.new_state_root.map(felt_from_u64);
        inputs.public_inputs_accumulator = [large_field_value; 8].map(felt_from_u64);

        let serializable = SerializableBatchProof::new(proof, inputs).unwrap();
        let json = serializable.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            value["proof"]["new_state_root"][3],
            serde_json::json!(large_field_value.to_string())
        );
        assert_eq!(
            value["proof"]["metadata"]["proving_time_ms"],
            serde_json::json!(u64::MAX.to_string())
        );
        assert_eq!(
            value["public_inputs"]["prev_state_root"][0],
            serde_json::json!(large_field_value.to_string())
        );
        assert_eq!(
            value["public_inputs"]["public_inputs_accumulator"][0],
            serde_json::json!(large_field_value.to_string())
        );
    }
}
