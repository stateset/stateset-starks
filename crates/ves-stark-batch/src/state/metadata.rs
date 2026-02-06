//! Batch metadata for state transitions

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ves_stark_primitives::{felt_from_u64, rescue::rescue_hash, Felt};

/// Metadata about a batch of compliance events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMetadata {
    /// Unique identifier for this batch
    pub batch_id: Uuid,

    /// Tenant identifier
    pub tenant_id: Uuid,

    /// Store identifier
    pub store_id: Uuid,

    /// First sequence number in this batch
    pub sequence_start: u64,

    /// Last sequence number in this batch (inclusive)
    pub sequence_end: u64,

    /// Timestamp when batch was created (Unix epoch seconds)
    pub timestamp: u64,
}

impl BatchMetadata {
    /// Create new batch metadata
    pub fn new(
        batch_id: Uuid,
        tenant_id: Uuid,
        store_id: Uuid,
        sequence_start: u64,
        sequence_end: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            batch_id,
            tenant_id,
            store_id,
            sequence_start,
            sequence_end,
            timestamp,
        }
    }

    /// Create batch metadata with auto-generated batch ID and current timestamp
    pub fn with_sequence(
        tenant_id: Uuid,
        store_id: Uuid,
        sequence_start: u64,
        sequence_end: u64,
    ) -> Self {
        Self {
            batch_id: Uuid::new_v4(),
            tenant_id,
            store_id,
            sequence_start,
            sequence_end,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create batch metadata with current timestamp (convenience constructor)
    pub fn with_ids(
        batch_id: Uuid,
        tenant_id: Uuid,
        store_id: Uuid,
        sequence_start: u64,
        sequence_end: u64,
    ) -> Self {
        Self {
            batch_id,
            tenant_id,
            store_id,
            sequence_start,
            sequence_end,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Convert UUID to 4 field elements (as u32 limbs)
    pub fn uuid_to_felts(uuid: &Uuid) -> [Felt; 4] {
        let bytes = uuid.as_bytes();
        [
            felt_from_u64(u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as u64),
            felt_from_u64(u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as u64),
            felt_from_u64(u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as u64),
            felt_from_u64(u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as u64),
        ]
    }

    /// Compute Rescue hash of metadata for state root computation
    pub fn to_rescue_hash(&self) -> [Felt; 4] {
        let batch_id_felts = Self::uuid_to_felts(&self.batch_id);
        let tenant_id_felts = Self::uuid_to_felts(&self.tenant_id);
        let store_id_felts = Self::uuid_to_felts(&self.store_id);

        // Build input: batch_id (4) + tenant_id (4) + store_id (4) + sequence (2) + timestamp (1) = 15 elements
        let input: Vec<Felt> = vec![
            batch_id_felts[0],
            batch_id_felts[1],
            batch_id_felts[2],
            batch_id_felts[3],
            tenant_id_felts[0],
            tenant_id_felts[1],
            tenant_id_felts[2],
            tenant_id_felts[3],
            store_id_felts[0],
            store_id_felts[1],
            store_id_felts[2],
            store_id_felts[3],
            felt_from_u64(self.sequence_start),
            felt_from_u64(self.sequence_end),
            felt_from_u64(self.timestamp),
        ];

        rescue_hash(&input)
    }

    /// Get batch_id as field elements
    pub fn batch_id_felts(&self) -> [Felt; 4] {
        Self::uuid_to_felts(&self.batch_id)
    }

    /// Get tenant_id as field elements
    pub fn tenant_id_felts(&self) -> [Felt; 4] {
        Self::uuid_to_felts(&self.tenant_id)
    }

    /// Get store_id as field elements
    pub fn store_id_felts(&self) -> [Felt; 4] {
        Self::uuid_to_felts(&self.store_id)
    }

    /// Number of events in this batch
    pub fn num_events(&self) -> u64 {
        self.sequence_end - self.sequence_start + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let metadata = BatchMetadata::with_sequence(Uuid::new_v4(), Uuid::new_v4(), 0, 9);

        assert_eq!(metadata.num_events(), 10);
        assert!(metadata.timestamp > 0);
    }

    #[test]
    fn test_uuid_to_felts() {
        let uuid = Uuid::new_v4();
        let felts = BatchMetadata::uuid_to_felts(&uuid);

        // Verify all elements are valid field elements (< 2^32 each)
        for felt in &felts {
            assert!(felt.as_int() < (1u64 << 32));
        }
    }

    #[test]
    fn test_metadata_hash_deterministic() {
        let metadata = BatchMetadata::new(
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            0,
            15,
            1234567890,
        );

        let hash1 = metadata.to_rescue_hash();
        let hash2 = metadata.to_rescue_hash();

        assert_eq!(hash1, hash2);
    }
}
