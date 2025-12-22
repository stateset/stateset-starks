//! Hash utilities for converting between 32-byte hashes and field elements
//!
//! In VES STARK, 32-byte hashes (SHA-256) are represented as 8 x u32 limbs,
//! each injected into a field element. This provides an injective mapping
//! from Hash256 to [Felt; 8].

use crate::field::{Felt, felt_from_u64, felt_to_u64, FeltArray8, felt_array8_zero};
use sha2::{Sha256, Digest};

/// A 256-bit hash (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// Create a zero hash
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes: Vec<u8> = hex::decode(hex)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Convert to hex string (lowercase, no 0x prefix)
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute SHA-256 hash of data
    pub fn sha256(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Compute SHA-256 with domain separation
    pub fn sha256_with_domain(domain: &[u8], data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl serde::Serialize for Hash256 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Hash256 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Convert a 32-byte hash to 8 field elements (each from a u32 limb)
///
/// The hash is interpreted as 8 little-endian u32 values, each mapped
/// to a field element. This is injective since u32 < Goldilocks prime.
pub fn hash_to_felts(hash: &Hash256) -> FeltArray8 {
    let mut result = felt_array8_zero();
    for i in 0..8 {
        let offset = i * 4;
        let limb = u32::from_le_bytes([
            hash.0[offset],
            hash.0[offset + 1],
            hash.0[offset + 2],
            hash.0[offset + 3],
        ]);
        result[i] = felt_from_u64(limb as u64);
    }
    result
}

/// Convert 8 field elements back to a 32-byte hash
///
/// Each field element is assumed to contain a u32 value (< 2^32).
pub fn felts_to_hash(felts: &FeltArray8) -> Hash256 {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let limb = felt_to_u64(felts[i]) as u32;
        let offset = i * 4;
        bytes[offset..offset + 4].copy_from_slice(&limb.to_le_bytes());
    }
    Hash256(bytes)
}

/// Convert a u64 value to 2 field elements (low and high u32)
pub fn u64_to_felt_pair(value: u64) -> (Felt, Felt) {
    let low = (value & 0xFFFFFFFF) as u32;
    let high = (value >> 32) as u32;
    (felt_from_u64(low as u64), felt_from_u64(high as u64))
}

/// Convert 2 field elements (low and high u32) back to u64
pub fn felt_pair_to_u64(low: Felt, high: Felt) -> u64 {
    let low_val = felt_to_u64(low) as u32;
    let high_val = felt_to_u64(high) as u32;
    (low_val as u64) | ((high_val as u64) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_felts_roundtrip() {
        let original = Hash256::sha256(b"test data");
        let felts = hash_to_felts(&original);
        let recovered = felts_to_hash(&felts);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_hash_from_hex() {
        let hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let hash = Hash256::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
    }

    #[test]
    fn test_hash_from_hex_with_prefix() {
        let hex = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let hash = Hash256::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), &hex[2..]);
    }

    #[test]
    fn test_sha256_domain() {
        let hash1 = Hash256::sha256(b"test");
        let hash2 = Hash256::sha256_with_domain(b"domain", b"test");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_u64_felt_pair_roundtrip() {
        let original = 0x123456789ABCDEF0u64;
        let (low, high) = u64_to_felt_pair(original);
        let recovered = felt_pair_to_u64(low, high);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_hash_serialization() {
        let hash = Hash256::sha256(b"test");
        let json = serde_json::to_string(&hash).unwrap();
        let recovered: Hash256 = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, recovered);
    }
}
