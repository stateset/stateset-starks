//! Field arithmetic using Winterfell's BaseElement (Goldilocks 64-bit prime field)
//!
//! The Goldilocks field is defined by the prime p = 2^64 - 2^32 + 1.
//! This field is chosen for its efficient arithmetic on 64-bit architectures.

use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

/// The field element type used throughout VES STARK
pub type Felt = BaseElement;

/// Zero in the field
pub const FELT_ZERO: Felt = BaseElement::ZERO;

/// One in the field
pub const FELT_ONE: Felt = BaseElement::ONE;

/// The Goldilocks prime: p = 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xFFFFFFFF00000001;

/// Convert a u64 to a field element
#[inline]
pub fn felt_from_u64(value: u64) -> Felt {
    BaseElement::new(value)
}

/// Convert a field element to u64 (canonical representative)
#[inline]
pub fn felt_to_u64(felt: Felt) -> u64 {
    felt.as_int()
}

/// Convert a u32 to a field element
#[inline]
pub fn felt_from_u32(value: u32) -> Felt {
    BaseElement::new(value as u64)
}

/// Convert bytes to field element (little-endian, mod p)
pub fn felt_from_bytes_le(bytes: &[u8]) -> Felt {
    let mut value = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        value |= (b as u64) << (i * 8);
    }
    // Reduce mod p
    felt_from_u64(value % GOLDILOCKS_PRIME)
}

/// Convert a u128 to a field element (reduces mod p)
pub fn felt_from_u128(value: u128) -> Felt {
    felt_from_u64((value % (GOLDILOCKS_PRIME as u128)) as u64)
}

/// Array of 8 field elements (used to represent 256-bit hashes)
pub type FeltArray8 = [Felt; 8];

/// Create an array of 8 zero field elements
pub fn felt_array8_zero() -> FeltArray8 {
    [FELT_ZERO; 8]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_felt_conversion() {
        let value = 12345678u64;
        let felt = felt_from_u64(value);
        assert_eq!(felt_to_u64(felt), value);
    }

    #[test]
    fn test_felt_zero_one() {
        assert_eq!(felt_to_u64(FELT_ZERO), 0);
        assert_eq!(felt_to_u64(FELT_ONE), 1);
    }

    #[test]
    fn test_felt_arithmetic() {
        let a = felt_from_u64(100);
        let b = felt_from_u64(200);
        let sum = a + b;
        assert_eq!(felt_to_u64(sum), 300);
    }

    #[test]
    fn test_felt_overflow() {
        // Test that overflow wraps correctly in the field
        let max = felt_from_u64(GOLDILOCKS_PRIME - 1);
        let one = FELT_ONE;
        let result = max + one;
        assert_eq!(felt_to_u64(result), 0);
    }

    #[test]
    fn test_felt_from_u128() {
        // Test reduction of large values
        let large: u128 = (GOLDILOCKS_PRIME as u128) + 42;
        let felt = felt_from_u128(large);
        assert_eq!(felt_to_u64(felt), 42);
    }
}
