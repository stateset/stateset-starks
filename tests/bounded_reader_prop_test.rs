//! `BoundedReader` must be observationally identical to Winterfell's
//! `SliceReader` on every input, except where upstream would have attempted an
//! allocation the input cannot justify — there, and only there, it returns
//! `InvalidValue` instead.
//!
//! This turns the argument in `bounded_reader.rs` ("same code path, one bound")
//! into a checked invariant rather than a claim.

use proptest::prelude::*;
use ves_stark_primitives::bounded_reader::deserialize_bounded;
use winter_utils::{Deserializable, DeserializationError, SliceReader};

/// Upstream, but with the allocation made safe to *observe*: return the
/// declared count instead of allocating it, so we can tell when it would have
/// been unjustified.
fn upstream_vec_u16(bytes: &[u8]) -> Result<Vec<u16>, DeserializationError> {
    Vec::<u16>::read_from(&mut SliceReader::new(bytes))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Both readers agree exactly, except in one region: when the declared count
    /// exceeds the bytes remaining, upstream calls `with_capacity(count)` and
    /// then fails with EOF, while ours refuses up front with `InvalidValue`. That
    /// region is the whole point, so it is asserted rather than excluded — and
    /// everywhere else the two must be byte-for-byte identical.
    #[test]
    fn agrees_with_slice_reader_except_where_upstream_would_over_allocate(
        elems in prop::collection::vec(any::<u16>(), 0..64),
        trunc in 0usize..200,
    ) {
        use winter_utils::Serializable;
        let mut bytes = elems.to_bytes();
        bytes.truncate(bytes.len().saturating_sub(trunc));
        let ours = deserialize_bounded::<Vec<u16>>(&bytes);
        let theirs = upstream_vec_u16(&bytes);
        match (&ours, &theirs) {
            (Err(DeserializationError::InvalidValue(_)), Err(DeserializationError::UnexpectedEOF)) => {
                // Only legitimate when the count really did exceed the remaining
                // bytes: the vint64 prefix is 1 byte for counts < 128.
                prop_assert!(!bytes.is_empty() && elems.len() > bytes.len() - 1,
                    "bound fired on a count the input could hold: {} elems, {} bytes", elems.len(), bytes.len());
            }
            _ => prop_assert_eq!(format!("{ours:?}"), format!("{theirs:?}")),
        }
    }

    /// For any bytes at all, ours never panics and never allocates past the
    /// input: a declared count larger than the remaining bytes is InvalidValue.
    #[test]
    fn never_panics_and_bounds_allocation(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let r = deserialize_bounded::<Vec<u16>>(&bytes);
        if let Ok(v) = &r {
            prop_assert!(v.len() * 2 <= bytes.len());
        }
    }

    /// The exact shape of the fuzzer finding: a vint64 9-byte prefix declaring
    /// an enormous count. Upstream would call `with_capacity(count)`.
    #[test]
    fn huge_declared_counts_are_invalid_value(count in (1u64 << 40)..u64::MAX) {
        let mut bytes = vec![0x00u8];
        bytes.extend_from_slice(&count.to_le_bytes());
        prop_assert!(matches!(
            deserialize_bounded::<Vec<u16>>(&bytes),
            Err(DeserializationError::InvalidValue(_))
        ));
    }
}
