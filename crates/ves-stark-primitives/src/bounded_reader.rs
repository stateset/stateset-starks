//! A `ByteReader` that refuses to allocate more than the input can justify.
//!
//! # The defect this closes
//!
//! `winter-utils`'s provided `ByteReader::read_many` is
//!
//! ```text
//! let mut result = Vec::with_capacity(num_elements);   // byte_reader.rs:194
//! ```
//!
//! where `num_elements` is a length prefix read straight from the input and
//! never compared against the bytes remaining. A 39-byte proof can declare
//! 2^56 elements; the measured request is ~72 PB. Rust handles allocation
//! failure with `handle_alloc_error`, which **aborts** rather than unwinds, so
//! no `catch_unwind` — including [`crate::panic_guard::guard_untrusted`] — can
//! contain it. Found by `fuzz_proof_deserialization`; still present in the
//! newest upstream release (`winter-air 0.13.1`).
//!
//! # Why this is fixable here after all
//!
//! `Proof::from_bytes` builds a `SliceReader` internally, so there is no way to
//! bound *that* reader. But `Deserializable::read_from` is generic over any
//! `R: ByteReader`, and `read_many` is a *provided* trait method — so a reader
//! that implements the six required methods can override it. [`BoundedReader`]
//! is `SliceReader` with one extra check:
//!
//! > every element occupies at least one byte, so a declared count larger than
//! > the bytes remaining is malformed by construction.
//!
//! That turns the abort into a `DeserializationError::InvalidValue` before any
//! allocation happens. Winterfell's own deserializers are otherwise unchanged:
//! this is the same code path, with a bound.
//!
//! Use [`deserialize_bounded`] wherever proof bytes from an untrusted source
//! are parsed. `Proof::from_bytes` must not be called on untrusted input.

use winter_utils::{ByteReader, Deserializable, DeserializationError};

/// A slice reader whose `read_many` refuses declared lengths the input cannot
/// hold. See the module docs.
pub struct BoundedReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> BoundedReader<'a> {
    /// Wrap a byte slice.
    pub fn new(source: &'a [u8]) -> Self {
        Self { source, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.source.len().saturating_sub(self.pos)
    }
}

impl ByteReader for BoundedReader<'_> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        let b = self.source[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        Ok(self.source[self.pos])
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.check_eor(len)?;
        let out = &self.source[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.check_eor(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.source[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    /// Checked rather than `pos + num_bytes` as upstream does: a caller-supplied
    /// `num_bytes` near `usize::MAX` must not wrap into a false "fits".
    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        match self.pos.checked_add(num_bytes) {
            Some(end) if end <= self.source.len() => Ok(()),
            _ => Err(DeserializationError::UnexpectedEOF),
        }
    }

    fn has_more_bytes(&self) -> bool {
        self.pos < self.source.len()
    }

    /// The override that closes the allocation DoS.
    fn read_many<D>(&mut self, num_elements: usize) -> Result<Vec<D>, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        let remaining = self.remaining();
        if num_elements > remaining {
            return Err(DeserializationError::InvalidValue(format!(
                "declared {num_elements} elements but only {remaining} bytes remain; \
                 every element needs at least one byte"
            )));
        }
        let mut result = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            result.push(D::read_from(self)?);
        }
        Ok(result)
    }
}

/// Deserialize `D` from untrusted bytes with allocation bounded by input size.
///
/// Drop-in for `D::read_from_bytes` / `Proof::from_bytes` at a trust boundary.
pub fn deserialize_bounded<D: Deserializable>(bytes: &[u8]) -> Result<D, DeserializationError> {
    D::read_from(&mut BoundedReader::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use winter_utils::Serializable;

    /// `Vec<T>` on the wire is a vint64 length prefix then the elements. The
    /// upstream `read_many` would `with_capacity` the declared length first.
    #[test]
    fn declared_length_beyond_input_is_rejected_before_allocating() {
        // vint64 9-byte form: 0x00 marker, then the u64 little-endian.
        let mut bytes = vec![0x00u8];
        bytes.extend_from_slice(&(1u64 << 56).to_le_bytes());
        let err = deserialize_bounded::<Vec<u8>>(&bytes).unwrap_err();
        assert!(
            matches!(err, DeserializationError::InvalidValue(_)),
            "expected InvalidValue, got {err:?}"
        );
    }

    #[test]
    fn honest_lengths_round_trip() {
        let bytes = vec![10u8, 20, 30].to_bytes();
        let v = deserialize_bounded::<Vec<u8>>(&bytes).unwrap();
        assert_eq!(v, vec![10, 20, 30]);
    }

    /// A declared count the input *can* hold, but whose elements run out of
    /// bytes part-way, is plain EOF — the bound must not fire spuriously.
    #[test]
    fn short_input_is_eof_not_panic() {
        // 3 x u16 = prefix + 6 bytes; keep prefix + 3, so count 3 <= remaining 3.
        let mut bytes = vec![1u16, 2, 3].to_bytes();
        bytes.truncate(1 + 3);
        assert!(matches!(
            deserialize_bounded::<Vec<u16>>(&bytes).unwrap_err(),
            DeserializationError::UnexpectedEOF
        ));
    }

    /// The bound fires before EOF when the count itself is impossible.
    #[test]
    fn impossible_count_is_invalid_value_not_eof() {
        let mut bytes = vec![10u8, 20, 30].to_bytes();
        bytes.truncate(2);
        assert!(matches!(
            deserialize_bounded::<Vec<u8>>(&bytes).unwrap_err(),
            DeserializationError::InvalidValue(_)
        ));
    }

    /// `check_eor` must not wrap on an adversarial length.
    #[test]
    fn check_eor_does_not_overflow() {
        let r = BoundedReader::new(&[1, 2, 3]);
        assert!(r.check_eor(usize::MAX).is_err());
        assert!(r.check_eor(3).is_ok());
        assert!(r.check_eor(4).is_err());
    }
}
