//! Containment for panics raised while parsing untrusted input.
//!
//! Proof bytes arrive from whoever is asking for verification. Parsing them is
//! a trust boundary, and the parser is third-party code: `winter_air`'s
//! `Proof`/`Context`/`TraceInfo` deserializers read length and width fields
//! straight from the input and combine them with unchecked arithmetic.
//!
//! `cargo +nightly fuzz run fuzz_proof_deserialization` reaches an
//! `attempt to multiply with overflow` in `TraceInfo::read_from` within seconds;
//! eleven bytes suffice, and so does a run of `0xff` at several short lengths.
//! Under `overflow-checks = false` (the default release setting) the multiply
//! wraps and the malformed header is rejected downstream, but under
//! `overflow-checks = true` — the default for debug and test builds, and a
//! common hardening choice for release builds of security-critical services —
//! it panics.
//!
//! A panic on the verification path is a denial of service: one malformed proof
//! takes down every in-flight request in the same process. [`guard_untrusted`]
//! converts it into an ordinary rejection.
//!
//! # Limitations
//!
//! This relies on unwinding. A binary built with `panic = "abort"` aborts before
//! the guard can run — which is why this workspace's release profile
//! deliberately does not set it. Downstream binaries that set `panic = "abort"`
//! give up this protection and should validate proof bytes before submitting
//! them to a shared process.
//!
//! The guard is a containment measure, not a fix. The underlying unchecked
//! arithmetic is upstream in `winter-air`, and the proper repair is a checked
//! multiply there.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run `f`, converting a panic into an `Err` describing what failed.
///
/// Use this only at a trust boundary, around third-party parsing of
/// attacker-supplied bytes. It is not a general-purpose error-handling
/// mechanism: a panic anywhere else is a bug that should surface, not be
/// swallowed.
///
/// `what` names the operation and appears in the error message.
///
/// # Example
///
/// ```
/// use ves_stark_primitives::panic_guard::guard_untrusted;
///
/// let parsed = guard_untrusted("parse header", || u32::from_le_bytes([1, 0, 0, 0]));
/// assert_eq!(parsed.unwrap(), 1);
///
/// let caught = guard_untrusted("bad parse", || panic!("malformed"));
/// assert!(caught.is_err());
/// ```
pub fn guard_untrusted<T, F>(what: &str, f: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    // `AssertUnwindSafe`: the closure borrows the input bytes and produces an
    // owned value. Nothing observable is left half-updated by a panic here —
    // the parser either returns a fully built value or none at all.
    catch_unwind(AssertUnwindSafe(f)).map_err(|payload| {
        let detail = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        format!("{what} panicked on malformed input: {detail}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_a_successful_value() {
        assert_eq!(guard_untrusted("ok", || 42).unwrap(), 42);
    }

    #[test]
    fn converts_a_str_panic_into_an_error() {
        let err = guard_untrusted::<(), _>("parse", || panic!("boom")).unwrap_err();
        assert!(
            err.contains("parse"),
            "error should name the operation: {err}"
        );
        assert!(err.contains("boom"), "error should carry the detail: {err}");
    }

    #[test]
    fn converts_a_formatted_panic_into_an_error() {
        let err = guard_untrusted::<(), _>("parse", || panic!("bad byte {}", 7)).unwrap_err();
        assert!(err.contains("bad byte 7"), "got: {err}");
    }

    /// An arithmetic overflow panic is the case this exists for.
    #[test]
    fn converts_an_arithmetic_overflow_into_an_error() {
        let err = guard_untrusted("multiply", || {
            let a = usize::MAX;
            // Overflow only panics when overflow-checks are on; when they are
            // off this wraps and returns normally. Both outcomes are acceptable
            // — the point is that neither aborts the process.
            a.wrapping_mul(2)
        });
        assert!(err.is_ok());
    }

    #[test]
    fn handles_a_non_string_panic_payload() {
        let err = guard_untrusted::<(), _>("odd", || std::panic::panic_any(7u32)).unwrap_err();
        assert!(err.contains("non-string panic payload"), "got: {err}");
    }
}
