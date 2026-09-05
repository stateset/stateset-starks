//! VES STARK Verifier
//!
//! **No confidentiality guarantee:** proof transcripts can disclose witness amounts.
//! Use only for disclosed computational integrity; zero-knowledge requirements fail closed
//! through the privacy-aware APIs. Legacy low-level APIs remain integrity-only.
//!
//! This crate provides STARK proof verification for VES compliance proofs.
//! The verifier is stateless and can verify proofs using only the proof
//! bytes and public inputs.
//!
//! # Choosing an entry point
//!
//! Prefer the builder — it is the same set of checks as the free functions,
//! expressed as one call a reviewer can read:
//!
//! ```ignore
//! ComplianceVerification::new(&proof_bytes, &public_inputs)
//!     .amount_binding(&binding)
//!     .strict()
//!     .run()?;
//! ```
//!
//! It keeps the free functions' tripwire: `run()` refuses unless you chose
//! either `.amount_binding(..)` or explicitly `.witness_only()`.
//!
//! The free functions remain for callers that already use them.
//!
//! This crate exposes many verification functions. They are not variations on
//! taste: each name spells out, in full, which checks it performs. The
//! alternative — one function with four booleans — makes a call site whose
//! security properties cannot be read without chasing the argument list, and
//! makes it easy to silently drop a check by passing `false`.
//!
//! Read a name as `verify_<statement>_[auto]_[bound]_[with_amount_binding]_[strict|witness_strict]`:
//!
//! | Fragment | Meaning |
//! |---|---|
//! | `_auto` | Derive the policy from the public inputs instead of taking one from the caller. |
//! | `_bound` | Require the public inputs to carry `witnessCommitment`, and bind it. |
//! | `_with_amount_binding` | Also validate a canonical `PayloadAmountBinding` artifact linking the proved amount to the event payload. |
//! | `_strict` | Return `Err` on an invalid proof rather than an `Ok(result)` with `valid == false`. |
//! | `_witness_strict` | `_strict`, but explicitly acknowledging that **no** payload binding is checked. |
//!
//! **Pick by what you have:**
//!
//! - You have a payload-derived binding artifact — use
//!   [`verify_compliance_proof_auto_with_amount_binding_strict`]. This is the
//!   strongest statement available and the right default.
//! - You do not have one, and accept the weaker statement — use
//!   [`verify_compliance_proof_witness_strict`]. It verifies the proof against
//!   the witness commitment but proves nothing about the payload.
//!
//! [`verify_compliance_proof_strict`] deliberately **always returns an error**.
//! It is a tripwire, not an oversight: the name is ambiguous about whether a
//! payload binding was intended, so rather than quietly picking the weaker
//! behaviour it refuses and names the two explicit alternatives. The same holds
//! for the `agent_authorization` family.
//!
//! Note that the plainest name, [`verify_compliance_proof`], is also the
//! weakest: it returns `Ok` for an invalid proof with `valid == false`, so a
//! caller that ignores the field accepts anything. Prefer a `_strict` form.
//!
//! # Usage
//!
//! ```ignore
//! use ves_stark_verifier::verify_compliance_proof_auto_with_amount_binding_strict;
//!
//! // Requires a canonical payload amount binding artifact for strict verification.
//! let result =
//!     verify_compliance_proof_auto_with_amount_binding_strict(&proof_bytes, &public_inputs, &binding)?;
//! assert!(result.valid);
//! ```

// Crate-level lints.
//
// `forbid(unsafe_code)` is meaningful here rather than decorative: this crate
// contains no `unsafe`, and the only crate in the workspace that does
// (`ves-stark-zig`, the C FFI surface) is deliberately excluded. `forbid` — not
// `deny` — so it cannot be locally overridden by an `allow` attribute.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod builder;
mod error;
mod verify;

pub use builder::ComplianceVerification;
pub use error::{validate_hex_string, VerifierError, MAX_PROOF_SIZE, PROOF_VERSION};
pub use verify::{
    verify_agent_authorization_proof, verify_agent_authorization_proof_auto,
    verify_agent_authorization_proof_auto_bound,
    verify_agent_authorization_proof_auto_bound_strict,
    verify_agent_authorization_proof_auto_bound_witness_strict,
    verify_agent_authorization_proof_auto_strict,
    verify_agent_authorization_proof_auto_with_amount_binding,
    verify_agent_authorization_proof_auto_with_amount_binding_strict,
    verify_agent_authorization_proof_auto_witness_strict, verify_agent_authorization_proof_strict,
    verify_agent_authorization_proof_with_amount_binding,
    verify_agent_authorization_proof_with_amount_binding_strict,
    verify_agent_authorization_proof_witness_strict, verify_compliance_proof,
    verify_compliance_proof_auto, verify_compliance_proof_auto_bound,
    verify_compliance_proof_auto_bound_strict, verify_compliance_proof_auto_bound_witness_strict,
    verify_compliance_proof_auto_strict, verify_compliance_proof_auto_with_amount_binding,
    verify_compliance_proof_auto_with_amount_binding_strict,
    verify_compliance_proof_auto_witness_strict, verify_compliance_proof_strict,
    verify_compliance_proof_with_amount_binding,
    verify_compliance_proof_with_amount_binding_strict, verify_compliance_proof_witness_strict,
    ComplianceVerifier, VerificationResult,
};
