//! One entry point for compliance verification, with the checks spelled out.
//!
//! The free functions in [`crate::verify`] encode every combination of checks
//! in their names (`_auto`, `_bound`, `_with_amount_binding`, `_strict`,
//! `_witness_strict`), which keeps a call site honest but leaves a reviewer
//! with 26 functions to tell apart. [`ComplianceVerification`] is the same
//! decision expressed as a builder:
//!
//! ```ignore
//! use ves_stark_verifier::ComplianceVerification;
//!
//! let result = ComplianceVerification::new(&proof_bytes, &public_inputs)
//!     .amount_binding(&binding)   // the strongest statement available
//!     .strict()                   // Err on an invalid proof, not Ok(valid=false)
//!     .run()?;
//! ```
//!
//! # The tripwire is preserved
//!
//! The free-function API refuses to let a caller *silently* skip the payload
//! binding: `verify_compliance_proof_strict` always errors, forcing a choice
//! between `_with_amount_binding_strict` and `_witness_strict`. The builder
//! keeps that property. [`ComplianceVerification::run`] returns
//! [`VerifierError::PayloadAmountBindingRequired`] unless the caller has either
//! supplied an [`amount_binding`](ComplianceVerification::amount_binding) or
//! explicitly acknowledged the weaker statement with
//! [`witness_only`](ComplianceVerification::witness_only). There is no default.
//!
//! Every path dispatches to the existing, tested free functions; the builder
//! adds no verification logic of its own.

use ves_stark_air::policy::Policy;
use ves_stark_primitives::public_inputs::{
    witness_commitment_hex_to_u64, CompliancePublicInputs, PayloadAmountBinding,
};

use crate::error::VerifierError;
use crate::verify::{
    verify_compliance_proof, verify_compliance_proof_auto, verify_compliance_proof_auto_bound,
    verify_compliance_proof_auto_with_amount_binding, verify_compliance_proof_with_amount_binding,
    VerificationResult,
};

/// How the proved witness is tied to something the verifier trusts.
#[derive(Clone, Copy)]
enum Binding<'a> {
    /// Validate a payload-derived amount binding artifact as well as the proof.
    Payload(&'a PayloadAmountBinding),
    /// Verify against a caller-supplied commitment only.
    Witness(&'a [u64; 4]),
    /// Verify against the `witnessCommitment` carried in the public inputs.
    WitnessFromPublicInputs,
}

/// Builder for a single compliance-proof verification. See the module docs.
#[must_use = "a verification that is never run checks nothing"]
pub struct ComplianceVerification<'a> {
    proof_bytes: &'a [u8],
    public_inputs: &'a CompliancePublicInputs,
    policy: Option<&'a Policy>,
    binding: Option<Binding<'a>>,
    strict: bool,
}

impl<'a> ComplianceVerification<'a> {
    /// Start a verification of `proof_bytes` against `public_inputs`.
    ///
    /// The policy is derived from the public inputs unless
    /// [`policy`](Self::policy) is given.
    pub fn new(proof_bytes: &'a [u8], public_inputs: &'a CompliancePublicInputs) -> Self {
        Self {
            proof_bytes,
            public_inputs,
            policy: None,
            binding: None,
            strict: false,
        }
    }

    /// Verify against this policy instead of the one named in the public
    /// inputs. The verifier still checks the two agree.
    pub fn policy(mut self, policy: &'a Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Also validate a payload-derived amount binding artifact. This is the
    /// strongest statement available and the right default for production.
    pub fn amount_binding(mut self, binding: &'a PayloadAmountBinding) -> Self {
        self.binding = Some(Binding::Payload(binding));
        self
    }

    /// Verify against an explicit witness commitment, acknowledging that **no
    /// payload binding is checked**: the proof shows a compliant amount exists
    /// behind this commitment, not that it is the amount on the event.
    pub fn witness_commitment(mut self, commitment: &'a [u64; 4]) -> Self {
        self.binding = Some(Binding::Witness(commitment));
        self
    }

    /// Verify against the `witnessCommitment` field of the public inputs,
    /// with the same acknowledgement as [`witness_commitment`](Self::witness_commitment).
    /// Errors at [`run`](Self::run) if the field is absent.
    pub fn witness_only(mut self) -> Self {
        self.binding = Some(Binding::WitnessFromPublicInputs);
        self
    }

    /// Return `Err` for an invalid proof instead of `Ok` with `valid == false`.
    ///
    /// Prefer this: a caller that ignores the `valid` field accepts anything.
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Run the verification.
    ///
    /// # Errors
    ///
    /// [`VerifierError::PayloadAmountBindingRequired`] if neither
    /// [`amount_binding`](Self::amount_binding) nor a witness-only choice was
    /// made — the builder refuses to pick the weaker statement on your behalf.
    /// Otherwise, whatever the underlying verifier returns.
    pub fn run(self) -> Result<VerificationResult, VerifierError> {
        let binding = self.binding.ok_or_else(|| {
            VerifierError::PayloadAmountBindingRequired(
                "choose .amount_binding(&b) for payload-complete verification, or \
                 .witness_only() / .witness_commitment(&c) to explicitly accept the \
                 weaker witness-only statement"
                    .to_string(),
            )
        })?;

        let result = match (binding, self.policy) {
            (Binding::Payload(b), Some(p)) => verify_compliance_proof_with_amount_binding(
                self.proof_bytes,
                self.public_inputs,
                p,
                b,
            ),
            (Binding::Payload(b), None) => verify_compliance_proof_auto_with_amount_binding(
                self.proof_bytes,
                self.public_inputs,
                b,
            ),
            (Binding::Witness(w), Some(p)) => {
                verify_compliance_proof(self.proof_bytes, self.public_inputs, p, w)
            }
            (Binding::Witness(w), None) => {
                verify_compliance_proof_auto(self.proof_bytes, self.public_inputs, w)
            }
            (Binding::WitnessFromPublicInputs, None) => {
                verify_compliance_proof_auto_bound(self.proof_bytes, self.public_inputs)
            }
            (Binding::WitnessFromPublicInputs, Some(p)) => {
                let hex = self
                    .public_inputs
                    .witness_commitment
                    .as_deref()
                    .ok_or(VerifierError::WitnessCommitmentMismatch)?;
                let w = witness_commitment_hex_to_u64(hex).map_err(|e| {
                    VerifierError::InvalidHexFormat {
                        field: "witnessCommitment".to_string(),
                        reason: e.to_string(),
                    }
                })?;
                verify_compliance_proof(self.proof_bytes, self.public_inputs, p, &w)
            }
        }?;

        if self.strict {
            result.ensure_valid()
        } else {
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ves_stark_primitives::public_inputs::{compute_policy_hash, PolicyParams};

    fn inputs() -> CompliancePublicInputs {
        let params = PolicyParams::threshold(10_000);
        let hash = compute_policy_hash("aml.threshold", &params)
            .unwrap()
            .to_hex();
        CompliancePublicInputs {
            event_id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            store_id: uuid::Uuid::nil(),
            sequence_number: 1,
            payload_kind: 1,
            payload_plain_hash: "0".repeat(64),
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: "aml.threshold".into(),
            policy_params: params,
            policy_hash: hash,
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
        }
    }

    /// The tripwire: no binding choice means no verification, loudly.
    #[test]
    fn run_without_a_binding_choice_is_refused() {
        let pi = inputs();
        let err = ComplianceVerification::new(&[1, 2, 3], &pi)
            .run()
            .unwrap_err();
        assert!(
            matches!(err, VerifierError::PayloadAmountBindingRequired(_)),
            "{err}"
        );
    }

    /// Choosing `.strict()` alone is not a binding choice either.
    #[test]
    fn strict_alone_is_still_refused() {
        let pi = inputs();
        let err = ComplianceVerification::new(&[1, 2, 3], &pi)
            .strict()
            .run()
            .unwrap_err();
        assert!(matches!(
            err,
            VerifierError::PayloadAmountBindingRequired(_)
        ));
    }

    /// `witness_only` with no `witnessCommitment` in the inputs cannot proceed.
    #[test]
    fn witness_only_requires_the_field() {
        let pi = inputs();
        let err = ComplianceVerification::new(&[1, 2, 3], &pi)
            .witness_only()
            .run()
            .unwrap_err();
        assert!(
            !matches!(err, VerifierError::PayloadAmountBindingRequired(_)),
            "{err}"
        );
    }

    /// With a binding chosen, garbage bytes reach the real verifier and are
    /// rejected there — as an `Err`, not a panic.
    #[test]
    fn explicit_witness_reaches_the_verifier() {
        let pi = inputs();
        let err = ComplianceVerification::new(&[0xff; 11], &pi)
            .witness_commitment(&[0; 4])
            .strict()
            .run()
            .unwrap_err();
        assert!(
            matches!(err, VerifierError::DeserializationError(_)),
            "{err}"
        );
    }
}
