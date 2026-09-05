//! Public refund accounting with STARK-bound transition context.
//!
//! Amounts and balances are disclosed. Arithmetic is verified natively with checked
//! u64 operations, not privately inside the AIR. Authenticated state continuity is
//! enforced by the ledger's compare-and-swap transaction.

use crate::{
    approval::{ApprovalAuthority, SignedApproval},
    prepare_with_salt, CommerceApproval, CommerceError, CommerceOperation, CommerceProof,
    CommerceRequest,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ves_stark_primitives::{
    hash::Hash256, payload_amount::amount_witness_commitment,
    public_inputs::witness_commitment_u64_to_hex,
};

/// Public state of one captured payment; imported from an authenticated capture feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefundState {
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Owning store.
    pub store_id: Uuid,
    /// Stable capture identifier.
    pub capture_id: String,
    /// Currency code.
    pub currency: String,
    /// Monetary decimal scale.
    pub decimal_places: u8,
    /// Captured balance in integer units.
    pub captured: u64,
    /// Total reserved or executed refunds in integer units.
    pub refunded: u64,
    /// Monotonically increasing state version.
    pub version: u64,
}

impl RefundState {
    /// Check scope, money representation, and conservation of the captured balance.
    pub fn validate(&self) -> Result<(), CommerceError> {
        if self.refunded > self.captured {
            return Err(CommerceError::Refund(
                "refunded total exceeds captured balance",
            ));
        }
        self.request(Uuid::from_u128(1), 0, None).validate()
    }

    /// Canonical state commitment, including capture identity, balances, and version.
    pub fn commitment(&self) -> Result<String, CommerceError> {
        self.validate()?;
        digest(b"STATESET_REFUND_STATE_V1", self)
    }

    fn request(
        &self,
        event_id: Uuid,
        sequence_number: u64,
        state_transition_hash: Option<String>,
    ) -> CommerceRequest {
        CommerceRequest {
            state_transition_hash,
            event_id,
            tenant_id: self.tenant_id,
            store_id: self.store_id,
            sequence_number,
            operation: CommerceOperation::Refund,
            reference: self.capture_id.clone(),
            currency: self.currency.clone(),
            decimal_places: self.decimal_places,
            cap: self.captured.saturating_sub(self.refunded),
        }
    }
}

/// Fully disclosed refund transition. Both states are committed into the approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefundTransition {
    /// Authenticated predecessor state.
    pub before: RefundState,
    /// Successor state after reserving the refund.
    pub after: RefundState,
    /// Positive refund amount in the state's currency units.
    pub amount: u64,
}

impl RefundTransition {
    /// Compute a transition without overflow or overspending.
    pub fn new(before: RefundState, amount: u64) -> Result<Self, CommerceError> {
        before.validate()?;
        if amount == 0 {
            return Err(CommerceError::Refund("refund amount must be positive"));
        }
        let mut after = before.clone();
        after.refunded = before
            .refunded
            .checked_add(amount)
            .ok_or(CommerceError::Refund("refunded total overflow"))?;
        after.version = before
            .version
            .checked_add(1)
            .ok_or(CommerceError::Refund("state version overflow"))?;
        after.validate()?;
        Ok(Self {
            before,
            after,
            amount,
        })
    }

    /// Reject changed currency, capture, scope, version, or incorrect arithmetic.
    pub fn validate(&self) -> Result<(), CommerceError> {
        if Self::new(self.before.clone(), self.amount)? != *self {
            return Err(CommerceError::Refund(
                "successor does not match the refund transition",
            ));
        }
        Ok(())
    }

    /// Canonical commitment to both states and the refund amount.
    pub fn commitment(&self) -> Result<String, CommerceError> {
        self.validate()?;
        digest(b"STATESET_REFUND_TRANSITION_V1", self)
    }

    /// Signed-record baseline: authenticate and check all disclosed accounting and
    /// payload commitments without evaluating a STARK. Does not consume an approval.
    pub fn verify_signed_disclosed(
        &self,
        signed: &SignedApproval,
        authority: &ApprovalAuthority,
        now: u64,
        expected_before: &str,
    ) -> Result<(), CommerceError> {
        signed.verify(authority, now)?;
        self.validate()?;
        if self.before.commitment()? != expected_before {
            return Err(CommerceError::Refund(
                "stale or unexpected predecessor state",
            ));
        }
        let request = &signed.terms.approval.request;
        let expected = self.before.request(
            request.event_id,
            request.sequence_number,
            Some(self.commitment()?),
        );
        if *request != expected {
            return Err(CommerceError::Refund(
                "approval does not authorize this transition",
            ));
        }
        let c = amount_witness_commitment(self.amount);
        let payload = ves_stark_primitives::payload_v2::payload_plain_hash_v2(
            &c,
            request.context_hash()?.as_bytes(),
        );
        if payload.to_hex() != signed.terms.approval.payload_hash {
            return Err(CommerceError::Refund(
                "approval payload does not commit the accounting amount",
            ));
        }
        Ok(())
    }
}

/// Disclosed state transition and its context-bound cap proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefundProof {
    /// Public before/after accounting.
    pub transition: RefundTransition,
    /// STARK proving the approved per-event amount cap.
    pub proof: CommerceProof,
}

/// Prepare and prove a disclosed refund at trusted intake.
/// Returns the unsigned approval for the intake authority to sign.
pub fn prove_refund_disclosed(
    before: RefundState,
    amount: u64,
    event_id: Uuid,
    sequence_number: u64,
) -> Result<(RefundProof, CommerceApproval), CommerceError> {
    let transition = RefundTransition::new(before, amount)?;
    let request =
        transition
            .before
            .request(event_id, sequence_number, Some(transition.commitment()?));
    // The amount is explicitly public. Zero salt permits the independent verifier
    // to check equality between the accounting amount and the proved commitment.
    let prepared = prepare_with_salt(amount, &request, [0; 4])?;
    let approval = prepared.approval();
    let proof = prepared.prove()?;
    Ok((RefundProof { transition, proof }, approval))
}

impl RefundProof {
    /// Verify signature, expiry, state continuity, arithmetic, and the exact proved amount.
    /// The predecessor commitment and authority must come from trusted local state.
    pub fn verify_disclosed(
        &self,
        signed: &SignedApproval,
        authority: &ApprovalAuthority,
        now: u64,
        expected_before: &str,
    ) -> Result<(), CommerceError> {
        self.transition
            .verify_signed_disclosed(signed, authority, now, expected_before)?;
        let c = amount_witness_commitment(self.transition.amount);
        if self.proof.public_inputs.witness_commitment.as_deref()
            != Some(witness_commitment_u64_to_hex(&c).as_str())
        {
            return Err(CommerceError::Refund(
                "accounting amount differs from proved amount",
            ));
        }
        signed.terms.approval.verify_disclosed(&self.proof)?;
        Ok(())
    }
}

fn digest(domain: &[u8], value: &impl Serialize) -> Result<String, CommerceError> {
    let bytes = serde_jcs::to_vec(value).map_err(|e| CommerceError::Encoding(e.to_string()))?;
    Ok(Hash256::sha256_with_domain(domain, &bytes).to_hex())
}
