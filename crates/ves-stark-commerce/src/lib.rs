//! Commerce amount caps bound to a currency, operation, reference, and event scope.
//!
//! **No confidentiality guarantee:** proof transcripts can disclose witness amounts.
//! Use only for disclosed computational integrity; zero-knowledge requirements fail closed
//! through the privacy-aware APIs. Legacy low-level APIs remain integrity-only.
//!
//! The STARK proves `amount <= cap`; V2 payload binding commits the amount and
//! canonical request together. Verification requires an independently trusted
//! payload hash, so a prover cannot substitute a different compliant amount.
//! Source authentication, replay prevention, ledger completeness, and cumulative
//! refund/spend accounting remain the integrating application's responsibility.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod approval;
#[cfg(feature = "ledger")]
pub mod ledger;
pub mod refund;

pub use ves_stark_primitives::privacy::ProofPrivacy;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ves_stark_primitives::{
    hash::Hash256,
    payload_amount::amount_witness_commitment_salted,
    payload_v2::{payload_plain_hash_v2, PAYLOAD_KIND_V2},
    public_inputs::{compute_policy_hash, CompliancePublicInputs, PolicyParams},
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
use ves_stark_verifier::{ComplianceVerification, VerificationResult};

/// Supported per-event commerce operations. Every operation uses an inclusive cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommerceOperation {
    /// An order total must not exceed a checkout limit.
    Order,
    /// A payment amount must not exceed an approved capture limit.
    Payment,
    /// A refund must not exceed a limit supplied by the refund ledger.
    Refund,
    /// A payout must not exceed an approved disbursement limit.
    Payout,
}

/// Public business context committed alongside the private amount.
///
/// Amount and cap use integer units of `10^-decimal_places` of `currency`.
/// Currency syntax is validated; the application selects supported codes/scales.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommerceRequest {
    /// Optional commitment to a public state transition, e.g. refund accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_transition_hash: Option<String>,
    /// Unique event identifier; persist consumption atomically to prevent replay.
    pub event_id: Uuid,
    /// Tenant that owns the event.
    pub tenant_id: Uuid,
    /// Store that owns the event.
    pub store_id: Uuid,
    /// Sequence supplied by the application's authoritative event stream.
    pub sequence_number: u64,
    /// Business operation being authorized.
    pub operation: CommerceOperation,
    /// Order, capture, refund, or payout reference (1–256 UTF-8 bytes).
    pub reference: String,
    /// Three uppercase ASCII letters, e.g. USD.
    pub currency: String,
    /// Explicit monetary scale, e.g. 2 for cents; maximum 18.
    pub decimal_places: u8,
    /// Inclusive amount limit in the same integer units as the witness.
    pub cap: u64,
}

impl CommerceRequest {
    /// Validate the public request before hashing or proving it.
    pub fn validate(&self) -> Result<(), CommerceError> {
        if let Some(hash) = &self.state_transition_hash {
            validate_hash(hash)?;
        }
        if self.event_id.is_nil() || self.tenant_id.is_nil() || self.store_id.is_nil() {
            return Err(CommerceError::InvalidRequest(
                "event, tenant, and store IDs must be non-nil",
            ));
        }
        if self.reference.is_empty()
            || self.reference.len() > 256
            || self.reference.trim() != self.reference
            || self.reference.chars().any(char::is_control)
        {
            return Err(CommerceError::InvalidRequest("reference must be 1–256 bytes without surrounding whitespace or control characters"));
        }
        if self.currency.len() != 3 || !self.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(CommerceError::InvalidRequest(
                "currency must contain three uppercase ASCII letters",
            ));
        }
        if self.decimal_places > 18 {
            return Err(CommerceError::InvalidRequest(
                "decimalPlaces must not exceed 18",
            ));
        }
        Ok(())
    }

    /// Versioned, domain-separated commitment to the canonical business context.
    pub fn context_hash(&self) -> Result<Hash256, CommerceError> {
        self.validate()?;
        let bytes = serde_jcs::to_vec(self).map_err(|e| CommerceError::Encoding(e.to_string()))?;
        Ok(Hash256::sha256_with_domain(
            b"STATESET_COMMERCE_CAP_V1",
            &bytes,
        ))
    }

    fn inputs(&self, payload_hash: String) -> Result<CompliancePublicInputs, CommerceError> {
        let rest_hash = self.context_hash()?.to_hex();
        let params = PolicyParams::cap(self.cap);
        let policy_hash = compute_policy_hash("order_total.cap", &params)
            .map_err(|e| CommerceError::Encoding(e.to_string()))?
            .to_hex();
        Ok(CompliancePublicInputs {
            event_id: self.event_id,
            tenant_id: self.tenant_id,
            store_id: self.store_id,
            sequence_number: self.sequence_number,
            payload_kind: PAYLOAD_KIND_V2,
            payload_plain_hash: payload_hash,
            // Standalone claims: no encrypted VES payload or source signature is asserted.
            payload_cipher_hash: "0".repeat(64),
            event_signing_hash: "0".repeat(64),
            policy_id: "order_total.cap".into(),
            policy_params: params,
            policy_hash,
            witness_commitment: None,
            authorization_receipt_hash: None,
            amount_binding_hash: None,
            rest_hash: Some(rest_hash),
        })
    }
}

/// A prepared private witness. Its payload hash can be authenticated before proving.
///
/// Deliberately implements neither Debug nor serialization to avoid exposing secrets.
pub struct PreparedCommerceProof {
    witness: ComplianceWitness,
    request: CommerceRequest,
}

impl PreparedCommerceProof {
    /// The commitment to authenticate in the application's event/approval record.
    pub fn payload_hash(&self) -> &str {
        &self.witness.public_inputs.payload_plain_hash
    }

    /// Public approval record for storage by trusted intake before proof delivery.
    /// This record is not signed; its provenance must be authenticated externally.
    pub fn approval(&self) -> CommerceApproval {
        CommerceApproval {
            request: self.request.clone(),
            payload_hash: self.payload_hash().to_owned(),
        }
    }

    /// Generate an integrity-only proof with the default proof options.
    pub fn prove(self) -> Result<CommerceProof, CommerceError> {
        let proof = ComplianceProver::with_policy(Policy::order_total_cap(self.request.cap))
            .prove(&self.witness)?;
        Ok(CommerceProof {
            proof_bytes: proof.proof_bytes,
            public_inputs: self.witness.public_inputs.clone(),
        })
    }
}

/// Public approval record kept independently of an untrusted proof submission.
///
/// Serialization does not authenticate this record. Store it in the trusted
/// approval system and retrieve it there when verifying a submitted proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommerceApproval {
    /// Expected business context and approved amount cap.
    pub request: CommerceRequest,
    /// Payload commitment authenticated by intake that knows the real amount.
    pub payload_hash: String,
}

impl CommerceApproval {
    /// Check the request and canonical lowercase 32-byte payload hash.
    pub fn validate(&self) -> Result<(), CommerceError> {
        self.request.validate()?;
        if self.payload_hash.len() != 64
            || !self
                .payload_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CommerceError::InvalidRequest(
                "payloadHash must be 64 lowercase hexadecimal characters",
            ));
        }
        Ok(())
    }

    /// Verify a submitted proof against this independently trusted approval record.
    pub fn verify(&self, proof: &CommerceProof) -> Result<VerificationResult, CommerceError> {
        self.validate()?;
        verify_cap_proof(proof, &self.request, &self.payload_hash)
    }

    /// Verify integrity while explicitly accepting witness disclosure.
    pub fn verify_disclosed(
        &self,
        proof: &CommerceProof,
    ) -> Result<VerificationResult, CommerceError> {
        self.validate()?;
        verify_cap_proof_disclosed(proof, &self.request, &self.payload_hash)
    }
}

/// Public proof bundle. Contains neither the amount nor its blinding salt.
///
/// Apply transport size limits before deserializing untrusted JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommerceProof {
    /// Winterfell proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Inputs bound by the proof, including the V2 payload commitment.
    pub public_inputs: CompliancePublicInputs,
}

/// Request a confidential cap proof. The current backend always rejects this request.
///
/// Use [`prepare_cap_proof_disclosed`] only when witness disclosure is acceptable.
pub fn prepare_cap_proof(
    amount: u64,
    request: &CommerceRequest,
) -> Result<PreparedCommerceProof, CommerceError> {
    ProofPrivacy::Confidential.enforce()?;
    prepare_cap_proof_disclosed(amount, request)
}

/// Prepare an integrity-only proof. Public proof bytes can reveal amount and salt.
pub fn prepare_cap_proof_disclosed(
    amount: u64,
    request: &CommerceRequest,
) -> Result<PreparedCommerceProof, CommerceError> {
    prepare_with_salt(amount, request, rand::random())
}

pub(crate) fn prepare_with_salt(
    amount: u64,
    request: &CommerceRequest,
    salt: [u32; 4],
) -> Result<PreparedCommerceProof, CommerceError> {
    let rest = request.context_hash()?;
    if amount > request.cap {
        return Err(CommerceError::ExceedsCap);
    }
    let commitment = amount_witness_commitment_salted(amount, &salt);
    let hash = payload_plain_hash_v2(&commitment, rest.as_bytes()).to_hex();
    let witness = ComplianceWitness::try_new_with_salt(amount, salt, request.inputs(hash)?)?;
    Ok(PreparedCommerceProof {
        witness,
        request: request.clone(),
    })
}

/// Request confidential verification. The current backend always rejects this request.
///
/// Use [`verify_cap_proof_disclosed`] for integrity-only verification against
/// an independently authenticated expected request and payload hash.
pub fn verify_cap_proof(
    proof: &CommerceProof,
    expected_request: &CommerceRequest,
    expected_payload_hash: &str,
) -> Result<VerificationResult, CommerceError> {
    ProofPrivacy::Confidential.enforce()?;
    verify_cap_proof_disclosed(proof, expected_request, expected_payload_hash)
}

/// Verify integrity only. Success does not establish confidentiality.
/// Expected request and hash must come from authenticated intake, not the proof sender.
pub fn verify_cap_proof_disclosed(
    proof: &CommerceProof,
    expected_request: &CommerceRequest,
    expected_payload_hash: &str,
) -> Result<VerificationResult, CommerceError> {
    let mut expected = expected_request.inputs(expected_payload_hash.to_owned())?;
    // The commitment depends on the private witness; the core verifier checks it.
    expected.witness_commitment = proof.public_inputs.witness_commitment.clone();
    if serde_jcs::to_vec(&expected).map_err(|e| CommerceError::Encoding(e.to_string()))?
        != serde_jcs::to_vec(&proof.public_inputs)
            .map_err(|e| CommerceError::Encoding(e.to_string()))?
    {
        return Err(CommerceError::ContextMismatch);
    }
    // V2 is mandatory above; the core verifier enforces its payload binding even
    // on this builder path, without requiring a plaintext amount artifact.
    Ok(
        ComplianceVerification::new(&proof.proof_bytes, &proof.public_inputs)
            .policy(&Policy::order_total_cap(expected_request.cap))
            .witness_only()
            .strict()
            .run()?,
    )
}

/// Errors returned by commerce proof preparation and verification.
#[derive(Debug, thiserror::Error)]
pub enum CommerceError {
    /// Confidentiality cannot be provided by the current backend.
    #[error(transparent)]
    ConfidentialityUnavailable(#[from] ves_stark_primitives::privacy::ConfidentialityUnavailable),
    /// Invalid or untrusted approval signature, scope, key, or validity interval.
    #[error("approval rejected: {0}")]
    Approval(&'static str),
    /// Invalid refund state transition.
    #[error("refund rejected: {0}")]
    Refund(&'static str),
    /// Malformed public business context.
    #[error("invalid commerce request: {0}")]
    InvalidRequest(&'static str),
    /// The private amount exceeds the approved cap. Amounts are omitted from errors.
    #[error("amount exceeds the approved commerce cap")]
    ExceedsCap,
    /// The proof does not match the verifier's trusted business request or payload.
    #[error("proof does not match the expected commerce context or payload hash")]
    ContextMismatch,
    /// Canonical encoding or policy hashing failed.
    #[error("commerce encoding failed: {0}")]
    Encoding(String),
    /// The underlying prover rejected the witness.
    #[error(transparent)]
    Prover(#[from] ves_stark_prover::ProverError),
    /// The underlying verifier rejected the proof.
    #[error(transparent)]
    Verifier(#[from] ves_stark_verifier::VerifierError),
}

pub(crate) fn validate_hash(hash: &str) -> Result<(), CommerceError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CommerceError::InvalidRequest(
            "hash must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}
