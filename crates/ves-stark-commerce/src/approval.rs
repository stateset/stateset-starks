//! Domain-separated Ed25519 approvals with externally trusted, scoped authority keys.

use crate::{CommerceApproval, CommerceError};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ves_stark_primitives::hash::Hash256;

/// The exact approval statement signed by trusted intake.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalTerms {
    /// Expected business request and payload commitment.
    pub approval: CommerceApproval,
    /// Identifier resolved against a trusted authority configuration.
    pub key_id: String,
    /// Business policy revision, compared with the verifier's configured revision.
    pub policy_version: u64,
    /// Unique consumption token, in addition to the event identifier.
    pub nonce: Uuid,
    /// Inclusive validity start in Unix seconds.
    pub not_before: u64,
    /// Exclusive expiration in Unix seconds.
    pub expires_at: u64,
}

impl ApprovalTerms {
    /// Validate canonical approval terms without authenticating them.
    pub fn validate(&self) -> Result<(), CommerceError> {
        self.approval.validate()?;
        if self.key_id.is_empty()
            || self.key_id.len() > 128
            || !self
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(CommerceError::Approval("invalid key identifier"));
        }
        if self.nonce.is_nil() || self.policy_version == 0 || self.not_before >= self.expires_at {
            return Err(CommerceError::Approval(
                "invalid nonce, policy version, or validity interval",
            ));
        }
        Ok(())
    }

    fn digest(&self) -> Result<Hash256, CommerceError> {
        self.validate()?;
        let bytes = serde_jcs::to_vec(self).map_err(|e| CommerceError::Encoding(e.to_string()))?;
        Ok(Hash256::sha256_with_domain(
            b"STATESET_COMMERCE_SIGNED_APPROVAL_V1",
            &bytes,
        ))
    }
}

/// Trusted verifier configuration. Never load this from the proof submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalAuthority {
    /// Locally configured signing key identifier.
    pub key_id: String,
    /// Ed25519 verifying key, raw 32 bytes.
    pub public_key: [u8; 32],
    /// Tenant this key may authorize.
    pub tenant_id: Uuid,
    /// Store this key may authorize.
    pub store_id: Uuid,
    /// Exact accepted policy revision.
    pub policy_version: u64,
    /// Inclusive key validity start.
    pub not_before: u64,
    /// Exclusive key validity end.
    pub expires_at: u64,
    /// Revoked keys reject all approvals, including previously issued ones.
    pub revoked: bool,
}

/// A signed approval; the verifying key is supplied independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedApproval {
    /// Authenticated statement.
    pub terms: ApprovalTerms,
    /// Canonical lowercase Ed25519 signature hex (128 characters).
    pub signature: String,
}

impl SignedApproval {
    /// Sign at trusted intake that has established the actual transaction amount.
    pub fn sign(terms: ApprovalTerms, key: &SigningKey) -> Result<Self, CommerceError> {
        let signature = hex::encode(key.sign(terms.digest()?.as_bytes()).to_bytes());
        Ok(Self { terms, signature })
    }

    /// Authenticate against trusted key configuration and trusted current Unix time.
    /// Does not verify a STARK or consume the approval.
    pub fn verify(&self, authority: &ApprovalAuthority, now: u64) -> Result<(), CommerceError> {
        self.terms.validate()?;
        let request = &self.terms.approval.request;
        if authority.revoked
            || authority.key_id != self.terms.key_id
            || authority.tenant_id != request.tenant_id
            || authority.store_id != request.store_id
            || authority.policy_version != self.terms.policy_version
        {
            return Err(CommerceError::Approval(
                "untrusted key, scope, or policy version",
            ));
        }
        if now < self.terms.not_before
            || now >= self.terms.expires_at
            || now < authority.not_before
            || now >= authority.expires_at
            || self.terms.not_before < authority.not_before
            || self.terms.expires_at > authority.expires_at
        {
            return Err(CommerceError::Approval(
                "approval or authority is outside its validity interval",
            ));
        }
        if self.signature.len() != 128
            || !self
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CommerceError::Approval("invalid signature encoding"));
        }
        let bytes = hex::decode(&self.signature)
            .map_err(|_| CommerceError::Approval("invalid signature"))?;
        let signature = Signature::from_slice(&bytes)
            .map_err(|_| CommerceError::Approval("invalid signature"))?;
        let key = VerifyingKey::from_bytes(&authority.public_key)
            .map_err(|_| CommerceError::Approval("invalid authority key"))?;
        key.verify_strict(self.terms.digest()?.as_bytes(), &signature)
            .map_err(|_| CommerceError::Approval("signature verification failed"))
    }
}
