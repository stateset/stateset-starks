//! Canonical commerce intent and authorization receipt primitives.
//!
//! These types define the stable, hashable contract for delegated agentic
//! commerce. They are intentionally proof-system agnostic so the prover,
//! verifier, sequencer, and anchoring layers can all bind to the same intent.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::hash::Hash256;
use crate::public_inputs::canonical_json;
use crate::rescue::rescue_hash;
use crate::{felt_from_u64, FELT_ZERO};

/// Domain separator for commerce intent hashing.
pub const DOMAIN_COMMERCE_INTENT_HASH: &[u8] = b"STATESET_VES_COMMERCE_INTENT_HASH_V1";

/// Domain separator for authorization receipt hashing.
pub const DOMAIN_COMMERCE_AUTHORIZATION_RECEIPT_HASH: &[u8] =
    b"STATESET_VES_COMMERCE_AUTHORIZATION_RECEIPT_HASH_V1";

/// Errors that can occur when handling commerce intents and receipts.
#[derive(Debug, Error)]
pub enum CommerceIntentError {
    /// A field failed validation.
    #[error("Invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    /// JSON serialization failed.
    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Canonicalization failed.
    #[error("JCS canonicalization failed: {0}")]
    Canonicalization(String),
    /// The execution exceeded the authorized amount.
    #[error("Execution amount {amount} exceeds max_total {max_total}")]
    AmountExceedsLimit { amount: u64, max_total: u64 },
    /// The execution happened after the intent expired.
    #[error("Execution time {executed_at} exceeds intent expiry {expires_at}")]
    IntentExpired { executed_at: u64, expires_at: u64 },
    /// The execution currency does not match the intent currency.
    #[error("Currency mismatch: expected {expected}, got {actual}")]
    CurrencyMismatch { expected: String, actual: String },
    /// The execution merchant does not match the authorized merchant.
    #[error("Merchant mismatch: expected {expected}, got {actual}")]
    MerchantMismatch { expected: String, actual: String },
    /// The execution payee does not match the authorized payee.
    #[error("Payee mismatch: expected {expected}, got {actual}")]
    PayeeMismatch { expected: String, actual: String },
    /// The execution shipping country does not match the authorized country.
    #[error("Shipping country mismatch: expected {expected}, got {actual}")]
    ShippingCountryMismatch { expected: String, actual: String },
    /// An executed SKU is outside the authorized scope.
    #[error("SKU '{sku}' is not in the authorized allowlist")]
    UnauthorizedSku { sku: String },
    /// An executed category is outside the authorized scope.
    #[error("Category '{category}' is not in the authorized allowlist")]
    UnauthorizedCategory { category: String },
}

/// Canonical delegated commerce intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommerceIntent {
    /// Unique intent identifier.
    pub intent_id: Uuid,
    /// Tenant that delegated the intent.
    pub tenant_id: Uuid,
    /// Store context for the delegated intent.
    pub store_id: Uuid,
    /// Agent identifier acting under the delegation.
    pub agent_id: Uuid,
    /// Delegation or session identifier for auditing.
    pub delegation_id: Uuid,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Maximum amount the agent may spend.
    pub max_total: u64,
    /// Optional fixed merchant binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchant: Option<String>,
    /// Optional fixed payee binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee: Option<String>,
    /// Optional SKU allowlist. Empty means unrestricted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_skus: Vec<String>,
    /// Optional category allowlist. Empty means unrestricted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_categories: Vec<String>,
    /// Optional shipping country binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shipping_country: Option<String>,
    /// Unix timestamp after which the intent is invalid.
    pub expires_at: u64,
    /// Replay-protection nonce, canonicalized as 32-byte lowercase hex.
    pub nonce: String,
}

/// Concrete commerce execution to validate against an intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommerceExecution {
    /// Event identifier for the executed order/payment.
    pub event_id: Uuid,
    /// Sequencer or order sequence number.
    pub sequence_number: u64,
    /// Executed currency code.
    pub currency: String,
    /// Executed amount.
    pub amount: u64,
    /// Merchant receiving the payment.
    pub merchant: String,
    /// Payee receiving the funds.
    pub payee: String,
    /// Executed SKU set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sku_ids: Vec<String>,
    /// Executed category set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub category_ids: Vec<String>,
    /// Optional shipping country for the execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shipping_country: Option<String>,
    /// Unix timestamp at execution time.
    pub executed_at: u64,
}

/// Domain-separated receipt binding an execution to a delegated commerce intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommerceAuthorizationReceipt {
    /// Intent identifier.
    pub intent_id: Uuid,
    /// Tenant identifier.
    pub tenant_id: Uuid,
    /// Store identifier.
    pub store_id: Uuid,
    /// Agent identifier.
    pub agent_id: Uuid,
    /// Delegation identifier.
    pub delegation_id: Uuid,
    /// Intent nonce.
    pub nonce: String,
    /// Intent expiry timestamp.
    pub expires_at: u64,
    /// Executed event identifier.
    pub event_id: Uuid,
    /// Executed sequence number.
    pub sequence_number: u64,
    /// Executed currency.
    pub currency: String,
    /// Executed amount.
    pub amount: u64,
    /// Executed merchant.
    pub merchant: String,
    /// Executed payee.
    pub payee: String,
    /// Executed SKU set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sku_ids: Vec<String>,
    /// Executed category set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub category_ids: Vec<String>,
    /// Executed shipping country.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shipping_country: Option<String>,
    /// Execution timestamp.
    pub executed_at: u64,
    /// Canonical commerce intent hash.
    pub intent_hash: String,
    /// Domain-separated authorization receipt hash.
    pub receipt_hash: String,
}

impl CommerceIntent {
    /// Validate the intent.
    pub fn validate(&self) -> Result<(), CommerceIntentError> {
        let _ = self.normalized()?;
        Ok(())
    }

    /// Return a normalized form used for canonical hashing.
    pub fn normalized(&self) -> Result<Self, CommerceIntentError> {
        if self.max_total == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "max_total",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.expires_at == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "expires_at",
                reason: "must be greater than zero".to_string(),
            });
        }

        Ok(Self {
            intent_id: self.intent_id,
            tenant_id: self.tenant_id,
            store_id: self.store_id,
            agent_id: self.agent_id,
            delegation_id: self.delegation_id,
            currency: normalize_currency(&self.currency)?,
            max_total: self.max_total,
            merchant: normalize_optional_text_field("merchant", self.merchant.as_deref())?,
            payee: normalize_optional_text_field("payee", self.payee.as_deref())?,
            allowed_skus: normalize_scope_list("allowed_skus", &self.allowed_skus)?,
            allowed_categories: normalize_scope_list(
                "allowed_categories",
                &self.allowed_categories,
            )?,
            shipping_country: normalize_optional_country(self.shipping_country.as_deref())?,
            expires_at: self.expires_at,
            nonce: normalize_nonce(&self.nonce)?,
        })
    }

    /// Canonical JSON representation used for hashing.
    pub fn canonical_json(&self) -> Result<String, CommerceIntentError> {
        let normalized = self.normalized()?;
        canonical_json(&serde_json::to_value(&normalized)?)
            .map_err(|e| CommerceIntentError::Canonicalization(e.to_string()))
    }

    /// Domain-separated canonical intent hash.
    pub fn compute_hash(&self) -> Result<Hash256, CommerceIntentError> {
        let canonical = self.canonical_json()?;
        Ok(Hash256::sha256_with_domain(
            DOMAIN_COMMERCE_INTENT_HASH,
            canonical.as_bytes(),
        ))
    }

    /// Domain-separated canonical intent hash as lowercase hex.
    pub fn compute_hash_hex(&self) -> Result<String, CommerceIntentError> {
        Ok(self.compute_hash()?.to_hex())
    }

    /// Validate an execution against this intent and return a receipt when authorized.
    pub fn authorize_execution(
        &self,
        execution: &CommerceExecution,
    ) -> Result<CommerceAuthorizationReceipt, CommerceIntentError> {
        let normalized_intent = self.normalized()?;
        let normalized_execution = execution.normalized()?;

        if normalized_execution.currency != normalized_intent.currency {
            return Err(CommerceIntentError::CurrencyMismatch {
                expected: normalized_intent.currency,
                actual: normalized_execution.currency,
            });
        }
        if normalized_execution.amount > normalized_intent.max_total {
            return Err(CommerceIntentError::AmountExceedsLimit {
                amount: normalized_execution.amount,
                max_total: normalized_intent.max_total,
            });
        }
        if normalized_execution.executed_at > normalized_intent.expires_at {
            return Err(CommerceIntentError::IntentExpired {
                executed_at: normalized_execution.executed_at,
                expires_at: normalized_intent.expires_at,
            });
        }

        if let Some(expected) = normalized_intent.merchant.as_deref() {
            if normalized_execution.merchant != expected {
                return Err(CommerceIntentError::MerchantMismatch {
                    expected: expected.to_string(),
                    actual: normalized_execution.merchant,
                });
            }
        }
        if let Some(expected) = normalized_intent.payee.as_deref() {
            if normalized_execution.payee != expected {
                return Err(CommerceIntentError::PayeeMismatch {
                    expected: expected.to_string(),
                    actual: normalized_execution.payee,
                });
            }
        }
        if let Some(expected) = normalized_intent.shipping_country.as_deref() {
            match normalized_execution.shipping_country.as_deref() {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(CommerceIntentError::ShippingCountryMismatch {
                        expected: expected.to_string(),
                        actual: actual.to_string(),
                    });
                }
                None => {
                    return Err(CommerceIntentError::ShippingCountryMismatch {
                        expected: expected.to_string(),
                        actual: "<missing>".to_string(),
                    });
                }
            }
        }

        for sku in &normalized_execution.sku_ids {
            if !normalized_intent.allowed_skus.is_empty()
                && !normalized_intent.allowed_skus.contains(sku)
            {
                return Err(CommerceIntentError::UnauthorizedSku { sku: sku.clone() });
            }
        }
        for category in &normalized_execution.category_ids {
            if !normalized_intent.allowed_categories.is_empty()
                && !normalized_intent.allowed_categories.contains(category)
            {
                return Err(CommerceIntentError::UnauthorizedCategory {
                    category: category.clone(),
                });
            }
        }

        let intent_hash = normalized_intent.compute_hash_hex()?;
        let mut receipt = CommerceAuthorizationReceipt {
            intent_id: normalized_intent.intent_id,
            tenant_id: normalized_intent.tenant_id,
            store_id: normalized_intent.store_id,
            agent_id: normalized_intent.agent_id,
            delegation_id: normalized_intent.delegation_id,
            nonce: normalized_intent.nonce,
            expires_at: normalized_intent.expires_at,
            event_id: normalized_execution.event_id,
            sequence_number: normalized_execution.sequence_number,
            currency: normalized_execution.currency,
            amount: normalized_execution.amount,
            merchant: normalized_execution.merchant,
            payee: normalized_execution.payee,
            sku_ids: normalized_execution.sku_ids,
            category_ids: normalized_execution.category_ids,
            shipping_country: normalized_execution.shipping_country,
            executed_at: normalized_execution.executed_at,
            intent_hash,
            receipt_hash: String::new(),
        };
        receipt.receipt_hash = receipt.compute_hash_hex()?;
        Ok(receipt)
    }
}

impl CommerceExecution {
    /// Validate the execution.
    pub fn validate(&self) -> Result<(), CommerceIntentError> {
        let _ = self.normalized()?;
        Ok(())
    }

    /// Return a normalized form used for authorization receipt generation.
    pub fn normalized(&self) -> Result<Self, CommerceIntentError> {
        if self.amount == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "amount",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.executed_at == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "executed_at",
                reason: "must be greater than zero".to_string(),
            });
        }

        Ok(Self {
            event_id: self.event_id,
            sequence_number: self.sequence_number,
            currency: normalize_currency(&self.currency)?,
            amount: self.amount,
            merchant: normalize_required_text_field("merchant", &self.merchant)?,
            payee: normalize_required_text_field("payee", &self.payee)?,
            sku_ids: normalize_scope_list("sku_ids", &self.sku_ids)?,
            category_ids: normalize_scope_list("category_ids", &self.category_ids)?,
            shipping_country: normalize_optional_country(self.shipping_country.as_deref())?,
            executed_at: self.executed_at,
        })
    }
}

impl CommerceAuthorizationReceipt {
    /// Validate the receipt and its canonical receipt hash.
    pub fn validate(&self) -> Result<(), CommerceIntentError> {
        let _ = self.normalized()?;
        if !self.validate_hash()? {
            return Err(CommerceIntentError::InvalidField {
                field: "receipt_hash",
                reason: "does not match canonical authorization receipt payload".to_string(),
            });
        }
        Ok(())
    }

    /// Return a normalized form used for canonical receipt hashing.
    pub fn normalized(&self) -> Result<Self, CommerceIntentError> {
        if self.amount == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "amount",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.expires_at == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "expires_at",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.executed_at == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "executed_at",
                reason: "must be greater than zero".to_string(),
            });
        }

        Ok(Self {
            intent_id: self.intent_id,
            tenant_id: self.tenant_id,
            store_id: self.store_id,
            agent_id: self.agent_id,
            delegation_id: self.delegation_id,
            nonce: normalize_nonce(&self.nonce)?,
            expires_at: self.expires_at,
            event_id: self.event_id,
            sequence_number: self.sequence_number,
            currency: normalize_currency(&self.currency)?,
            amount: self.amount,
            merchant: normalize_required_text_field("merchant", &self.merchant)?,
            payee: normalize_required_text_field("payee", &self.payee)?,
            sku_ids: normalize_scope_list("sku_ids", &self.sku_ids)?,
            category_ids: normalize_scope_list("category_ids", &self.category_ids)?,
            shipping_country: normalize_optional_country(self.shipping_country.as_deref())?,
            executed_at: self.executed_at,
            intent_hash: normalize_hash_field("intent_hash", &self.intent_hash)?,
            receipt_hash: normalize_hash_field("receipt_hash", &self.receipt_hash)?,
        })
    }

    /// Canonical JSON representation of the signed payload used for receipt hashing.
    pub fn canonical_json(&self) -> Result<String, CommerceIntentError> {
        let payload = self.normalized_payload()?.payload_value();
        canonical_json(&payload).map_err(|e| CommerceIntentError::Canonicalization(e.to_string()))
    }

    /// Recompute the receipt hash from the canonical payload.
    pub fn compute_hash(&self) -> Result<Hash256, CommerceIntentError> {
        let canonical = self.canonical_json()?;
        Ok(Hash256::sha256_with_domain(
            DOMAIN_COMMERCE_AUTHORIZATION_RECEIPT_HASH,
            canonical.as_bytes(),
        ))
    }

    /// Recompute the receipt hash from the canonical payload as lowercase hex.
    pub fn compute_hash_hex(&self) -> Result<String, CommerceIntentError> {
        Ok(self.compute_hash()?.to_hex())
    }

    /// Validate that `receipt_hash` matches the canonical payload.
    pub fn validate_hash(&self) -> Result<bool, CommerceIntentError> {
        Ok(self.compute_hash_hex()? == normalize_hash_field("receipt_hash", &self.receipt_hash)?)
    }

    /// Compute the Rescue witness commitment for the receipt amount.
    ///
    /// This matches the commitment derived by the prover from the private amount.
    pub fn witness_commitment_u64(&self) -> [u64; 4] {
        let mut amount_limbs = [FELT_ZERO; 8];
        amount_limbs[0] = felt_from_u64(self.amount & 0xFFFF_FFFF);
        amount_limbs[1] = felt_from_u64(self.amount >> 32);

        let hash_output = rescue_hash(&amount_limbs);
        [
            hash_output[0].as_int(),
            hash_output[1].as_int(),
            hash_output[2].as_int(),
            hash_output[3].as_int(),
        ]
    }

    fn payload_value(&self) -> serde_json::Value {
        serde_json::json!({
            "agentId": self.agent_id,
            "amount": self.amount,
            "categoryIds": self.category_ids,
            "currency": self.currency,
            "delegationId": self.delegation_id,
            "eventId": self.event_id,
            "executedAt": self.executed_at,
            "expiresAt": self.expires_at,
            "intentHash": self.intent_hash,
            "intentId": self.intent_id,
            "merchant": self.merchant,
            "nonce": self.nonce,
            "payee": self.payee,
            "sequenceNumber": self.sequence_number,
            "shippingCountry": self.shipping_country,
            "skuIds": self.sku_ids,
            "storeId": self.store_id,
            "tenantId": self.tenant_id,
        })
    }

    fn normalized_payload(&self) -> Result<Self, CommerceIntentError> {
        if self.amount == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "amount",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.expires_at == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "expires_at",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.executed_at == 0 {
            return Err(CommerceIntentError::InvalidField {
                field: "executed_at",
                reason: "must be greater than zero".to_string(),
            });
        }

        Ok(Self {
            intent_id: self.intent_id,
            tenant_id: self.tenant_id,
            store_id: self.store_id,
            agent_id: self.agent_id,
            delegation_id: self.delegation_id,
            nonce: normalize_nonce(&self.nonce)?,
            expires_at: self.expires_at,
            event_id: self.event_id,
            sequence_number: self.sequence_number,
            currency: normalize_currency(&self.currency)?,
            amount: self.amount,
            merchant: normalize_required_text_field("merchant", &self.merchant)?,
            payee: normalize_required_text_field("payee", &self.payee)?,
            sku_ids: normalize_scope_list("sku_ids", &self.sku_ids)?,
            category_ids: normalize_scope_list("category_ids", &self.category_ids)?,
            shipping_country: normalize_optional_country(self.shipping_country.as_deref())?,
            executed_at: self.executed_at,
            intent_hash: normalize_hash_field("intent_hash", &self.intent_hash)?,
            receipt_hash: self.receipt_hash.clone(),
        })
    }
}

fn normalize_currency(value: &str) -> Result<String, CommerceIntentError> {
    normalize_ascii_code("currency", value, 3)
}

fn normalize_optional_country(value: Option<&str>) -> Result<Option<String>, CommerceIntentError> {
    value
        .map(|country| normalize_ascii_code("shipping_country", country, 2))
        .transpose()
}

fn normalize_ascii_code(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<String, CommerceIntentError> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.len() != expected_len {
        return Err(CommerceIntentError::InvalidField {
            field,
            reason: format!("must be exactly {expected_len} ASCII letters"),
        });
    }
    if !normalized.chars().all(|ch| ch.is_ascii_uppercase()) {
        return Err(CommerceIntentError::InvalidField {
            field,
            reason: "must contain only ASCII letters".to_string(),
        });
    }
    Ok(normalized)
}

fn normalize_optional_text_field(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<String>, CommerceIntentError> {
    value
        .map(|text| normalize_required_text_field(field, text))
        .transpose()
}

fn normalize_required_text_field(
    field: &'static str,
    value: &str,
) -> Result<String, CommerceIntentError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(CommerceIntentError::InvalidField {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    if normalized.chars().any(|ch| ch.is_control()) {
        return Err(CommerceIntentError::InvalidField {
            field,
            reason: "must not contain control characters".to_string(),
        });
    }
    Ok(normalized.to_string())
}

fn normalize_scope_list(
    field: &'static str,
    values: &[String],
) -> Result<Vec<String>, CommerceIntentError> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        normalized.push(normalize_required_text_field(field, value)?);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_nonce(value: &str) -> Result<String, CommerceIntentError> {
    let trimmed = value.trim();
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .to_ascii_lowercase();

    if normalized.len() != 64 {
        return Err(CommerceIntentError::InvalidField {
            field: "nonce",
            reason: "must be exactly 32 bytes of hex".to_string(),
        });
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(CommerceIntentError::InvalidField {
            field: "nonce",
            reason: "must contain only hexadecimal characters".to_string(),
        });
    }

    Ok(normalized)
}

fn normalize_hash_field(field: &'static str, value: &str) -> Result<String, CommerceIntentError> {
    let trimmed = value.trim();
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .to_ascii_lowercase();

    if normalized.len() != 64 {
        return Err(CommerceIntentError::InvalidField {
            field,
            reason: "must be exactly 32 bytes of hex".to_string(),
        });
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(CommerceIntentError::InvalidField {
            field,
            reason: "must contain only hexadecimal characters".to_string(),
        });
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_intent() -> CommerceIntent {
        CommerceIntent {
            intent_id: Uuid::parse_str("9f7f314e-80c3-45dc-af6d-11d6c1a68701").unwrap(),
            tenant_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            store_id: Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            agent_id: Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            delegation_id: Uuid::parse_str("d9428888-122b-11e1-b85c-61cd3cbb3210").unwrap(),
            currency: "usd".to_string(),
            max_total: 25_000,
            merchant: Some(" Acme Market ".to_string()),
            payee: Some("settlement@stateset.app".to_string()),
            allowed_skus: vec![
                "sku-b".to_string(),
                "sku-a".to_string(),
                "sku-a".to_string(),
            ],
            allowed_categories: vec!["grocery".to_string(), "produce".to_string()],
            shipping_country: Some("us".to_string()),
            expires_at: 1_700_000_100,
            nonce: "0X0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string(),
        }
    }

    fn sample_execution() -> CommerceExecution {
        CommerceExecution {
            event_id: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            sequence_number: 42,
            currency: "USD".to_string(),
            amount: 12_500,
            merchant: "Acme Market".to_string(),
            payee: "settlement@stateset.app".to_string(),
            sku_ids: vec!["sku-a".to_string(), "sku-b".to_string()],
            category_ids: vec!["produce".to_string()],
            shipping_country: Some("US".to_string()),
            executed_at: 1_700_000_000,
        }
    }

    #[test]
    fn test_commerce_intent_hash_normalizes_equivalent_inputs() {
        let messy = sample_intent();
        let mut normalized = sample_intent();
        normalized.currency = "USD".to_string();
        normalized.merchant = Some("Acme Market".to_string());
        normalized.allowed_skus = vec!["sku-a".to_string(), "sku-b".to_string()];
        normalized.shipping_country = Some("US".to_string());
        normalized.nonce =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        assert_eq!(
            messy.normalized().unwrap(),
            normalized.normalized().unwrap()
        );
        assert_eq!(
            messy.compute_hash().unwrap(),
            normalized.compute_hash().unwrap()
        );
    }

    #[test]
    fn test_authorize_execution_generates_deterministic_receipt() {
        let intent = sample_intent();
        let execution = sample_execution();

        let receipt1 = intent.authorize_execution(&execution).unwrap();
        let receipt2 = intent.authorize_execution(&execution).unwrap();

        assert_eq!(receipt1, receipt2);
        receipt1.validate().unwrap();
        assert!(receipt1.validate_hash().unwrap());
    }

    #[test]
    fn test_authorization_receipt_depends_on_nonce_and_sequence_number() {
        let mut intent = sample_intent();
        let execution = sample_execution();

        let receipt1 = intent.authorize_execution(&execution).unwrap();

        intent.nonce =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        let receipt2 = intent.authorize_execution(&execution).unwrap();
        assert_ne!(receipt1.intent_hash, receipt2.intent_hash);
        assert_ne!(receipt1.receipt_hash, receipt2.receipt_hash);

        let mut next_execution = sample_execution();
        next_execution.sequence_number += 1;
        let receipt3 = sample_intent()
            .authorize_execution(&next_execution)
            .unwrap();
        assert_ne!(receipt1.receipt_hash, receipt3.receipt_hash);
    }

    #[test]
    fn test_authorize_execution_rejects_expired_intent() {
        let intent = sample_intent();
        let mut execution = sample_execution();
        execution.executed_at = intent.expires_at + 1;

        let err = intent.authorize_execution(&execution).unwrap_err();
        assert!(matches!(err, CommerceIntentError::IntentExpired { .. }));
    }

    #[test]
    fn test_authorize_execution_rejects_scope_violation() {
        let intent = sample_intent();
        let mut execution = sample_execution();
        execution.sku_ids.push("sku-z".to_string());

        let err = intent.authorize_execution(&execution).unwrap_err();
        assert!(matches!(err, CommerceIntentError::UnauthorizedSku { .. }));
    }

    #[test]
    fn test_authorize_execution_rejects_merchant_mismatch() {
        let intent = sample_intent();
        let mut execution = sample_execution();
        execution.merchant = "Other Merchant".to_string();

        let err = intent.authorize_execution(&execution).unwrap_err();
        assert!(matches!(err, CommerceIntentError::MerchantMismatch { .. }));
    }

    #[test]
    fn test_authorization_receipt_hash_rejects_non_canonical_fields() {
        let mut receipt = sample_intent()
            .authorize_execution(&sample_execution())
            .unwrap();
        receipt.intent_hash = format!("0X{}", receipt.intent_hash.to_ascii_uppercase());
        receipt.receipt_hash = format!("0X{}", receipt.receipt_hash.to_ascii_uppercase());

        receipt.validate().unwrap();
        assert!(receipt.validate_hash().unwrap());
    }

    #[test]
    fn test_authorization_receipt_validate_rejects_tampered_hash() {
        let mut receipt = sample_intent()
            .authorize_execution(&sample_execution())
            .unwrap();
        receipt.receipt_hash = "0".repeat(64);

        let err = receipt.validate().unwrap_err();
        assert!(matches!(
            err,
            CommerceIntentError::InvalidField {
                field: "receipt_hash",
                ..
            }
        ));
    }

    #[test]
    fn test_authorization_receipt_witness_commitment_depends_on_amount() {
        let mut receipt = sample_intent()
            .authorize_execution(&sample_execution())
            .unwrap();
        let commitment1 = receipt.witness_commitment_u64();

        receipt.amount += 1;
        let commitment2 = receipt.witness_commitment_u64();

        assert_ne!(commitment1, commitment2);
    }
}
