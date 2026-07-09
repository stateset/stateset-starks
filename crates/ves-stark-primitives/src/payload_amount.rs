//! Canonical payload-to-amount extraction for VES compliance proofs.
//!
//! This module is the **single source of truth** for how an `amount` is derived
//! from a canonical VES event payload. Every party that needs the amount bound
//! by a [`crate::public_inputs::PayloadAmountBinding`] — provers, the sequencer
//! at proof verification time, and auditors — MUST derive it with
//! [`extract_payload_amount`] so that all parties agree on the same value.
//!
//! # Canonical extraction rules
//!
//! 1. The payload MUST be a JSON object. The amount is read from a top-level
//!    field; nested fields are never consulted.
//! 2. The field searched depends on the event type (see
//!    [`amount_field_candidates`]). Candidates are tried in priority order and
//!    the **first candidate key present in the payload wins**. A present but
//!    malformed value is a hard error — extraction never falls through to a
//!    later candidate, otherwise a prover could shadow the real amount with a
//!    malformed decoy field.
//! 3. Amounts are integer **minor units** (e.g. cents, or 6dp stable-coin
//!    units — whatever the tenant's ledger uses), never decimal currency:
//!    - a JSON number is accepted only if it is a non-negative integer that
//!      fits in `u64` (floats, fractions, and negative values are rejected);
//!    - a JSON string is accepted only if it consists solely of ASCII digits
//!      and parses into `u64` (no sign, no decimal point, no whitespace);
//!    - every other JSON type is rejected.
//!
//! Payloads that only carry a lossy decimal amount (e.g. `"total": 1482.37`)
//! are intentionally **not extractable**: a floating-point amount has no
//! canonical integer value, so it cannot be soundly bound by a range proof.
//! Such events must also carry an integer minor-unit field to be provable.

use serde_json::Value;
use thiserror::Error;

use crate::field::felt_from_u64;
use crate::rescue::rescue_hash;
use crate::FELT_ZERO;

/// Amount field candidates for `order.*` events (except payment receipt).
const ORDER_AMOUNT_FIELDS: &[&str] = &[
    "total_amount",
    "totalAmount",
    "total",
    "amount",
    "amount_units",
    "amountUnits",
];

/// Amount field candidates for payment-style events.
const PAYMENT_AMOUNT_FIELDS: &[&str] = &["amount", "amount_units", "amountUnits"];

/// Amount field candidates for `x402_payment.*` events (see
/// `stateset-sequencer::domain::x402_payment`, which defines `amount` as the
/// smallest-unit payment amount).
const X402_AMOUNT_FIELDS: &[&str] = &["amount"];

/// Amount field candidates for `return.*` events.
const RETURN_AMOUNT_FIELDS: &[&str] = &["refund_amount", "refundAmount", "amount"];

/// Default candidates for event types without a dedicated rule.
const DEFAULT_AMOUNT_FIELDS: &[&str] = &[
    "amount",
    "amount_units",
    "amountUnits",
    "total_amount",
    "totalAmount",
    "total",
];

/// Errors produced by canonical payload amount extraction.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AmountExtractionError {
    /// The payload is not a JSON object.
    #[error("payload must be a JSON object to extract an amount (got {actual})")]
    PayloadNotObject {
        /// JSON type name of the actual payload value.
        actual: &'static str,
    },
    /// None of the canonical candidate fields are present in the payload.
    #[error(
        "no canonical amount field found in payload for event type \"{event_type}\" \
         (searched, in order: {candidates:?})"
    )]
    MissingAmountField {
        /// Event type the candidate list was derived from.
        event_type: String,
        /// The candidate fields that were searched, in priority order.
        candidates: &'static [&'static str],
    },
    /// A candidate field is present but does not hold a canonical amount.
    #[error("non-canonical amount in payload field \"{field}\": {reason}")]
    NonCanonicalAmount {
        /// The offending payload field.
        field: &'static str,
        /// Human-readable reason the value was rejected.
        reason: String,
    },
}

/// Return the canonical, priority-ordered amount field candidates for an event type.
pub fn amount_field_candidates(event_type: &str) -> &'static [&'static str] {
    if event_type.starts_with("x402_payment.") {
        X402_AMOUNT_FIELDS
    } else if event_type == "order.payment_received" || event_type.starts_with("payment.") {
        PAYMENT_AMOUNT_FIELDS
    } else if event_type.starts_with("order.") {
        ORDER_AMOUNT_FIELDS
    } else if event_type.starts_with("return.") {
        RETURN_AMOUNT_FIELDS
    } else {
        DEFAULT_AMOUNT_FIELDS
    }
}

/// Extract the canonical amount (integer minor units) from an event payload.
///
/// This is the single source of truth used by provers when building a
/// [`crate::public_inputs::PayloadAmountBinding`] and by verifiers when
/// re-extracting the amount to check that binding. See the module docs for
/// the exact rules.
pub fn extract_payload_amount(
    event_type: &str,
    payload: &Value,
) -> Result<u64, AmountExtractionError> {
    let object = payload
        .as_object()
        .ok_or(AmountExtractionError::PayloadNotObject {
            actual: json_type_name(payload),
        })?;

    let candidates = amount_field_candidates(event_type);
    for &field in candidates {
        if let Some(value) = object.get(field) {
            return parse_amount_value(field, value);
        }
    }

    Err(AmountExtractionError::MissingAmountField {
        event_type: event_type.to_string(),
        candidates,
    })
}

/// Parse a single payload value as a canonical integer minor-unit amount.
fn parse_amount_value(field: &'static str, value: &Value) -> Result<u64, AmountExtractionError> {
    let non_canonical =
        |reason: String| AmountExtractionError::NonCanonicalAmount { field, reason };

    match value {
        Value::Number(n) => n.as_u64().ok_or_else(|| {
            non_canonical(format!(
                "amount must be a non-negative integer in minor units that fits in u64 \
                 (got {n}); decimal currency values are not canonically bindable"
            ))
        }),
        Value::String(s) => {
            if s.is_empty() {
                return Err(non_canonical("amount string must not be empty".to_string()));
            }
            if !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(non_canonical(format!(
                    "amount string must contain only ASCII digits \
                     (no sign, decimal point, or whitespace); got {s:?}"
                )));
            }
            s.parse::<u64>()
                .map_err(|_| non_canonical(format!("amount string {s:?} does not fit in u64")))
        }
        other => Err(non_canonical(format!(
            "amount must be a u64 integer or digit string (got {})",
            json_type_name(other)
        ))),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Compute the Rescue witness commitment for an amount.
///
/// This is the commitment format used across the prover, verifier, and
/// sequencer: the amount is split into two 32-bit limbs, zero-padded to a
/// Rescue input block, and hashed.
pub fn amount_witness_commitment(amount: u64) -> [u64; 4] {
    let mut amount_limbs = [FELT_ZERO; 8];
    amount_limbs[0] = felt_from_u64(amount & 0xFFFF_FFFF);
    amount_limbs[1] = felt_from_u64(amount >> 32);

    let hash_output = rescue_hash(&amount_limbs);
    [
        hash_output[0].as_int(),
        hash_output[1].as_int(),
        hash_output[2].as_int(),
        hash_output[3].as_int(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ------------------------------------------------------------------
    // Supported event types / field selection
    // ------------------------------------------------------------------

    #[test]
    fn extracts_order_total_amount() {
        let payload = json!({ "orderId": "ORD-1", "total_amount": 1482u64 });
        assert_eq!(
            extract_payload_amount("order.created", &payload).unwrap(),
            1482
        );
    }

    #[test]
    fn extracts_order_total_fallback() {
        let payload = json!({ "orderId": "ORD-1", "total": 163u64 });
        assert_eq!(
            extract_payload_amount("order.created", &payload).unwrap(),
            163
        );
    }

    #[test]
    fn order_prefers_total_amount_over_total() {
        let payload = json!({ "total_amount": 100u64, "total": 999u64 });
        assert_eq!(
            extract_payload_amount("order.confirmed", &payload).unwrap(),
            100
        );
    }

    #[test]
    fn extracts_payment_amount() {
        let payload = json!({ "paymentId": "PAY-1", "amount": 4_500_000_000u64 });
        assert_eq!(
            extract_payload_amount("order.payment_received", &payload).unwrap(),
            4_500_000_000
        );
        assert_eq!(
            extract_payload_amount("payment.captured", &payload).unwrap(),
            4_500_000_000
        );
    }

    #[test]
    fn extracts_x402_payment_amount() {
        let payload = json!({ "amount": 1_000_000u64 });
        assert_eq!(
            extract_payload_amount("x402_payment.created", &payload).unwrap(),
            1_000_000
        );
    }

    #[test]
    fn x402_only_accepts_amount_field() {
        let payload = json!({ "total": 5u64 });
        assert!(matches!(
            extract_payload_amount("x402_payment.created", &payload),
            Err(AmountExtractionError::MissingAmountField { .. })
        ));
    }

    #[test]
    fn extracts_return_refund_amount() {
        let payload = json!({ "refund_amount": 999u64, "amount": 1u64 });
        assert_eq!(
            extract_payload_amount("return.refunded", &payload).unwrap(),
            999
        );
    }

    #[test]
    fn unknown_event_type_uses_default_candidates() {
        let payload = json!({ "amountUnits": "4500000000" });
        assert_eq!(
            extract_payload_amount("custom.event", &payload).unwrap(),
            4_500_000_000
        );
    }

    // ------------------------------------------------------------------
    // Value forms
    // ------------------------------------------------------------------

    #[test]
    fn accepts_u64_integer() {
        let payload = json!({ "amount": u64::MAX });
        assert_eq!(
            extract_payload_amount("payment.captured", &payload).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn accepts_zero() {
        let payload = json!({ "amount": 0u64 });
        assert_eq!(
            extract_payload_amount("payment.captured", &payload).unwrap(),
            0
        );
    }

    #[test]
    fn accepts_digit_string() {
        let payload = json!({ "amount": "12345" });
        assert_eq!(
            extract_payload_amount("payment.captured", &payload).unwrap(),
            12345
        );
    }

    #[test]
    fn rejects_float_amount() {
        let payload = json!({ "amount": 1482.37 });
        assert!(matches!(
            extract_payload_amount("payment.captured", &payload),
            Err(AmountExtractionError::NonCanonicalAmount {
                field: "amount",
                ..
            })
        ));
    }

    #[test]
    fn rejects_negative_amount() {
        let payload = json!({ "amount": -5 });
        assert!(matches!(
            extract_payload_amount("payment.captured", &payload),
            Err(AmountExtractionError::NonCanonicalAmount { .. })
        ));
    }

    #[test]
    fn rejects_decimal_string() {
        let payload = json!({ "amount": "14.99" });
        assert!(matches!(
            extract_payload_amount("payment.captured", &payload),
            Err(AmountExtractionError::NonCanonicalAmount { .. })
        ));
    }

    #[test]
    fn rejects_signed_string() {
        let payload = json!({ "amount": "+5" });
        assert!(matches!(
            extract_payload_amount("payment.captured", &payload),
            Err(AmountExtractionError::NonCanonicalAmount { .. })
        ));
    }

    #[test]
    fn rejects_empty_string() {
        let payload = json!({ "amount": "" });
        assert!(matches!(
            extract_payload_amount("payment.captured", &payload),
            Err(AmountExtractionError::NonCanonicalAmount { .. })
        ));
    }

    #[test]
    fn rejects_string_overflowing_u64() {
        let payload = json!({ "amount": "18446744073709551616" }); // u64::MAX + 1
        assert!(matches!(
            extract_payload_amount("payment.captured", &payload),
            Err(AmountExtractionError::NonCanonicalAmount { .. })
        ));
    }

    #[test]
    fn rejects_non_scalar_amount() {
        for bad in [
            json!({ "amount": null }),
            json!({ "amount": [1] }),
            json!({ "amount": { "v": 1 } }),
            json!({ "amount": true }),
        ] {
            assert!(matches!(
                extract_payload_amount("payment.captured", &bad),
                Err(AmountExtractionError::NonCanonicalAmount { .. })
            ));
        }
    }

    // ------------------------------------------------------------------
    // Malformed payloads / anti-shadowing
    // ------------------------------------------------------------------

    #[test]
    fn rejects_non_object_payload() {
        for bad in [json!(5), json!("x"), json!([1, 2]), json!(null)] {
            assert!(matches!(
                extract_payload_amount("order.created", &bad),
                Err(AmountExtractionError::PayloadNotObject { .. })
            ));
        }
    }

    #[test]
    fn missing_amount_field_is_reported_with_candidates() {
        let payload = json!({ "trackingNumber": "1Z" });
        let err = extract_payload_amount("order.shipped", &payload).unwrap_err();
        match err {
            AmountExtractionError::MissingAmountField {
                event_type,
                candidates,
            } => {
                assert_eq!(event_type, "order.shipped");
                assert!(!candidates.is_empty());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_first_candidate_does_not_fall_through() {
        // "total_amount" is present but malformed; a well-formed "total" decoy
        // later in the candidate list must NOT be used instead.
        let payload = json!({ "total_amount": 1482.37, "total": 1u64 });
        assert!(matches!(
            extract_payload_amount("order.created", &payload),
            Err(AmountExtractionError::NonCanonicalAmount {
                field: "total_amount",
                ..
            })
        ));
    }

    // ------------------------------------------------------------------
    // Witness commitment
    // ------------------------------------------------------------------

    #[test]
    fn witness_commitment_matches_binding_commitment() {
        // Must be identical to PayloadAmountBinding::witness_commitment_u64.
        use crate::public_inputs::PayloadAmountBinding;
        use uuid::Uuid;

        let binding = PayloadAmountBinding {
            event_id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            store_id: Uuid::from_u128(3),
            sequence_number: 7,
            payload_kind: 0,
            payload_plain_hash: "a".repeat(64),
            payload_cipher_hash: "b".repeat(64),
            event_signing_hash: "c".repeat(64),
            amount: 12_500,
            binding_hash: String::new(),
        };
        assert_eq!(
            amount_witness_commitment(12_500),
            binding.witness_commitment_u64()
        );
        assert_ne!(
            amount_witness_commitment(12_500),
            amount_witness_commitment(12_501)
        );
    }

    #[test]
    fn candidates_are_stable() {
        assert_eq!(amount_field_candidates("x402_payment.created"), &["amount"]);
        assert_eq!(
            amount_field_candidates("order.payment_received"),
            &["amount", "amount_units", "amountUnits"]
        );
        assert_eq!(
            amount_field_candidates("order.created")[..3],
            ["total_amount", "totalAmount", "total"]
        );
    }
}
