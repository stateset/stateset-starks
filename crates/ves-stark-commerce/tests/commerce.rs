use uuid::Uuid;
use ves_stark_commerce::{
    prepare_cap_proof_disclosed as prepare_cap_proof,
    verify_cap_proof_disclosed as verify_cap_proof, CommerceApproval, CommerceError,
    CommerceOperation, CommerceProof, CommerceRequest,
};

fn request() -> CommerceRequest {
    CommerceRequest {
        state_transition_hash: None,
        event_id: Uuid::from_u128(1),
        tenant_id: Uuid::from_u128(2),
        store_id: Uuid::from_u128(3),
        sequence_number: 42,
        operation: CommerceOperation::Refund,
        reference: "capture-123/refund-1".into(),
        currency: "USD".into(),
        decimal_places: 2,
        cap: 5_000,
    }
}

#[test]
fn confidential_commerce_fails_closed() {
    assert!(matches!(
        ves_stark_commerce::prepare_cap_proof(100, &request()),
        Err(CommerceError::ConfidentialityUnavailable(_))
    ));
    let prepared = prepare_cap_proof(100, &request()).unwrap();
    let approval = prepared.approval();
    let proof = prepared.prove().unwrap();
    assert!(matches!(
        approval.verify(&proof),
        Err(CommerceError::ConfidentialityUnavailable(_))
    ));
}

#[test]
fn refund_proof_roundtrip_rejects_substitution_and_tampering() {
    let expected = request();
    let prepared = prepare_cap_proof(4_242, &expected).unwrap();
    let approval = prepared.approval();
    let approval: CommerceApproval =
        serde_json::from_str(&serde_json::to_string(&approval).unwrap()).unwrap();
    let trusted_hash = prepared.payload_hash().to_owned();
    let proof = prepared.prove().unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let decoded: CommerceProof = serde_json::from_str(&json).unwrap();
    assert!(approval.verify_disclosed(&decoded).unwrap().valid);
    assert!(decoded.public_inputs.amount_binding_hash.is_none());
    assert!(
        verify_cap_proof(&decoded, &expected, &trusted_hash)
            .unwrap()
            .valid
    );

    let mutations: &[fn(&mut CommerceRequest)] = &[
        |r| r.event_id = Uuid::from_u128(11),
        |r| r.tenant_id = Uuid::from_u128(12),
        |r| r.store_id = Uuid::from_u128(13),
        |r| r.sequence_number += 1,
        |r| r.operation = CommerceOperation::Payment,
        |r| r.reference = "another-capture".into(),
        |r| r.currency = "EUR".into(),
        |r| r.decimal_places = 3,
        |r| r.cap += 1,
    ];
    for mutate in mutations {
        let mut other = expected.clone();
        mutate(&mut other);
        assert!(matches!(
            verify_cap_proof(&proof, &other, &trusted_hash),
            Err(CommerceError::ContextMismatch)
        ));
    }

    // A valid proof for a cheaper amount must not pass for the original event.
    let substitute = prepare_cap_proof(1, &expected).unwrap().prove().unwrap();
    assert!(verify_cap_proof(&substitute, &expected, &trusted_hash).is_err());

    let mut tampered = proof.clone();
    tampered.proof_bytes[0] ^= 0xff;
    assert!(verify_cap_proof(&tampered, &expected, &trusted_hash).is_err());
    let mut tampered = proof.clone();
    tampered.public_inputs.witness_commitment = Some("0".repeat(64));
    assert!(verify_cap_proof(&tampered, &expected, &trusted_hash).is_err());
    let mut tampered = proof.clone();
    tampered.public_inputs.payload_kind = 1;
    assert!(verify_cap_proof(&tampered, &expected, &trusted_hash).is_err());
    let mut tampered = proof;
    tampered.public_inputs.amount_binding_hash = Some("0".repeat(64));
    assert!(verify_cap_proof(&tampered, &expected, &trusted_hash).is_err());
}

#[test]
fn approval_requires_canonical_hash_and_valid_request() {
    let approval = prepare_cap_proof(100, &request()).unwrap().approval();
    for bad in [
        "".to_owned(),
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        format!("0x{}", "a".repeat(64)),
    ] {
        let mut changed = approval.clone();
        changed.payload_hash = bad;
        assert!(changed.validate().is_err());
    }
    let mut invalid = approval;
    invalid.request.currency = "usd".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn all_operations_and_full_u64_boundaries_verify() {
    for (operation, amount, cap) in [
        (CommerceOperation::Order, 0, 0),
        (CommerceOperation::Payment, 5_000, 5_000),
        (CommerceOperation::Refund, 0, 1),
        (CommerceOperation::Payout, u64::MAX, u64::MAX),
    ] {
        let request = CommerceRequest {
            operation,
            cap,
            ..request()
        };
        let prepared = prepare_cap_proof(amount, &request).unwrap();
        let hash = prepared.payload_hash().to_owned();
        assert!(
            verify_cap_proof(&prepared.prove().unwrap(), &request, &hash)
                .unwrap()
                .valid
        );
    }
}

#[test]
fn invalid_requests_fail_before_proving() {
    let mutations: &[fn(&mut CommerceRequest)] = &[
        |r| r.event_id = Uuid::nil(),
        |r| r.tenant_id = Uuid::nil(),
        |r| r.store_id = Uuid::nil(),
        |r| r.reference.clear(),
        |r| r.reference = "x".repeat(257),
        |r| r.reference = " ref".into(),
        |r| r.reference = "ref\n1".into(),
        |r| r.currency = "usd".into(),
        |r| r.currency = "US".into(),
        |r| r.currency = "€".into(),
        |r| r.decimal_places = 19,
    ];
    for mutate in mutations {
        let mut invalid = request();
        mutate(&mut invalid);
        assert!(matches!(
            prepare_cap_proof(0, &invalid),
            Err(CommerceError::InvalidRequest(_))
        ));
    }
    assert!(matches!(
        prepare_cap_proof(5_001, &request()),
        Err(CommerceError::ExceedsCap)
    ));
}

#[test]
fn repeated_amounts_use_different_commitments() {
    let request = request();
    let first = prepare_cap_proof(100, &request).unwrap();
    let second = prepare_cap_proof(100, &request).unwrap();
    assert_ne!(first.payload_hash(), second.payload_hash());
}

#[test]
fn request_json_rejects_ambiguous_money_and_unknown_fields() {
    let mut value = serde_json::to_value(request()).unwrap();
    value["cap"] = serde_json::json!(50.5);
    assert!(serde_json::from_value::<CommerceRequest>(value).is_err());
    let mut value = serde_json::to_value(request()).unwrap();
    value["cap"] = serde_json::json!(-1);
    assert!(serde_json::from_value::<CommerceRequest>(value).is_err());
    let mut value = serde_json::to_value(request()).unwrap();
    value["ignoredCurrency"] = serde_json::json!("EUR");
    assert!(serde_json::from_value::<CommerceRequest>(value).is_err());
}
