use ed25519_dalek::SigningKey;
use uuid::Uuid;
use ves_stark_commerce::{
    approval::{ApprovalAuthority, ApprovalTerms, SignedApproval},
    refund::{prove_refund_disclosed, RefundProof, RefundState, RefundTransition},
    CommerceApproval,
};

fn state() -> RefundState {
    RefundState {
        tenant_id: Uuid::from_u128(1),
        store_id: Uuid::from_u128(2),
        capture_id: "capture-123".into(),
        currency: "USD".into(),
        decimal_places: 2,
        captured: 10_000,
        refunded: 0,
        version: 0,
    }
}

fn authority() -> (SigningKey, ApprovalAuthority) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let authority = ApprovalAuthority {
        key_id: "refund-key-1".into(),
        public_key: key.verifying_key().to_bytes(),
        tenant_id: state().tenant_id,
        store_id: state().store_id,
        policy_version: 1,
        not_before: 10,
        expires_at: 1000,
        revoked: false,
    };
    (key, authority)
}

fn sign(approval: CommerceApproval) -> SignedApproval {
    let (key, _) = authority();
    SignedApproval::sign(
        ApprovalTerms {
            approval,
            key_id: "refund-key-1".into(),
            policy_version: 1,
            nonce: Uuid::new_v4(),
            not_before: 20,
            expires_at: 900,
        },
        &key,
    )
    .unwrap()
}

fn proof(before: RefundState, amount: u64) -> (RefundProof, SignedApproval) {
    let (proof, approval) = prove_refund_disclosed(before, amount, Uuid::new_v4(), 1).unwrap();
    (proof, sign(approval))
}

#[test]
fn signed_refund_verifies_and_rejects_tampering() {
    let (proof, signed) = proof(state(), 4242);
    let (_, authority) = authority();
    let before = state().commitment().unwrap();
    proof
        .transition
        .verify_signed_disclosed(&signed, &authority, 100, &before)
        .unwrap();
    proof
        .verify_disclosed(&signed, &authority, 100, &before)
        .unwrap();
    for mutate in [
        (|p: &mut RefundProof| p.transition.amount += 1) as fn(&mut RefundProof),
        |p| p.transition.after.refunded -= 1,
        |p| p.transition.after.version += 1,
        |p| p.transition.after.currency = "EUR".into(),
        |p| p.transition.before.capture_id = "other".into(),
        |p| p.proof.proof_bytes[0] ^= 255,
        |p| p.proof.public_inputs.witness_commitment = Some("0".repeat(64)),
    ] {
        let mut tampered = proof.clone();
        mutate(&mut tampered);
        assert!(tampered
            .verify_disclosed(&signed, &authority, 100, &before)
            .is_err());
    }
    assert!(proof
        .verify_disclosed(&signed, &authority, 100, &"0".repeat(64))
        .is_err());
    for now in [0, 19, 900, 1000, u64::MAX] {
        assert!(proof
            .verify_disclosed(&signed, &authority, now, &before)
            .is_err());
    }
    for mutate in [
        (|a: &mut ApprovalAuthority| a.revoked = true) as fn(&mut ApprovalAuthority),
        |a| a.policy_version = 2,
        |a| a.public_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        |a| a.key_id = "other".into(),
        |a| a.tenant_id = Uuid::new_v4(),
        |a| a.store_id = Uuid::new_v4(),
        |a| a.not_before = 21,
        |a| a.expires_at = 899,
    ] {
        let mut wrong = authority.clone();
        mutate(&mut wrong);
        assert!(signed.verify(&wrong, 100).is_err());
    }
    for mutate in [
        (|s: &mut SignedApproval| s.terms.nonce = Uuid::new_v4()) as fn(&mut SignedApproval),
        |s| s.terms.policy_version = 2,
        |s| s.terms.expires_at = 901,
        |s| s.terms.approval.request.cap += 1,
        |s| s.terms.approval.payload_hash = "0".repeat(64),
        |s| s.signature = "0".repeat(128),
    ] {
        let mut wrong = signed.clone();
        mutate(&mut wrong);
        assert!(wrong.verify(&authority, 100).is_err());
    }
}

#[test]
fn exact_amount_and_transition_are_bound_even_with_a_fresh_signature() {
    let (mut proof, signed) = proof(state(), 100);
    // An authority can sign a context but cannot make an unrelated STARK prove
    // the accounting amount. Re-sign the changed transition with the real key.
    proof.transition = RefundTransition::new(state(), 200).unwrap();
    let mut approval = signed.terms.approval;
    approval.request.state_transition_hash = Some(proof.transition.commitment().unwrap());
    let signed = sign(approval);
    assert!(proof
        .verify_disclosed(&signed, &authority().1, 100, &state().commitment().unwrap())
        .is_err());
}

#[test]
fn arithmetic_boundaries_are_checked_without_field_wraparound() {
    assert!(RefundTransition::new(state(), 0).is_err());
    assert!(RefundTransition::new(state(), 10_001).is_err());
    let full = RefundTransition::new(state(), 10_000).unwrap();
    assert!(RefundTransition::new(full.after, 1).is_err());
    let max = RefundState {
        captured: u64::MAX,
        ..state()
    };
    assert_eq!(
        RefundTransition::new(max.clone(), u64::MAX)
            .unwrap()
            .after
            .refunded,
        u64::MAX
    );
    assert!(RefundTransition::new(
        RefundState {
            refunded: u64::MAX,
            ..max
        },
        1
    )
    .is_err());
    assert!(RefundTransition::new(
        RefundState {
            version: u64::MAX,
            ..state()
        },
        1
    )
    .is_err());
    assert_ne!(
        RefundState {
            captured: u64::MAX,
            ..state()
        }
        .commitment()
        .unwrap(),
        RefundState {
            captured: u64::MAX - 1,
            ..state()
        }
        .commitment()
        .unwrap()
    );
}

#[cfg(feature = "ledger")]
mod ledger_tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::{Arc, Barrier},
    };
    use ves_stark_commerce::ledger::{LedgerError, RefundLedger};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("refund-ledger-{}", Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn db(&self) -> PathBuf {
            self.0.join("ledger.db")
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn concurrent_refunds_cannot_spend_the_same_predecessor() {
        let scratch = Scratch::new();
        let first = RefundLedger::open(scratch.db()).unwrap();
        first.register_capture(&state()).unwrap();
        let second = RefundLedger::open(scratch.db()).unwrap();
        let pair1 = proof(state(), 7000);
        let pair2 = proof(state(), 7000);
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [(first, pair1), (second, pair2)]
            .into_iter()
            .map(|(mut ledger, (proof, signed))| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    ledger.apply_refund(&proof, &signed, &authority().1, 100)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(LedgerError::StaleState)))
                .count(),
            1
        );
        let ledger = RefundLedger::open(scratch.db()).unwrap();
        assert_eq!(
            ledger
                .state(state().tenant_id, state().store_id, "capture-123")
                .unwrap()
                .refunded,
            7000
        );
        assert_eq!(ledger.pending(10).unwrap().len(), 1);
    }

    #[test]
    fn unrelated_database_and_future_schema_are_rejected_without_modification() {
        let scratch = Scratch::new();
        let db = rusqlite::Connection::open(scratch.db()).unwrap();
        db.execute_batch(
            "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES ('keep');",
        )
        .unwrap();
        assert!(matches!(
            RefundLedger::open(scratch.db()),
            Err(LedgerError::UnsupportedSchema)
        ));
        let tables: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
        let value: String = db
            .query_row("SELECT value FROM unrelated", [], |r| r.get(0))
            .unwrap();
        assert_eq!(value, "keep");
        let future = scratch.0.join("future.db");
        let db = rusqlite::Connection::open(&future).unwrap();
        db.execute_batch("PRAGMA application_id=1397969478; PRAGMA user_version=2;")
            .unwrap();
        assert!(matches!(
            RefundLedger::open(future),
            Err(LedgerError::UnsupportedSchema)
        ));
    }

    #[test]
    fn rollback_restart_replay_and_provider_retry_are_safe() {
        let scratch = Scratch::new();
        let mut ledger = RefundLedger::open(scratch.db()).unwrap();
        ledger.register_capture(&state()).unwrap();
        let (proof, signed) = proof(state(), 4242);
        let db = rusqlite::Connection::open(scratch.db()).unwrap();
        db.execute_batch("CREATE TRIGGER fail_outbox BEFORE INSERT ON refund_outbox BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        assert!(ledger
            .apply_refund(&proof, &signed, &authority().1, 100)
            .is_err());
        assert_eq!(
            ledger
                .state(state().tenant_id, state().store_id, "capture-123")
                .unwrap(),
            state()
        );
        assert!(ledger.pending(10).unwrap().is_empty());
        let consumed: u64 = db
            .query_row("SELECT COUNT(*) FROM refund_consumptions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(consumed, 0);
        db.execute_batch("DROP TRIGGER fail_outbox").unwrap();
        let execution = ledger
            .apply_refund(&proof, &signed, &authority().1, 100)
            .unwrap();
        assert!(matches!(
            ledger.apply_refund(&proof, &signed, &authority().1, 100),
            Err(LedgerError::AlreadyConsumed)
        ));
        assert!(ledger.register_capture(&state()).is_err());
        drop(ledger);
        let ledger = RefundLedger::open(scratch.db()).unwrap();
        assert_eq!(ledger.pending(10).unwrap(), vec![execution.clone()]);
        assert_eq!(ledger.pending(10).unwrap(), vec![execution.clone()]); // worker crash/retry
        ledger
            .mark_executed(&execution.idempotency_key, "provider-refund-1")
            .unwrap();
        ledger
            .mark_executed(&execution.idempotency_key, "provider-refund-1")
            .unwrap();
        assert!(ledger
            .mark_executed(&execution.idempotency_key, "different")
            .is_err());
        assert!(ledger.pending(10).unwrap().is_empty());
        assert_eq!(
            ledger
                .state(state().tenant_id, state().store_id, "capture-123")
                .unwrap()
                .refunded,
            4242
        );
    }

    #[test]
    fn reused_nonce_and_revocation_do_not_advance_state() {
        let scratch = Scratch::new();
        let mut ledger = RefundLedger::open(scratch.db()).unwrap();
        ledger.register_capture(&state()).unwrap();
        let (first, signed) = proof(state(), 100);
        ledger
            .apply_refund(&first, &signed, &authority().1, 100)
            .unwrap();
        let (second, mut next) = proof(first.transition.after.clone(), 100);
        next.terms.nonce = signed.terms.nonce;
        next = SignedApproval::sign(next.terms, &authority().0).unwrap();
        assert!(matches!(
            ledger.apply_refund(&second, &next, &authority().1, 100),
            Err(LedgerError::AlreadyConsumed)
        ));
        let mut revoked = authority().1;
        revoked.revoked = true;
        assert!(ledger.apply_refund(&second, &next, &revoked, 100).is_err());
        assert_eq!(
            ledger
                .state(state().tenant_id, state().store_id, "capture-123")
                .unwrap()
                .refunded,
            100
        );
    }
}
