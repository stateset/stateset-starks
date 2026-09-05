//! Synthetic disclosed-refund rehearsal with a signed-record verification baseline.
use ed25519_dalek::SigningKey;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use ves_stark_commerce::{
    approval::{ApprovalAuthority, ApprovalTerms, SignedApproval},
    ledger::RefundLedger,
    refund::{prove_refund_disclosed, RefundState},
};

fn percentile(values: &mut [u128], percentile: usize) -> u128 {
    values.sort_unstable();
    values[(values.len() * percentile).div_ceil(100).saturating_sub(1)]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: refund_pilot NEW_LEDGER_PATH")?;
    if std::path::Path::new(&path).exists() {
        return Err("pilot requires a new database path".into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let key = SigningKey::from_bytes(&rand::random());
    let mut state = RefundState {
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        capture_id: "synthetic-capture-1".into(),
        currency: "USD".into(),
        decimal_places: 2,
        captured: 10_000,
        refunded: 0,
        version: 0,
    };
    let authority = ApprovalAuthority {
        key_id: "pilot-only".into(),
        public_key: key.verifying_key().to_bytes(),
        tenant_id: state.tenant_id,
        store_id: state.store_id,
        policy_version: 1,
        not_before: now,
        expires_at: now + 3600,
        revoked: false,
    };
    let mut ledger = RefundLedger::open(&path)?;
    ledger.register_capture(&state)?;
    let mut prove_times = Vec::new();
    let mut verify_times = Vec::new();
    let mut baseline_times = Vec::new();
    let mut samples = Vec::new();
    for sequence in 0..10 {
        let start = Instant::now();
        let (proof, approval) =
            prove_refund_disclosed(state.clone(), 500, Uuid::new_v4(), sequence)?;
        let prove_us = start.elapsed().as_micros();
        let signed = SignedApproval::sign(
            ApprovalTerms {
                approval,
                key_id: authority.key_id.clone(),
                policy_version: 1,
                nonce: Uuid::new_v4(),
                not_before: now,
                expires_at: now + 600,
            },
            &key,
        )?;
        let expected_before = state.commitment()?;
        let start = Instant::now();
        // Baseline: trust intake's signed disclosed transition and check arithmetic;
        // no STARK evaluation. This is verification-only, not a second ledger implementation.
        proof
            .transition
            .verify_signed_disclosed(&signed, &authority, now, &expected_before)?;
        let baseline_us = start.elapsed().as_micros();
        let start = Instant::now();
        proof.verify_disclosed(&signed, &authority, now, &expected_before)?;
        let verify_us = start.elapsed().as_micros();
        let start = Instant::now();
        let execution = ledger.apply_refund(&proof, &signed, &authority, now)?;
        let reserve_us = start.elapsed().as_micros();
        assert!(ledger
            .apply_refund(&proof, &signed, &authority, now)
            .is_err());
        // Simulate restart after provider success but before local completion.
        drop(ledger);
        ledger = RefundLedger::open(&path)?;
        assert!(ledger
            .pending(100)?
            .iter()
            .any(|e| e.idempotency_key == execution.idempotency_key));
        ledger.mark_executed(
            &execution.idempotency_key,
            &format!("synthetic-provider-{sequence}"),
        )?;
        prove_times.push(prove_us);
        verify_times.push(verify_us);
        baseline_times.push(baseline_us);
        samples.push(serde_json::json!({"proveUs": prove_us, "verifyUs": verify_us,
            "signedBaselineVerifyUs": baseline_us, "reserveUs": reserve_us, "proofBytes": proof.proof.proof_bytes.len()}));
        state = proof.transition.after;
    }
    assert_eq!(state.refunded, 5000);
    assert!(ledger.pending(100)?.is_empty());
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "synthetic": true, "zeroKnowledge": false, "build": if cfg!(debug_assertions) {"debug"} else {"optimized"},
            "sampleCount": samples.len(), "proveP95Us": percentile(&mut prove_times, 95),
            "verifyP95Us": percentile(&mut verify_times, 95), "signedBaselineVerifyP95Us": percentile(&mut baseline_times, 95),
            "finalRefunded": state.refunded, "pendingExecutions": 0, "samples": samples
        }))?
    );
    Ok(())
}
