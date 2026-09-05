use uuid::Uuid;
use ves_stark_commerce::{
    prepare_cap_proof_disclosed, verify_cap_proof_disclosed, CommerceOperation, CommerceRequest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The refund ledger approves up to $50 against this capture.
    let request = CommerceRequest {
        state_transition_hash: None,
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::from_u128(1),
        store_id: Uuid::from_u128(2),
        sequence_number: 42,
        operation: CommerceOperation::Refund,
        reference: "capture-123/refund-1".into(),
        currency: "USD".into(),
        decimal_places: 2,
        cap: 5_000,
    };
    // Trusted intake knows the actual refund amount ($42.42).
    let prepared = prepare_cap_proof_disclosed(4_242, &request)?;
    // Production: authenticate and store this hash with the request in the
    // approval record. The verifier retrieves it independently of the proof.
    let approved_payload_hash = prepared.payload_hash().to_owned();
    let proof = prepared.prove()?;
    let result = verify_cap_proof_disclosed(&proof, &request, &approved_payload_hash)?;
    println!(
        "Refund cap verified: {}; proof: {} bytes",
        result.valid,
        proof.proof_bytes.len()
    );
    // Production: atomically consume event_id before executing the refund.
    Ok(())
}
