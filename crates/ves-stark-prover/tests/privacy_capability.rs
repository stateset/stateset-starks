use ves_stark_air::trace::cols;
use ves_stark_primitives::{
    public_inputs::{compute_policy_hash, CompliancePublicInputs, PolicyParams},
    Felt,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness, Policy};
use winter_math::{fields::QuadExtension, FieldElement};
use winter_prover::{ByteReader, Serializable, SliceReader};

#[test]
fn recover_synthetic_amount_from_public_proof() {
    let amount = (1u64 << 40) + 4242;
    let cap = u64::MAX;
    let params = PolicyParams::cap(cap);
    let inputs: CompliancePublicInputs = serde_json::from_value(serde_json::json!({
        "eventId": uuid::Uuid::new_v4(), "tenantId": uuid::Uuid::new_v4(),
        "storeId": uuid::Uuid::new_v4(), "sequenceNumber": 1, "payloadKind": 1,
        "payloadPlainHash": "a".repeat(64), "payloadCipherHash": "b".repeat(64),
        "eventSigningHash": "c".repeat(64), "policyId": "order_total.cap",
        "policyParams": params, "policyHash": compute_policy_hash("order_total.cap", &params).unwrap().to_hex()
    })).unwrap();
    let witness = ComplianceWitness::try_new_salted(amount, inputs).unwrap();
    let mut v2_inputs = witness.public_inputs.clone();
    let c = ves_stark_primitives::payload_amount::amount_witness_commitment_salted(
        amount,
        &witness.salt,
    );
    v2_inputs.payload_kind = 2;
    v2_inputs.amount_binding_hash = None;
    v2_inputs.rest_hash = Some("11".repeat(32));
    v2_inputs.payload_plain_hash =
        ves_stark_primitives::payload_v2::payload_plain_hash_v2(&c, &[0x11; 32]).to_hex();
    let witness = ComplianceWitness::try_new_with_salt(amount, witness.salt, v2_inputs).unwrap();
    let prover = ComplianceProver::with_policy(Policy::order_total_cap(cap));
    assert!(prover
        .prove_with_privacy(
            &witness,
            ves_stark_primitives::privacy::ProofPrivacy::default()
        )
        .is_err());
    let bundle = prover
        .prove_with_privacy(
            &witness,
            ves_stark_primitives::privacy::ProofPrivacy::AllowDisclosure,
        )
        .unwrap();
    // Only public proof bytes are used below, not the witness or salt.
    let proof: winter_air::proof::Proof =
        ves_stark_primitives::bounded_reader::deserialize_bounded(&bundle.proof_bytes).unwrap();
    let bytes = proof.ood_frame.to_bytes();
    // u16 byte length followed by u8 frame size, then interleaved current/next columns.
    let mut reader = SliceReader::new(&bytes[3..]);
    let evaluations: Vec<QuadExtension<Felt>> =
        reader.read_many((cols::FLAG_IS_FIRST + 1) * 2).unwrap();
    let selector = evaluations[cols::FLAG_IS_FIRST * 2];
    let lo = (evaluations[cols::AMOUNT_START * 2] / selector).to_base_elements();
    let hi = (evaluations[(cols::AMOUNT_START + 1) * 2] / selector).to_base_elements();
    assert_eq!(lo[1], Felt::ZERO);
    assert_eq!(hi[1], Felt::ZERO);
    let recovered = lo[0].as_int() + (hi[0].as_int() << 32);
    assert_eq!(recovered, amount);
    println!("Recovered synthetic amount from public proof alone: {recovered}");
}
