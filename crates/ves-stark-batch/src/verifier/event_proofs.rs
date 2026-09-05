//! Stronger batch verification using independent V2 event proofs.
//! This is proof composition, not a compressed aggregate proof or a zero-knowledge backend.

use super::{verify_batch_proof, BatchVerificationResult};
use crate::{
    compute_public_inputs_accumulator, BatchError, BatchPublicInputs, BatchStateRoot, EventLeaf,
    EventMerkleTree,
};
use std::collections::HashSet;
use uuid::Uuid;
use ves_stark_air::policy::Policy;
use ves_stark_primitives::{
    felt_from_u64, hash_to_felts,
    privacy::ProofPrivacy,
    public_inputs::{witness_commitment_hex_to_u64, CompliancePublicInputs},
    Felt,
};
use ves_stark_verifier::ComplianceVerification;

/// Verify aggregate integrity AND payload binding for every expected V2 event.
///
/// `expected_events` and `batch_inputs` must be authenticated independently of the
/// prover. Event proofs are positional and must exactly match that ordered list.
/// The reconstructed Merkle/final state root binds the proven amount commitments
/// to the batch, closing the gap that checking the ordered accumulator alone cannot.
///
/// This retains each individual proof and adds its verification cost. It does
/// not upgrade the aggregate AIR or provide proof compression or confidentiality.
pub fn verify_batch_with_event_proofs(
    batch_bytes: &[u8],
    batch_inputs: &BatchPublicInputs,
    expected_events: &[CompliancePublicInputs],
    event_proofs: &[Vec<u8>],
    privacy: ProofPrivacy,
) -> Result<BatchVerificationResult, BatchError> {
    let invalid = |message: &str| BatchError::InvalidPublicInputs(message.to_owned());
    privacy.enforce().map_err(|e| invalid(&e.to_string()))?;
    let count = batch_inputs.validate()?;
    if expected_events.len() != count
        || event_proofs.len() != count
        || !batch_inputs.is_all_compliant()
    {
        return Err(invalid(
            "payload-bound verification requires one compliant V2 proof per expected event",
        ));
    }
    let policy_kind = batch_inputs
        .policy_kind_enum()
        .ok_or_else(|| invalid("invalid policy kind"))?;
    let policy = Policy::from_public_inputs(
        policy_kind.policy_id(),
        &policy_kind.policy_params(batch_inputs.policy_limit_u64()),
    )
    .map_err(|e| invalid(&e.to_string()))?;
    let policy_hash = batch_inputs.try_policy_hash()?;
    let mut ids = HashSet::new();
    let mut leaves = Vec::with_capacity(count);
    for (index, (inputs, proof)) in expected_events.iter().zip(event_proofs).enumerate() {
        let seq = batch_inputs
            .sequence_start
            .as_int()
            .checked_add(index as u64)
            .ok_or_else(|| invalid("sequence overflow"))?;
        if inputs.payload_kind != 2
            || uuid_felts(inputs.tenant_id) != batch_inputs.tenant_id
            || uuid_felts(inputs.store_id) != batch_inputs.store_id
            || inputs.sequence_number != seq
            || !ids.insert(inputs.event_id)
        {
            return Err(invalid("V2 event scope, sequence, or uniqueness mismatch"));
        }
        ComplianceVerification::new(proof, inputs)
            .policy(&policy)
            .witness_only()
            .strict()
            .run()
            .map_err(|e| invalid(&format!("event {index}: {e}")))?;
        let commitment = witness_commitment_hex_to_u64(
            inputs
                .witness_commitment
                .as_deref()
                .ok_or_else(|| invalid("event witness commitment is required"))?,
        )
        .map_err(|e| invalid(&e.to_string()))?;
        leaves.push(EventLeaf::new(
            uuid_felts(inputs.event_id),
            commitment.map(felt_from_u64),
            policy_hash,
            hash_to_felts(
                &inputs
                    .compute_bound_hash()
                    .map_err(|e| invalid(&e.to_string()))?,
            ),
            true,
        ));
    }
    if compute_public_inputs_accumulator(expected_events)? != batch_inputs.public_inputs_accumulator
    {
        return Err(invalid("event accumulator mismatch"));
    }
    let tree = EventMerkleTree::from_leaves(leaves)?;
    let root = BatchStateRoot::from_components(
        &tree.root(),
        &batch_inputs.metadata_hash(),
        &batch_inputs.prev_state_root,
    );
    if root.root != batch_inputs.new_state_root {
        return Err(invalid(
            "proven event commitments do not reconstruct the batch state root",
        ));
    }
    let mut result = verify_batch_proof(batch_bytes, batch_inputs)?;
    if !result.valid {
        return Err(invalid("aggregate STARK verification failed"));
    }
    result.payload_binding_verified = true;
    Ok(result)
}

fn uuid_felts(id: Uuid) -> [Felt; 4] {
    let bytes = id.as_bytes();
    std::array::from_fn(|i| {
        felt_from_u64(
            u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("UUID chunk")) as u64,
        )
    })
}
