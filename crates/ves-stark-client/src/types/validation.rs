//! Shared validation for responses, bundles and submissions.

use super::*;

pub(crate) fn validate_bundle_proof_artifact(
    proof_bytes: &[u8],
    proof_hash: &str,
    metadata: &ProofMetadata,
    witness_commitment: &[u64; 4],
    witness_commitment_hex: Option<&str>,
) -> Result<()> {
    if proof_bytes.is_empty() {
        return Err(ClientError::InvalidProofBundle(
            "proof_bytes must not be empty".to_string(),
        ));
    }

    let expected_proof_hash = ComplianceProof::compute_hash(proof_bytes).to_hex();
    if proof_hash != expected_proof_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "proof_hash mismatch: expected {}, got {}",
            expected_proof_hash, proof_hash
        )));
    }

    if metadata.proof_size != proof_bytes.len() {
        return Err(ClientError::InvalidProofBundle(format!(
            "metadata.proof_size mismatch: expected {}, got {}",
            proof_bytes.len(),
            metadata.proof_size
        )));
    }

    let expected_commitment_hex = witness_commitment_u64_to_hex(witness_commitment);
    match witness_commitment_hex {
        Some(actual) if actual == expected_commitment_hex => {}
        Some(actual) => {
            return Err(ClientError::InvalidProofBundle(format!(
                "witness_commitment_hex mismatch: expected {}, got {}",
                expected_commitment_hex, actual
            )));
        }
        None => {
            return Err(ClientError::InvalidProofBundle(
                "missing witness_commitment_hex".to_string(),
            ));
        }
    }

    Ok(())
}

pub(crate) fn normalized_optional_witness_commitment(
    witness_commitment: Option<[u64; 4]>,
    witness_commitment_hex: Option<&str>,
    context: &str,
) -> Result<Option<[u64; 4]>> {
    let parsed_hex = witness_commitment_hex
        .map(|hex| {
            witness_commitment_hex_to_u64(hex).map_err(|e| {
                ClientError::InvalidProofBundle(format!(
                    "{context} has invalid witnessCommitmentHex: {e}"
                ))
            })
        })
        .transpose()?;

    match (witness_commitment, parsed_hex) {
        (Some(commitment), Some(parsed)) => {
            if commitment != parsed {
                return Err(ClientError::InvalidProofBundle(format!(
                    "{context} witness commitment array does not match witnessCommitmentHex"
                )));
            }
            Ok(Some(commitment))
        }
        (Some(commitment), None) => Ok(Some(commitment)),
        (None, Some(parsed)) => Ok(Some(parsed)),
        (None, None) => Ok(None),
    }
}

pub(crate) fn parse_optional_public_inputs_value(
    value: &Option<serde_json::Value>,
    context: &str,
) -> Result<Option<CompliancePublicInputs>> {
    value
        .as_ref()
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|e| {
                ClientError::InvalidPublicInputs(format!(
                    "failed to parse {context} public_inputs: {e}"
                ))
            })
        })
        .transpose()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_response_public_inputs(
    context: &str,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &str,
    witness_commitment: Option<[u64; 4]>,
    public_inputs: &CompliancePublicInputs,
) -> Result<()> {
    if public_inputs.event_id != event_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs event_id mismatch: expected {}, got {}",
            event_id, public_inputs.event_id
        )));
    }
    if public_inputs.tenant_id != tenant_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs tenant_id mismatch: expected {}, got {}",
            tenant_id, public_inputs.tenant_id
        )));
    }
    if public_inputs.store_id != store_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs store_id mismatch: expected {}, got {}",
            store_id, public_inputs.store_id
        )));
    }
    if public_inputs.policy_id != policy_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policy_id mismatch: expected {}, got {}",
            policy_id, public_inputs.policy_id
        )));
    }
    if public_inputs.policy_params.to_json_value() != *policy_params {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policy_params mismatch"
        )));
    }
    if public_inputs.policy_hash != policy_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policy_hash mismatch: expected {}, got {}",
            policy_hash, public_inputs.policy_hash
        )));
    }

    let policy_hash_valid = public_inputs
        .validate_policy_hash()
        .map_err(|e| ClientError::InvalidProofBundle(format!("{context} public_inputs: {e}")))?;
    if !policy_hash_valid {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs policyHash does not match canonical policy params"
        )));
    }

    if let Some(expected_witness_commitment) = witness_commitment {
        if let Some(actual_witness_commitment) = public_inputs
            .witness_commitment_u64()
            .map_err(|e| ClientError::InvalidProofBundle(format!("{context} public_inputs: {e}")))?
        {
            if actual_witness_commitment != expected_witness_commitment {
                return Err(ClientError::InvalidProofBundle(format!(
                    "{context} public_inputs witnessCommitment does not match response witness commitment"
                )));
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_public_inputs_equal(
    expected: &CompliancePublicInputs,
    actual: &CompliancePublicInputs,
    context: &str,
) -> Result<()> {
    let expected_hash = expected
        .compute_full_hash()
        .map_err(|e| ClientError::InvalidProofBundle(format!("{context}: {e}")))?
        .to_hex();
    let actual_hash = actual
        .compute_full_hash()
        .map_err(|e| ClientError::InvalidProofBundle(format!("{context}: {e}")))?
        .to_hex();

    if expected_hash != actual_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} public_inputs do not match bundle public_inputs"
        )));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_compliance_bundle_response_common(
    context: &str,
    bundle: &ComplianceProofBundle,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: &str,
    proof_version: u32,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &str,
    proof_hash: &str,
    witness_commitment: Option<[u64; 4]>,
    witness_commitment_hex: Option<&str>,
) -> Result<()> {
    let normalized_witness_commitment = normalized_optional_witness_commitment(
        witness_commitment,
        witness_commitment_hex,
        context,
    )?;

    if event_id != bundle.public_inputs.event_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} event_id mismatch: expected {}, got {}",
            bundle.public_inputs.event_id, event_id
        )));
    }
    if tenant_id != bundle.public_inputs.tenant_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} tenant_id mismatch: expected {}, got {}",
            bundle.public_inputs.tenant_id, tenant_id
        )));
    }
    if store_id != bundle.public_inputs.store_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} store_id mismatch: expected {}, got {}",
            bundle.public_inputs.store_id, store_id
        )));
    }
    if proof_type != bundle.proof_type {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_type mismatch: expected {}, got {}",
            bundle.proof_type, proof_type
        )));
    }
    if proof_version != bundle.proof_version {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_version mismatch: expected {}, got {}",
            bundle.proof_version, proof_version
        )));
    }
    if policy_id != bundle.public_inputs.policy_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_id mismatch: expected {}, got {}",
            bundle.public_inputs.policy_id, policy_id
        )));
    }
    if *policy_params != bundle.public_inputs.policy_params.to_json_value() {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_params do not match bundle policy params"
        )));
    }
    if policy_hash != bundle.public_inputs.policy_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_hash mismatch: expected {}, got {}",
            bundle.public_inputs.policy_hash, policy_hash
        )));
    }
    if proof_hash != bundle.proof_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_hash mismatch: expected {}, got {}",
            bundle.proof_hash, proof_hash
        )));
    }
    if let Some(witness_commitment) = normalized_witness_commitment {
        if witness_commitment != bundle.witness_commitment {
            return Err(ClientError::InvalidProofBundle(format!(
                "{context} witness commitment does not match bundle witness commitment"
            )));
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_bundle_response_common(
    context: &str,
    bundle: &AgentAuthorizationProofBundle,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: &str,
    proof_version: u32,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &str,
    proof_hash: &str,
    witness_commitment: Option<[u64; 4]>,
    witness_commitment_hex: Option<&str>,
) -> Result<()> {
    let normalized_witness_commitment = normalized_optional_witness_commitment(
        witness_commitment,
        witness_commitment_hex,
        context,
    )?;

    if event_id != bundle.receipt.event_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} event_id mismatch: expected {}, got {}",
            bundle.receipt.event_id, event_id
        )));
    }
    if tenant_id != bundle.receipt.tenant_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} tenant_id mismatch: expected {}, got {}",
            bundle.receipt.tenant_id, tenant_id
        )));
    }
    if store_id != bundle.receipt.store_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} store_id mismatch: expected {}, got {}",
            bundle.receipt.store_id, store_id
        )));
    }
    if proof_type != bundle.proof_type {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_type mismatch: expected {}, got {}",
            bundle.proof_type, proof_type
        )));
    }
    if proof_version != bundle.proof_version {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_version mismatch: expected {}, got {}",
            bundle.proof_version, proof_version
        )));
    }
    if policy_id != bundle.public_inputs.policy_id {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_id mismatch: expected {}, got {}",
            bundle.public_inputs.policy_id, policy_id
        )));
    }
    if *policy_params != bundle.public_inputs.policy_params.to_json_value() {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_params do not match bundle policy params"
        )));
    }
    if policy_hash != bundle.public_inputs.policy_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} policy_hash mismatch: expected {}, got {}",
            bundle.public_inputs.policy_hash, policy_hash
        )));
    }
    if proof_hash != bundle.proof_hash {
        return Err(ClientError::InvalidProofBundle(format!(
            "{context} proof_hash mismatch: expected {}, got {}",
            bundle.proof_hash, proof_hash
        )));
    }
    if let Some(witness_commitment) = normalized_witness_commitment {
        if witness_commitment != bundle.witness_commitment {
            return Err(ClientError::InvalidProofBundle(format!(
                "{context} witness commitment does not match bundle witness commitment"
            )));
        }
    }

    Ok(())
}

pub(crate) fn validate_submission_public_inputs(
    event_id: Uuid,
    policy_id: &str,
    policy_params: &serde_json::Value,
    witness_commitment: &[u64; 4],
    public_inputs: &CompliancePublicInputs,
) -> Result<()> {
    if public_inputs.event_id != event_id {
        return Err(ClientError::InvalidPublicInputs(format!(
            "event_id mismatch: submission targets {}, but public inputs are for {}",
            event_id, public_inputs.event_id
        )));
    }
    if public_inputs.policy_id != policy_id {
        return Err(ClientError::InvalidPublicInputs(format!(
            "policy_id mismatch: submission targets {}, but public inputs are for {}",
            policy_id, public_inputs.policy_id
        )));
    }
    if public_inputs.policy_params.to_json_value() != *policy_params {
        return Err(ClientError::InvalidPublicInputs(format!(
            "policy_params mismatch for policy {}",
            policy_id
        )));
    }
    let policy_hash_valid = public_inputs
        .validate_policy_hash()
        .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?;
    if !policy_hash_valid {
        return Err(ClientError::InvalidPublicInputs(
            "policyHash does not match canonical policy params".to_string(),
        ));
    }
    if let Some(expected) = public_inputs
        .witness_commitment_u64()
        .map_err(|e| ClientError::InvalidPublicInputs(format!("{e}")))?
    {
        if &expected != witness_commitment {
            return Err(ClientError::InvalidPublicInputs(
                "witnessCommitment in public inputs does not match submission witness commitment"
                    .to_string(),
            ));
        }
    }

    Ok(())
}
