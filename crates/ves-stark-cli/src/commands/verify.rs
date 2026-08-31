//! `verify` command(s). Shared helpers live in `main.rs`.

use super::*;

pub(crate) fn verify_compliance_bundle(
    bundle: ComplianceProofBundle,
    inputs_path: Option<PathBuf>,
    witness_commitment_hex: Option<String>,
    amount_binding_path: Option<PathBuf>,
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<String>,
) -> Result<()> {
    let intent_hash = resolve_intent_hash(policy_type, intent_hash, Some(&bundle.public_inputs))?;
    validate_public_inputs_match_policy(
        &bundle.public_inputs,
        policy_type,
        limit,
        intent_hash.as_deref(),
    )?;

    if let Some(path) = inputs_path.as_ref() {
        let inputs_str = read_text_input(path, "inputs")?;
        let inputs = serde_json::from_str::<CompliancePublicInputs>(&inputs_str)
            .with_context(|| "Failed to parse public inputs JSON")?;
        ensure_public_inputs_match(&bundle.public_inputs, &inputs, "provided")?;
    }

    if let Some(path) = amount_binding_path.as_ref() {
        let binding_str = read_text_input(path, "payload amount binding")?;
        let binding = serde_json::from_str::<PayloadAmountBinding>(&binding_str)
            .with_context(|| "Failed to parse payload amount binding JSON")?;
        ensure_payload_amount_binding_match(&bundle.amount_binding, &binding, "provided")?;
    }

    if let Some(hex) = witness_commitment_hex.as_deref() {
        let expected = bundle
            .witness_commitment_hex
            .clone()
            .unwrap_or_else(|| witness_commitment_u64_to_hex(&bundle.witness_commitment));
        if hex != expected {
            anyhow::bail!("--witness-commitment-hex does not match the canonical proof bundle");
        }
    }

    eprintln!("Verifying canonical proof bundle...");
    eprintln!("  Policy: {}", bundle.public_inputs.policy_id);
    eprintln!("  Limit: {}", limit);
    eprintln!("  Event ID: {}", bundle.public_inputs.event_id);
    eprintln!("  Bundle hash: {}", bundle.bundle_hash);

    let result = bundle
        .verify_strict()
        .map_err(|e| anyhow::anyhow!("Verification error: {e}"))?;

    eprintln!(
        "Proof VALID (verified in {} ms)",
        result.verification_time_ms
    );
    println!("VALID");
    Ok(())
}

// Arguments map 1:1 to CLI flags for this subcommand; grouping them into a
// struct would only add indirection over the clap-parsed values.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_agent_authorization_bundle(
    bundle: AgentAuthorizationProofBundle,
    inputs_path: Option<PathBuf>,
    witness_commitment_hex: Option<String>,
    authorization_receipt_path: Option<PathBuf>,
    amount_binding_path: Option<PathBuf>,
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<String>,
) -> Result<()> {
    let intent_hash = resolve_intent_hash(policy_type, intent_hash, Some(&bundle.public_inputs))?;
    validate_public_inputs_match_policy(
        &bundle.public_inputs,
        policy_type,
        limit,
        intent_hash.as_deref(),
    )?;

    if let Some(path) = inputs_path.as_ref() {
        let inputs_str = read_text_input(path, "inputs")?;
        let inputs = serde_json::from_str::<CompliancePublicInputs>(&inputs_str)
            .with_context(|| "Failed to parse public inputs JSON")?;
        ensure_public_inputs_match(&bundle.public_inputs, &inputs, "provided")?;
    }

    if let Some(path) = amount_binding_path.as_ref() {
        let binding_str = read_text_input(path, "payload amount binding")?;
        let binding = serde_json::from_str::<PayloadAmountBinding>(&binding_str)
            .with_context(|| "Failed to parse payload amount binding JSON")?;
        ensure_payload_amount_binding_match(&bundle.amount_binding, &binding, "provided")?;
    }

    if let Some(path) = authorization_receipt_path.as_ref() {
        let receipt_str = read_text_input(path, "authorization receipt")?;
        let receipt = serde_json::from_str::<CommerceAuthorizationReceipt>(&receipt_str)
            .with_context(|| "Failed to parse authorization receipt JSON")?;
        ensure_authorization_receipt_match(&bundle.receipt, &receipt, "provided")?;
    }

    if let Some(hex) = witness_commitment_hex.as_deref() {
        let expected = bundle
            .witness_commitment_hex
            .clone()
            .unwrap_or_else(|| witness_commitment_u64_to_hex(&bundle.witness_commitment));
        if hex != expected {
            anyhow::bail!("--witness-commitment-hex does not match the canonical proof bundle");
        }
    }

    eprintln!("Verifying canonical authorization proof bundle...");
    eprintln!("  Policy: {}", bundle.public_inputs.policy_id);
    eprintln!("  Limit: {}", limit);
    eprintln!("  Event ID: {}", bundle.public_inputs.event_id);
    eprintln!("  Bundle hash: {}", bundle.bundle_hash);

    let result = bundle
        .verify_strict()
        .map_err(|e| anyhow::anyhow!("Verification error: {e}"))?;

    eprintln!(
        "Proof VALID (verified in {} ms)",
        result.verification_time_ms
    );
    println!("VALID");
    Ok(())
}

// Arguments map 1:1 to CLI flags for this subcommand; grouping them into a
// struct would only add indirection over the clap-parsed values.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    proof_path: PathBuf,
    inputs_path: Option<PathBuf>,
    cli_witness_commitment_hex: Option<String>,
    authorization_receipt_path: Option<PathBuf>,
    amount_binding_path: Option<PathBuf>,
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<String>,
) -> Result<()> {
    if authorization_receipt_path.is_some()
        && !matches!(policy_type, PolicyType::AgentAuthorization)
    {
        anyhow::bail!("--authorization-receipt requires --policy agent.authorization.v1");
    }

    let proof_str = read_text_input(&proof_path, "proof")?;
    let proof_json = if proof_str.trim().starts_with('{') {
        Some(serde_json::from_str::<serde_json::Value>(&proof_str)?)
    } else {
        None
    };

    if let Some(json) = proof_json.as_ref() {
        let is_bundle = json.get("bundleHash").is_some()
            && json.get("publicInputs").is_some()
            && json.get("amountBinding").is_some();
        if is_bundle {
            if json.get("receipt").is_some() {
                let bundle = AgentAuthorizationProofBundle::from_json(&proof_str)
                    .map_err(|e| anyhow::anyhow!("Invalid authorization proof bundle: {e}"))?;
                return verify_agent_authorization_bundle(
                    bundle,
                    inputs_path,
                    cli_witness_commitment_hex,
                    authorization_receipt_path,
                    amount_binding_path,
                    limit,
                    policy_type,
                    intent_hash,
                );
            }

            let bundle = ComplianceProofBundle::from_json(&proof_str)
                .map_err(|e| anyhow::anyhow!("Invalid compliance proof bundle: {e}"))?;
            return verify_compliance_bundle(
                bundle,
                inputs_path,
                cli_witness_commitment_hex,
                amount_binding_path,
                limit,
                policy_type,
                intent_hash,
            );
        }
    }

    let public_inputs: CompliancePublicInputs = if let Some(path) = inputs_path.as_ref() {
        let inputs_str = read_text_input(path, "inputs")?;
        serde_json::from_str(&inputs_str).with_context(|| "Failed to parse public inputs JSON")?
    } else if let Some(value) = proof_json.as_ref().and_then(|json| {
        json.get("public_inputs")
            .or_else(|| json.get("publicInputs"))
    }) {
        parse_public_inputs_value(value, "proof JSON")?
    } else {
        anyhow::bail!(
            "Verification requires --inputs unless the proof JSON embeds canonical publicInputs"
        );
    };
    let intent_hash = resolve_intent_hash(policy_type, intent_hash, Some(&public_inputs))?;
    validate_public_inputs_match_policy(
        &public_inputs,
        policy_type,
        limit,
        intent_hash.as_deref(),
    )?;

    let authorization_receipt = if let Some(path) = authorization_receipt_path.as_ref() {
        let receipt_str = read_text_input(path, "authorization receipt")?;
        Some(
            serde_json::from_str::<CommerceAuthorizationReceipt>(&receipt_str)
                .with_context(|| "Failed to parse authorization receipt JSON")?,
        )
    } else if let Some(value) = proof_json.as_ref().and_then(|json| json.get("receipt")) {
        Some(parse_authorization_receipt_value(value, "proof JSON")?)
    } else {
        None
    };
    let amount_binding = if let Some(path) = amount_binding_path.as_ref() {
        let binding_str = read_text_input(path, "payload amount binding")?;
        Some(
            serde_json::from_str::<PayloadAmountBinding>(&binding_str)
                .with_context(|| "Failed to parse payload amount binding JSON")?,
        )
    } else if let Some(value) = proof_json
        .as_ref()
        .and_then(|json| json.get("amountBinding"))
    {
        Some(parse_payload_amount_binding_value(value, "proof JSON")?)
    } else if let Some(receipt) = authorization_receipt.as_ref() {
        Some(
            public_inputs
                .payload_amount_binding(receipt.amount)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to derive payload amount binding from authorization receipt: {e}"
                    )
                })?,
        )
    } else {
        None
    };

    // Try to parse as JSON first, then as raw base64
    let (proof_bytes, witness_commitment, witness_commitment_hex): (Vec<u8>, [u64; 4], String) =
        if let Some(json) = proof_json.as_ref() {
            let b64 = json
                .get("proof_b64")
                .or_else(|| json.get("proofB64"))
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing proof_b64 field in JSON"))?;
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;

            // Load witness commitment from JSON
            let parse_witness_commitment_value = |value: &serde_json::Value| -> Result<[u64; 4]> {
                let arr = value.as_array().ok_or_else(|| {
                    anyhow::anyhow!(
                        "witness_commitment must be an array of numbers or decimal strings"
                    )
                })?;

                if arr.len() != 4 {
                    anyhow::bail!("witness_commitment must have exactly 4 elements");
                }

                let mut commitment = [0u64; 4];
                for (idx, element) in arr.iter().enumerate() {
                    commitment[idx] = match element {
                        serde_json::Value::String(s) => s.parse::<u64>().map_err(|_| {
                            anyhow::anyhow!("Invalid witness_commitment[{}] element", idx)
                        })?,
                        serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| {
                            anyhow::anyhow!("Invalid witness_commitment[{}] element", idx)
                        })?,
                        _ => {
                            anyhow::bail!("Invalid witness_commitment[{}] element", idx);
                        }
                    };
                }

                Ok(commitment)
            };

            let (commitment, commitment_hex) = if let Some(wc_hex) = json
                .get("witness_commitment_hex")
                .or_else(|| json.get("witnessCommitmentHex"))
                .and_then(|v| v.as_str())
            {
                (
                    witness_commitment_hex_to_u64(wc_hex)
                        .map_err(|e| anyhow::anyhow!("Invalid witness_commitment_hex: {e}"))?,
                    wc_hex.to_string(),
                )
            } else if let Some(wc) = json.get("witness_commitment") {
                let commitment = parse_witness_commitment_value(wc)?;
                (commitment, witness_commitment_u64_to_hex(&commitment))
            } else if let Some(wc) = json.get("witnessCommitment") {
                let commitment = parse_witness_commitment_value(wc)?;
                (commitment, witness_commitment_u64_to_hex(&commitment))
            } else {
                anyhow::bail!("Missing witness_commitment or witness_commitment_hex in proof JSON");
            };

            (bytes, commitment, commitment_hex)
        } else {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(proof_str.trim())
                .context("Failed to decode raw base64 proof")?;

            let (commitment, commitment_hex) = if let Some(hex) =
                cli_witness_commitment_hex.as_deref()
            {
                (
                    witness_commitment_hex_to_u64(hex)
                        .map_err(|e| anyhow::anyhow!("Invalid --witness-commitment-hex: {e}"))?,
                    hex.to_string(),
                )
            } else if let Some(binding) = amount_binding.as_ref() {
                let commitment = binding.witness_commitment_u64();
                (commitment, witness_commitment_u64_to_hex(&commitment))
            } else if let Some(commitment) = public_inputs
                .witness_commitment_u64()
                .map_err(|e| anyhow::anyhow!("Invalid witnessCommitment in public inputs: {e}"))?
            {
                (commitment, witness_commitment_u64_to_hex(&commitment))
            } else {
                anyhow::bail!(
                "Raw base64 proofs require --witness-commitment-hex, --amount-binding, or inputs.witnessCommitment"
            );
            };

            (bytes, commitment, commitment_hex)
        };

    if proof_bytes.len() > MAX_PROOF_SIZE {
        anyhow::bail!(
            "Proof file is too large: {} bytes (max {})",
            proof_bytes.len(),
            MAX_PROOF_SIZE
        );
    }

    eprintln!("Verifying proof...");
    eprintln!("  Policy: {}", policy_type.policy_id());
    eprintln!("  Limit: {}", limit);
    eprintln!("  Event ID: {}", public_inputs.event_id);
    eprintln!("  Proof size: {} bytes", proof_bytes.len());

    let start = Instant::now();

    let bound_public_inputs = match (amount_binding.as_ref(), authorization_receipt.as_ref()) {
        (Some(binding), Some(receipt)) => public_inputs
            .bind_payload_amount_binding_and_authorization_receipt(binding, receipt)
            .map_err(|e| anyhow::anyhow!("Verification error: {e}"))?,
        (Some(binding), None) => public_inputs
            .bind_payload_amount_binding(binding)
            .map_err(|e| anyhow::anyhow!("Verification error: {e}"))?,
        (None, Some(receipt)) => public_inputs
            .bind_amount_and_authorization_receipt(receipt)
            .map_err(|e| anyhow::anyhow!("Verification error: {e}"))?,
        (None, None) => public_inputs
            .bind_witness_commitment(&witness_commitment)
            .map_err(|e| anyhow::anyhow!("Verification error: {e}"))?,
    };
    if bound_public_inputs.witness_commitment.as_deref() != Some(witness_commitment_hex.as_str()) {
        anyhow::bail!("witness commitment hex does not match the bound public inputs");
    }

    let result = match (amount_binding.as_ref(), authorization_receipt.as_ref()) {
        (Some(binding), Some(receipt)) => {
            verify_agent_authorization_proof_auto_with_amount_binding(
                &proof_bytes,
                &bound_public_inputs,
                binding,
                receipt,
            )
        }
        (Some(binding), None) => verify_compliance_proof_auto_with_amount_binding(
            &proof_bytes,
            &bound_public_inputs,
            binding,
        ),
        (None, Some(receipt)) => {
            eprintln!(
                "  Note: verifying a witness-bound proof only; no payload amount binding provided"
            );
            verify_agent_authorization_proof_auto_bound(&proof_bytes, &bound_public_inputs, receipt)
        }
        (None, None) => {
            eprintln!(
                "  Note: verifying a witness-bound proof only; no payload amount binding provided"
            );
            verify_compliance_proof_auto_bound(&proof_bytes, &bound_public_inputs)
        }
    }
    .map_err(|e| anyhow::anyhow!("Verification error: {:?}", e))?;

    match (amount_binding.as_ref(), authorization_receipt.as_ref()) {
        (Some(binding), Some(receipt)) => {
            verify_agent_authorization_proof_auto_with_amount_binding_strict(
                &proof_bytes,
                &bound_public_inputs,
                binding,
                receipt,
            )
        }
        (Some(binding), None) => verify_compliance_proof_auto_with_amount_binding_strict(
            &proof_bytes,
            &bound_public_inputs,
            binding,
        ),
        (None, Some(receipt)) => verify_agent_authorization_proof_auto_bound_witness_strict(
            &proof_bytes,
            &bound_public_inputs,
            receipt,
        ),
        (None, None) => {
            verify_compliance_proof_auto_bound_witness_strict(&proof_bytes, &bound_public_inputs)
        }
    }
    .map_err(|e| anyhow::anyhow!("Verification error: {:?}", e))?;

    let elapsed = start.elapsed();

    if result.valid {
        eprintln!("Proof VALID (verified in {:?})", elapsed);
        println!("VALID");
        Ok(())
    } else {
        eprintln!("Proof INVALID: {:?}", result.error);
        println!("INVALID: {:?}", result.error);
        std::process::exit(1);
    }
}
