//! `prove` command(s). Shared helpers live in `main.rs`.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove(
    amount: u64,
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<String>,
    inputs_path: Option<PathBuf>,
    authorization_receipt_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    json_output: bool,
) -> Result<()> {
    if authorization_receipt_path.is_some()
        && !matches!(policy_type, PolicyType::AgentAuthorization)
    {
        anyhow::bail!("--authorization-receipt requires --policy agent.authorization.v1");
    }
    if authorization_receipt_path.is_some() && !json_output {
        anyhow::bail!(
            "--authorization-receipt requires --json so the receipt-bound bundle can be emitted"
        );
    }

    let authorization_receipt = if let Some(path) = authorization_receipt_path.as_ref() {
        let receipt_str = read_text_input(path, "authorization receipt")?;
        Some(
            serde_json::from_str::<CommerceAuthorizationReceipt>(&receipt_str)
                .with_context(|| "Failed to parse authorization receipt JSON")?,
        )
    } else {
        None
    };

    if let Some(receipt) = authorization_receipt.as_ref() {
        if amount != receipt.amount {
            anyhow::bail!(
                "Amount ({}) must match authorization receipt amount ({})",
                amount,
                receipt.amount
            );
        }
    }
    let mut intent_hash = intent_hash;
    if let Some(receipt) = authorization_receipt.as_ref() {
        let receipt_intent_hash = normalize_intent_hash(&receipt.intent_hash)?;
        if let Some(provided) = intent_hash.as_deref() {
            if normalize_intent_hash(provided)? != receipt_intent_hash {
                anyhow::bail!("--intent-hash does not match authorization receipt.intentHash");
            }
        } else {
            intent_hash = Some(receipt_intent_hash);
        }
    }

    // Load or generate public inputs
    let public_inputs = if let Some(path) = inputs_path {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read inputs file: {}", path.display()))?;
        serde_json::from_str(&contents).with_context(|| "Failed to parse public inputs JSON")?
    } else {
        let intent_hash = resolve_intent_hash(policy_type, intent_hash.clone(), None)?;
        generate_random_public_inputs(limit, policy_type, intent_hash.as_deref())?
    };
    let intent_hash = resolve_intent_hash(policy_type, intent_hash, Some(&public_inputs))?;
    validate_public_inputs_match_policy(
        &public_inputs,
        policy_type,
        limit,
        intent_hash.as_deref(),
    )?;
    let policy = policy_type.as_policy(limit, intent_hash.as_deref())?;

    if !policy.validate_amount(amount) {
        anyhow::bail!(
            "Amount ({}) must be {} limit ({}) for {} policy",
            amount,
            policy_type.comparison_desc(),
            limit,
            policy_type.policy_id()
        );
    }

    eprintln!("Generating proof...");
    eprintln!("  Policy: {}", policy_type.policy_id());
    eprintln!(
        "  Amount: {} {} {}",
        amount,
        policy_type.comparison_desc(),
        limit
    );
    eprintln!("  Event ID: {}", public_inputs.event_id);

    let start = Instant::now();

    // Create witness and prover
    let witness = ComplianceWitness::try_new(amount, public_inputs.clone())
        .map_err(|e| anyhow::anyhow!("Invalid witness/public inputs: {e}"))?;
    let prover = ComplianceProver::with_policy(policy);

    // Generate proof
    let proof = prover
        .prove(&witness)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {:?}", e))?;

    let elapsed = start.elapsed();

    eprintln!("Proof generated in {:?}", elapsed);
    eprintln!("  Proof size: {} bytes", proof.proof_bytes.len());
    eprintln!("  Proof hash: {}", &proof.proof_hash[..16]);
    if let Some(hex) = proof.witness_commitment_hex.as_deref() {
        eprintln!("  Witness commitment (hex): {}", hex);
    }

    // Output proof
    if json_output {
        let binding = public_inputs
            .payload_amount_binding(amount)
            .map_err(|e| anyhow::anyhow!("Failed to derive payload amount binding: {e}"))?;
        let json_str = if let Some(receipt) = authorization_receipt.as_ref() {
            let bundle =
                AgentAuthorizationProofBundle::new(&proof, &public_inputs, &binding, receipt)
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to build authorization proof bundle: {e}")
                    })?;
            bundle.to_json()?
        } else {
            let bundle = ComplianceProofBundle::new(&proof, &public_inputs, &binding)
                .map_err(|e| anyhow::anyhow!("Failed to build compliance proof bundle: {e}"))?;
            bundle.to_json()?
        };

        if let Some(path) = output_path {
            fs::write(&path, &json_str)
                .with_context(|| format!("Failed to write output file: {}", path.display()))?;
            eprintln!("Proof written to: {}", path.display());
        } else {
            println!("{}", json_str);
        }
    } else {
        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes);

        if let Some(path) = output_path {
            fs::write(&path, &proof_b64)
                .with_context(|| format!("Failed to write output file: {}", path.display()))?;
            eprintln!("Proof written to: {}", path.display());
        } else {
            println!("{}", proof_b64);
        }
    }

    Ok(())
}

// Arguments map 1:1 to CLI flags for this subcommand; grouping them into a
// struct would only add indirection over the clap-parsed values.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_submit(
    sequencer_url: String,
    event_id: Uuid,
    amount: u64,
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<String>,
    authorization_receipt_path: Option<PathBuf>,
    verify_after: bool,
) -> Result<()> {
    if authorization_receipt_path.is_some()
        && !matches!(policy_type, PolicyType::AgentAuthorization)
    {
        anyhow::bail!("--authorization-receipt requires --policy agent.authorization.v1");
    }

    let authorization_receipt = if let Some(path) = authorization_receipt_path.as_ref() {
        let receipt_str = read_text_input(path, "authorization receipt")?;
        Some(
            serde_json::from_str::<CommerceAuthorizationReceipt>(&receipt_str)
                .with_context(|| "Failed to parse authorization receipt JSON")?,
        )
    } else {
        None
    };

    if let Some(receipt) = authorization_receipt.as_ref() {
        if receipt.event_id != event_id {
            anyhow::bail!(
                "event_id mismatch: submission targets {}, but authorization receipt is for {}",
                event_id,
                receipt.event_id
            );
        }
        if amount != receipt.amount {
            anyhow::bail!(
                "Amount ({}) must match authorization receipt amount ({})",
                amount,
                receipt.amount
            );
        }
    }
    let mut intent_hash = intent_hash;
    if let Some(receipt) = authorization_receipt.as_ref() {
        let receipt_intent_hash = normalize_intent_hash(&receipt.intent_hash)?;
        if let Some(provided) = intent_hash.as_deref() {
            if normalize_intent_hash(provided)? != receipt_intent_hash {
                anyhow::bail!("--intent-hash does not match authorization receipt.intentHash");
            }
        } else {
            intent_hash = Some(receipt_intent_hash);
        }
    }

    let intent_hash = resolve_intent_hash(policy_type, intent_hash, None)?;
    let policy = policy_type.as_policy(limit, intent_hash.as_deref())?;
    if !policy.validate_amount(amount) {
        anyhow::bail!(
            "Amount ({}) must be {} limit ({}) for {} policy",
            amount,
            policy_type.comparison_desc(),
            limit,
            policy_type.policy_id()
        );
    }

    let policy_id = policy_type.policy_id();
    let policy_params = policy_type
        .create_policy_params(limit, intent_hash.as_deref())?
        .to_json_value();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    rt.block_on(async move {
        let api_key = std::env::var("STATESET_API_KEY").context(
            "STATESET_API_KEY environment variable is required.\n\
             Set it with: export STATESET_API_KEY=your-api-key",
        )?;
        let client = SequencerClient::try_new(&sequencer_url, &api_key)
            .map_err(|e| anyhow::anyhow!("failed to create sequencer client: {e}"))?;

        eprintln!("Fetching canonical public inputs from sequencer...");
        eprintln!("  URL: {}", sequencer_url);
        eprintln!("  Event ID: {}", event_id);
        eprintln!("  Policy: {}", policy_id);

        let public_inputs = if let Some(receipt) = authorization_receipt.as_ref() {
            client
                .get_authorization_public_inputs_validated_for_receipt(limit, receipt)
                .await
                .map_err(|e| anyhow::anyhow!("failed to fetch authorization public inputs: {e}"))?
        } else {
            client
                .get_public_inputs_validated_with_params(event_id, policy_id, policy_params.clone())
                .await
                .map_err(|e| anyhow::anyhow!("failed to fetch public inputs: {e}"))?
        };
        validate_public_inputs_match_policy(
            &public_inputs,
            policy_type,
            limit,
            intent_hash.as_deref(),
        )?;

        eprintln!("Generating proof...");
        eprintln!(
            "  Amount: {} {} {}",
            amount,
            policy_type.comparison_desc(),
            limit
        );
        eprintln!("Submitting proof to sequencer...");
        let resp = if let Some(receipt) = authorization_receipt.as_ref() {
            let bundle = client
                .prove_agent_authorization_bundle(limit, receipt, &public_inputs)
                .map_err(|e| anyhow::anyhow!("proof generation failed: {e}"))?;
            client
                .submit_agent_authorization_bundle(&bundle)
                .await
                .map_err(|e| anyhow::anyhow!("proof submission failed: {e}"))?
        } else {
            if matches!(policy_type, PolicyType::AgentAuthorization) {
                eprintln!(
                    "  Note: submitting a payload-bound proof only; no authorization receipt provided"
                );
            }
            let bundle = client
                .prove_compliance_bundle(amount, limit, &public_inputs)
                .map_err(|e| anyhow::anyhow!("proof generation failed: {e}"))?;
            client
                .submit_compliance_bundle(&bundle)
                .await
                .map_err(|e| anyhow::anyhow!("proof submission failed: {e}"))?
        };

        println!("Submitted proof_id={}", resp.proof_id);
        println!("  proof_hash={}", resp.proof_hash);
        println!("  policy_hash={}", resp.policy_hash);
        if let Some(hex) = resp.witness_commitment_hex.as_deref() {
            println!("  witness_commitment_hex={}", hex);
        }

        if verify_after {
            eprintln!("Verifying stored proof via sequencer...");
            let verify = client
                .verify_proof(resp.proof_id)
                .await
                .map_err(|e| anyhow::anyhow!("proof verify failed: {e}"))?;
            println!("Verified valid={}", verify.valid);
            if let Some(stark_valid) = verify.stark_valid {
                println!("  stark_valid={}", stark_valid);
            }
            if let Some(err) = verify.stark_error.as_deref() {
                println!("  stark_error={}", err);
            }
            if let Some(ms) = verify.stark_verification_time_ms {
                println!("  stark_verification_time_ms={}", ms);
            }
        }

        Ok(())
    })
}
