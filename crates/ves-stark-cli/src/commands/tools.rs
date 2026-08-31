//! `tools` command(s). Shared helpers live in `main.rs`.

use super::*;

pub(crate) fn generate_inputs(
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<String>,
    output_path: Option<PathBuf>,
) -> Result<()> {
    let intent_hash = resolve_intent_hash(policy_type, intent_hash, None)?;
    let inputs = generate_random_public_inputs(limit, policy_type, intent_hash.as_deref())?;
    let json = serde_json::to_string_pretty(&inputs)?;

    if let Some(path) = output_path {
        fs::write(&path, &json)
            .with_context(|| format!("Failed to write output file: {}", path.display()))?;
        eprintln!("Public inputs written to: {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}

pub(crate) fn generate_random_public_inputs(
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<&str>,
) -> Result<CompliancePublicInputs> {
    let policy_id = policy_type.policy_id();
    let params = policy_type.create_policy_params(limit, intent_hash)?;
    let hash = compute_policy_hash(policy_id, &params)?;

    Ok(CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        store_id: Uuid::new_v4(),
        sequence_number: 1,
        payload_kind: 1,
        payload_plain_hash: hex::encode([0u8; 32]),
        payload_cipher_hash: hex::encode([0u8; 32]),
        event_signing_hash: hex::encode([0u8; 32]),
        policy_id: policy_id.to_string(),
        policy_params: params,
        policy_hash: hash.to_hex(),
        witness_commitment: None,
        authorization_receipt_hash: None,
        amount_binding_hash: None,
        rest_hash: None,
    })
}

pub(crate) fn benchmark(
    count: usize,
    max_amount: u64,
    limit: u64,
    policy_type: PolicyType,
    intent_hash: Option<String>,
) -> Result<()> {
    use std::time::Duration;

    if count == 0 {
        anyhow::bail!("count must be greater than 0");
    }
    if count > u32::MAX as usize {
        anyhow::bail!("count must be at most {}", u32::MAX);
    }

    println!("VES STARK Benchmark");
    println!("==================");
    println!("  Policy: {}", policy_type.policy_id());
    println!("  Proofs to generate: {}", count);
    println!("  Max amount: {}", max_amount);
    println!("  Limit: {}", limit);
    println!();

    let intent_hash = resolve_intent_hash(policy_type, intent_hash, None)?;
    let policy = policy_type.as_policy(limit, intent_hash.as_deref())?;
    let mut prove_times: Vec<Duration> = Vec::with_capacity(count);
    let mut verify_times: Vec<Duration> = Vec::with_capacity(count);
    let mut proof_sizes: Vec<usize> = Vec::with_capacity(count);

    for i in 0..count {
        // Generate random amount that satisfies the policy
        let amount = match policy_type {
            PolicyType::AmlThreshold => {
                if limit == 0 {
                    anyhow::bail!("Aml threshold limit must be greater than 0");
                }
                let bound = max_amount.min(limit);
                rand_u64() % bound
            }
            PolicyType::OrderTotalCap => {
                let bound = max_amount.min(limit.saturating_add(1));
                if bound == 0 {
                    0
                } else {
                    rand_u64() % bound
                }
            }
            PolicyType::AgentAuthorization => {
                let bound = max_amount.min(limit.saturating_add(1));
                if bound == 0 {
                    0
                } else {
                    rand_u64() % bound
                }
            }
        };

        // Generate inputs
        let inputs = generate_random_public_inputs(limit, policy_type, intent_hash.as_deref())?;

        // Create witness and prover
        let witness = ComplianceWitness::new(amount, inputs.clone());
        let prover = ComplianceProver::with_policy(policy.clone());

        // Time proof generation
        let start = Instant::now();
        let proof = prover
            .prove(&witness)
            .map_err(|e| anyhow::anyhow!("Proof generation failed: {:?}", e))?;
        let prove_time = start.elapsed();
        prove_times.push(prove_time);
        proof_sizes.push(proof.proof_bytes.len());

        // Time verification against witness-bound public inputs
        let bound_inputs = inputs
            .bind_witness_commitment(&proof.witness_commitment)
            .map_err(|e| anyhow::anyhow!("Verification error: {e}"))?;
        let start = Instant::now();
        let result = verify_compliance_proof_auto_bound(&proof.proof_bytes, &bound_inputs)
            .map_err(|e| anyhow::anyhow!("Verification error: {:?}", e))?;
        let verify_time = start.elapsed();
        verify_times.push(verify_time);

        if !result.valid {
            anyhow::bail!("Proof {} was invalid!", i);
        }

        print!(".");
        io::stdout().flush()?;
    }
    println!();
    println!();

    // Calculate statistics
    let avg_prove = prove_times.iter().sum::<Duration>() / count as u32;
    let avg_verify = verify_times.iter().sum::<Duration>() / count as u32;
    let avg_size = proof_sizes.iter().sum::<usize>() / count;

    let Some(min_prove) = prove_times.iter().min() else {
        anyhow::bail!("No proof timing data was collected")
    };
    let Some(max_prove) = prove_times.iter().max() else {
        anyhow::bail!("No proof timing data was collected")
    };
    let Some(min_verify) = verify_times.iter().min() else {
        anyhow::bail!("No verification timing data was collected")
    };
    let Some(max_verify) = verify_times.iter().max() else {
        anyhow::bail!("No verification timing data was collected")
    };
    let Some(min_size) = proof_sizes.iter().min() else {
        anyhow::bail!("No proof size data was collected")
    };
    let Some(max_size) = proof_sizes.iter().max() else {
        anyhow::bail!("No proof size data was collected")
    };

    println!("Results:");
    println!("--------");
    println!("Proof Generation:");
    println!("  Average: {:?}", avg_prove);
    println!("  Min: {:?}", min_prove);
    println!("  Max: {:?}", max_prove);
    println!();
    println!("Verification:");
    println!("  Average: {:?}", avg_verify);
    println!("  Min: {:?}", min_verify);
    println!("  Max: {:?}", max_verify);
    println!();
    println!("Proof Size:");
    println!(
        "  Average: {} bytes ({:.2} KB)",
        avg_size,
        avg_size as f64 / 1024.0
    );
    println!("  Min: {} bytes", min_size);
    println!("  Max: {} bytes", max_size);

    Ok(())
}

/// Generate a random u64 for benchmarks and test data generation.
pub(crate) fn rand_u64() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen()
}

// ============================================================================
// Batch Proving Functions
// ============================================================================
