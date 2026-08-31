//! `sequencer` command(s). Shared helpers live in `main.rs`.

use super::*;

pub(crate) fn run_sequencer(
    num_events: usize,
    batch_size: usize,
    limit: u64,
    include_violations: bool,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    ensure_experimental_batch_enabled()?;

    if limit == 0 {
        anyhow::bail!("limit must be greater than 0");
    }
    if batch_size == 0 {
        anyhow::bail!("batch_size must be greater than 0");
    }
    if include_violations && limit == u64::MAX {
        anyhow::bail!(
            "cannot generate violations with limit {limit} because no larger amount fits in u64"
        );
    }

    println!();
    println!("========================================");
    println!("  VES STARK Sequencer Simulation");
    println!("========================================");
    println!();
    println!("Configuration:");
    println!("  Total events: {}", num_events);
    println!("  Batch size: {}", batch_size);
    println!("  Policy: aml.threshold < {}", limit);
    println!("  Include violations: {}", include_violations);
    println!();

    // Create output directory if specified
    if let Some(ref dir) = output_dir {
        fs::create_dir_all(dir)?;
    }

    // Generate policy hash
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(limit);
    let policy_hash_obj = compute_policy_hash(policy_id, &params)?;
    let policy_hash = hash_to_felts(&policy_hash_obj);

    // Shared IDs for the simulation
    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();

    println!("Tenant: {}", tenant_id);
    println!("Store: {}", store_id);
    println!();

    // Track state
    let mut current_state_root = BatchStateRoot::genesis();
    let mut total_events_processed = 0;
    let mut batch_num = 0;
    let mut total_proving_time = std::time::Duration::ZERO;
    let mut total_proof_size = 0;

    println!("Processing events...");
    println!();

    while total_events_processed < num_events {
        batch_num += 1;
        let events_in_batch = (num_events - total_events_processed).min(batch_size);
        let batch_last_index = total_events_processed
            .checked_add(events_in_batch)
            .and_then(|v| v.checked_sub(1))
            .ok_or_else(|| anyhow::anyhow!("event index overflow while batching"))?;

        println!("--- Batch {} ---", batch_num);
        println!(
            "  Events: {} - {}",
            total_events_processed, batch_last_index
        );

        // Create metadata for this batch
        let metadata = BatchMetadata::with_ids(
            Uuid::new_v4(),
            tenant_id,
            store_id,
            total_events_processed as u64,
            batch_last_index as u64,
        );

        // Build witness
        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata.clone())
            .prev_state_root(current_state_root)
            .policy_hash(policy_hash)
            .policy_limit(limit);

        let mut compliant_count = 0;
        let mut violation_count = 0;

        for i in 0..events_in_batch {
            let seq = total_events_processed + i;

            // Decide if this event should be a violation
            let is_violation = include_violations && (seq % 5 == 4); // Every 5th event
            let amount = if is_violation {
                limit.saturating_add(1).saturating_add(rand_u64() % 1000) // Over limit
            } else {
                rand_u64() % limit // Under limit
            };

            let inputs = generate_batch_public_inputs(
                limit,
                PolicyType::AmlThreshold,
                seq,
                tenant_id,
                store_id,
            )?;
            builder = builder
                .add_event(amount, inputs)
                .map_err(|e| anyhow::anyhow!("Failed to add event {seq}: {e}"))?;

            if amount < limit {
                compliant_count += 1;
            } else {
                violation_count += 1;
            }
        }

        println!(
            "  Compliant: {}, Violations: {}",
            compliant_count, violation_count
        );

        let witness = builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build witness: {:?}", e))?;

        // Generate batch proof
        print!("  Proving... ");
        io::stdout().flush()?;

        let start = Instant::now();
        let prover = BatchProver::new();
        let (proof, new_state_root) = prover
            .prove_and_get_root(&witness)
            .map_err(|e| anyhow::anyhow!("Batch proof failed: {:?}", e))?;
        let prove_time = start.elapsed();

        total_proving_time += prove_time;
        total_proof_size += proof.metadata.proof_size;

        println!(
            "Done! ({:?}, {} bytes)",
            prove_time, proof.metadata.proof_size
        );

        // Verify the proof
        print!("  Verifying... ");
        io::stdout().flush()?;

        let verifier = BatchVerifier::new();
        let pub_inputs = BatchPublicInputs::new(
            current_state_root.root,
            new_state_root.root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            metadata.sequence_start,
            metadata.sequence_end,
            metadata.timestamp,
            events_in_batch,
            witness.all_compliant(),
            BatchPolicyKind::AmlThreshold,
            limit,
            witness.public_inputs_accumulator()?,
        );

        let start = Instant::now();
        let result = verifier
            .verify(&proof.proof_bytes, &pub_inputs)
            .map_err(|e| anyhow::anyhow!("Verification error: {:?}", e))?;
        let verify_time = start.elapsed();

        if result.valid {
            println!("VALID ({:?})", verify_time);
        } else {
            println!("INVALID: {:?}", result.error);
            return Err(anyhow::anyhow!("Batch {} verification failed", batch_num));
        }

        // Update state
        println!(
            "  State: {:?} -> {:?}",
            current_state_root.root, new_state_root.root
        );

        // Save proof if output directory specified
        if let Some(ref dir) = output_dir {
            let proof_file = dir.join(format!("batch_{:04}.json", batch_num));
            let serialized = SerializableBatchProof::new(proof.clone(), pub_inputs.clone())?;
            fs::write(&proof_file, serialized.to_json()?)?;
            println!("  Saved: {}", proof_file.display());
        }

        // Advance state
        current_state_root = new_state_root;
        total_events_processed += events_in_batch;
        println!();
    }

    // Summary
    println!("========================================");
    println!("  Sequencer Simulation Complete!");
    println!("========================================");
    println!();
    println!("Summary:");
    println!("  Total events: {}", total_events_processed);
    println!("  Total batches: {}", batch_num);
    println!("  Total proving time: {:?}", total_proving_time);
    println!(
        "  Avg proving time/batch: {:?}",
        total_proving_time / batch_num as u32
    );
    println!(
        "  Total proof size: {} bytes ({:.2} KB)",
        total_proof_size,
        total_proof_size as f64 / 1024.0
    );
    println!("  Final state root: {:?}", current_state_root.root);
    println!();

    if let Some(dir) = output_dir {
        // Write final state
        let state_file = dir.join("final_state.json");
        let state = serde_json::json!({
            "final_state_root": [
                current_state_root.root[0].as_int(),
                current_state_root.root[1].as_int(),
                current_state_root.root[2].as_int(),
                current_state_root.root[3].as_int(),
            ],
            "total_events": total_events_processed,
            "total_batches": batch_num,
        });
        fs::write(&state_file, serde_json::to_string_pretty(&state)?)?;
        println!("Final state written to: {}", state_file.display());
    }

    Ok(())
}
