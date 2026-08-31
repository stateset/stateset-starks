//! `batch` command(s). Shared helpers live in `main.rs`.

use super::*;

pub(crate) fn ensure_experimental_batch_enabled() -> Result<()> {
    match std::env::var("VES_STARK_EXPERIMENTAL_BATCH") {
        Ok(value) if value == "1" => Ok(()),
        _ => anyhow::bail!(
            "Batch proof commands are experimental; set VES_STARK_EXPERIMENTAL_BATCH=1 to enable."
        ),
    }
}

/// A single event entry in a batch events JSON file
#[derive(Debug, serde::Deserialize)]
pub(crate) struct BatchEventEntry {
    amount: u64,
    #[serde(rename = "publicInputs")]
    public_inputs: CompliancePublicInputs,
}

pub(crate) fn batch_prove(
    num_events: usize,
    limit: u64,
    policy_type: PolicyType,
    events_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
) -> Result<()> {
    ensure_experimental_batch_enabled()?;
    ensure_batch_policy_supported(policy_type)?;

    if limit == 0 {
        anyhow::bail!("limit must be greater than 0");
    }

    let policy_id = policy_type.policy_id();
    let params = policy_type.create_policy_params(limit, None)?;
    let policy_hash_obj = compute_policy_hash(policy_id, &params)?;
    let policy_hash = hash_to_felts(&policy_hash_obj);

    let batch_policy_kind = match policy_type {
        PolicyType::AmlThreshold => BatchPolicyKind::AmlThreshold,
        PolicyType::OrderTotalCap => BatchPolicyKind::OrderTotalCap,
        PolicyType::AgentAuthorization => {
            anyhow::bail!("agent.authorization.v1 is not supported by batch proofs")
        }
    };

    // Load events from file or generate randomly
    let (event_entries, tenant_id, store_id) = if let Some(ref path) = events_path {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read events file: {}", path.display()))?;
        let entries: Vec<BatchEventEntry> =
            serde_json::from_str(&contents).with_context(|| "Failed to parse events JSON")?;
        if entries.is_empty() {
            anyhow::bail!("events file must contain at least one event");
        }
        let tid = entries[0].public_inputs.tenant_id;
        let sid = entries[0].public_inputs.store_id;
        (entries, tid, sid)
    } else {
        if num_events == 0 {
            anyhow::bail!("num_events must be at least 1");
        }
        let tid = Uuid::new_v4();
        let sid = Uuid::new_v4();
        let mut entries = Vec::with_capacity(num_events);
        for i in 0..num_events {
            let amount = rand_u64() % limit;
            let inputs = generate_batch_public_inputs(limit, policy_type, i, tid, sid)?;
            entries.push(BatchEventEntry {
                amount,
                public_inputs: inputs,
            });
        }
        (entries, tid, sid)
    };

    let actual_num_events = event_entries.len();

    println!("Batch Proof Generation");
    println!("======================");
    println!("  Events: {}", actual_num_events);
    println!("  Policy: {}", policy_id);
    println!("  Limit: {}", limit);
    if events_path.is_some() {
        println!("  Source: events file");
    }
    println!();

    // Create metadata
    let metadata = BatchMetadata::with_ids(
        Uuid::new_v4(),
        tenant_id,
        store_id,
        0,
        (actual_num_events - 1) as u64,
    );

    println!("Batch ID: {}", metadata.batch_id);
    println!("Tenant ID: {}", tenant_id);
    println!();

    // Build witness
    let mut builder = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(limit);

    println!("Loading {} events...", actual_num_events);
    for (i, entry) in event_entries.into_iter().enumerate() {
        builder = builder
            .add_event(entry.amount, entry.public_inputs)
            .map_err(|e| anyhow::anyhow!("Failed to add event {i}: {e}"))?;
        print!(".");
        io::stdout().flush()?;
    }
    println!(" Done");
    println!();

    let witness = builder
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build witness: {:?}", e))?;

    println!("Witness built:");
    println!("  Events: {}", witness.num_events());
    println!("  All compliant: {}", witness.all_compliant());
    println!();

    // Generate proof
    println!("Generating batch STARK proof...");
    let start = Instant::now();

    let prover = BatchProver::new();
    let (proof, _new_state_root) = prover
        .prove_and_get_root(&witness)
        .map_err(|e| anyhow::anyhow!("Batch proof generation failed: {:?}", e))?;

    let elapsed = start.elapsed();

    println!();
    println!("Batch Proof Generated!");
    println!("  Proving time: {:?}", elapsed);
    println!(
        "  Proof size: {} bytes ({:.2} KB)",
        proof.metadata.proof_size,
        proof.metadata.proof_size as f64 / 1024.0
    );
    println!("  Trace length: {}", proof.metadata.trace_length);
    println!("  Proof hash: {}...", &proof.proof_hash[..16]);
    println!();
    println!("State Transition:");
    println!("  Prev root: {:?}", proof.prev_state_root);
    println!("  New root:  {:?}", proof.new_state_root);

    let public_inputs = BatchPublicInputs::new(
        array_to_felts(&proof.prev_state_root),
        array_to_felts(&proof.new_state_root),
        witness.batch_id_felts(),
        witness.tenant_id_felts(),
        witness.store_id_felts(),
        witness.metadata.sequence_start,
        witness.metadata.sequence_end,
        witness.metadata.timestamp,
        witness.num_events(),
        witness.all_compliant(),
        batch_policy_kind,
        limit,
        witness.public_inputs_accumulator()?,
    );
    let serializable = SerializableBatchProof::new(proof.clone(), public_inputs)
        .map_err(|e| anyhow::anyhow!("Failed to construct serializable batch proof: {:?}", e))?;
    let json_str = serializable
        .to_json()
        .map_err(|e| anyhow::anyhow!("Failed to serialize batch proof: {:?}", e))?;

    if let Some(path) = output_path {
        fs::write(&path, &json_str)
            .with_context(|| format!("Failed to write output file: {}", path.display()))?;
        println!();
        println!("Proof written to: {}", path.display());
    } else {
        println!();
        println!("Proof JSON:");
        println!("{}", json_str);
    }

    Ok(())
}

pub(crate) fn batch_verify(proof_path: PathBuf, inputs_path: Option<PathBuf>) -> Result<()> {
    ensure_experimental_batch_enabled()?;

    println!("Batch Proof Verification");
    println!("========================");
    println!();

    // Load proof
    let proof_str = fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    let (proof_bytes, proof_hash, pub_inputs, prev_root_dbg, new_root_dbg) = if let Some(ref ip) =
        inputs_path
    {
        // Load public inputs from separate file
        let inputs_str = fs::read_to_string(ip)
            .with_context(|| format!("Failed to read inputs file: {}", ip.display()))?;
        let ser_inputs: ves_stark_batch::SerializableBatchPublicInputs =
            serde_json::from_str(&inputs_str)
                .with_context(|| "Failed to parse batch inputs JSON")?;
        let prev_dbg = format!("{:?}", ser_inputs.prev_state_root);
        let new_dbg = format!("{:?}", ser_inputs.new_state_root);
        let pi: BatchPublicInputs = ser_inputs
            .try_into()
            .map_err(|e| anyhow::anyhow!("Invalid batch public inputs: {:?}", e))?;
        // Load proof - try JSON first, fall back to raw bytes
        let raw_proof = fs::read(&proof_path)
            .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;
        let (bytes, hash) =
            if let Ok(batch_file) = serde_json::from_slice::<SerializableBatchProof>(&raw_proof) {
                (batch_file.proof.proof_bytes, batch_file.proof.proof_hash)
            } else {
                let h = ves_stark_batch::BatchProof::compute_hash(&raw_proof).to_hex();
                (raw_proof, h)
            };
        (bytes, hash, pi, prev_dbg, new_dbg)
    } else {
        // Extract public inputs from the proof JSON file
        let batch_file: SerializableBatchProof = serde_json::from_str(&proof_str).map_err(|e| {
            anyhow::anyhow!(
                "Expected serialized batch proof JSON with `public_inputs`: {}",
                e
            )
        })?;
        let prev_dbg = format!("{:?}", batch_file.proof.prev_state_root);
        let new_dbg = format!("{:?}", batch_file.proof.new_state_root);
        let pi = batch_file
            .to_batch_public_inputs()
            .map_err(|e| anyhow::anyhow!("Invalid batch public inputs: {:?}", e))?;
        let proof = batch_file.proof;
        (proof.proof_bytes, proof.proof_hash, pi, prev_dbg, new_dbg)
    };

    if proof_bytes.len() > MAX_BATCH_PROOF_SIZE {
        anyhow::bail!(
            "Batch proof payload is too large: {} bytes (max {})",
            proof_bytes.len(),
            MAX_BATCH_PROOF_SIZE
        );
    }

    let expected_hash = ves_stark_batch::BatchProof::compute_hash(&proof_bytes).to_hex();
    if expected_hash != proof_hash {
        println!("Warning: embedded proof hash does not match computed hash");
        println!("  embedded: {}", proof_hash);
        println!("  computed: {}", expected_hash);
    }

    println!("Loaded proof:");
    println!("  Size: {} bytes", proof_bytes.len());
    println!(
        "  Hash: {}...",
        proof_hash.chars().take(16).collect::<String>()
    );
    println!("  Prev root: {}", prev_root_dbg);
    println!("  New root:  {}", new_root_dbg);
    println!();

    // Verify proof
    println!("Verifying batch proof...");
    let start = Instant::now();

    let verifier = BatchVerifier::new();

    let result = verifier
        .verify(&proof_bytes, &pub_inputs)
        .map_err(|e| anyhow::anyhow!("Verification error: {:?}", e))?;

    let elapsed = start.elapsed();

    if result.valid {
        println!();
        println!("Batch Proof VALID!");
        println!("  Verification time: {:?}", elapsed);
        println!(
            "  State transition verified: {} -> {}",
            prev_root_dbg, new_root_dbg
        );
        Ok(())
    } else {
        println!();
        println!("Batch Proof INVALID: {:?}", result.error);
        std::process::exit(1);
    }
}

pub(crate) fn array_to_felts(arr: &[u64; 4]) -> [Felt; 4] {
    [
        Felt::new(arr[0]),
        Felt::new(arr[1]),
        Felt::new(arr[2]),
        Felt::new(arr[3]),
    ]
}

pub(crate) fn generate_batch_public_inputs(
    limit: u64,
    policy_type: PolicyType,
    seq: usize,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<CompliancePublicInputs> {
    ensure_batch_policy_supported(policy_type)?;
    let policy_id = policy_type.policy_id();
    let params = policy_type.create_policy_params(limit, None)?;
    let hash = compute_policy_hash(policy_id, &params)?;

    Ok(CompliancePublicInputs {
        event_id: Uuid::new_v4(),
        tenant_id,
        store_id,
        sequence_number: seq as u64,
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

// ============================================================================
// Sequencer Simulation
// ============================================================================
