//! VES STARK CLI - Command-line tool for proof generation and verification
//!
//! This tool provides commands for:
//! - Generating compliance proofs for multiple policies
//! - Verifying existing proofs
//! - Inspecting proof metadata
//! - Generating test data
//! - Batch proving (zkRollup-style state transitions)
//! - Sequencer simulation for end-to-end testing
//!
//! # Supported Policies
//!
//! - `aml.threshold`: Proves amount < threshold (strict less-than)
//! - `order_total.cap`: Proves amount <= cap (less-than-or-equal)

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

use ves_stark_primitives::public_inputs::{
    compute_policy_hash, CompliancePublicInputs, PolicyParams,
};
use ves_stark_primitives::{hash_to_felts, Felt};
use ves_stark_prover::{ComplianceProof, ComplianceProver, ComplianceWitness, Policy};
use ves_stark_verifier::verify_compliance_proof;

// Batch proving imports
use ves_stark_batch::{
    BatchMetadata, BatchProver, BatchStateRoot, BatchVerifier, BatchWitnessBuilder,
};

/// Policy type for CLI
#[derive(Debug, Clone, Copy, ValueEnum)]
enum PolicyType {
    /// AML threshold: proves amount < threshold
    #[value(name = "aml.threshold")]
    AmlThreshold,
    /// Order total cap: proves amount <= cap
    #[value(name = "order_total.cap")]
    OrderTotalCap,
}

impl PolicyType {
    fn to_policy(&self, limit: u64) -> Policy {
        match self {
            PolicyType::AmlThreshold => Policy::aml_threshold(limit),
            PolicyType::OrderTotalCap => Policy::order_total_cap(limit),
        }
    }

    fn policy_id(&self) -> &'static str {
        match self {
            PolicyType::AmlThreshold => "aml.threshold",
            PolicyType::OrderTotalCap => "order_total.cap",
        }
    }

    fn comparison_desc(&self) -> &'static str {
        match self {
            PolicyType::AmlThreshold => "<",
            PolicyType::OrderTotalCap => "<=",
        }
    }

    fn create_policy_params(&self, limit: u64) -> PolicyParams {
        match self {
            PolicyType::AmlThreshold => PolicyParams::threshold(limit),
            PolicyType::OrderTotalCap => PolicyParams::cap(limit),
        }
    }
}

/// VES STARK - Zero-Knowledge Compliance Proofs
#[derive(Parser)]
#[command(name = "ves-stark")]
#[command(author = "StateSet Engineering")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Generate and verify STARK proofs for VES compliance", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a compliance proof
    Prove {
        /// The amount to prove (must satisfy policy constraint)
        #[arg(short, long)]
        amount: u64,

        /// The policy limit (threshold for aml.threshold, cap for order_total.cap)
        #[arg(short, long)]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,

        /// Path to public inputs JSON file (optional, will generate random if not provided)
        #[arg(short, long)]
        inputs: Option<PathBuf>,

        /// Output file for the proof (default: stdout as base64)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output as JSON with metadata
        #[arg(long)]
        json: bool,
    },

    /// Verify a compliance proof
    Verify {
        /// Path to the proof file (or - for stdin)
        #[arg(short = 'f', long)]
        proof: PathBuf,

        /// Path to public inputs JSON file
        #[arg(short, long)]
        inputs: PathBuf,

        /// The limit value used for the proof
        #[arg(short, long)]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,
    },

    /// Inspect proof metadata
    Inspect {
        /// Path to the proof file
        #[arg(short = 'f', long)]
        proof: PathBuf,
    },

    /// Generate sample public inputs for testing
    #[command(name = "gen-inputs")]
    GenerateInputs {
        /// The limit value for the policy
        #[arg(short, long)]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Run a benchmark with multiple proofs
    Benchmark {
        /// Number of proofs to generate
        #[arg(short = 'n', long, default_value = "10")]
        count: usize,

        /// Maximum amount value (random amounts will be < this)
        #[arg(short, long, default_value = "10000")]
        max_amount: u64,

        /// Limit value
        #[arg(short, long, default_value = "10000")]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,
    },

    /// Generate a batch state transition proof (zkRollup-style)
    #[command(name = "batch-prove")]
    BatchProve {
        /// Number of events in the batch
        #[arg(short = 'n', long, default_value = "8")]
        num_events: usize,

        /// Policy limit (threshold)
        #[arg(short, long, default_value = "10000")]
        limit: u64,

        /// Output file for the proof
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a batch proof
    #[command(name = "batch-verify")]
    BatchVerify {
        /// Path to the batch proof file
        #[arg(short = 'f', long)]
        proof: PathBuf,
    },

    /// Run a sequencer simulation (end-to-end test)
    Sequencer {
        /// Number of events to process
        #[arg(short = 'n', long, default_value = "16")]
        num_events: usize,

        /// Events per batch
        #[arg(short, long, default_value = "8")]
        batch_size: usize,

        /// Policy limit (threshold)
        #[arg(short, long, default_value = "10000")]
        limit: u64,

        /// Include some non-compliant events
        #[arg(long)]
        include_violations: bool,

        /// Output directory for proofs
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove {
            amount,
            limit,
            policy,
            inputs,
            output,
            json,
        } => prove(amount, limit, policy, inputs, output, json),

        Commands::Verify {
            proof,
            inputs,
            limit,
            policy,
        } => verify(proof, inputs, limit, policy),

        Commands::Inspect { proof } => inspect(proof),

        Commands::GenerateInputs {
            limit,
            policy,
            output,
        } => generate_inputs(limit, policy, output),

        Commands::Benchmark {
            count,
            max_amount,
            limit,
            policy,
        } => benchmark(count, max_amount, limit, policy),

        Commands::BatchProve {
            num_events,
            limit,
            output,
        } => batch_prove(num_events, limit, output),

        Commands::BatchVerify { proof } => batch_verify(proof),

        Commands::Sequencer {
            num_events,
            batch_size,
            limit,
            include_violations,
            output_dir,
        } => run_sequencer(
            num_events,
            batch_size,
            limit,
            include_violations,
            output_dir,
        ),
    }
}

fn prove(
    amount: u64,
    limit: u64,
    policy_type: PolicyType,
    inputs_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    json_output: bool,
) -> Result<()> {
    let policy = policy_type.to_policy(limit);

    // Validate inputs
    if !policy.validate_amount(amount) {
        anyhow::bail!(
            "Amount ({}) must be {} limit ({}) for {} policy",
            amount,
            policy_type.comparison_desc(),
            limit,
            policy_type.policy_id()
        );
    }

    // Load or generate public inputs
    let public_inputs = if let Some(path) = inputs_path {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read inputs file: {}", path.display()))?;
        serde_json::from_str(&contents).with_context(|| "Failed to parse public inputs JSON")?
    } else {
        generate_random_public_inputs(limit, policy_type)?
    };

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
    let witness = ComplianceWitness::new(amount, public_inputs.clone());
    let prover = ComplianceProver::with_policy(policy);

    // Generate proof
    let proof = prover
        .prove(&witness)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {:?}", e))?;

    let elapsed = start.elapsed();

    eprintln!("Proof generated in {:?}", elapsed);
    eprintln!("  Proof size: {} bytes", proof.proof_bytes.len());
    eprintln!("  Proof hash: {}", &proof.proof_hash[..16]);

    // Output proof
    if json_output {
        let output = serde_json::json!({
            "proof_b64": base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
            "proof_hash": proof.proof_hash,
            "metadata": proof.metadata,
            "witness_commitment": proof.witness_commitment,
            "policy": {
                "type": policy_type.policy_id(),
                "limit": limit,
            },
            "public_inputs": public_inputs,
        });

        let json_str = serde_json::to_string_pretty(&output)?;

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

fn verify(
    proof_path: PathBuf,
    inputs_path: PathBuf,
    limit: u64,
    policy_type: PolicyType,
) -> Result<()> {
    // Load public inputs
    let inputs_str = fs::read_to_string(&inputs_path)
        .with_context(|| format!("Failed to read inputs file: {}", inputs_path.display()))?;
    let public_inputs: CompliancePublicInputs =
        serde_json::from_str(&inputs_str).with_context(|| "Failed to parse public inputs JSON")?;

    // Load proof
    let proof_str = fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    // Try to parse as JSON first, then as raw base64
    let (proof_bytes, witness_commitment): (Vec<u8>, [u64; 4]) = if proof_str
        .trim()
        .starts_with('{')
    {
        let json: serde_json::Value = serde_json::from_str(&proof_str)?;
        let b64 = json["proof_b64"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing proof_b64 field in JSON"))?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;

        // Load witness commitment from JSON
        let commitment = if let Some(wc) = json.get("witness_commitment") {
            let arr = wc
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("witness_commitment must be an array"))?;
            if arr.len() != 4 {
                anyhow::bail!("witness_commitment must have exactly 4 elements");
            }
            [
                arr[0]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("Invalid commitment element"))?,
                arr[1]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("Invalid commitment element"))?,
                arr[2]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("Invalid commitment element"))?,
                arr[3]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("Invalid commitment element"))?,
            ]
        } else {
            anyhow::bail!("Missing witness_commitment in proof JSON");
        };

        (bytes, commitment)
    } else {
        anyhow::bail!("Raw base64 proofs no longer supported - please use JSON format with witness_commitment");
    };

    eprintln!("Verifying proof...");
    eprintln!("  Policy: {}", policy_type.policy_id());
    eprintln!("  Limit: {}", limit);
    eprintln!("  Event ID: {}", public_inputs.event_id);
    eprintln!("  Proof size: {} bytes", proof_bytes.len());

    let start = Instant::now();

    // Verify with explicit policy parameters (verifier will check they match public inputs)
    let policy = policy_type.to_policy(limit);
    let result =
        verify_compliance_proof(&proof_bytes, &public_inputs, &policy, &witness_commitment)
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

fn inspect(proof_path: PathBuf) -> Result<()> {
    // Load proof
    let proof_str = fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    // Try to parse as JSON first
    if proof_str.trim().starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(&proof_str)?;

        println!("Proof Inspection:");
        println!("  Format: JSON with metadata");

        if let Some(hash) = json.get("proof_hash") {
            println!("  Proof Hash: {}", hash.as_str().unwrap_or("unknown"));
        }

        if let Some(policy) = json.get("policy") {
            if let Some(ptype) = policy.get("type") {
                println!("  Policy Type: {}", ptype.as_str().unwrap_or("unknown"));
            }
            if let Some(plimit) = policy.get("limit") {
                println!("  Policy Limit: {}", plimit);
            }
        }

        if let Some(metadata) = json.get("metadata") {
            if let Some(time) = metadata.get("proving_time_ms") {
                println!("  Proving Time: {} ms", time);
            }
            if let Some(size) = metadata.get("proof_size") {
                println!("  Proof Size: {} bytes", size);
            }
            if let Some(constraints) = metadata.get("num_constraints") {
                println!("  Constraints: {}", constraints);
            }
            if let Some(trace_len) = metadata.get("trace_length") {
                println!("  Trace Length: {}", trace_len);
            }
            if let Some(version) = metadata.get("prover_version") {
                println!(
                    "  Prover Version: {}",
                    version.as_str().unwrap_or("unknown")
                );
            }
        }

        if let Some(inputs) = json.get("public_inputs") {
            if let Some(event_id) = inputs.get("eventId") {
                println!("  Event ID: {}", event_id.as_str().unwrap_or("unknown"));
            }
            if let Some(policy_id) = inputs.get("policyId") {
                println!(
                    "  Input Policy: {}",
                    policy_id.as_str().unwrap_or("unknown")
                );
            }
        }

        if let Some(b64) = json.get("proof_b64") {
            if let Some(s) = b64.as_str() {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
                    println!("  Raw Proof Size: {} bytes", bytes.len());
                }
            }
        }
    } else {
        // Raw base64
        let proof_bytes = base64::engine::general_purpose::STANDARD.decode(proof_str.trim())?;

        println!("Proof Inspection:");
        println!("  Format: Raw base64");
        println!("  Proof Size: {} bytes", proof_bytes.len());

        // Compute hash
        let hash = ComplianceProof::compute_hash(&proof_bytes);
        println!("  Proof Hash: {}", hash.to_hex());
    }

    Ok(())
}

fn generate_inputs(
    limit: u64,
    policy_type: PolicyType,
    output_path: Option<PathBuf>,
) -> Result<()> {
    let inputs = generate_random_public_inputs(limit, policy_type)?;
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

fn generate_random_public_inputs(
    limit: u64,
    policy_type: PolicyType,
) -> Result<CompliancePublicInputs> {
    let policy_id = policy_type.policy_id();
    let params = policy_type.create_policy_params(limit);
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
    })
}

fn benchmark(count: usize, max_amount: u64, limit: u64, policy_type: PolicyType) -> Result<()> {
    use std::time::Duration;

    println!("VES STARK Benchmark");
    println!("==================");
    println!("  Policy: {}", policy_type.policy_id());
    println!("  Proofs to generate: {}", count);
    println!("  Max amount: {}", max_amount);
    println!("  Limit: {}", limit);
    println!();

    let policy = policy_type.to_policy(limit);
    let mut prove_times: Vec<Duration> = Vec::with_capacity(count);
    let mut verify_times: Vec<Duration> = Vec::with_capacity(count);
    let mut proof_sizes: Vec<usize> = Vec::with_capacity(count);

    for i in 0..count {
        // Generate random amount that satisfies the policy
        let amount = match policy_type {
            PolicyType::AmlThreshold => (rand_u64() % max_amount.min(limit - 1)).max(1),
            PolicyType::OrderTotalCap => (rand_u64() % max_amount.min(limit + 1)).max(1),
        };

        // Generate inputs
        let inputs = generate_random_public_inputs(limit, policy_type)?;

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

        // Time verification (use the same policy parameters as the inputs)
        let verify_policy = policy.clone();
        let start = Instant::now();
        let result = verify_compliance_proof(
            &proof.proof_bytes,
            &inputs,
            &verify_policy,
            &proof.witness_commitment,
        )
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

    let min_prove = prove_times.iter().min().unwrap();
    let max_prove = prove_times.iter().max().unwrap();
    let min_verify = verify_times.iter().min().unwrap();
    let max_verify = verify_times.iter().max().unwrap();
    let min_size = *proof_sizes.iter().min().unwrap();
    let max_size = *proof_sizes.iter().max().unwrap();

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

// Simple random number generator (not cryptographically secure, just for benchmarks)
fn rand_u64() -> u64 {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Simple xorshift
    let mut x = seed ^ 0x5DEECE66D;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

// ============================================================================
// Batch Proving Functions
// ============================================================================

fn ensure_experimental_batch_enabled() -> Result<()> {
    match std::env::var("VES_STARK_EXPERIMENTAL_BATCH") {
        Ok(value) if value == "1" => Ok(()),
        _ => anyhow::bail!(
            "Batch proof commands are experimental; set VES_STARK_EXPERIMENTAL_BATCH=1 to enable."
        ),
    }
}

fn batch_prove(num_events: usize, limit: u64, output_path: Option<PathBuf>) -> Result<()> {
    ensure_experimental_batch_enabled()?;

    println!("Batch Proof Generation");
    println!("======================");
    println!("  Events: {}", num_events);
    println!("  Policy: aml.threshold");
    println!("  Limit: {}", limit);
    println!();

    // Generate policy hash
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(limit);
    let policy_hash_obj = compute_policy_hash(policy_id, &params)?;
    let policy_hash = hash_to_felts(&policy_hash_obj);

    // Create metadata
    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let metadata = BatchMetadata::with_ids(
        Uuid::new_v4(),
        tenant_id,
        store_id,
        0,
        (num_events - 1) as u64,
    );

    println!("Batch ID: {}", metadata.batch_id);
    println!("Tenant ID: {}", tenant_id);
    println!();

    // Build witness with random compliant events
    let mut builder = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(limit);

    println!("Generating {} events...", num_events);
    for i in 0..num_events {
        let amount = (rand_u64() % (limit - 1)).max(1);
        let inputs = generate_batch_public_inputs(limit, i, tenant_id, store_id)?;
        builder = builder.add_event(amount, inputs);
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

    // Output proof
    let output = serde_json::json!({
        "proof_b64": base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
        "proof_hash": proof.proof_hash,
        "prev_state_root": proof.prev_state_root,
        "new_state_root": proof.new_state_root,
        "metadata": proof.metadata,
    });

    let json_str = serde_json::to_string_pretty(&output)?;

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

fn batch_verify(proof_path: PathBuf) -> Result<()> {
    ensure_experimental_batch_enabled()?;

    println!("Batch Proof Verification");
    println!("========================");
    println!();

    // Load proof
    let proof_str = fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    let json: serde_json::Value = serde_json::from_str(&proof_str)?;

    let proof_b64 = json["proof_b64"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing proof_b64 field"))?;
    let proof_bytes = base64::engine::general_purpose::STANDARD.decode(proof_b64)?;

    let proof_hash = json["proof_hash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing proof_hash field"))?;

    let prev_state_root: [u64; 4] = serde_json::from_value(json["prev_state_root"].clone())?;
    let new_state_root: [u64; 4] = serde_json::from_value(json["new_state_root"].clone())?;

    println!("Loaded proof:");
    println!("  Size: {} bytes", proof_bytes.len());
    println!("  Hash: {}...", &proof_hash[..16]);
    println!("  Prev root: {:?}", prev_state_root);
    println!("  New root:  {:?}", new_state_root);
    println!();

    // Verify proof
    println!("Verifying batch proof...");
    let start = Instant::now();

    let verifier = BatchVerifier::new();

    // For now, construct public inputs from the JSON metadata
    // In production, this would come from the chain state
    let metadata = &json["metadata"];
    let num_events = metadata["num_events"].as_u64().unwrap_or(0) as usize;
    let all_compliant = metadata["all_compliant"].as_bool().unwrap_or(false);

    // Create public inputs for verification
    let pub_inputs = ves_stark_batch::BatchPublicInputs::new(
        array_to_felts(&prev_state_root),
        array_to_felts(&new_state_root),
        [Felt::new(0); 4], // batch_id placeholder
        [Felt::new(0); 4], // tenant_id placeholder
        [Felt::new(0); 4], // store_id placeholder
        0,
        (num_events - 1) as u64,
        num_events,
        all_compliant,
        [Felt::new(0); 8], // policy_hash placeholder
        10000,             // policy_limit placeholder
    );

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
            format!("{:?}", prev_state_root),
            format!("{:?}", new_state_root)
        );
        Ok(())
    } else {
        println!();
        println!("Batch Proof INVALID: {:?}", result.error);
        std::process::exit(1);
    }
}

fn array_to_felts(arr: &[u64; 4]) -> [Felt; 4] {
    [
        Felt::new(arr[0]),
        Felt::new(arr[1]),
        Felt::new(arr[2]),
        Felt::new(arr[3]),
    ]
}

fn generate_batch_public_inputs(
    limit: u64,
    seq: usize,
    tenant_id: Uuid,
    store_id: Uuid,
) -> Result<CompliancePublicInputs> {
    let policy_id = "aml.threshold";
    let params = PolicyParams::threshold(limit);
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
    })
}

// ============================================================================
// Sequencer Simulation
// ============================================================================

fn run_sequencer(
    num_events: usize,
    batch_size: usize,
    limit: u64,
    include_violations: bool,
    output_dir: Option<PathBuf>,
) -> Result<()> {
    ensure_experimental_batch_enabled()?;

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

        println!("--- Batch {} ---", batch_num);
        println!(
            "  Events: {} - {}",
            total_events_processed,
            total_events_processed + events_in_batch - 1
        );

        // Create metadata for this batch
        let metadata = BatchMetadata::with_ids(
            Uuid::new_v4(),
            tenant_id,
            store_id,
            total_events_processed as u64,
            (total_events_processed + events_in_batch - 1) as u64,
        );

        // Build witness
        let mut builder = BatchWitnessBuilder::new()
            .metadata(metadata.clone())
            .prev_state_root(current_state_root.clone())
            .policy_hash(policy_hash)
            .policy_limit(limit);

        let mut compliant_count = 0;
        let mut violation_count = 0;

        for i in 0..events_in_batch {
            let seq = total_events_processed + i;

            // Decide if this event should be a violation
            let is_violation = include_violations && (seq % 5 == 4); // Every 5th event

            let amount = if is_violation {
                limit + (rand_u64() % 1000) + 1 // Over limit
            } else {
                (rand_u64() % (limit - 1)).max(1) // Under limit
            };

            let inputs = generate_batch_public_inputs(limit, seq, tenant_id, store_id)?;
            builder = builder.add_event(amount, inputs);

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
        let pub_inputs = ves_stark_batch::BatchPublicInputs::new(
            current_state_root.root,
            new_state_root.root,
            witness.batch_id_felts(),
            witness.tenant_id_felts(),
            witness.store_id_felts(),
            metadata.sequence_start,
            metadata.sequence_end,
            events_in_batch,
            witness.all_compliant(),
            policy_hash,
            limit,
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
            let output = serde_json::json!({
                "batch_num": batch_num,
                "proof_b64": base64::engine::general_purpose::STANDARD.encode(&proof.proof_bytes),
                "proof_hash": proof.proof_hash,
                "prev_state_root": proof.prev_state_root,
                "new_state_root": proof.new_state_root,
                "metadata": proof.metadata,
            });
            fs::write(&proof_file, serde_json::to_string_pretty(&output)?)?;
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
