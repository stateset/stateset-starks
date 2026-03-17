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
//! - `agent.authorization.v1`: Proves amount <= maxTotal for a delegated intent hash

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

use ves_stark_client::{AgentAuthorizationProofBundle, ComplianceProofBundle, SequencerClient};
use ves_stark_primitives::public_inputs::{
    compute_policy_hash, witness_commitment_hex_to_u64, witness_commitment_u64_to_hex,
    CompliancePublicInputs, PayloadAmountBinding, PolicyParams,
};
use ves_stark_primitives::{hash_to_felts, CommerceAuthorizationReceipt, Felt};
use ves_stark_prover::{ComplianceProof, ComplianceProver, ComplianceWitness, Policy};
use ves_stark_verifier::{
    verify_agent_authorization_proof_auto_bound,
    verify_agent_authorization_proof_auto_bound_witness_strict,
    verify_agent_authorization_proof_auto_with_amount_binding,
    verify_agent_authorization_proof_auto_with_amount_binding_strict,
    verify_compliance_proof_auto_bound, verify_compliance_proof_auto_bound_witness_strict,
    verify_compliance_proof_auto_with_amount_binding,
    verify_compliance_proof_auto_with_amount_binding_strict, MAX_PROOF_SIZE,
};

// Batch proving imports
use ves_stark_batch::verifier::MAX_BATCH_PROOF_SIZE;
use ves_stark_batch::{
    BatchMetadata, BatchPolicyKind, BatchProver, BatchPublicInputs, BatchStateRoot, BatchVerifier,
    BatchWitnessBuilder, SerializableBatchProof,
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
    /// Agent authorization: proves amount <= maxTotal for a delegated intent hash
    #[value(name = "agent.authorization.v1")]
    AgentAuthorization,
}

impl PolicyType {
    fn as_policy(&self, limit: u64, intent_hash: Option<&str>) -> Result<Policy> {
        match self {
            PolicyType::AmlThreshold => Ok(Policy::aml_threshold(limit)),
            PolicyType::OrderTotalCap => Ok(Policy::order_total_cap(limit)),
            PolicyType::AgentAuthorization => Policy::agent_authorization(
                limit,
                intent_hash.ok_or_else(|| {
                    anyhow::anyhow!(
                        "--intent-hash is required for agent.authorization.v1 unless it is already present in the public inputs"
                    )
                })?,
            )
            .map_err(|e| anyhow::anyhow!("Invalid agent authorization policy: {e}")),
        }
    }

    fn policy_id(&self) -> &'static str {
        match self {
            PolicyType::AmlThreshold => "aml.threshold",
            PolicyType::OrderTotalCap => "order_total.cap",
            PolicyType::AgentAuthorization => "agent.authorization.v1",
        }
    }

    fn comparison_desc(&self) -> &'static str {
        match self {
            PolicyType::AmlThreshold => "<",
            PolicyType::OrderTotalCap => "<=",
            PolicyType::AgentAuthorization => "<=",
        }
    }

    fn create_policy_params(&self, limit: u64, intent_hash: Option<&str>) -> Result<PolicyParams> {
        match self {
            PolicyType::AmlThreshold => Ok(PolicyParams::threshold(limit)),
            PolicyType::OrderTotalCap => Ok(PolicyParams::cap(limit)),
            PolicyType::AgentAuthorization => PolicyParams::agent_authorization(
                limit,
                intent_hash.ok_or_else(|| {
                    anyhow::anyhow!(
                        "--intent-hash is required for agent.authorization.v1 unless it is already present in the public inputs"
                    )
                })?,
            )
            .map_err(|e| anyhow::anyhow!("Invalid agent authorization policy params: {e}")),
        }
    }

    fn supports_batch(&self) -> bool {
        !matches!(self, PolicyType::AgentAuthorization)
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

        /// The policy limit (threshold, cap, or maxTotal depending on policy)
        #[arg(short, long)]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,

        /// Delegated commerce intent hash for agent.authorization.v1
        #[arg(long)]
        intent_hash: Option<String>,

        /// Path to public inputs JSON file (optional, will generate random if not provided)
        #[arg(short, long)]
        inputs: Option<PathBuf>,

        /// Authorization receipt JSON for emitting a canonical agent authorization bundle
        #[arg(long)]
        authorization_receipt: Option<PathBuf>,

        /// Output file for the proof (default: stdout as base64)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output as JSON with metadata
        #[arg(long)]
        json: bool,
    },

    /// Generate a compliance proof for an event and submit it to the sequencer.
    ///
    /// Authentication: set the STATESET_API_KEY environment variable.
    ProveSubmit {
        /// Sequencer base URL (e.g., http://localhost:8080)
        #[arg(long, default_value = "http://localhost:8080")]
        sequencer_url: String,

        /// Event ID to prove about
        #[arg(long)]
        event_id: Uuid,

        /// The amount to prove (must satisfy policy constraint)
        #[arg(short, long)]
        amount: u64,

        /// The policy limit (threshold, cap, or maxTotal depending on policy)
        #[arg(short, long)]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,

        /// Delegated commerce intent hash for agent.authorization.v1
        #[arg(long)]
        intent_hash: Option<String>,

        /// Authorization receipt JSON for canonical agent authorization bundle submission
        #[arg(long)]
        authorization_receipt: Option<PathBuf>,

        /// Verify the stored proof after submission
        #[arg(long)]
        verify: bool,
    },

    /// Verify a compliance proof
    Verify {
        /// Path to the proof file (or `-` for stdin)
        #[arg(short = 'f', long)]
        proof: PathBuf,

        /// Path to public inputs JSON file. Optional when the proof JSON embeds canonical
        /// `publicInputs` (for example, canonical proof bundles).
        #[arg(short, long)]
        inputs: Option<PathBuf>,

        /// Witness commitment hex for raw base64 proofs. If omitted, the CLI
        /// falls back to `public_inputs.witnessCommitment`.
        #[arg(long)]
        witness_commitment_hex: Option<String>,

        /// Authorization receipt JSON to bind an agent.authorization.v1 proof to a canonical receipt
        #[arg(long)]
        authorization_receipt: Option<PathBuf>,

        /// Payload amount binding JSON to bind the proved witness back to payload hashes
        #[arg(long)]
        amount_binding: Option<PathBuf>,

        /// The limit value used for the proof
        #[arg(short, long)]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,

        /// Delegated commerce intent hash for agent.authorization.v1
        #[arg(long)]
        intent_hash: Option<String>,
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

        /// Delegated commerce intent hash for agent.authorization.v1
        #[arg(long)]
        intent_hash: Option<String>,

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

        /// Delegated commerce intent hash for agent.authorization.v1
        #[arg(long)]
        intent_hash: Option<String>,
    },

    /// Generate a batch state transition proof (zkRollup-style)
    #[command(name = "batch-prove")]
    BatchProve {
        /// Number of events to generate randomly (ignored if --events is provided)
        #[arg(short = 'n', long, default_value = "8")]
        num_events: usize,

        /// Policy limit (threshold)
        #[arg(short, long, default_value = "10000")]
        limit: u64,

        /// Policy type
        #[arg(short, long, value_enum, default_value = "aml.threshold")]
        policy: PolicyType,

        /// Path to events JSON file (array of {amount, publicInputs} objects)
        #[arg(short, long)]
        events: Option<PathBuf>,

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

        /// Path to batch public inputs JSON file (optional; extracted from proof file if omitted)
        #[arg(short, long)]
        inputs: Option<PathBuf>,
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
            intent_hash,
            inputs,
            authorization_receipt,
            output,
            json,
        } => prove(
            amount,
            limit,
            policy,
            intent_hash,
            inputs,
            authorization_receipt,
            output,
            json,
        ),

        Commands::ProveSubmit {
            sequencer_url,
            event_id,
            amount,
            limit,
            policy,
            intent_hash,
            authorization_receipt,
            verify,
        } => prove_submit(
            sequencer_url,
            event_id,
            amount,
            limit,
            policy,
            intent_hash,
            authorization_receipt,
            verify,
        ),

        Commands::Verify {
            proof,
            inputs,
            witness_commitment_hex,
            authorization_receipt,
            amount_binding,
            limit,
            policy,
            intent_hash,
        } => verify(
            proof,
            inputs,
            witness_commitment_hex,
            authorization_receipt,
            amount_binding,
            limit,
            policy,
            intent_hash,
        ),

        Commands::Inspect { proof } => inspect(proof),

        Commands::GenerateInputs {
            limit,
            policy,
            intent_hash,
            output,
        } => generate_inputs(limit, policy, intent_hash, output),

        Commands::Benchmark {
            count,
            max_amount,
            limit,
            policy,
            intent_hash,
        } => benchmark(count, max_amount, limit, policy, intent_hash),

        Commands::BatchProve {
            num_events,
            limit,
            policy,
            events,
            output,
        } => batch_prove(num_events, limit, policy, events, output),

        Commands::BatchVerify { proof, inputs } => batch_verify(proof, inputs),

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

fn read_text_input(path: &PathBuf, label: &str) -> Result<String> {
    if path.to_string_lossy() == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .with_context(|| format!("Failed to read {label} from stdin"))?;
        Ok(buf)
    } else {
        fs::read_to_string(path)
            .with_context(|| format!("Failed to read {label} file: {}", path.display()))
    }
}

fn normalize_intent_hash(intent_hash: &str) -> Result<String> {
    let params = PolicyParams::agent_authorization(1, intent_hash)
        .map_err(|e| anyhow::anyhow!("Invalid --intent-hash: {e}"))?;
    Ok(params
        .get_intent_hash()
        .expect("agent authorization params must include intentHash")
        .to_string())
}

fn resolve_intent_hash(
    policy_type: PolicyType,
    provided: Option<String>,
    public_inputs: Option<&CompliancePublicInputs>,
) -> Result<Option<String>> {
    if !matches!(policy_type, PolicyType::AgentAuthorization) {
        if provided.is_some() {
            anyhow::bail!("--intent-hash is only valid for agent.authorization.v1");
        }
        return Ok(None);
    }

    let provided = provided.as_deref().map(normalize_intent_hash).transpose()?;
    let inputs_hash = public_inputs
        .and_then(|inputs| inputs.policy_params.get_intent_hash())
        .map(|value| value.to_string());

    match (provided, inputs_hash) {
        (Some(provided), Some(from_inputs)) => {
            if provided != from_inputs {
                anyhow::bail!(
                    "--intent-hash does not match public_inputs.policyParams.intentHash"
                );
            }
            Ok(Some(provided))
        }
        (Some(provided), None) => Ok(Some(provided)),
        (None, Some(from_inputs)) => Ok(Some(from_inputs)),
        (None, None) => anyhow::bail!(
            "--intent-hash is required for agent.authorization.v1 unless it is already present in the public inputs"
        ),
    }
}

fn validate_public_inputs_match_policy(
    public_inputs: &CompliancePublicInputs,
    policy_type: PolicyType,
    limit: u64,
    intent_hash: Option<&str>,
) -> Result<()> {
    let expected_policy_id = policy_type.policy_id();
    if public_inputs.policy_id != expected_policy_id {
        anyhow::bail!(
            "public inputs policyId {} does not match requested policy {}",
            public_inputs.policy_id,
            expected_policy_id
        );
    }

    let expected_params = policy_type.create_policy_params(limit, intent_hash)?;
    if public_inputs.policy_params != expected_params {
        anyhow::bail!("public inputs policyParams do not match the requested policy arguments");
    }

    let expected_hash = compute_policy_hash(expected_policy_id, &expected_params)?;
    if public_inputs.policy_hash != expected_hash.to_hex() {
        anyhow::bail!("public inputs policyHash does not match the requested policy arguments");
    }

    Ok(())
}

fn ensure_batch_policy_supported(policy_type: PolicyType) -> Result<()> {
    if policy_type.supports_batch() {
        Ok(())
    } else {
        anyhow::bail!("agent.authorization.v1 is not supported by batch proofs")
    }
}

fn parse_public_inputs_value(
    value: &serde_json::Value,
    context: &str,
) -> Result<CompliancePublicInputs> {
    serde_json::from_value(value.clone())
        .with_context(|| format!("Failed to parse {context} public inputs JSON"))
}

fn parse_payload_amount_binding_value(
    value: &serde_json::Value,
    context: &str,
) -> Result<PayloadAmountBinding> {
    serde_json::from_value(value.clone())
        .with_context(|| format!("Failed to parse {context} payload amount binding JSON"))
}

fn parse_authorization_receipt_value(
    value: &serde_json::Value,
    context: &str,
) -> Result<CommerceAuthorizationReceipt> {
    serde_json::from_value(value.clone())
        .with_context(|| format!("Failed to parse {context} authorization receipt JSON"))
}

fn ensure_public_inputs_match(
    expected: &CompliancePublicInputs,
    actual: &CompliancePublicInputs,
    context: &str,
) -> Result<()> {
    let expected_hash = expected
        .compute_full_hash()
        .map_err(|e| anyhow::anyhow!("Failed to hash expected {context} public inputs: {e}"))?
        .to_hex();
    let actual_hash = actual
        .compute_full_hash()
        .map_err(|e| anyhow::anyhow!("Failed to hash provided {context} public inputs: {e}"))?
        .to_hex();

    if expected_hash != actual_hash {
        anyhow::bail!("{context} public inputs do not match the canonical proof bundle");
    }

    Ok(())
}

fn ensure_payload_amount_binding_match(
    expected: &PayloadAmountBinding,
    actual: &PayloadAmountBinding,
    context: &str,
) -> Result<()> {
    if expected
        .normalized()
        .map_err(|e| anyhow::anyhow!("Invalid canonical {context} amount binding: {e}"))?
        != actual
            .normalized()
            .map_err(|e| anyhow::anyhow!("Invalid provided {context} amount binding: {e}"))?
    {
        anyhow::bail!("{context} amount binding does not match the canonical proof bundle");
    }

    Ok(())
}

fn ensure_authorization_receipt_match(
    expected: &CommerceAuthorizationReceipt,
    actual: &CommerceAuthorizationReceipt,
    context: &str,
) -> Result<()> {
    if expected
        .normalized()
        .map_err(|e| anyhow::anyhow!("Invalid canonical {context} authorization receipt: {e}"))?
        != actual
            .normalized()
            .map_err(|e| anyhow::anyhow!("Invalid provided {context} authorization receipt: {e}"))?
    {
        anyhow::bail!("{context} authorization receipt does not match the canonical proof bundle");
    }

    Ok(())
}

fn verify_compliance_bundle(
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

fn verify_agent_authorization_bundle(
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

fn prove(
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

fn prove_submit(
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

#[allow(clippy::too_many_arguments)]
fn verify(
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

fn inspect(proof_path: PathBuf) -> Result<()> {
    // Load proof
    let proof_str = fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    // Try to parse as JSON first
    if proof_str.trim().starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(&proof_str)?;

        println!("Proof Inspection:");
        println!("  Format: JSON with metadata");

        if let Some(hash) = json.get("bundleHash") {
            println!("  Bundle Hash: {}", hash.as_str().unwrap_or("unknown"));
        }
        if let Some(hash) = json.get("proof_hash").or_else(|| json.get("proofHash")) {
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

        if let Some(inputs) = json
            .get("public_inputs")
            .or_else(|| json.get("publicInputs"))
        {
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

        if let Some(hash) = json.get("publicInputsHash") {
            println!(
                "  Public Inputs Hash: {}",
                hash.as_str().unwrap_or("unknown")
            );
        }
        if let Some(hash) = json.get("boundPublicInputsHash") {
            println!(
                "  Bound Public Inputs Hash: {}",
                hash.as_str().unwrap_or("unknown")
            );
        }
        if let Some(b64) = json.get("proof_b64").or_else(|| json.get("proofB64")) {
            if let Some(s) = b64.as_str() {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
                    println!("  Raw Proof Size: {} bytes", bytes.len());
                }
            }
        }
        if let Some(binding) = json.get("amountBinding") {
            if let Some(amount) = binding.get("amount") {
                println!("  Bound Amount: {}", amount);
            }
            if let Some(binding_hash) = binding.get("bindingHash") {
                println!(
                    "  Amount Binding Hash: {}",
                    binding_hash.as_str().unwrap_or("unknown")
                );
            }
        }
        if let Some(receipt) = json.get("receipt") {
            if let Some(amount) = receipt.get("amount") {
                println!("  Receipt Amount: {}", amount);
            }
            if let Some(receipt_hash) = receipt.get("receiptHash") {
                println!(
                    "  Authorization Receipt Hash: {}",
                    receipt_hash.as_str().unwrap_or("unknown")
                );
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

fn generate_random_public_inputs(
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
    })
}

fn benchmark(
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
fn rand_u64() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen()
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

/// A single event entry in a batch events JSON file
#[derive(Debug, serde::Deserialize)]
struct BatchEventEntry {
    amount: u64,
    #[serde(rename = "publicInputs")]
    public_inputs: CompliancePublicInputs,
}

fn batch_prove(
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

fn batch_verify(proof_path: PathBuf, inputs_path: Option<PathBuf>) -> Result<()> {
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
