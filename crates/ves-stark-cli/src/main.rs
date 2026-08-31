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

// Crate-level lints.
//
// `forbid(unsafe_code)` is meaningful here rather than decorative: this crate
// contains no `unsafe`, and the only crate in the workspace that does
// (`ves-stark-zig`, the C FFI surface) is deliberately excluded. `forbid` — not
// `deny` — so it cannot be locally overridden by an `allow` attribute.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

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
        /// Sequencer base URL (e.g., `http://localhost:8080`)
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

// One file per command; the CLI definition, `main`, and the helpers every
// command shares stay here.
mod commands {
    use super::*;
    pub(crate) mod batch;
    pub(crate) mod inspect;
    pub(crate) mod prove;
    pub(crate) mod sequencer;
    pub(crate) mod tools;
    pub(crate) mod verify;
}
use commands::{batch::*, inspect::*, prove::*, sequencer::*, tools::*, verify::*};
