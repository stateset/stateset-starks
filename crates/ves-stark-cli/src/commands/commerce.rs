//! Commerce CLI: bounded inputs, private amount intake, and independent approvals.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use ves_stark_commerce::approval::{ApprovalAuthority, ApprovalTerms, SignedApproval};
use ves_stark_commerce::ledger::RefundLedger;
use ves_stark_commerce::refund::{prove_refund_disclosed, RefundProof, RefundState};
use ves_stark_commerce::{
    prepare_cap_proof_disclosed, CommerceApproval, CommerceProof, CommerceRequest, ProofPrivacy,
};
use ves_stark_verifier::MAX_PROOF_SIZE;
use zeroize::Zeroizing;

const MAX_CONTEXT_BYTES: usize = 16 * 1024;
const MAX_PROOF_JSON_BYTES: usize = MAX_PROOF_SIZE * 8 + MAX_CONTEXT_BYTES;

#[derive(Subcommand)]
pub(crate) enum CommerceCommand {
    /// Prepare and prove a cap at trusted intake; writes proof.json and approval.json
    Prove {
        /// Accept that public proof bytes can disclose the amount
        #[arg(long)]
        allow_amount_disclosure: bool,
        /// CommerceRequest JSON from the approval system
        #[arg(long)]
        request: PathBuf,
        /// Private integer amount file (or - for stdin); never echoed
        #[arg(long)]
        amount_file: PathBuf,
        /// New output directory; existing directories are never overwritten
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Verify a submitted proof against an independently trusted approval record
    Verify {
        /// Accept integrity-only verification, without confidentiality
        #[arg(long)]
        allow_amount_disclosure: bool,
        /// Trusted authority configuration for a signed approval
        #[arg(long, conflicts_with = "allow_unsigned_approval")]
        authority: Option<PathBuf>,
        /// Explicit legacy mode: approval file provenance is authenticated externally
        #[arg(long)]
        allow_unsigned_approval: bool,
        /// CommerceProof JSON (or - for stdin)
        #[arg(long)]
        proof: PathBuf,
        /// CommerceApproval JSON retrieved from the trusted approval system
        #[arg(long)]
        approval: PathBuf,
    },
    /// Sign an approval at trusted intake (not an authentication of arbitrary prover input)
    SignApproval {
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        authority: PathBuf,
        /// Protected file containing a 32-byte Ed25519 seed as 64 hexadecimal characters
        #[arg(long)]
        secret_key_file: PathBuf,
        /// Exclusive expiration in Unix seconds
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import a capture from an authenticated source into the local ledger
    CaptureImport {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        ledger: PathBuf,
    },
    /// Prove disclosed refund accounting from the current local capture state
    RefundProve {
        #[arg(long)]
        allow_amount_disclosure: bool,
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        tenant_id: Uuid,
        #[arg(long)]
        store_id: Uuid,
        #[arg(long)]
        capture_id: String,
        #[arg(long)]
        event_id: Uuid,
        #[arg(long)]
        sequence_number: u64,
        #[arg(long)]
        amount_file: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Verify a signed refund and atomically reserve it and enqueue execution
    RefundApply {
        #[arg(long)]
        allow_amount_disclosure: bool,
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        authority: PathBuf,
    },
    /// List durable pending refunds for an idempotent payment worker
    RefundPending {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Record provider-confirmed execution; never sends a payment itself
    RefundComplete {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        provider_reference: String,
    },
}

impl CommerceCommand {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            Self::Prove {
                request,
                amount_file,
                output_dir,
                allow_amount_disclosure,
            } => {
                enforce_disclosure(allow_amount_disclosure)?;
                let request: CommerceRequest = read_json_file(&request, MAX_CONTEXT_BYTES)?;
                request.validate()?;
                // Only this input accepts stdin; request and approval always name files.
                let input = if amount_file == Path::new("-") {
                    read_bounded(io::stdin().lock(), 64)?
                } else {
                    read_bounded(
                        File::open(&amount_file).context("Cannot open amount file")?,
                        64,
                    )?
                };
                let input = Zeroizing::new(input);
                let amount = Zeroizing::new(parse_amount(&input)?);
                let prepared = prepare_cap_proof_disclosed(*amount, &request)?;
                let approval = prepared.approval();
                let proof = prepared.prove()?;
                // Serialize before creating anything, and use a new directory so a
                // mistaken path cannot overwrite an existing proof or approval.
                let proof_json = serde_json::to_vec(&proof)?;
                let approval_json = serde_json::to_vec_pretty(&approval)?;
                fs::create_dir(&output_dir)
                    .context("Output directory must be new and its parent must exist")?;
                let proof_path = output_dir.join("proof.json");
                let approval_path = output_dir.join("approval.json");
                write_new(&proof_path, &proof_json)?;
                write_new(&approval_path, &approval_json)?;
                println!(
                    "{}",
                    serde_json::json!({
                        "proofPath": proof_path,
                        "approvalPath": approval_path,
                        "payloadHash": approval.payload_hash,
                        "zeroKnowledge": false,
                    })
                );
                Ok(())
            }
            Self::Verify {
                proof,
                approval,
                authority,
                allow_unsigned_approval,
                allow_amount_disclosure,
            } => {
                enforce_disclosure(allow_amount_disclosure)?;
                let approval: CommerceApproval = if let Some(authority) = authority {
                    let authority: ApprovalAuthority =
                        read_json_file(&authority, MAX_CONTEXT_BYTES)?;
                    let signed: SignedApproval = read_json_file(&approval, MAX_CONTEXT_BYTES)?;
                    signed.verify(&authority, unix_now()?)?;
                    signed.terms.approval
                } else if allow_unsigned_approval {
                    read_json_file(&approval, MAX_CONTEXT_BYTES)?
                } else {
                    bail!("--authority is required for signed verification; legacy trusted-file use requires --allow-unsigned-approval");
                };
                approval.validate()?;
                let bytes = if proof == Path::new("-") {
                    read_bounded(io::stdin().lock(), MAX_PROOF_JSON_BYTES)?
                } else {
                    read_bounded(
                        File::open(&proof).context("Cannot open proof file")?,
                        MAX_PROOF_JSON_BYTES,
                    )?
                };
                let proof: CommerceProof =
                    serde_json::from_slice(&bytes).context("Invalid commerce proof JSON")?;
                let result = approval.verify_disclosed(&proof)?;
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": result.valid,
                        "zeroKnowledge": false,
                        "eventId": approval.request.event_id,
                        "operation": approval.request.operation,
                        "currency": approval.request.currency,
                        "decimalPlaces": approval.request.decimal_places,
                        "cap": approval.request.cap,
                    })
                );
                Ok(())
            }
            Self::SignApproval {
                approval,
                authority,
                secret_key_file,
                expires_at,
                output,
            } => {
                let approval: CommerceApproval = read_json_file(&approval, MAX_CONTEXT_BYTES)?;
                let authority: ApprovalAuthority = read_json_file(&authority, MAX_CONTEXT_BYTES)?;
                let bytes = Zeroizing::new(read_bounded(File::open(secret_key_file)?, 128)?);
                let text = std::str::from_utf8(&bytes)?.trim();
                if text.len() != 64 {
                    bail!("Signing seed must contain exactly 64 hex characters");
                }
                let mut seed = Zeroizing::new([0u8; 32]);
                hex::decode_to_slice(text, &mut *seed).context("Invalid signing seed encoding")?;
                let now = unix_now()?;
                let signed = SignedApproval::sign(
                    ApprovalTerms {
                        approval,
                        key_id: authority.key_id.clone(),
                        policy_version: authority.policy_version,
                        nonce: Uuid::new_v4(),
                        not_before: now,
                        expires_at,
                    },
                    &SigningKey::from_bytes(&seed),
                )?;
                signed.verify(&authority, now)?;
                write_new(&output, &serde_json::to_vec_pretty(&signed)?)?;
                println!("{}", serde_json::json!({"approvalPath": output}));
                Ok(())
            }
            Self::CaptureImport { state, ledger } => {
                let state: RefundState = read_json_file(&state, MAX_CONTEXT_BYTES)?;
                RefundLedger::open(ledger)?.register_capture(&state)?;
                println!(
                    "{}",
                    serde_json::json!({"stateCommitment": state.commitment()?})
                );
                Ok(())
            }
            Self::RefundProve {
                allow_amount_disclosure,
                ledger,
                tenant_id,
                store_id,
                capture_id,
                event_id,
                sequence_number,
                amount_file,
                output_dir,
            } => {
                enforce_disclosure(allow_amount_disclosure)?;
                let state = RefundLedger::open(ledger)?.state(tenant_id, store_id, &capture_id)?;
                let amount = read_amount(&amount_file)?;
                let (proof, approval) =
                    prove_refund_disclosed(state, *amount, event_id, sequence_number)?;
                fs::create_dir(&output_dir).context("Output directory must be new")?;
                write_new(&output_dir.join("proof.json"), &serde_json::to_vec(&proof)?)?;
                write_new(
                    &output_dir.join("approval.json"),
                    &serde_json::to_vec_pretty(&approval)?,
                )?;
                println!(
                    "{}",
                    serde_json::json!({"outputDir": output_dir, "zeroKnowledge": false})
                );
                Ok(())
            }
            Self::RefundApply {
                allow_amount_disclosure,
                ledger,
                proof,
                approval,
                authority,
            } => {
                enforce_disclosure(allow_amount_disclosure)?;
                let proof: RefundProof = read_json_file(&proof, MAX_PROOF_JSON_BYTES)?;
                let signed: SignedApproval = read_json_file(&approval, MAX_CONTEXT_BYTES)?;
                let authority: ApprovalAuthority = read_json_file(&authority, MAX_CONTEXT_BYTES)?;
                let execution = RefundLedger::open(ledger)?.apply_refund(
                    &proof,
                    &signed,
                    &authority,
                    unix_now()?,
                )?;
                println!("{}", serde_json::to_string(&execution)?);
                Ok(())
            }
            Self::RefundPending { ledger, limit } => {
                println!(
                    "{}",
                    serde_json::to_string(&RefundLedger::open(ledger)?.pending(limit)?)?
                );
                Ok(())
            }
            Self::RefundComplete {
                ledger,
                idempotency_key,
                provider_reference,
            } => {
                RefundLedger::open(ledger)?.mark_executed(&idempotency_key, &provider_reference)?;
                println!(
                    "{}",
                    serde_json::json!({"completed": true, "idempotencyKey": idempotency_key})
                );
                Ok(())
            }
        }
    }
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn enforce_disclosure(allow: bool) -> Result<()> {
    let privacy = if allow {
        ProofPrivacy::AllowDisclosure
    } else {
        ProofPrivacy::Confidential
    };
    privacy
        .enforce()
        .context("--allow-amount-disclosure is required for this integrity-only backend")?;
    Ok(())
}

fn read_amount(path: &Path) -> Result<Zeroizing<u64>> {
    let bytes = Zeroizing::new(if path == Path::new("-") {
        read_bounded(io::stdin().lock(), 64)?
    } else {
        read_bounded(File::open(path)?, 64)?
    });
    Ok(Zeroizing::new(parse_amount(&bytes)?))
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .context("Cannot read input")?;
    if bytes.len() > limit {
        bail!("Input exceeds {limit} byte limit");
    }
    Ok(bytes)
}

fn read_json_file<T: DeserializeOwned>(path: &Path, limit: usize) -> Result<T> {
    if path == Path::new("-") {
        bail!(
            "Request and approval inputs must name files; stdin is reserved for amounts or proofs"
        );
    }
    let bytes = read_bounded(
        File::open(path).with_context(|| format!("Cannot open {}", path.display()))?,
        limit,
    )?;
    serde_json::from_slice(&bytes).context("Invalid commerce context JSON")
}

fn parse_amount(bytes: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(bytes)
        .context("Amount must be UTF-8 integer text")?
        .trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Amount must be an unsigned integer in the request's monetary units");
    }
    text.parse().context("Amount is outside the u64 range")
}

fn write_new(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("Cannot create {}", path.display()))?;
    file.write_all(contents)
        .context("Cannot write commerce artifact")?;
    file.sync_all().context("Cannot persist commerce artifact")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_read_checks_actual_bytes_including_streams() {
        assert_eq!(read_bounded(&b"1234"[..], 4).unwrap(), b"1234");
        assert!(read_bounded(&b"12345"[..], 4).is_err());
    }

    #[test]
    fn amounts_reject_floats_signs_and_overflow_without_echoing_secrets() {
        assert_eq!(parse_amount(b"18446744073709551615\n").unwrap(), u64::MAX);
        assert_eq!(parse_amount(b"0").unwrap(), 0);
        for bad in [
            "4242.50",
            "-4242",
            "+4242",
            "18446744073709551616",
            "4e3",
            "",
        ] {
            let error = format!("{:#}", parse_amount(bad.as_bytes()).unwrap_err());
            if !bad.is_empty() {
                assert!(!error.contains(bad));
            }
        }
    }
}
