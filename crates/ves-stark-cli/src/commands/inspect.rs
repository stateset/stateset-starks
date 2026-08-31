//! `inspect` command(s). Shared helpers live in `main.rs`.

use super::*;

pub(crate) fn inspect(proof_path: PathBuf) -> Result<()> {
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
