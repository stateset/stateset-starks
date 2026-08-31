//! Prove — one section of the C API. See lib.rs.

use super::*;

// ---------------------------------------------------------------------------
// Proof Generation
// ---------------------------------------------------------------------------

/// Generate a STARK compliance proof.
///
/// `policy_type`: one of "aml.threshold", "order_total.cap", "agent.authorization.v1"
///
/// On success, `*out_proof` is set to a new proof handle. Free with `ves_proof_free()`.
///
/// # Safety
/// `inputs` must be a valid, unfreed handle from [`ves_public_inputs_from_json`].
/// `policy_type` must be a valid NUL-terminated C string. `out_proof` must be a
/// valid, writable pointer to a `*mut VesProof`; on success it receives a handle
/// that must be released with [`ves_proof_free`]. `inputs` and `out_proof` may be
/// NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_prove(
    amount: u64,
    inputs: *const VesPublicInputs,
    policy_type: *const c_char,
    policy_limit: u64,
    out_proof: *mut *mut VesProof,
) -> i32 {
    if inputs.is_null() || out_proof.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let policy_type_str = match unsafe { cstr_to_str(policy_type) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let rust_inputs = &unsafe { &*inputs }.inner;

    if rust_inputs.policy_id != policy_type_str {
        set_last_error(format!(
            "policy_type '{}' does not match public_inputs.policy_id '{}'",
            policy_type_str, rust_inputs.policy_id
        ));
        return VES_ERR_INVALID_ARG;
    }

    let policy =
        match Policy::from_public_inputs(&rust_inputs.policy_id, &rust_inputs.policy_params) {
            Ok(p) => p,
            Err(e) => {
                set_last_error(format!("Invalid policy parameters: {}", e));
                return VES_ERR_INVALID_ARG;
            }
        };

    if policy.limit() != policy_limit {
        set_last_error(format!(
            "policy_limit {} does not match public_inputs policy limit {}",
            policy_limit,
            policy.limit()
        ));
        return VES_ERR_INVALID_ARG;
    }

    if !policy.validate_amount(amount) {
        set_last_error(format!(
            "amount must be {} policy limit for {}",
            match policy_type_str {
                "aml.threshold" => "<",
                _ => "<=",
            },
            policy_type_str
        ));
        return VES_ERR_INVALID_ARG;
    }

    let witness = match ComplianceWitness::try_new(amount, rust_inputs.clone()) {
        Ok(w) => w,
        Err(e) => {
            set_last_error(format!("Invalid witness/public inputs: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let prover = ComplianceProver::with_policy(policy);
    let proof = match prover.prove(&witness) {
        Ok(p) => p,
        Err(e) => {
            set_last_error(format!("Proof generation failed: {}", e));
            return VES_ERR_PROOF_FAILED;
        }
    };

    let witness_commitment_hex_str = match proof.witness_commitment_hex {
        Some(ref h) => h.clone(),
        None => {
            set_last_error("Missing witness_commitment_hex in proof".into());
            return VES_ERR_PROOF_FAILED;
        }
    };

    let ves_proof = Box::new(VesProof {
        proof_bytes: proof.proof_bytes,
        proof_hash: CString::new(proof.proof_hash).unwrap(),
        proving_time_ms: proof.metadata.proving_time_ms,
        proof_size: proof.metadata.proof_size,
        witness_commitment: proof.witness_commitment,
        witness_commitment_hex: CString::new(witness_commitment_hex_str).unwrap(),
    });

    unsafe { *out_proof = Box::into_raw(ves_proof) };
    VES_OK
}
