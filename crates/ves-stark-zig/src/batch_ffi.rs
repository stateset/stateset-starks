//! Batch proofs (feature-gated) — one section of the C API. See lib.rs.

use super::*;
use ves_stark_batch::{
    BatchMetadata, BatchPolicyKind, BatchProver, BatchVerifier, BatchWitnessBuilder,
    SerializableBatchProof,
};
use ves_stark_primitives::hash_to_felts;

pub struct VesBatchProof {
    proof_bytes: Vec<u8>,
    proof_hash: CString,
    prev_state_root: [u64; 4],
    new_state_root: [u64; 4],
    num_events: usize,
    all_compliant: bool,
    proving_time_ms: u64,
    proof_size: usize,
    serialized_json: CString,
}

pub struct VesBatchVerificationResult {
    valid: bool,
    verification_time_ms: u64,
    error: Option<CString>,
    prev_state_root: [u64; 4],
    new_state_root: [u64; 4],
    num_events: usize,
    all_compliant: bool,
}

/// Generate a batch proof from a JSON array of events.
///
/// `events_json`: JSON array like `[{"amount": 5000, "publicInputs": {...}}, ...]`
/// `policy_type`: "aml.threshold" or "order_total.cap"
/// `policy_limit`: the policy limit value
///
/// On success, `*out_proof` receives a batch proof handle. Free with `ves_batch_proof_free()`.
///
/// # Safety
/// `events_json` and `policy_type` must each be a valid NUL-terminated C string.
/// `out_proof` must be a valid, writable `*mut *mut VesBatchProof`; on success it
/// receives a handle that must be released with [`ves_batch_proof_free`].
/// `out_proof` may be NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_batch_prove_json(
    events_json: *const c_char,
    policy_type: *const c_char,
    policy_limit: u64,
    out_proof: *mut *mut VesBatchProof,
) -> i32 {
    if out_proof.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let events_str = match unsafe { cstr_to_str(events_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let policy_type_str = match unsafe { cstr_to_str(policy_type) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let policy_kind = match policy_type_str {
        "aml.threshold" => BatchPolicyKind::AmlThreshold,
        "order_total.cap" => BatchPolicyKind::OrderTotalCap,
        _ => {
            set_last_error(format!(
                "Unsupported batch policy type: {}",
                policy_type_str
            ));
            return VES_ERR_INVALID_ARG;
        }
    };

    // Parse events JSON
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EventEntry {
        amount: u64,
        public_inputs: CompliancePublicInputs,
    }

    let entries: Vec<EventEntry> = match serde_json::from_str(events_str) {
        Ok(e) => e,
        Err(e) => {
            set_last_error(format!("Invalid events JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    if entries.is_empty() {
        set_last_error("events array must not be empty".into());
        return VES_ERR_INVALID_ARG;
    }

    // Compute policy hash
    let params = &entries[0].public_inputs.policy_params;
    let policy_hash_obj = match ves_stark_primitives::compute_policy_hash(policy_type_str, params) {
        Ok(h) => h,
        Err(e) => {
            set_last_error(format!("Failed to compute policy hash: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };
    let policy_hash = hash_to_felts(&policy_hash_obj);

    // Build witness
    let tenant_id = entries[0].public_inputs.tenant_id;
    let store_id = entries[0].public_inputs.store_id;
    let num_events = entries.len();
    let metadata = BatchMetadata::with_ids(
        Uuid::new_v4(),
        tenant_id,
        store_id,
        0,
        (num_events - 1) as u64,
    );

    let mut builder = BatchWitnessBuilder::new()
        .metadata(metadata)
        .policy_hash(policy_hash)
        .policy_limit(policy_limit);

    for (i, entry) in entries.into_iter().enumerate() {
        builder = match builder.add_event(entry.amount, entry.public_inputs) {
            Ok(b) => b,
            Err(e) => {
                set_last_error(format!("Failed to add event {}: {}", i, e));
                return VES_ERR_INVALID_ARG;
            }
        };
    }

    let witness = match builder.build() {
        Ok(w) => w,
        Err(e) => {
            set_last_error(format!("Failed to build batch witness: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    // Generate proof
    let prover = BatchProver::new();
    let (proof, _state_root) = match prover.prove_and_get_root(&witness) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("Batch proof generation failed: {}", e));
            return VES_ERR_PROOF_FAILED;
        }
    };

    // Build public inputs for serialization
    let new_state_root = match witness.compute_new_state_root() {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("Failed to compute new state root: {}", e));
            return VES_ERR_PROOF_FAILED;
        }
    };
    let accumulator = match witness.public_inputs_accumulator() {
        Ok(a) => a,
        Err(e) => {
            set_last_error(format!("Failed to compute accumulator: {}", e));
            return VES_ERR_PROOF_FAILED;
        }
    };
    let batch_public_inputs = ves_stark_batch::BatchPublicInputs::new(
        witness.prev_state_root.root,
        new_state_root.root,
        witness.batch_id_felts(),
        witness.tenant_id_felts(),
        witness.store_id_felts(),
        witness.metadata.sequence_start,
        witness.metadata.sequence_end,
        0, // timestamp
        witness.num_events(),
        witness.all_compliant(),
        policy_kind,
        policy_limit,
        accumulator,
    );

    let serializable = match SerializableBatchProof::new(proof.clone(), batch_public_inputs) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("Failed to serialize batch proof: {}", e));
            return VES_ERR_JSON;
        }
    };
    let json = match serializable.to_json() {
        Ok(j) => j,
        Err(e) => {
            set_last_error(format!("Failed to serialize batch proof JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let batch_proof = Box::new(VesBatchProof {
        proof_bytes: proof.proof_bytes.clone(),
        proof_hash: CString::new(proof.proof_hash.clone()).unwrap(),
        prev_state_root: proof.prev_state_root,
        new_state_root: proof.new_state_root,
        num_events: proof.metadata.num_events,
        all_compliant: proof.metadata.all_compliant,
        proving_time_ms: proof.metadata.proving_time_ms,
        proof_size: proof.metadata.proof_size,
        serialized_json: CString::new(json).unwrap(),
    });

    unsafe { *out_proof = Box::into_raw(batch_proof) };
    VES_OK
}

/// Returns the batch proof hash as a NUL-terminated string.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle. The
/// returned string borrows memory owned by `proof` and is valid only until it
/// is freed.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_hash(proof: *const VesBatchProof) -> *const c_char {
    if proof.is_null() {
        return std::ptr::null();
    }
    unsafe { &*proof }.proof_hash.as_ptr()
}

/// Returns the serialized batch proof JSON as a NUL-terminated string.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle. The
/// returned string borrows memory owned by `proof` and is valid only until it
/// is freed.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_json(proof: *const VesBatchProof) -> *const c_char {
    if proof.is_null() {
        return std::ptr::null();
    }
    unsafe { &*proof }.serialized_json.as_ptr()
}

/// Get the raw batch proof bytes pointer and length.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle. `out_len`
/// must be NULL or a valid, writable `*mut usize`. The returned pointer borrows
/// memory owned by `proof` and is valid only until `proof` is freed.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_bytes(
    proof: *const VesBatchProof,
    out_len: *mut usize,
) -> *const u8 {
    if proof.is_null() {
        // See `ves_proof_bytes`: the length must be zeroed on the NULL path
        // so a caller cannot pair a NULL pointer with a stale length.
        if !out_len.is_null() {
            unsafe { *out_len = 0 };
        }
        return std::ptr::null();
    }
    let p = unsafe { &*proof };
    if !out_len.is_null() {
        unsafe { *out_len = p.proof_bytes.len() };
    }
    p.proof_bytes.as_ptr()
}

/// Returns the batch proof size in bytes.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_size(proof: *const VesBatchProof) -> usize {
    if proof.is_null() {
        return 0;
    }
    unsafe { &*proof }.proof_size
}

/// Write the previous state root (4 x u64) into `out`.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle. `out` must
/// be NULL or a valid, writable pointer to an array of at least 4 `u64` values.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_prev_state_root(
    proof: *const VesBatchProof,
    out: *mut u64,
) -> i32 {
    if proof.is_null() || out.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }
    let p = unsafe { &*proof };
    let out_slice = unsafe { slice::from_raw_parts_mut(out, 4) };
    out_slice.copy_from_slice(&p.prev_state_root);
    VES_OK
}

/// Write the new state root (4 x u64) into `out`.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle. `out` must
/// be NULL or a valid, writable pointer to an array of at least 4 `u64` values.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_new_state_root(
    proof: *const VesBatchProof,
    out: *mut u64,
) -> i32 {
    if proof.is_null() || out.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }
    let p = unsafe { &*proof };
    let out_slice = unsafe { slice::from_raw_parts_mut(out, 4) };
    out_slice.copy_from_slice(&p.new_state_root);
    VES_OK
}

/// Returns the number of events in the batch proof.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_num_events(proof: *const VesBatchProof) -> usize {
    if proof.is_null() {
        return 0;
    }
    unsafe { &*proof }.num_events
}

/// Returns whether all events in the batch are compliant.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_all_compliant(proof: *const VesBatchProof) -> bool {
    if proof.is_null() {
        return false;
    }
    unsafe { &*proof }.all_compliant
}

/// Returns the batch proving time in milliseconds.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesBatchProof`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_proving_time_ms(proof: *const VesBatchProof) -> u64 {
    if proof.is_null() {
        return 0;
    }
    unsafe { &*proof }.proving_time_ms
}

/// Free a batch proof handle.
///
/// # Safety
/// `proof` must be NULL or a handle previously returned by
/// [`ves_batch_prove_json`] that has not already been freed. After this call the
/// pointer is dangling and must not be used again (no double-free).
#[no_mangle]
pub unsafe extern "C" fn ves_batch_proof_free(proof: *mut VesBatchProof) {
    if !proof.is_null() {
        drop(unsafe { Box::from_raw(proof) });
    }
}

/// Verify a batch proof from its serialized JSON.
///
/// # Safety
/// `proof_json` must be a valid NUL-terminated C string. `out_result` must be a
/// valid, writable `*mut *mut VesBatchVerificationResult`; on success it receives
/// a handle that must be released with [`ves_batch_verification_result_free`].
/// `out_result` may be NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verify_json(
    proof_json: *const c_char,
    out_result: *mut *mut VesBatchVerificationResult,
) -> i32 {
    if out_result.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let json_str = match unsafe { cstr_to_str(proof_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let batch_file = match SerializableBatchProof::from_json(json_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Invalid batch proof JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let pi = match batch_file.to_batch_public_inputs() {
        Ok(p) => p,
        Err(e) => {
            set_last_error(format!("Failed to extract batch public inputs: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let verifier = match BatchVerifier::try_new() {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Failed to create batch verifier: {}", e));
            return VES_ERR_VERIFY_FAILED;
        }
    };

    let result = match verifier.verify(&batch_file.proof.proof_bytes, &pi) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("Batch verification error: {}", e));
            return VES_ERR_VERIFY_FAILED;
        }
    };

    let vr = Box::new(VesBatchVerificationResult {
        valid: result.valid,
        verification_time_ms: result.verification_time_ms,
        error: result.error.and_then(|s| CString::new(s).ok()),
        prev_state_root: result.prev_state_root,
        new_state_root: result.new_state_root,
        num_events: result.num_events,
        all_compliant: result.all_compliant,
    });

    unsafe { *out_result = Box::into_raw(vr) };
    VES_OK
}

/// Returns whether the batch verification succeeded.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesBatchVerificationResult`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_valid(
    result: *const VesBatchVerificationResult,
) -> bool {
    if result.is_null() {
        return false;
    }
    unsafe { &*result }.valid
}

/// Returns the batch verification time in milliseconds.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesBatchVerificationResult`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_time_ms(
    result: *const VesBatchVerificationResult,
) -> u64 {
    if result.is_null() {
        return 0;
    }
    unsafe { &*result }.verification_time_ms
}

/// Returns the number of events covered by the verified batch.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesBatchVerificationResult`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_num_events(
    result: *const VesBatchVerificationResult,
) -> usize {
    if result.is_null() {
        return 0;
    }
    unsafe { &*result }.num_events
}

/// Returns whether all events in the verified batch are compliant.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesBatchVerificationResult`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_all_compliant(
    result: *const VesBatchVerificationResult,
) -> bool {
    if result.is_null() {
        return false;
    }
    unsafe { &*result }.all_compliant
}

/// Returns the batch verification error message, or NULL if there is none.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesBatchVerificationResult`] handle.
/// The returned string borrows memory owned by `result` and is valid only until
/// it is freed.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_error(
    result: *const VesBatchVerificationResult,
) -> *const c_char {
    if result.is_null() {
        return std::ptr::null();
    }
    unsafe { &*result }
        .error
        .as_ref()
        .map_or(std::ptr::null(), |s| s.as_ptr())
}

/// Write the verified batch's previous state root (4 x u64) into `out`.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesBatchVerificationResult`] handle.
/// `out` must be NULL or a valid, writable pointer to an array of at least 4 `u64`.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_prev_state_root(
    result: *const VesBatchVerificationResult,
    out: *mut u64,
) -> i32 {
    if result.is_null() || out.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }
    let r = unsafe { &*result };
    let out_slice = unsafe { slice::from_raw_parts_mut(out, 4) };
    out_slice.copy_from_slice(&r.prev_state_root);
    VES_OK
}

/// Write the verified batch's new state root (4 x u64) into `out`.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesBatchVerificationResult`] handle.
/// `out` must be NULL or a valid, writable pointer to an array of at least 4 `u64`.
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_new_state_root(
    result: *const VesBatchVerificationResult,
    out: *mut u64,
) -> i32 {
    if result.is_null() || out.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }
    let r = unsafe { &*result };
    let out_slice = unsafe { slice::from_raw_parts_mut(out, 4) };
    out_slice.copy_from_slice(&r.new_state_root);
    VES_OK
}

/// Free a batch verification result handle.
///
/// # Safety
/// `result` must be NULL or a handle previously returned by
/// [`ves_batch_verify_json`] that has not already been freed. After this call the
/// pointer is dangling and must not be used again (no double-free).
#[no_mangle]
pub unsafe extern "C" fn ves_batch_verification_result_free(
    result: *mut VesBatchVerificationResult,
) {
    if !result.is_null() {
        drop(unsafe { Box::from_raw(result) });
    }
}
