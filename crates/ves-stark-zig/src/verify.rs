//! Verify — one section of the C API. See lib.rs.

use super::*;

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

pub(crate) fn do_verify_bound(
    proof_bytes: &[u8],
    inputs: &CompliancePublicInputs,
    commitment: &[u64; 4],
) -> Result<VesVerificationResult, i32> {
    let bound_inputs = inputs
        .clone()
        .bind_witness_commitment(commitment)
        .map_err(|e| {
            set_last_error(format!("Failed to bind witness commitment: {}", e));
            VES_ERR_INVALID_ARG
        })?;

    let result = verify_compliance_proof_auto_bound(proof_bytes, &bound_inputs).map_err(|e| {
        set_last_error(format!("Verification error: {}", e));
        VES_ERR_VERIFY_FAILED
    })?;

    Ok(VesVerificationResult {
        valid: result.valid,
        verification_time_ms: result.verification_time_ms,
        error: result.error.and_then(|s| CString::new(s).ok()),
        policy_id: CString::new(result.policy_id).unwrap(),
        policy_limit: result.policy_limit,
    })
}

/// Verify a STARK compliance proof with witness commitment (4 x u64).
///
/// # Safety
/// `proof_bytes_ptr` must point to at least `proof_len` readable bytes. `inputs`
/// must be a valid, unfreed [`VesPublicInputs`] handle. `witness_commitment` must
/// point to at least 4 readable `u64` values. `out_result` must be a valid,
/// writable `*mut *mut VesVerificationResult`; on success it receives a handle
/// that must be released with [`ves_verification_result_free`]. Any of these
/// pointers may be NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_verify(
    proof_bytes_ptr: *const u8,
    proof_len: usize,
    inputs: *const VesPublicInputs,
    witness_commitment: *const u64,
    out_result: *mut *mut VesVerificationResult,
) -> i32 {
    if proof_bytes_ptr.is_null()
        || inputs.is_null()
        || witness_commitment.is_null()
        || out_result.is_null()
    {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let proof_bytes = unsafe { slice::from_raw_parts(proof_bytes_ptr, proof_len) };
    let rust_inputs = &unsafe { &*inputs }.inner;
    let commitment_slice = unsafe { slice::from_raw_parts(witness_commitment, 4) };
    let commitment: [u64; 4] = [
        commitment_slice[0],
        commitment_slice[1],
        commitment_slice[2],
        commitment_slice[3],
    ];

    match do_verify_bound(proof_bytes, rust_inputs, &commitment) {
        Ok(result) => {
            unsafe { *out_result = Box::into_raw(Box::new(result)) };
            VES_OK
        }
        Err(e) => e,
    }
}

/// Verify a STARK compliance proof with witness commitment as hex string.
///
/// # Safety
/// `proof_bytes_ptr` must point to at least `proof_len` readable bytes. `inputs`
/// must be a valid, unfreed [`VesPublicInputs`] handle. `witness_commitment_hex`
/// must be a valid NUL-terminated C string. `out_result` must be a valid, writable
/// `*mut *mut VesVerificationResult`; on success it receives a handle that must be
/// released with [`ves_verification_result_free`]. The required pointers may be
/// NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_verify_hex(
    proof_bytes_ptr: *const u8,
    proof_len: usize,
    inputs: *const VesPublicInputs,
    witness_commitment_hex: *const c_char,
    out_result: *mut *mut VesVerificationResult,
) -> i32 {
    if proof_bytes_ptr.is_null() || inputs.is_null() || out_result.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let hex_str = match unsafe { cstr_to_str(witness_commitment_hex) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let commitment = match witness_commitment_hex_to_u64(hex_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("Invalid witness commitment hex: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let proof_bytes = unsafe { slice::from_raw_parts(proof_bytes_ptr, proof_len) };
    let rust_inputs = &unsafe { &*inputs }.inner;

    match do_verify_bound(proof_bytes, rust_inputs, &commitment) {
        Ok(result) => {
            unsafe { *out_result = Box::into_raw(Box::new(result)) };
            VES_OK
        }
        Err(e) => e,
    }
}

/// Verify a STARK compliance proof against a canonical payload amount binding (JSON).
///
/// # Safety
/// `proof_bytes_ptr` must point to at least `proof_len` readable bytes. `inputs`
/// must be a valid, unfreed [`VesPublicInputs`] handle. `amount_binding_json` must
/// be a valid NUL-terminated C string. `out_result` must be a valid, writable
/// `*mut *mut VesVerificationResult`; on success it receives a handle that must be
/// released with [`ves_verification_result_free`]. The required pointers may be
/// NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_verify_with_amount_binding(
    proof_bytes_ptr: *const u8,
    proof_len: usize,
    inputs: *const VesPublicInputs,
    amount_binding_json: *const c_char,
    out_result: *mut *mut VesVerificationResult,
) -> i32 {
    if proof_bytes_ptr.is_null() || inputs.is_null() || out_result.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let binding_str = match unsafe { cstr_to_str(amount_binding_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let binding: PayloadAmountBinding = match serde_json::from_str(binding_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Invalid amount binding JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let proof_bytes = unsafe { slice::from_raw_parts(proof_bytes_ptr, proof_len) };
    let rust_inputs = &unsafe { &*inputs }.inner;

    let result =
        verify_compliance_proof_auto_with_amount_binding(proof_bytes, rust_inputs, &binding);

    match result {
        Ok(verification) => {
            let vr = VesVerificationResult {
                valid: verification.valid,
                verification_time_ms: verification.verification_time_ms,
                error: verification.error.and_then(|s| CString::new(s).ok()),
                policy_id: CString::new(verification.policy_id).unwrap(),
                policy_limit: verification.policy_limit,
            };
            unsafe { *out_result = Box::into_raw(Box::new(vr)) };
            VES_OK
        }
        Err(e) => {
            set_last_error(format!("Verification error: {}", e));
            VES_ERR_VERIFY_FAILED
        }
    }
}

/// Verify an agent.authorization.v1 proof with witness commitment (4 x u64).
///
/// # Safety
/// `proof_bytes_ptr` must point to at least `proof_len` readable bytes. `inputs`
/// must be a valid, unfreed [`VesPublicInputs`] handle. `witness_commitment` must
/// point to at least 4 readable `u64` values. `receipt_json` must be a valid
/// NUL-terminated C string. `out_result` must be a valid, writable
/// `*mut *mut VesVerificationResult`; on success it receives a handle that must be
/// released with [`ves_verification_result_free`]. The required pointers may be
/// NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_verify_agent_authorization(
    proof_bytes_ptr: *const u8,
    proof_len: usize,
    inputs: *const VesPublicInputs,
    witness_commitment: *const u64,
    receipt_json: *const c_char,
    out_result: *mut *mut VesVerificationResult,
) -> i32 {
    if proof_bytes_ptr.is_null()
        || inputs.is_null()
        || witness_commitment.is_null()
        || out_result.is_null()
    {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let receipt_str = match unsafe { cstr_to_str(receipt_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let receipt: CommerceAuthorizationReceipt = match serde_json::from_str(receipt_str) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("Invalid receipt JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let proof_bytes = unsafe { slice::from_raw_parts(proof_bytes_ptr, proof_len) };
    let rust_inputs = &unsafe { &*inputs }.inner;
    let commitment_slice = unsafe { slice::from_raw_parts(witness_commitment, 4) };
    let commitment: [u64; 4] = [
        commitment_slice[0],
        commitment_slice[1],
        commitment_slice[2],
        commitment_slice[3],
    ];

    let bound_inputs = match rust_inputs.clone().bind_witness_commitment(&commitment) {
        Ok(i) => i,
        Err(e) => {
            set_last_error(format!("Failed to bind witness commitment: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let binding = match bound_inputs.payload_amount_binding(receipt.amount) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Failed to compute amount binding: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        proof_bytes,
        &bound_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => {
            let vr = VesVerificationResult {
                valid: verification.valid,
                verification_time_ms: verification.verification_time_ms,
                error: verification.error.and_then(|s| CString::new(s).ok()),
                policy_id: CString::new(verification.policy_id).unwrap(),
                policy_limit: verification.policy_limit,
            };
            unsafe { *out_result = Box::into_raw(Box::new(vr)) };
            VES_OK
        }
        Err(e) => {
            set_last_error(format!("Verification error: {}", e));
            VES_ERR_VERIFY_FAILED
        }
    }
}

/// Verify an agent.authorization.v1 proof with witness commitment as hex.
///
/// # Safety
/// `proof_bytes_ptr` must point to at least `proof_len` readable bytes. `inputs`
/// must be a valid, unfreed [`VesPublicInputs`] handle. `witness_commitment_hex`
/// and `receipt_json` must each be a valid NUL-terminated C string. `out_result`
/// must be a valid, writable `*mut *mut VesVerificationResult`; on success it
/// receives a handle that must be released with [`ves_verification_result_free`].
/// The required pointers may be NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_verify_agent_authorization_hex(
    proof_bytes_ptr: *const u8,
    proof_len: usize,
    inputs: *const VesPublicInputs,
    witness_commitment_hex: *const c_char,
    receipt_json: *const c_char,
    out_result: *mut *mut VesVerificationResult,
) -> i32 {
    if proof_bytes_ptr.is_null() || inputs.is_null() || out_result.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let hex_str = match unsafe { cstr_to_str(witness_commitment_hex) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let commitment = match witness_commitment_hex_to_u64(hex_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("Invalid witness commitment hex: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let receipt_str = match unsafe { cstr_to_str(receipt_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let receipt: CommerceAuthorizationReceipt = match serde_json::from_str(receipt_str) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("Invalid receipt JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let proof_bytes = unsafe { slice::from_raw_parts(proof_bytes_ptr, proof_len) };
    let rust_inputs = &unsafe { &*inputs }.inner;

    let bound_inputs = match rust_inputs.clone().bind_witness_commitment(&commitment) {
        Ok(i) => i,
        Err(e) => {
            set_last_error(format!("Failed to bind witness commitment: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let binding = match bound_inputs.payload_amount_binding(receipt.amount) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Failed to compute amount binding: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        proof_bytes,
        &bound_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => {
            let vr = VesVerificationResult {
                valid: verification.valid,
                verification_time_ms: verification.verification_time_ms,
                error: verification.error.and_then(|s| CString::new(s).ok()),
                policy_id: CString::new(verification.policy_id).unwrap(),
                policy_limit: verification.policy_limit,
            };
            unsafe { *out_result = Box::into_raw(Box::new(vr)) };
            VES_OK
        }
        Err(e) => {
            set_last_error(format!("Verification error: {}", e));
            VES_ERR_VERIFY_FAILED
        }
    }
}

/// Verify an agent.authorization.v1 proof against both amount binding and receipt (JSON).
///
/// # Safety
/// `proof_bytes_ptr` must point to at least `proof_len` readable bytes. `inputs`
/// must be a valid, unfreed [`VesPublicInputs`] handle. `amount_binding_json` and
/// `receipt_json` must each be a valid NUL-terminated C string. `out_result` must
/// be a valid, writable `*mut *mut VesVerificationResult`; on success it receives a
/// handle that must be released with [`ves_verification_result_free`]. The required
/// pointers may be NULL (handled as an error).
#[no_mangle]
pub unsafe extern "C" fn ves_verify_agent_authorization_with_amount_binding(
    proof_bytes_ptr: *const u8,
    proof_len: usize,
    inputs: *const VesPublicInputs,
    amount_binding_json: *const c_char,
    receipt_json: *const c_char,
    out_result: *mut *mut VesVerificationResult,
) -> i32 {
    if proof_bytes_ptr.is_null() || inputs.is_null() || out_result.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let binding_str = match unsafe { cstr_to_str(amount_binding_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let receipt_str = match unsafe { cstr_to_str(receipt_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let binding: PayloadAmountBinding = match serde_json::from_str(binding_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Invalid amount binding JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let receipt: CommerceAuthorizationReceipt = match serde_json::from_str(receipt_str) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("Invalid receipt JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let proof_bytes = unsafe { slice::from_raw_parts(proof_bytes_ptr, proof_len) };
    let rust_inputs = &unsafe { &*inputs }.inner;

    let result = verify_agent_authorization_proof_auto_with_amount_binding(
        proof_bytes,
        rust_inputs,
        &binding,
        &receipt,
    );

    match result {
        Ok(verification) => {
            let vr = VesVerificationResult {
                valid: verification.valid,
                verification_time_ms: verification.verification_time_ms,
                error: verification.error.and_then(|s| CString::new(s).ok()),
                policy_id: CString::new(verification.policy_id).unwrap(),
                policy_limit: verification.policy_limit,
            };
            unsafe { *out_result = Box::into_raw(Box::new(vr)) };
            VES_OK
        }
        Err(e) => {
            set_last_error(format!("Verification error: {}", e));
            VES_ERR_VERIFY_FAILED
        }
    }
}
