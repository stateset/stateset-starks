//! C FFI bindings for VES STARK proof system.
//!
//! This crate exposes the STARK prover/verifier as a C-compatible static library
//! for consumption by the Zig client (and any other C-ABI-compatible language).

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;

use uuid::Uuid;

use ves_stark_air::Policy;
use ves_stark_primitives::{
    witness_commitment_hex_to_u64, CommerceAuthorizationReceipt, CompliancePublicInputs,
    PayloadAmountBinding, PolicyParams,
};
use ves_stark_prover::{ComplianceProver, ComplianceWitness};
use ves_stark_verifier::{
    verify_agent_authorization_proof_auto_with_amount_binding, verify_compliance_proof_auto_bound,
    verify_compliance_proof_auto_with_amount_binding,
};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const VES_OK: i32 = 0;
pub const VES_ERR_INVALID_ARG: i32 = -1;
pub const VES_ERR_PROOF_FAILED: i32 = -2;
pub const VES_ERR_VERIFY_FAILED: i32 = -3;
pub const VES_ERR_JSON: i32 = -4;
pub const VES_ERR_NULL_PTR: i32 = -5;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: String) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = CString::new(msg).ok();
    });
}

/// Get the last error message. Returns NULL if no error.
/// The returned pointer is valid until the next FFI call on the same thread.
#[no_mangle]
pub extern "C" fn ves_stark_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        cell.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr())
    })
}

// ---------------------------------------------------------------------------
// Opaque handles
// ---------------------------------------------------------------------------

/// Opaque handle to CompliancePublicInputs.
pub struct VesPublicInputs {
    inner: CompliancePublicInputs,
}

/// Opaque handle to a generated proof.
pub struct VesProof {
    proof_bytes: Vec<u8>,
    proof_hash: CString,
    proving_time_ms: u64,
    proof_size: usize,
    witness_commitment: [u64; 4],
    witness_commitment_hex: CString,
}

/// Opaque handle to a verification result.
pub struct VesVerificationResult {
    valid: bool,
    verification_time_ms: u64,
    error: Option<CString>,
    policy_id: CString,
    policy_limit: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    if ptr.is_null() {
        set_last_error("null string pointer".into());
        return Err(VES_ERR_NULL_PTR);
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|e| {
        set_last_error(format!("Invalid UTF-8 string: {}", e));
        VES_ERR_INVALID_ARG
    })
}

fn parse_public_inputs_json(json: &str) -> Result<CompliancePublicInputs, i32> {
    // First try serde deserialization (handles camelCase from Rust serialization)
    if let Ok(inputs) = serde_json::from_str::<CompliancePublicInputs>(json) {
        return Ok(inputs);
    }

    // Fallback: try manual snake_case parsing for Zig/Python/JS-style JSON
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        set_last_error(format!("Invalid public inputs JSON: {}", e));
        VES_ERR_JSON
    })?;

    let obj = v.as_object().ok_or_else(|| {
        set_last_error("Public inputs JSON must be an object".into());
        VES_ERR_JSON
    })?;

    let get_str = |key: &str| -> Result<String, i32> {
        obj.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                set_last_error(format!("Missing or invalid field: {}", key));
                VES_ERR_INVALID_ARG
            })
    };

    let get_uuid = |key: &str| -> Result<Uuid, i32> {
        let s = get_str(key)?;
        Uuid::parse_str(&s).map_err(|e| {
            set_last_error(format!("Invalid UUID for {}: {}", key, e));
            VES_ERR_INVALID_ARG
        })
    };

    let event_id = get_uuid("event_id")?;
    let tenant_id = get_uuid("tenant_id")?;
    let store_id = get_uuid("store_id")?;

    let sequence_number = obj
        .get("sequence_number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            set_last_error("Missing or invalid field: sequence_number".into());
            VES_ERR_INVALID_ARG
        })?;

    let payload_kind = obj
        .get("payload_kind")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| {
            set_last_error("Missing or invalid field: payload_kind".into());
            VES_ERR_INVALID_ARG
        })?;

    let policy_params_value = obj.get("policy_params").cloned().ok_or_else(|| {
        set_last_error("Missing field: policy_params".into());
        VES_ERR_INVALID_ARG
    })?;

    let witness_commitment = obj
        .get("witness_commitment")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let authorization_receipt_hash = obj
        .get("authorization_receipt_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let amount_binding_hash = obj
        .get("amount_binding_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(CompliancePublicInputs {
        event_id,
        tenant_id,
        store_id,
        sequence_number,
        payload_kind,
        payload_plain_hash: get_str("payload_plain_hash")?,
        payload_cipher_hash: get_str("payload_cipher_hash")?,
        event_signing_hash: get_str("event_signing_hash")?,
        policy_id: get_str("policy_id")?,
        policy_params: PolicyParams(policy_params_value),
        policy_hash: get_str("policy_hash")?,
        witness_commitment,
        authorization_receipt_hash,
        amount_binding_hash,
    })
}

// ---------------------------------------------------------------------------
// Public Inputs
// ---------------------------------------------------------------------------

/// Create public inputs from a JSON string.
///
/// Returns NULL on error (check `ves_stark_last_error()`).
#[no_mangle]
pub unsafe extern "C" fn ves_public_inputs_from_json(json: *const c_char) -> *mut VesPublicInputs {
    let json_str = match unsafe { cstr_to_str(json) } {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match parse_public_inputs_json(json_str) {
        Ok(inner) => Box::into_raw(Box::new(VesPublicInputs { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Serialize public inputs to a JSON string.
/// The returned string must be freed with `ves_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn ves_public_inputs_to_json(
    inputs: *const VesPublicInputs,
    out_json: *mut *mut c_char,
) -> i32 {
    if inputs.is_null() || out_json.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let rust_inputs = &unsafe { &*inputs }.inner;
    let json = match serde_json::to_string(rust_inputs) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(format!("Failed to serialize public inputs: {}", e));
            return VES_ERR_JSON;
        }
    };

    let cstring = CString::new(json).unwrap();
    unsafe { *out_json = cstring.into_raw() };
    VES_OK
}

/// Free public inputs.
#[no_mangle]
pub unsafe extern "C" fn ves_public_inputs_free(inputs: *mut VesPublicInputs) {
    if !inputs.is_null() {
        drop(unsafe { Box::from_raw(inputs) });
    }
}

// ---------------------------------------------------------------------------
// Proof Generation
// ---------------------------------------------------------------------------

/// Generate a STARK compliance proof.
///
/// `policy_type`: one of "aml.threshold", "order_total.cap", "agent.authorization.v1"
///
/// On success, `*out_proof` is set to a new proof handle. Free with `ves_proof_free()`.
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

// ---------------------------------------------------------------------------
// Proof Accessors
// ---------------------------------------------------------------------------

/// Get proof bytes pointer and length.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_bytes(proof: *const VesProof, out_len: *mut usize) -> *const u8 {
    if proof.is_null() {
        return std::ptr::null();
    }
    let p = unsafe { &*proof };
    if !out_len.is_null() {
        unsafe { *out_len = p.proof_bytes.len() };
    }
    p.proof_bytes.as_ptr()
}

/// Get proof hash as a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_hash(proof: *const VesProof) -> *const c_char {
    if proof.is_null() {
        return std::ptr::null();
    }
    unsafe { &*proof }.proof_hash.as_ptr()
}

/// Get proving time in milliseconds.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_proving_time_ms(proof: *const VesProof) -> u64 {
    if proof.is_null() {
        return 0;
    }
    unsafe { &*proof }.proving_time_ms
}

/// Get proof size in bytes.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_size(proof: *const VesProof) -> usize {
    if proof.is_null() {
        return 0;
    }
    unsafe { &*proof }.proof_size
}

/// Get witness commitment as 4 x u64.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_witness_commitment(
    proof: *const VesProof,
    out: *mut u64,
) -> i32 {
    if proof.is_null() || out.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }
    let p = unsafe { &*proof };
    let out_slice = unsafe { slice::from_raw_parts_mut(out, 4) };
    out_slice.copy_from_slice(&p.witness_commitment);
    VES_OK
}

/// Get witness commitment as hex string (64 chars).
#[no_mangle]
pub unsafe extern "C" fn ves_proof_witness_commitment_hex(proof: *const VesProof) -> *const c_char {
    if proof.is_null() {
        return std::ptr::null();
    }
    unsafe { &*proof }.witness_commitment_hex.as_ptr()
}

/// Free a proof handle.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_free(proof: *mut VesProof) {
    if !proof.is_null() {
        drop(unsafe { Box::from_raw(proof) });
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

fn do_verify_bound(
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

// ---------------------------------------------------------------------------
// Verification Result Accessors
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn ves_verification_valid(result: *const VesVerificationResult) -> bool {
    if result.is_null() {
        return false;
    }
    unsafe { &*result }.valid
}

#[no_mangle]
pub unsafe extern "C" fn ves_verification_time_ms(result: *const VesVerificationResult) -> u64 {
    if result.is_null() {
        return 0;
    }
    unsafe { &*result }.verification_time_ms
}

/// Returns NULL if there is no error message.
#[no_mangle]
pub unsafe extern "C" fn ves_verification_error(
    result: *const VesVerificationResult,
) -> *const c_char {
    if result.is_null() {
        return std::ptr::null();
    }
    unsafe { &*result }
        .error
        .as_ref()
        .map_or(std::ptr::null(), |s| s.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn ves_verification_policy_id(
    result: *const VesVerificationResult,
) -> *const c_char {
    if result.is_null() {
        return std::ptr::null();
    }
    unsafe { &*result }.policy_id.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn ves_verification_policy_limit(
    result: *const VesVerificationResult,
) -> u64 {
    if result.is_null() {
        return 0;
    }
    unsafe { &*result }.policy_limit
}

#[no_mangle]
pub unsafe extern "C" fn ves_verification_result_free(result: *mut VesVerificationResult) {
    if !result.is_null() {
        drop(unsafe { Box::from_raw(result) });
    }
}

// ---------------------------------------------------------------------------
// Policy Helpers
// ---------------------------------------------------------------------------

/// Compute the policy hash. On success, `*out_hash` is set to a new string. Free with `ves_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn ves_compute_policy_hash(
    policy_id: *const c_char,
    policy_params_json: *const c_char,
    out_hash: *mut *mut c_char,
) -> i32 {
    if out_hash.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let policy_id_str = match unsafe { cstr_to_str(policy_id) } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let params_str = match unsafe { cstr_to_str(policy_params_json) } {
        Ok(s) => s,
        Err(e) => return e,
    };

    let params_value: serde_json::Value = match serde_json::from_str(params_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(format!("Invalid policy params JSON: {}", e));
            return VES_ERR_JSON;
        }
    };

    let hash =
        match ves_stark_primitives::compute_policy_hash(policy_id_str, &PolicyParams(params_value))
        {
            Ok(h) => h,
            Err(e) => {
                set_last_error(format!("Failed to compute policy hash: {}", e));
                return VES_ERR_INVALID_ARG;
            }
        };

    let hash_cstring = CString::new(hash.to_hex()).unwrap();
    unsafe { *out_hash = hash_cstring.into_raw() };
    VES_OK
}

/// Create a canonical payload amount binding (returned as JSON string).
/// Free the result with `ves_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn ves_create_payload_amount_binding(
    inputs: *const VesPublicInputs,
    amount: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    if inputs.is_null() || out_json.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let rust_inputs = &unsafe { &*inputs }.inner;

    let binding = match rust_inputs.payload_amount_binding(amount) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(format!("Invalid payload amount binding inputs: {}", e));
            return VES_ERR_INVALID_ARG;
        }
    };

    let json_str = match serde_json::to_string(&binding) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("Failed to serialize binding: {}", e));
            return VES_ERR_JSON;
        }
    };

    let cstring = CString::new(json_str).unwrap();
    unsafe { *out_json = cstring.into_raw() };
    VES_OK
}

// ---------------------------------------------------------------------------
// Proof Inspection
// ---------------------------------------------------------------------------

/// Inspect proof bytes and return metadata as JSON.
///
/// Returns a JSON object with: proofHash, proofSize, domainHash.
/// Free the result with `ves_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_inspect(
    proof_bytes_ptr: *const u8,
    proof_len: usize,
    out_json: *mut *mut c_char,
) -> i32 {
    if proof_bytes_ptr.is_null() || out_json.is_null() {
        set_last_error("null pointer argument".into());
        return VES_ERR_NULL_PTR;
    }

    let proof_bytes = unsafe { slice::from_raw_parts(proof_bytes_ptr, proof_len) };

    // Compute domain-separated proof hash (same as Rust prover)
    let hash = ves_stark_primitives::Hash256::sha256_with_domain(
        b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1",
        proof_bytes,
    );

    let json = serde_json::json!({
        "proofHash": hash.to_hex(),
        "proofSize": proof_len,
        "proofVersion": ves_stark_verifier::PROOF_VERSION,
        "maxProofSize": ves_stark_verifier::MAX_PROOF_SIZE,
    });

    let json_str = serde_json::to_string(&json).unwrap();
    let cstring = CString::new(json_str).unwrap();
    unsafe { *out_json = cstring.into_raw() };
    VES_OK
}

// ---------------------------------------------------------------------------
// Batch Proof (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "batch")]
mod batch_ffi {
    use super::*;
    use ves_stark_batch::{
        BatchMetadata, BatchPolicyKind, BatchProver, BatchVerifier, BatchWitnessBuilder,
        SerializableBatchProof,
    };
    use ves_stark_primitives::{hash_to_felts, Hash256};

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
        let policy_hash_obj =
            match ves_stark_primitives::compute_policy_hash(policy_type_str, params) {
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
        use ves_stark_primitives::{felt_from_u64, Felt, FELT_ONE, FELT_ZERO};
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

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_proof_hash(proof: *const VesBatchProof) -> *const c_char {
        if proof.is_null() {
            return std::ptr::null();
        }
        unsafe { &*proof }.proof_hash.as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_proof_json(proof: *const VesBatchProof) -> *const c_char {
        if proof.is_null() {
            return std::ptr::null();
        }
        unsafe { &*proof }.serialized_json.as_ptr()
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_proof_num_events(proof: *const VesBatchProof) -> usize {
        if proof.is_null() {
            return 0;
        }
        unsafe { &*proof }.num_events
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_proof_all_compliant(proof: *const VesBatchProof) -> bool {
        if proof.is_null() {
            return false;
        }
        unsafe { &*proof }.all_compliant
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_proof_proving_time_ms(proof: *const VesBatchProof) -> u64 {
        if proof.is_null() {
            return 0;
        }
        unsafe { &*proof }.proving_time_ms
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_proof_free(proof: *mut VesBatchProof) {
        if !proof.is_null() {
            drop(unsafe { Box::from_raw(proof) });
        }
    }

    /// Verify a batch proof from its serialized JSON.
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

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_verification_valid(
        result: *const VesBatchVerificationResult,
    ) -> bool {
        if result.is_null() {
            return false;
        }
        unsafe { &*result }.valid
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_verification_time_ms(
        result: *const VesBatchVerificationResult,
    ) -> u64 {
        if result.is_null() {
            return 0;
        }
        unsafe { &*result }.verification_time_ms
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_verification_num_events(
        result: *const VesBatchVerificationResult,
    ) -> usize {
        if result.is_null() {
            return 0;
        }
        unsafe { &*result }.num_events
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_verification_all_compliant(
        result: *const VesBatchVerificationResult,
    ) -> bool {
        if result.is_null() {
            return false;
        }
        unsafe { &*result }.all_compliant
    }

    #[no_mangle]
    pub unsafe extern "C" fn ves_batch_verification_result_free(
        result: *mut VesBatchVerificationResult,
    ) {
        if !result.is_null() {
            drop(unsafe { Box::from_raw(result) });
        }
    }
}

/// Free a string allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn ves_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}
