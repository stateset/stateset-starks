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
    let rest_hash = obj
        .get("rest_hash")
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
        rest_hash,
    })
}

// The FFI surface is split by concern. Every `unsafe` block in the workspace
// lives in this crate, and one 1.7k-line file was where review attention went
// to die; each module below is one section of the C API. Helpers, error codes
// and the opaque handle types stay here because every module uses them.
#[cfg(feature = "batch")]
mod batch_ffi;
mod inspect;
mod policy;
mod proof_accessors;
mod prove;
mod public_inputs;
mod verification_result;
mod verify;

// The modules only talk to each other through `super::*` (helpers, handles,
// error codes); the glob re-exports exist so the test module can name every
// entry point without a path per module.
#[cfg(test)]
pub(crate) use {
    policy::*, proof_accessors::*, prove::*, public_inputs::*, verification_result::*, verify::*,
};

/// Free a string allocated by this library.
///
/// # Safety
/// `s` must be NULL or a string previously returned by one of this library's
/// functions (e.g. via an `out_json`/`out_hash` parameter) that has not already
/// been freed. Do not pass strings borrowed from a handle accessor, and do not
/// free the same pointer twice.
#[no_mangle]
pub unsafe extern "C" fn ves_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Tests for the C FFI boundary.
    //!
    //! This crate holds every `unsafe` block in the workspace (the other ten
    //! crates are `#![forbid(unsafe_code)]`), so it is where memory-safety bugs
    //! can live: null dereferences, mismatched allocate/free pairs, and strings
    //! handed across the boundary with the wrong ownership.
    //!
    //! The pointer-lifecycle tests below are written to run under Miri, which
    //! checks exactly those properties. Anything that generates or verifies a
    //! real STARK proof is `#[cfg_attr(miri, ignore)]` — sound, but far too slow
    //! to interpret.

    use super::*;
    use std::ffi::CString;

    /// A syntactically valid `CompliancePublicInputs` document.
    fn valid_public_inputs_json() -> CString {
        let zero_hash = "0".repeat(64);
        let params = ves_stark_primitives::public_inputs::PolicyParams::threshold(10_000);
        let policy_hash = ves_stark_primitives::compute_policy_hash("aml.threshold", &params)
            .expect("policy hash")
            .to_hex();
        let json = serde_json::json!({
            "eventId": uuid::Uuid::nil(),
            "tenantId": uuid::Uuid::nil(),
            "storeId": uuid::Uuid::nil(),
            "sequenceNumber": 1,
            "payloadKind": 1,
            "payloadPlainHash": zero_hash,
            "payloadCipherHash": zero_hash,
            "eventSigningHash": zero_hash,
            "policyId": "aml.threshold",
            "policyParams": { "threshold": 10_000 },
            "policyHash": policy_hash,
        });
        CString::new(json.to_string()).expect("no interior NUL")
    }

    /// Every entry point documented as NULL-tolerant must return an error
    /// rather than dereference. A regression here is a crash triggerable by any
    /// caller, in any language binding built on this ABI.
    #[test]
    fn null_pointers_are_rejected_not_dereferenced() {
        unsafe {
            assert!(ves_public_inputs_from_json(std::ptr::null()).is_null());

            let mut out: *mut c_char = std::ptr::null_mut();
            assert_eq!(
                ves_public_inputs_to_json(std::ptr::null(), &mut out),
                VES_ERR_NULL_PTR
            );

            // A valid handle with a NULL out-parameter must also be refused.
            let inputs = ves_public_inputs_from_json(valid_public_inputs_json().as_ptr());
            assert!(!inputs.is_null(), "fixture should parse");
            assert_eq!(
                ves_public_inputs_to_json(inputs, std::ptr::null_mut()),
                VES_ERR_NULL_PTR
            );
            ves_public_inputs_free(inputs);
        }
    }

    /// Accessors on a NULL handle must yield defined values, not read from
    /// address zero.
    #[test]
    fn proof_accessors_tolerate_a_null_handle() {
        unsafe {
            let mut len: usize = 12345;
            assert!(ves_proof_bytes(std::ptr::null(), &mut len).is_null());
            assert_eq!(len, 0, "length must be zeroed when no proof is available");

            assert!(ves_proof_hash(std::ptr::null()).is_null());
            assert_eq!(ves_proof_proving_time_ms(std::ptr::null()), 0);
            assert_eq!(ves_proof_size(std::ptr::null()), 0);
            assert!(ves_proof_witness_commitment_hex(std::ptr::null()).is_null());
        }
    }

    /// Regression: a NULL handle must also zero the out-length on the batch
    /// entry point, not only the single-proof one.
    #[cfg(feature = "batch")]
    #[test]
    fn batch_proof_bytes_zeroes_out_len_on_null_handle() {
        unsafe {
            let mut len: usize = 999;
            assert!(batch_ffi::ves_batch_proof_bytes(std::ptr::null(), &mut len).is_null());
            assert_eq!(len, 0, "length must be zeroed when no proof is available");
        }
    }

    /// Verification accessors must be equally defensive.
    #[test]
    fn verification_accessors_tolerate_a_null_handle() {
        unsafe {
            assert!(!ves_verification_valid(std::ptr::null()));
            assert_eq!(ves_verification_time_ms(std::ptr::null()), 0);
            assert_eq!(ves_verification_policy_limit(std::ptr::null()), 0);
        }
    }

    /// Freeing NULL is a documented no-op; C callers rely on it.
    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe {
            ves_public_inputs_free(std::ptr::null_mut());
            ves_proof_free(std::ptr::null_mut());
            ves_verification_result_free(std::ptr::null_mut());
            ves_free_string(std::ptr::null_mut());
        }
    }

    /// Full allocate/borrow/free cycle. Under Miri this checks that the handle
    /// is boxed and unboxed consistently and that the returned string is owned
    /// by the caller — a `CString::from_raw` / `into_raw` mismatch shows up here.
    #[test]
    fn public_inputs_round_trip_allocates_and_frees_cleanly() {
        unsafe {
            let handle = ves_public_inputs_from_json(valid_public_inputs_json().as_ptr());
            assert!(!handle.is_null(), "valid JSON must parse");

            let mut out: *mut c_char = std::ptr::null_mut();
            assert_eq!(ves_public_inputs_to_json(handle, &mut out), VES_OK);
            assert!(!out.is_null());

            let round_tripped = CStr::from_ptr(out).to_str().expect("valid UTF-8");
            assert!(
                round_tripped.contains("aml.threshold"),
                "serialized inputs should retain the policy id, got: {round_tripped}"
            );

            ves_free_string(out);
            ves_public_inputs_free(handle);
        }
    }

    /// Repeating the cycle catches allocator state corrupted by the first pass.
    #[test]
    fn repeated_round_trips_do_not_corrupt_allocator_state() {
        for _ in 0..8 {
            unsafe {
                let handle = ves_public_inputs_from_json(valid_public_inputs_json().as_ptr());
                assert!(!handle.is_null());
                let mut out: *mut c_char = std::ptr::null_mut();
                assert_eq!(ves_public_inputs_to_json(handle, &mut out), VES_OK);
                ves_free_string(out);
                ves_public_inputs_free(handle);
            }
        }
    }

    /// Malformed input must fail closed and leave a retrievable message rather
    /// than returning a partially built handle.
    #[test]
    fn invalid_json_returns_null_and_records_an_error() {
        unsafe {
            let bad = CString::new("{ not json").unwrap();
            assert!(ves_public_inputs_from_json(bad.as_ptr()).is_null());

            let err = ves_stark_last_error();
            assert!(!err.is_null(), "an error message must be recorded");
            let msg = CStr::from_ptr(err).to_str().expect("valid UTF-8");
            assert!(!msg.is_empty(), "error message must not be empty");
        }
    }

    /// Well-formed JSON that is not a valid public-inputs document must also be
    /// rejected, exercising the fallback parser's error path.
    #[test]
    fn structurally_valid_but_wrong_json_is_rejected() {
        unsafe {
            for doc in ["[]", "42", "\"a string\"", "{}"] {
                let c = CString::new(doc).unwrap();
                assert!(
                    ves_public_inputs_from_json(c.as_ptr()).is_null(),
                    "`{doc}` must not parse as public inputs"
                );
            }
        }
    }

    /// The policy-hash helper is pure and cheap, so it is a good Miri subject
    /// for the out-parameter string protocol.
    #[test]
    fn compute_policy_hash_writes_an_owned_string() {
        unsafe {
            let policy = CString::new("aml.threshold").unwrap();
            let params = CString::new(r#"{"threshold":10000}"#).unwrap();
            let mut out: *mut c_char = std::ptr::null_mut();

            let rc = ves_compute_policy_hash(policy.as_ptr(), params.as_ptr(), &mut out);
            assert_eq!(rc, VES_OK, "valid policy must hash");
            assert!(!out.is_null());

            let hex = CStr::from_ptr(out).to_str().expect("valid UTF-8");
            assert_eq!(hex.len(), 64, "policy hash must be 32 bytes of hex");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

            ves_free_string(out);
        }
    }

    /// A real STARK generated and verified end to end through the C ABI,
    /// interpreted under Miri. Ignored by default: this takes minutes to hours
    /// under the interpreter. The nightly workflow runs it with
    /// `-- --ignored miri_full_prove_verify_cycle`; it also runs natively for a
    /// cheap sanity check.
    #[test]
    #[ignore = "slow under Miri; run by the nightly workflow"]
    fn miri_full_prove_verify_cycle() {
        unsafe {
            let inputs = ves_public_inputs_from_json(valid_public_inputs_json().as_ptr());
            assert!(!inputs.is_null());
            let policy = CString::new("aml.threshold").unwrap();
            let mut proof: *mut VesProof = std::ptr::null_mut();
            let rc = ves_prove(5_000, inputs, policy.as_ptr(), 10_000, &mut proof);
            assert_eq!(
                rc,
                VES_OK,
                "prove failed: {:?}",
                CStr::from_ptr(ves_stark_last_error())
            );
            assert!(!proof.is_null());

            let mut len = 0usize;
            let bytes = ves_proof_bytes(proof, &mut len);
            assert!(!bytes.is_null() && len > 0);
            let mut commitment = [0u64; 4];
            assert_eq!(
                ves_proof_witness_commitment(proof, commitment.as_mut_ptr()),
                VES_OK
            );

            let mut result: *mut VesVerificationResult = std::ptr::null_mut();
            let rc = ves_verify(bytes, len, inputs, commitment.as_ptr(), &mut result);
            assert_eq!(
                rc,
                VES_OK,
                "verify failed: {:?}",
                CStr::from_ptr(ves_stark_last_error())
            );
            assert!(ves_verification_valid(result), "a fresh proof must verify");

            ves_verification_result_free(result);
            ves_proof_free(proof);
            ves_public_inputs_free(inputs);
        }
    }

    /// NULL arguments to the hash helper must not be dereferenced.
    #[test]
    fn compute_policy_hash_rejects_null_arguments() {
        unsafe {
            let policy = CString::new("aml.threshold").unwrap();
            let params = CString::new(r#"{"threshold":10000}"#).unwrap();
            let mut out: *mut c_char = std::ptr::null_mut();

            assert_ne!(
                ves_compute_policy_hash(std::ptr::null(), params.as_ptr(), &mut out),
                VES_OK
            );
            assert_ne!(
                ves_compute_policy_hash(policy.as_ptr(), std::ptr::null(), &mut out),
                VES_OK
            );
            assert_ne!(
                ves_compute_policy_hash(policy.as_ptr(), params.as_ptr(), std::ptr::null_mut()),
                VES_OK
            );
        }
    }
}
