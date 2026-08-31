//! Policy — one section of the C API. See lib.rs.

use super::*;

// ---------------------------------------------------------------------------
// Policy Helpers
// ---------------------------------------------------------------------------

/// Compute the policy hash. On success, `*out_hash` is set to a new string. Free with `ves_free_string()`.
///
/// # Safety
/// `policy_id` and `policy_params_json` must each be a valid NUL-terminated C
/// string. `out_hash` must be a valid, writable `*mut *mut c_char`; on success it
/// receives an owned string that must be released with [`ves_free_string`].
/// `out_hash` may be NULL (handled as an error).
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
///
/// # Safety
/// `inputs` must be a valid, unfreed [`VesPublicInputs`] handle. `out_json` must be
/// a valid, writable `*mut *mut c_char`; on success it receives an owned string
/// that must be released with [`ves_free_string`]. Both pointers may be NULL
/// (handled as an error).
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
