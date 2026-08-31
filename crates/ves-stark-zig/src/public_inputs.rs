//! Public Inputs — one section of the C API. See lib.rs.

use super::*;

// ---------------------------------------------------------------------------
// Public Inputs
// ---------------------------------------------------------------------------

/// Create public inputs from a JSON string.
///
/// Returns NULL on error (check `ves_stark_last_error()`).
///
/// # Safety
/// `json` must be either NULL or a pointer to a valid, NUL-terminated C string
/// that remains valid for the duration of this call. The returned handle, if
/// non-NULL, must be released exactly once with [`ves_public_inputs_free`].
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
///
/// # Safety
/// `inputs` must be a valid handle returned by [`ves_public_inputs_from_json`]
/// (and not yet freed). `out_json` must be a valid, writable pointer to a
/// `*mut c_char`; on success it receives an owned string that must be released
/// with [`ves_free_string`]. Both pointers may be NULL (handled as an error).
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
///
/// # Safety
/// `inputs` must be NULL or a handle previously returned by
/// [`ves_public_inputs_from_json`] that has not already been freed. After this
/// call the pointer is dangling and must not be used again (no double-free).
#[no_mangle]
pub unsafe extern "C" fn ves_public_inputs_free(inputs: *mut VesPublicInputs) {
    if !inputs.is_null() {
        drop(unsafe { Box::from_raw(inputs) });
    }
}
