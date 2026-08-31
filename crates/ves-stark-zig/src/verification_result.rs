//! Verification Result — one section of the C API. See lib.rs.

use super::*;

// ---------------------------------------------------------------------------
// Verification Result Accessors
// ---------------------------------------------------------------------------

/// Returns whether the verification succeeded.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesVerificationResult`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_verification_valid(result: *const VesVerificationResult) -> bool {
    if result.is_null() {
        return false;
    }
    unsafe { &*result }.valid
}

/// Returns the verification time in milliseconds.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesVerificationResult`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_verification_time_ms(result: *const VesVerificationResult) -> u64 {
    if result.is_null() {
        return 0;
    }
    unsafe { &*result }.verification_time_ms
}

/// Returns NULL if there is no error message.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesVerificationResult`] handle.
/// The returned string borrows memory owned by `result` and is valid only until
/// it is freed.
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

/// Returns the policy id as a NUL-terminated string.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesVerificationResult`] handle.
/// The returned string borrows memory owned by `result` and is valid only until
/// it is freed.
#[no_mangle]
pub unsafe extern "C" fn ves_verification_policy_id(
    result: *const VesVerificationResult,
) -> *const c_char {
    if result.is_null() {
        return std::ptr::null();
    }
    unsafe { &*result }.policy_id.as_ptr()
}

/// Returns the policy limit.
///
/// # Safety
/// `result` must be NULL or a valid, unfreed [`VesVerificationResult`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_verification_policy_limit(
    result: *const VesVerificationResult,
) -> u64 {
    if result.is_null() {
        return 0;
    }
    unsafe { &*result }.policy_limit
}

/// Free a verification result handle.
///
/// # Safety
/// `result` must be NULL or a handle previously returned by one of the
/// `ves_verify*` functions that has not already been freed. After this call the
/// pointer is dangling and must not be used again (no double-free).
#[no_mangle]
pub unsafe extern "C" fn ves_verification_result_free(result: *mut VesVerificationResult) {
    if !result.is_null() {
        drop(unsafe { Box::from_raw(result) });
    }
}
