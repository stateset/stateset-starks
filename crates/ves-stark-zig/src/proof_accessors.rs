//! Proof Accessors — one section of the C API. See lib.rs.

use super::*;

// ---------------------------------------------------------------------------
// Proof Accessors
// ---------------------------------------------------------------------------

/// Get proof bytes pointer and length.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesProof`] handle. `out_len` must
/// be NULL or a valid, writable `*mut usize`. The returned pointer borrows memory
/// owned by `proof` and is valid only until `proof` is freed.
///
/// When `proof` is NULL this returns NULL and writes `0` to `*out_len` (when
/// `out_len` is non-NULL), so the returned length is never stale.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_bytes(proof: *const VesProof, out_len: *mut usize) -> *const u8 {
    if proof.is_null() {
        // Zero the out-parameter before bailing out. Returning NULL while
        // leaving `*out_len` untouched hands the caller a garbage (often
        // uninitialized) length next to a NULL pointer, which the usual C
        // idiom `p = f(h, &len); memcpy(dst, p, len);` will happily act on.
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

/// Get proof hash as a null-terminated string.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesProof`] handle. The returned
/// string borrows memory owned by `proof` and is valid only until it is freed.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_hash(proof: *const VesProof) -> *const c_char {
    if proof.is_null() {
        return std::ptr::null();
    }
    unsafe { &*proof }.proof_hash.as_ptr()
}

/// Get proving time in milliseconds.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesProof`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_proving_time_ms(proof: *const VesProof) -> u64 {
    if proof.is_null() {
        return 0;
    }
    unsafe { &*proof }.proving_time_ms
}

/// Get proof size in bytes.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesProof`] handle.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_size(proof: *const VesProof) -> usize {
    if proof.is_null() {
        return 0;
    }
    unsafe { &*proof }.proof_size
}

/// Get witness commitment as 4 x u64.
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesProof`] handle. `out` must be
/// NULL or a valid, writable pointer to an array of at least 4 `u64` values.
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
///
/// # Safety
/// `proof` must be NULL or a valid, unfreed [`VesProof`] handle. The returned
/// string borrows memory owned by `proof` and is valid only until it is freed.
#[no_mangle]
pub unsafe extern "C" fn ves_proof_witness_commitment_hex(proof: *const VesProof) -> *const c_char {
    if proof.is_null() {
        return std::ptr::null();
    }
    unsafe { &*proof }.witness_commitment_hex.as_ptr()
}

/// Free a proof handle.
///
/// # Safety
/// `proof` must be NULL or a handle previously returned by [`ves_prove`] that has
/// not already been freed. After this call the pointer is dangling and must not
/// be used again (no double-free).
#[no_mangle]
pub unsafe extern "C" fn ves_proof_free(proof: *mut VesProof) {
    if !proof.is_null() {
        drop(unsafe { Box::from_raw(proof) });
    }
}
