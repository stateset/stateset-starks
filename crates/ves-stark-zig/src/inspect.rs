//! Inspect — one section of the C API. See lib.rs.

use super::*;

// ---------------------------------------------------------------------------
// Proof Inspection
// ---------------------------------------------------------------------------

/// Inspect proof bytes and return metadata as JSON.
///
/// Returns a JSON object with: proofHash, proofSize, domainHash.
/// Free the result with `ves_free_string()`.
///
/// # Safety
/// `proof_bytes_ptr` must point to at least `proof_len` readable bytes. `out_json`
/// must be a valid, writable `*mut *mut c_char`; on success it receives an owned
/// string that must be released with [`ves_free_string`]. Both pointers may be NULL
/// (handled as an error).
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
        ves_stark_primitives::COMPLIANCE_PROOF_HASH_DOMAIN,
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
