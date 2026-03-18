/**
 * VES STARK C FFI – consumed by the Zig client.
 *
 * All opaque handles must be freed through their corresponding `*_free` function.
 * Strings returned by accessor functions are valid until the parent handle is freed.
 * Strings returned via `out_*` output parameters must be freed with `ves_free_string()`.
 *
 * Thread-safety: each function is safe to call from any thread, but opaque handles
 * must not be shared across threads without external synchronisation.
 */

#ifndef VES_STARK_H
#define VES_STARK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ───────────────────────────────────────────────────────── */

#define VES_OK              0
#define VES_ERR_INVALID_ARG -1
#define VES_ERR_PROOF_FAILED -2
#define VES_ERR_VERIFY_FAILED -3
#define VES_ERR_JSON        -4
#define VES_ERR_NULL_PTR    -5

typedef int32_t VesResult;

/**
 * Get the last error message for the calling thread.
 * Returns NULL if no error has occurred.
 * The pointer is valid until the next FFI call on the same thread.
 */
const char *ves_stark_last_error(void);

/* ── Opaque handles ────────────────────────────────────────────────────── */

typedef struct VesPublicInputs       VesPublicInputs;
typedef struct VesProof              VesProof;
typedef struct VesVerificationResult VesVerificationResult;

/* ── Public Inputs ─────────────────────────────────────────────────────── */

/**
 * Create public inputs from a JSON string.
 *
 * Required JSON fields:
 *   event_id, tenant_id, store_id (UUID strings),
 *   sequence_number (u64), payload_kind (u32),
 *   payload_plain_hash, payload_cipher_hash, event_signing_hash (hex64),
 *   policy_id (string), policy_params (object), policy_hash (hex64)
 *
 * Optional: witness_commitment, authorization_receipt_hash, amount_binding_hash (hex64)
 *
 * Returns NULL on error (check ves_stark_last_error()).
 */
VesPublicInputs *ves_public_inputs_from_json(const char *json);

/**
 * Serialize public inputs to a JSON string.
 * Free the result with ves_free_string().
 */
VesResult ves_public_inputs_to_json(const VesPublicInputs *inputs, char **out_json);

void ves_public_inputs_free(VesPublicInputs *inputs);

/* ── Proof Generation ──────────────────────────────────────────────────── */

/**
 * Generate a STARK compliance proof.
 *
 * @param amount        The amount to prove compliance for.
 * @param inputs        Public inputs handle.
 * @param policy_type   "aml.threshold", "order_total.cap", or "agent.authorization.v1"
 * @param policy_limit  The policy limit value.
 * @param out_proof     On success, receives a new proof handle. Free with ves_proof_free().
 * @return VES_OK on success, negative error code on failure.
 */
VesResult ves_prove(
    uint64_t amount,
    const VesPublicInputs *inputs,
    const char *policy_type,
    uint64_t policy_limit,
    VesProof **out_proof);

/* ── Proof Accessors ───────────────────────────────────────────────────── */

const uint8_t *ves_proof_bytes(const VesProof *proof, size_t *out_len);
const char    *ves_proof_hash(const VesProof *proof);
uint64_t       ves_proof_proving_time_ms(const VesProof *proof);
size_t         ves_proof_size(const VesProof *proof);
VesResult      ves_proof_witness_commitment(const VesProof *proof, uint64_t out[4]);
const char    *ves_proof_witness_commitment_hex(const VesProof *proof);
void           ves_proof_free(VesProof *proof);

/* ── Verification ──────────────────────────────────────────────────────── */

VesResult ves_verify(
    const uint8_t *proof_bytes, size_t proof_len,
    const VesPublicInputs *inputs,
    const uint64_t witness_commitment[4],
    VesVerificationResult **out_result);

VesResult ves_verify_hex(
    const uint8_t *proof_bytes, size_t proof_len,
    const VesPublicInputs *inputs,
    const char *witness_commitment_hex,
    VesVerificationResult **out_result);

VesResult ves_verify_with_amount_binding(
    const uint8_t *proof_bytes, size_t proof_len,
    const VesPublicInputs *inputs,
    const char *amount_binding_json,
    VesVerificationResult **out_result);

VesResult ves_verify_agent_authorization(
    const uint8_t *proof_bytes, size_t proof_len,
    const VesPublicInputs *inputs,
    const uint64_t witness_commitment[4],
    const char *receipt_json,
    VesVerificationResult **out_result);

VesResult ves_verify_agent_authorization_hex(
    const uint8_t *proof_bytes, size_t proof_len,
    const VesPublicInputs *inputs,
    const char *witness_commitment_hex,
    const char *receipt_json,
    VesVerificationResult **out_result);

VesResult ves_verify_agent_authorization_with_amount_binding(
    const uint8_t *proof_bytes, size_t proof_len,
    const VesPublicInputs *inputs,
    const char *amount_binding_json,
    const char *receipt_json,
    VesVerificationResult **out_result);

/* ── Verification Result Accessors ─────────────────────────────────────── */

bool        ves_verification_valid(const VesVerificationResult *result);
uint64_t    ves_verification_time_ms(const VesVerificationResult *result);
const char *ves_verification_error(const VesVerificationResult *result);
const char *ves_verification_policy_id(const VesVerificationResult *result);
uint64_t    ves_verification_policy_limit(const VesVerificationResult *result);
void        ves_verification_result_free(VesVerificationResult *result);

/* ── Policy Helpers ────────────────────────────────────────────────────── */

/**
 * Compute the policy hash. On success, *out_hash receives a new string.
 * Free with ves_free_string().
 */
VesResult ves_compute_policy_hash(
    const char *policy_id,
    const char *policy_params_json,
    char **out_hash);

/**
 * Create a canonical payload amount binding (returned as JSON string).
 * Free with ves_free_string().
 */
VesResult ves_create_payload_amount_binding(
    const VesPublicInputs *inputs,
    uint64_t amount,
    char **out_json);

/* ── Proof Inspection ──────────────────────────────────────────────────── */

/**
 * Inspect proof bytes and return metadata as JSON.
 * Returns: {"proofHash":"...", "proofSize": N, "proofVersion": V, "maxProofSize": M}
 * Free the result with ves_free_string().
 */
VesResult ves_proof_inspect(
    const uint8_t *proof_bytes, size_t proof_len,
    char **out_json);

/* ── Batch Proofs (requires batch feature) ────────────────────────────── */

typedef struct VesBatchProof              VesBatchProof;
typedef struct VesBatchVerificationResult VesBatchVerificationResult;

VesResult ves_batch_prove_json(
    const char *events_json,
    const char *policy_type,
    uint64_t policy_limit,
    VesBatchProof **out_proof);

const char    *ves_batch_proof_hash(const VesBatchProof *proof);
const char    *ves_batch_proof_json(const VesBatchProof *proof);
size_t         ves_batch_proof_num_events(const VesBatchProof *proof);
bool           ves_batch_proof_all_compliant(const VesBatchProof *proof);
uint64_t       ves_batch_proof_proving_time_ms(const VesBatchProof *proof);
void           ves_batch_proof_free(VesBatchProof *proof);

VesResult ves_batch_verify_json(
    const char *proof_json,
    VesBatchVerificationResult **out_result);

bool     ves_batch_verification_valid(const VesBatchVerificationResult *result);
uint64_t ves_batch_verification_time_ms(const VesBatchVerificationResult *result);
size_t   ves_batch_verification_num_events(const VesBatchVerificationResult *result);
bool     ves_batch_verification_all_compliant(const VesBatchVerificationResult *result);
void     ves_batch_verification_result_free(VesBatchVerificationResult *result);

/* ── Memory ────────────────────────────────────────────────────────────── */

void ves_free_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* VES_STARK_H */
