///! Batch proof generation and verification for zkRollup-style proofs.
///!
///! Batch proofs aggregate multiple compliance events into a single STARK proof
///! with Merkle state root transitions, providing O(1) verification for N events.
///!
///! Example:
///! ```zig
///! const batch = @import("batch");
///!
///! // Build witness
///! var witness = try batch.BatchWitness.init(
///!     "batch-uuid", "tenant-uuid", "store-uuid",
///!     10000, .aml_threshold,
///! );
///! defer witness.deinit();
///!
///! try witness.addEvent(1, 5000, hash, hash, hash);
///! try witness.addEvent(2, 3000, hash, hash, hash);
///!
///! // Prove
///! var proof = try batch.batchProve(&witness);
///! defer proof.deinit();
///!
///! // Verify from serialized JSON
///! var result = try batch.batchVerifyJson(proof.json());
///! defer result.deinit();
///! ```
const std = @import("std");
const ves = @import("ves_stark");

const c = @cImport({
    @cInclude("ves_stark.h");
});

pub const BatchError = error{
    InvalidArg,
    ProofFailed,
    VerifyFailed,
    JsonError,
    NullPointer,
    Unknown,
};

fn mapResult(code: c.VesResult) BatchError!void {
    return switch (code) {
        c.VES_OK => {},
        c.VES_ERR_INVALID_ARG => BatchError.InvalidArg,
        c.VES_ERR_PROOF_FAILED => BatchError.ProofFailed,
        c.VES_ERR_VERIFY_FAILED => BatchError.VerifyFailed,
        c.VES_ERR_JSON => BatchError.JsonError,
        c.VES_ERR_NULL_PTR => BatchError.NullPointer,
        else => BatchError.Unknown,
    };
}

// ---------------------------------------------------------------------------
// BatchPolicyKind
// ---------------------------------------------------------------------------

pub const BatchPolicyKind = enum {
    aml_threshold,
    order_total_cap,

    pub fn toString(self: BatchPolicyKind) [*:0]const u8 {
        return switch (self) {
            .aml_threshold => "aml.threshold",
            .order_total_cap => "order_total.cap",
        };
    }
};

// ---------------------------------------------------------------------------
// BatchWitness – builder for batch proof inputs
// ---------------------------------------------------------------------------

pub const BatchWitness = struct {
    handle: *c.VesBatchWitness,

    pub fn init(
        batch_id: [*:0]const u8,
        tenant_id: [*:0]const u8,
        store_id: [*:0]const u8,
        policy_limit: u64,
        policy_kind: BatchPolicyKind,
    ) BatchError!BatchWitness {
        const ptr = c.ves_batch_witness_new(
            batch_id,
            tenant_id,
            store_id,
            policy_limit,
            policy_kind.toString(),
        );
        if (ptr == null) return BatchError.InvalidArg;
        return BatchWitness{ .handle = ptr.? };
    }

    /// Add a compliance event to the batch.
    pub fn addEvent(
        self: *const BatchWitness,
        sequence_number: u64,
        amount: u64,
        payload_plain_hash: [*:0]const u8,
        payload_cipher_hash: [*:0]const u8,
        event_signing_hash: [*:0]const u8,
    ) BatchError!void {
        try mapResult(c.ves_batch_witness_add_event(
            self.handle,
            sequence_number,
            amount,
            payload_plain_hash,
            payload_cipher_hash,
            event_signing_hash,
        ));
    }

    pub fn deinit(self: *BatchWitness) void {
        c.ves_batch_witness_free(self.handle);
        self.handle = undefined;
    }
};

// ---------------------------------------------------------------------------
// BatchProof
// ---------------------------------------------------------------------------

pub const BatchProof = struct {
    handle: *c.VesBatchProof,

    /// Raw proof bytes.
    pub fn proofBytes(self: *const BatchProof) []const u8 {
        var len: usize = 0;
        const ptr = c.ves_batch_proof_bytes(self.handle, &len);
        if (ptr == null) return &[_]u8{};
        return ptr[0..len];
    }

    /// Domain-separated proof hash (hex).
    pub fn proofHash(self: *const BatchProof) ?[]const u8 {
        const ptr = c.ves_batch_proof_hash(self.handle);
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    /// Full serialized proof as JSON (includes public inputs and metadata).
    pub fn json(self: *const BatchProof) ?[]const u8 {
        const ptr = c.ves_batch_proof_json(self.handle);
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    /// Number of events in the batch.
    pub fn numEvents(self: *const BatchProof) usize {
        return c.ves_batch_proof_num_events(self.handle);
    }

    /// Whether all events passed compliance.
    pub fn allCompliant(self: *const BatchProof) bool {
        return c.ves_batch_proof_all_compliant(self.handle);
    }

    /// Proving time in milliseconds.
    pub fn provingTimeMs(self: *const BatchProof) u64 {
        return c.ves_batch_proof_proving_time_ms(self.handle);
    }

    /// State roots: (prev_state_root, new_state_root) as [4]u64.
    pub fn stateRoots(self: *const BatchProof) BatchError!struct { prev: [4]u64, new: [4]u64 } {
        var prev: [4]u64 = undefined;
        var new_root: [4]u64 = undefined;
        try mapResult(c.ves_batch_proof_state_roots(self.handle, &prev, &new_root));
        return .{ .prev = prev, .new = new_root };
    }

    pub fn deinit(self: *BatchProof) void {
        c.ves_batch_proof_free(self.handle);
        self.handle = undefined;
    }
};

// ---------------------------------------------------------------------------
// BatchVerificationResult
// ---------------------------------------------------------------------------

pub const BatchVerificationResult = struct {
    handle: *c.VesBatchVerificationResult,

    pub fn valid(self: *const BatchVerificationResult) bool {
        return c.ves_batch_verification_valid(self.handle);
    }

    pub fn verificationTimeMs(self: *const BatchVerificationResult) u64 {
        return c.ves_batch_verification_time_ms(self.handle);
    }

    pub fn numEvents(self: *const BatchVerificationResult) usize {
        return c.ves_batch_verification_num_events(self.handle);
    }

    pub fn allCompliant(self: *const BatchVerificationResult) bool {
        return c.ves_batch_verification_all_compliant(self.handle);
    }

    pub fn deinit(self: *BatchVerificationResult) void {
        c.ves_batch_verification_result_free(self.handle);
        self.handle = undefined;
    }
};

// ---------------------------------------------------------------------------
// Top-level API
// ---------------------------------------------------------------------------

/// Generate a batch proof from a witness.
pub fn batchProve(witness: *const BatchWitness) BatchError!BatchProof {
    var proof_ptr: ?*c.VesBatchProof = null;
    try mapResult(c.ves_batch_prove(witness.handle, &proof_ptr));
    return BatchProof{ .handle = proof_ptr.? };
}

/// Verify a batch proof from its serialized JSON representation.
pub fn batchVerifyJson(proof_json: [*:0]const u8) BatchError!BatchVerificationResult {
    var result_ptr: ?*c.VesBatchVerificationResult = null;
    try mapResult(c.ves_batch_verify_json(proof_json, &result_ptr));
    return BatchVerificationResult{ .handle = result_ptr.? };
}
