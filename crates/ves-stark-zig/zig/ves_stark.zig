///! VES STARK Zig client – idiomatic wrapper around the Rust C FFI.
///!
///! Usage:
///! ```zig
///! const ves = @import("ves_stark");
///!
///! var inputs = try ves.PublicInputs.fromJson(json_string);
///! defer inputs.deinit();
///!
///! var proof = try ves.prove(5000, &inputs, .aml_threshold, 10000);
///! defer proof.deinit();
///!
///! var result = try ves.verifyHex(proof.bytes(), &inputs, proof.witnessCommitmentHex());
///! defer result.deinit();
///!
///! if (result.valid()) {
///!     std.debug.print("Proof is valid!\n", .{});
///! }
///! ```
const std = @import("std");

// ---------------------------------------------------------------------------
// C FFI imports
// ---------------------------------------------------------------------------

const c = @cImport({
    @cInclude("ves_stark.h");
});

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

pub const Error = error{
    InvalidArg,
    ProofFailed,
    VerifyFailed,
    JsonError,
    NullPointer,
    Unknown,
};

fn mapResult(code: c.VesResult) Error!void {
    return switch (code) {
        c.VES_OK => {},
        c.VES_ERR_INVALID_ARG => Error.InvalidArg,
        c.VES_ERR_PROOF_FAILED => Error.ProofFailed,
        c.VES_ERR_VERIFY_FAILED => Error.VerifyFailed,
        c.VES_ERR_JSON => Error.JsonError,
        c.VES_ERR_NULL_PTR => Error.NullPointer,
        else => Error.Unknown,
    };
}

/// Get the last error message from the FFI layer.
/// The returned slice is valid until the next FFI call on the same thread.
pub fn lastError() ?[]const u8 {
    const ptr = c.ves_stark_last_error();
    if (ptr == null) return null;
    return std.mem.span(ptr);
}

// ---------------------------------------------------------------------------
// Policy type enum
// ---------------------------------------------------------------------------

pub const PolicyType = enum {
    aml_threshold,
    order_total_cap,
    agent_authorization,

    pub fn toString(self: PolicyType) [*:0]const u8 {
        return switch (self) {
            .aml_threshold => "aml.threshold",
            .order_total_cap => "order_total.cap",
            .agent_authorization => "agent.authorization.v1",
        };
    }
};

// ---------------------------------------------------------------------------
// PublicInputs
// ---------------------------------------------------------------------------

pub const PublicInputs = struct {
    handle: *c.VesPublicInputs,

    /// Create public inputs from a JSON string (null-terminated).
    ///
    /// Required JSON fields:
    ///   event_id, tenant_id, store_id (UUID strings),
    ///   sequence_number (u64), payload_kind (u32),
    ///   payload_plain_hash, payload_cipher_hash, event_signing_hash (hex64),
    ///   policy_id (string), policy_params (object), policy_hash (hex64)
    ///
    /// Optional: witness_commitment, authorization_receipt_hash, amount_binding_hash
    pub fn fromJson(json: [*:0]const u8) Error!PublicInputs {
        const ptr = c.ves_public_inputs_from_json(json);
        if (ptr == null) return Error.InvalidArg;
        return PublicInputs{ .handle = ptr.? };
    }

    /// Create public inputs from a Zig slice (copies and null-terminates internally).
    pub fn fromJsonSlice(allocator: std.mem.Allocator, json: []const u8) (std.mem.Allocator.Error || Error)!PublicInputs {
        const z = try allocator.dupeZ(u8, json);
        defer allocator.free(z);
        return fromJson(z);
    }

    /// Serialize the public inputs back to a JSON string.
    /// Caller owns the returned OwnedString.
    pub fn toJson(self: *const PublicInputs) Error!OwnedString {
        var json_ptr: ?[*:0]u8 = null;
        try mapResult(c.ves_public_inputs_to_json(
            self.handle,
            @ptrCast(&json_ptr),
        ));
        return OwnedString{ .ptr = json_ptr.? };
    }

    pub fn deinit(self: *PublicInputs) void {
        c.ves_public_inputs_free(self.handle);
        self.handle = undefined;
    }
};

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

pub const Proof = struct {
    handle: *c.VesProof,

    /// Raw proof bytes. The slice is valid for the lifetime of this Proof.
    pub fn proofBytes(self: *const Proof) []const u8 {
        var len: usize = 0;
        const ptr = c.ves_proof_bytes(self.handle, &len);
        if (ptr == null) return &[_]u8{};
        return ptr[0..len];
    }

    /// SHA-256 hash of proof bytes (hex string).
    pub fn proofHash(self: *const Proof) ?[]const u8 {
        const ptr = c.ves_proof_hash(self.handle);
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    /// Time taken to generate proof in milliseconds.
    pub fn provingTimeMs(self: *const Proof) u64 {
        return c.ves_proof_proving_time_ms(self.handle);
    }

    /// Size of proof in bytes.
    pub fn proofSize(self: *const Proof) usize {
        return c.ves_proof_size(self.handle);
    }

    /// Witness commitment as 4 x u64.
    pub fn witnessCommitment(self: *const Proof) Error![4]u64 {
        var out: [4]u64 = undefined;
        try mapResult(c.ves_proof_witness_commitment(self.handle, &out));
        return out;
    }

    /// Witness commitment as hex string (64 chars). Recommended over witnessCommitment().
    pub fn witnessCommitmentHex(self: *const Proof) ?[]const u8 {
        const ptr = c.ves_proof_witness_commitment_hex(self.handle);
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    pub fn deinit(self: *Proof) void {
        c.ves_proof_free(self.handle);
        self.handle = undefined;
    }
};

// ---------------------------------------------------------------------------
// VerificationResult
// ---------------------------------------------------------------------------

pub const VerificationResult = struct {
    handle: *c.VesVerificationResult,

    /// Whether the proof is valid.
    pub fn valid(self: *const VerificationResult) bool {
        return c.ves_verification_valid(self.handle);
    }

    /// Time taken to verify in milliseconds.
    pub fn verificationTimeMs(self: *const VerificationResult) u64 {
        return c.ves_verification_time_ms(self.handle);
    }

    /// Error message if verification failed. Returns null if no error.
    pub fn err(self: *const VerificationResult) ?[]const u8 {
        const ptr = c.ves_verification_error(self.handle);
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    /// Policy ID that was verified.
    pub fn policyId(self: *const VerificationResult) ?[]const u8 {
        const ptr = c.ves_verification_policy_id(self.handle);
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    /// Policy limit that was verified against.
    pub fn policyLimit(self: *const VerificationResult) u64 {
        return c.ves_verification_policy_limit(self.handle);
    }

    pub fn deinit(self: *VerificationResult) void {
        c.ves_verification_result_free(self.handle);
        self.handle = undefined;
    }
};

// ---------------------------------------------------------------------------
// OwnedString – a string allocated by the FFI that must be freed
// ---------------------------------------------------------------------------

pub const OwnedString = struct {
    ptr: [*:0]u8,

    pub fn slice(self: *const OwnedString) []const u8 {
        return std.mem.span(self.ptr);
    }

    pub fn deinit(self: *OwnedString) void {
        c.ves_free_string(self.ptr);
        self.ptr = undefined;
    }
};

// ---------------------------------------------------------------------------
// Top-level API
// ---------------------------------------------------------------------------

/// Generate a STARK compliance proof.
///
/// Example:
/// ```zig
/// var proof = try ves.prove(5000, &inputs, .aml_threshold, 10000);
/// defer proof.deinit();
/// ```
pub fn prove(
    amount: u64,
    inputs: *const PublicInputs,
    policy_type: PolicyType,
    policy_limit: u64,
) Error!Proof {
    var proof_ptr: ?*c.VesProof = null;
    try mapResult(c.ves_prove(
        amount,
        inputs.handle,
        policy_type.toString(),
        policy_limit,
        &proof_ptr,
    ));
    return Proof{ .handle = proof_ptr.? };
}

/// Verify a proof with witness commitment (4 x u64).
pub fn verify(
    proof_bytes: []const u8,
    inputs: *const PublicInputs,
    witness_commitment: *const [4]u64,
) Error!VerificationResult {
    var result_ptr: ?*c.VesVerificationResult = null;
    try mapResult(c.ves_verify(
        proof_bytes.ptr,
        proof_bytes.len,
        inputs.handle,
        witness_commitment,
        &result_ptr,
    ));
    return VerificationResult{ .handle = result_ptr.? };
}

/// Verify a proof with witness commitment as hex string (recommended).
pub fn verifyHex(
    proof_bytes: []const u8,
    inputs: *const PublicInputs,
    witness_commitment_hex: [*:0]const u8,
) Error!VerificationResult {
    var result_ptr: ?*c.VesVerificationResult = null;
    try mapResult(c.ves_verify_hex(
        proof_bytes.ptr,
        proof_bytes.len,
        inputs.handle,
        witness_commitment_hex,
        &result_ptr,
    ));
    return VerificationResult{ .handle = result_ptr.? };
}

/// Verify a proof against a canonical payload amount binding (JSON string).
pub fn verifyWithAmountBinding(
    proof_bytes: []const u8,
    inputs: *const PublicInputs,
    amount_binding_json: [*:0]const u8,
) Error!VerificationResult {
    var result_ptr: ?*c.VesVerificationResult = null;
    try mapResult(c.ves_verify_with_amount_binding(
        proof_bytes.ptr,
        proof_bytes.len,
        inputs.handle,
        amount_binding_json,
        &result_ptr,
    ));
    return VerificationResult{ .handle = result_ptr.? };
}

/// Verify an agent.authorization.v1 proof with witness commitment (4 x u64).
pub fn verifyAgentAuthorization(
    proof_bytes: []const u8,
    inputs: *const PublicInputs,
    witness_commitment: *const [4]u64,
    receipt_json: [*:0]const u8,
) Error!VerificationResult {
    var result_ptr: ?*c.VesVerificationResult = null;
    try mapResult(c.ves_verify_agent_authorization(
        proof_bytes.ptr,
        proof_bytes.len,
        inputs.handle,
        witness_commitment,
        receipt_json,
        &result_ptr,
    ));
    return VerificationResult{ .handle = result_ptr.? };
}

/// Verify an agent.authorization.v1 proof with witness commitment as hex (recommended).
pub fn verifyAgentAuthorizationHex(
    proof_bytes: []const u8,
    inputs: *const PublicInputs,
    witness_commitment_hex: [*:0]const u8,
    receipt_json: [*:0]const u8,
) Error!VerificationResult {
    var result_ptr: ?*c.VesVerificationResult = null;
    try mapResult(c.ves_verify_agent_authorization_hex(
        proof_bytes.ptr,
        proof_bytes.len,
        inputs.handle,
        witness_commitment_hex,
        receipt_json,
        &result_ptr,
    ));
    return VerificationResult{ .handle = result_ptr.? };
}

/// Verify an agent.authorization.v1 proof against both amount binding and receipt.
pub fn verifyAgentAuthorizationWithAmountBinding(
    proof_bytes: []const u8,
    inputs: *const PublicInputs,
    amount_binding_json: [*:0]const u8,
    receipt_json: [*:0]const u8,
) Error!VerificationResult {
    var result_ptr: ?*c.VesVerificationResult = null;
    try mapResult(c.ves_verify_agent_authorization_with_amount_binding(
        proof_bytes.ptr,
        proof_bytes.len,
        inputs.handle,
        amount_binding_json,
        receipt_json,
        &result_ptr,
    ));
    return VerificationResult{ .handle = result_ptr.? };
}

/// Compute the policy hash for given policy ID and parameters.
pub fn computePolicyHash(
    policy_id: [*:0]const u8,
    policy_params_json: [*:0]const u8,
) Error!OwnedString {
    var hash_ptr: ?[*:0]u8 = null;
    try mapResult(c.ves_compute_policy_hash(
        policy_id,
        policy_params_json,
        @ptrCast(&hash_ptr),
    ));
    return OwnedString{ .ptr = hash_ptr.? };
}

/// Create a canonical payload amount binding (returned as JSON string).
pub fn createPayloadAmountBinding(
    inputs: *const PublicInputs,
    amount: u64,
) Error!OwnedString {
    var json_ptr: ?[*:0]u8 = null;
    try mapResult(c.ves_create_payload_amount_binding(
        inputs.handle,
        amount,
        @ptrCast(&json_ptr),
    ));
    return OwnedString{ .ptr = json_ptr.? };
}

// ---------------------------------------------------------------------------
// Proof Inspection
// ---------------------------------------------------------------------------

/// Inspect raw proof bytes and return metadata as a JSON string.
///
/// Returns: {"proofHash":"...", "proofSize": N, "proofVersion": V, "maxProofSize": M}
pub fn inspectProof(proof_bytes: []const u8) Error!OwnedString {
    var json_ptr: ?[*:0]u8 = null;
    try mapResult(c.ves_proof_inspect(
        proof_bytes.ptr,
        proof_bytes.len,
        @ptrCast(&json_ptr),
    ));
    return OwnedString{ .ptr = json_ptr.? };
}

// ---------------------------------------------------------------------------
// Policy parameter helpers (pure Zig JSON builders)
// ---------------------------------------------------------------------------

pub const PolicyParams = struct {
    /// Create AML threshold policy parameters JSON.
    /// Caller owns the returned slice.
    pub fn amlThreshold(allocator: std.mem.Allocator, threshold: u64) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(allocator, "{{\"threshold\":{d}}}", .{threshold});
    }

    /// Create order total cap policy parameters JSON.
    pub fn orderTotalCap(allocator: std.mem.Allocator, cap: u64) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(allocator, "{{\"cap\":{d}}}", .{cap});
    }

    /// Create agent authorization policy parameters JSON.
    pub fn agentAuthorization(allocator: std.mem.Allocator, max_total: u64, intent_hash: []const u8) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(allocator, "{{\"max_total\":{d},\"intent_hash\":\"{s}\"}}", .{ max_total, intent_hash });
    }
};

// ---------------------------------------------------------------------------
// PublicInputsBuilder – ergonomic builder for constructing public inputs JSON
// ---------------------------------------------------------------------------

pub const PublicInputsBuilder = struct {
    allocator: std.mem.Allocator,
    event_id: []const u8,
    tenant_id: []const u8,
    store_id: []const u8,
    sequence_number: u64,
    payload_kind: u32,
    payload_plain_hash: []const u8,
    payload_cipher_hash: []const u8,
    event_signing_hash: []const u8,
    policy_id: []const u8,
    policy_params_json: []const u8,
    policy_hash: ?[]const u8 = null,
    witness_commitment: ?[]const u8 = null,
    authorization_receipt_hash: ?[]const u8 = null,
    amount_binding_hash: ?[]const u8 = null,

    fn validateHex64(field: []const u8) Error!void {
        if (field.len != 64) return Error.InvalidArg;
        for (field) |ch| {
            if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f')))
                return Error.InvalidArg;
        }
    }

    /// Build a PublicInputs handle. Computes the policy hash automatically if not set.
    /// Returns the JSON string used for construction via `toJson()`.
    pub fn build(self: *const PublicInputsBuilder) (std.mem.Allocator.Error || Error)!PublicInputs {
        // Validate hex fields
        try validateHex64(self.payload_plain_hash);
        try validateHex64(self.payload_cipher_hash);
        try validateHex64(self.event_signing_hash);
        // Compute policy hash if not provided
        var computed_hash: ?OwnedString = null;
        defer if (computed_hash) |*h| h.deinit();

        const policy_hash = if (self.policy_hash) |ph|
            ph
        else blk: {
            const params_z = try self.allocator.dupeZ(u8, self.policy_params_json);
            defer self.allocator.free(params_z);
            const pid_z = try self.allocator.dupeZ(u8, self.policy_id);
            defer self.allocator.free(pid_z);
            computed_hash = try computePolicyHash(pid_z, params_z);
            break :blk computed_hash.?.slice();
        };

        // Build optional fields
        var opt_buf: [3]u8 = undefined;
        _ = &opt_buf;

        const wc_field = if (self.witness_commitment) |wc|
            try std.fmt.allocPrint(self.allocator, ",\"witness_commitment\":\"{s}\"", .{wc})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(wc_field);

        const arh_field = if (self.authorization_receipt_hash) |arh|
            try std.fmt.allocPrint(self.allocator, ",\"authorization_receipt_hash\":\"{s}\"", .{arh})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(arh_field);

        const abh_field = if (self.amount_binding_hash) |abh|
            try std.fmt.allocPrint(self.allocator, ",\"amount_binding_hash\":\"{s}\"", .{abh})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(abh_field);

        const json = try std.fmt.allocPrint(self.allocator,
            \\{{"event_id":"{s}","tenant_id":"{s}","store_id":"{s}",
            \\"sequence_number":{d},"payload_kind":{d},
            \\"payload_plain_hash":"{s}","payload_cipher_hash":"{s}",
            \\"event_signing_hash":"{s}","policy_id":"{s}",
            \\"policy_params":{s},"policy_hash":"{s}"{s}{s}{s}}}
        , .{
            self.event_id,
            self.tenant_id,
            self.store_id,
            self.sequence_number,
            self.payload_kind,
            self.payload_plain_hash,
            self.payload_cipher_hash,
            self.event_signing_hash,
            self.policy_id,
            self.policy_params_json,
            policy_hash,
            wc_field,
            arh_field,
            abh_field,
        });
        defer self.allocator.free(json);

        return PublicInputs.fromJsonSlice(self.allocator, json);
    }

    /// Build and also return the JSON string used (caller owns the JSON slice).
    /// Useful for embedding public inputs into a ComplianceProofBundle.
    pub fn buildWithJson(self: *const PublicInputsBuilder) (std.mem.Allocator.Error || Error)!struct { inputs: PublicInputs, json: []u8 } {
        try validateHex64(self.payload_plain_hash);
        try validateHex64(self.payload_cipher_hash);
        try validateHex64(self.event_signing_hash);

        var computed_hash: ?OwnedString = null;
        defer if (computed_hash) |*h| h.deinit();

        const policy_hash = if (self.policy_hash) |ph|
            ph
        else blk: {
            const params_z = try self.allocator.dupeZ(u8, self.policy_params_json);
            defer self.allocator.free(params_z);
            const pid_z = try self.allocator.dupeZ(u8, self.policy_id);
            defer self.allocator.free(pid_z);
            computed_hash = try computePolicyHash(pid_z, params_z);
            break :blk computed_hash.?.slice();
        };

        const wc_field = if (self.witness_commitment) |wc|
            try std.fmt.allocPrint(self.allocator, ",\"witness_commitment\":\"{s}\"", .{wc})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(wc_field);

        const arh_field = if (self.authorization_receipt_hash) |arh|
            try std.fmt.allocPrint(self.allocator, ",\"authorization_receipt_hash\":\"{s}\"", .{arh})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(arh_field);

        const abh_field = if (self.amount_binding_hash) |abh|
            try std.fmt.allocPrint(self.allocator, ",\"amount_binding_hash\":\"{s}\"", .{abh})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(abh_field);

        const json = try std.fmt.allocPrint(self.allocator,
            \\{{"event_id":"{s}","tenant_id":"{s}","store_id":"{s}",
            \\"sequence_number":{d},"payload_kind":{d},
            \\"payload_plain_hash":"{s}","payload_cipher_hash":"{s}",
            \\"event_signing_hash":"{s}","policy_id":"{s}",
            \\"policy_params":{s},"policy_hash":"{s}"{s}{s}{s}}}
        , .{
            self.event_id, self.tenant_id, self.store_id,
            self.sequence_number, self.payload_kind,
            self.payload_plain_hash, self.payload_cipher_hash,
            self.event_signing_hash, self.policy_id,
            self.policy_params_json, policy_hash,
            wc_field, arh_field, abh_field,
        });
        errdefer self.allocator.free(json);

        const inputs = try PublicInputs.fromJsonSlice(self.allocator, json);
        return .{ .inputs = inputs, .json = json };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PolicyType.toString" {
    try std.testing.expectEqualStrings("aml.threshold", std.mem.span(PolicyType.aml_threshold.toString()));
    try std.testing.expectEqualStrings("order_total.cap", std.mem.span(PolicyType.order_total_cap.toString()));
    try std.testing.expectEqualStrings("agent.authorization.v1", std.mem.span(PolicyType.agent_authorization.toString()));
}

test "PublicInputs.fromJson rejects invalid JSON" {
    const result = PublicInputs.fromJson("not json");
    try std.testing.expectError(Error.InvalidArg, result);
}

test "PublicInputs.fromJson rejects missing fields" {
    const result = PublicInputs.fromJson("{}");
    try std.testing.expectError(Error.InvalidArg, result);
}

test "lastError returns error detail" {
    _ = PublicInputs.fromJson("{}") catch {};
    const err_msg = lastError();
    try std.testing.expect(err_msg != null);
}

test "PolicyParams.amlThreshold" {
    const allocator = std.testing.allocator;
    const json = try PolicyParams.amlThreshold(allocator, 10000);
    defer allocator.free(json);
    try std.testing.expectEqualStrings("{\"threshold\":10000}", json);
}

test "PolicyParams.orderTotalCap" {
    const allocator = std.testing.allocator;
    const json = try PolicyParams.orderTotalCap(allocator, 25000);
    defer allocator.free(json);
    try std.testing.expectEqualStrings("{\"cap\":25000}", json);
}

test "PolicyParams.agentAuthorization" {
    const allocator = std.testing.allocator;
    const json = try PolicyParams.agentAuthorization(allocator, 50000, "abcd1234" ** 8);
    defer allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"max_total\":50000") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"intent_hash\":\"") != null);
}

test "computePolicyHash returns 64-char hex" {
    var hash = try computePolicyHash("aml.threshold", "{\"threshold\":10000}");
    defer hash.deinit();
    try std.testing.expectEqual(@as(usize, 64), hash.slice().len);
}

test "computePolicyHash is deterministic" {
    var h1 = try computePolicyHash("aml.threshold", "{\"threshold\":10000}");
    defer h1.deinit();
    var h2 = try computePolicyHash("aml.threshold", "{\"threshold\":10000}");
    defer h2.deinit();
    try std.testing.expectEqualStrings(h1.slice(), h2.slice());
}

test "computePolicyHash differs for different limits" {
    var h1 = try computePolicyHash("aml.threshold", "{\"threshold\":10000}");
    defer h1.deinit();
    var h2 = try computePolicyHash("aml.threshold", "{\"threshold\":20000}");
    defer h2.deinit();
    try std.testing.expect(!std.mem.eql(u8, h1.slice(), h2.slice()));
}

// Helper: build valid PublicInputs for tests
fn testPublicInputs(allocator: std.mem.Allocator) !PublicInputs {
    const builder = PublicInputsBuilder{
        .allocator = allocator,
        .event_id = "00000000-0000-0000-0000-000000000001",
        .tenant_id = "00000000-0000-0000-0000-000000000002",
        .store_id = "00000000-0000-0000-0000-000000000003",
        .sequence_number = 1,
        .payload_kind = 1,
        .payload_plain_hash = "0" ** 64,
        .payload_cipher_hash = "0" ** 64,
        .event_signing_hash = "0" ** 64,
        .policy_id = "aml.threshold",
        .policy_params_json = "{\"threshold\":10000}",
    };
    return builder.build();
}

test "PublicInputsBuilder auto-computes policy hash" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();
    // If we get here without error, the builder computed the hash and the FFI accepted it
}

test "prove generates valid proof" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    var proof = try prove(5000, &inputs, .aml_threshold, 10000);
    defer proof.deinit();

    try std.testing.expect(proof.proofSize() > 0);
    try std.testing.expect(proof.provingTimeMs() >= 0);
    try std.testing.expect(proof.proofHash() != null);
    try std.testing.expect(proof.witnessCommitmentHex() != null);
    try std.testing.expectEqual(@as(usize, 64), proof.witnessCommitmentHex().?.len);
}

test "prove rejects amount exceeding limit" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    const result = prove(10000, &inputs, .aml_threshold, 10000);
    try std.testing.expectError(Error.InvalidArg, result);
}

test "prove + verifyHex roundtrip" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    var proof = try prove(5000, &inputs, .aml_threshold, 10000);
    defer proof.deinit();

    const wc_hex: [*:0]const u8 = @ptrCast(proof.witnessCommitmentHex().?.ptr);

    var result = try verifyHex(proof.proofBytes(), &inputs, wc_hex);
    defer result.deinit();

    try std.testing.expect(result.valid());
    try std.testing.expectEqualStrings("aml.threshold", result.policyId().?);
    try std.testing.expectEqual(@as(u64, 10000), result.policyLimit());
}

test "prove + verify (u64 commitment) roundtrip" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    var proof = try prove(1, &inputs, .aml_threshold, 10000);
    defer proof.deinit();

    const commitment = try proof.witnessCommitment();

    var result = try verify(proof.proofBytes(), &inputs, &commitment);
    defer result.deinit();

    try std.testing.expect(result.valid());
}

test "createPayloadAmountBinding returns valid JSON" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    var binding = try createPayloadAmountBinding(&inputs, 5000);
    defer binding.deinit();

    // Should be a JSON object with "amount" field
    try std.testing.expect(std.mem.indexOf(u8, binding.slice(), "\"amount\"") != null);
}

test "PublicInputs.toJson serializes correctly" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    var json = try inputs.toJson();
    defer json.deinit();

    const s = json.slice();
    try std.testing.expect(s.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, s, "aml.threshold") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "00000000-0000-0000-0000-000000000001") != null);
}

test "PublicInputs.toJson roundtrips through fromJson" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    var json = try inputs.toJson();
    defer json.deinit();

    // Parse the JSON back into a new handle
    var inputs2 = try PublicInputs.fromJsonSlice(allocator, json.slice());
    defer inputs2.deinit();

    // Both should produce the same policy hash when proofs are generated
    var proof1 = try prove(100, &inputs, .aml_threshold, 10000);
    defer proof1.deinit();
    var proof2 = try prove(100, &inputs2, .aml_threshold, 10000);
    defer proof2.deinit();

    // Same witness commitment hex means same public inputs
    try std.testing.expectEqualStrings(
        proof1.witnessCommitmentHex().?,
        proof2.witnessCommitmentHex().?,
    );
}

test "inspectProof returns metadata" {
    const allocator = std.testing.allocator;
    var inputs = try testPublicInputs(allocator);
    defer inputs.deinit();

    var proof = try prove(5000, &inputs, .aml_threshold, 10000);
    defer proof.deinit();

    var metadata = try inspectProof(proof.proofBytes());
    defer metadata.deinit();

    const s = metadata.slice();
    try std.testing.expect(s.len > 0);
    // Should contain the proof hash
    try std.testing.expect(std.mem.indexOf(u8, s, "proofHash") != null);
    // proofHash should match the proof's own hash
    if (proof.proofHash()) |ph| {
        try std.testing.expect(std.mem.indexOf(u8, s, ph) != null);
    }
    // Should contain size info
    try std.testing.expect(std.mem.indexOf(u8, s, "proofSize") != null);
}

test "builder rejects invalid hex fields" {
    const allocator = std.testing.allocator;
    const bad_builder = PublicInputsBuilder{
        .allocator = allocator,
        .event_id = "00000000-0000-0000-0000-000000000001",
        .tenant_id = "00000000-0000-0000-0000-000000000002",
        .store_id = "00000000-0000-0000-0000-000000000003",
        .sequence_number = 1,
        .payload_kind = 1,
        .payload_plain_hash = "tooshort",
        .payload_cipher_hash = "0" ** 64,
        .event_signing_hash = "0" ** 64,
        .policy_id = "aml.threshold",
        .policy_params_json = "{\"threshold\":10000}",
    };
    try std.testing.expectError(Error.InvalidArg, bad_builder.build());
}

test "builder rejects uppercase hex" {
    const allocator = std.testing.allocator;
    const bad_builder = PublicInputsBuilder{
        .allocator = allocator,
        .event_id = "00000000-0000-0000-0000-000000000001",
        .tenant_id = "00000000-0000-0000-0000-000000000002",
        .store_id = "00000000-0000-0000-0000-000000000003",
        .sequence_number = 1,
        .payload_kind = 1,
        .payload_plain_hash = "0" ** 64,
        .payload_cipher_hash = "0" ** 64,
        .event_signing_hash = "ABCD" ++ "0" ** 60,
        .policy_id = "aml.threshold",
        .policy_params_json = "{\"threshold\":10000}",
    };
    try std.testing.expectError(Error.InvalidArg, bad_builder.build());
}

test "buildWithJson returns inputs and JSON" {
    const allocator = std.testing.allocator;
    const builder = PublicInputsBuilder{
        .allocator = allocator,
        .event_id = "00000000-0000-0000-0000-000000000001",
        .tenant_id = "00000000-0000-0000-0000-000000000002",
        .store_id = "00000000-0000-0000-0000-000000000003",
        .sequence_number = 1,
        .payload_kind = 1,
        .payload_plain_hash = "0" ** 64,
        .payload_cipher_hash = "0" ** 64,
        .event_signing_hash = "0" ** 64,
        .policy_id = "aml.threshold",
        .policy_params_json = "{\"threshold\":10000}",
    };
    var result = try builder.buildWithJson();
    defer result.inputs.deinit();
    defer allocator.free(result.json);

    try std.testing.expect(result.json.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, result.json, "aml.threshold") != null);
}

test "order_total_cap prove + verify" {
    const allocator = std.testing.allocator;
    const builder = PublicInputsBuilder{
        .allocator = allocator,
        .event_id = "00000000-0000-0000-0000-000000000001",
        .tenant_id = "00000000-0000-0000-0000-000000000002",
        .store_id = "00000000-0000-0000-0000-000000000003",
        .sequence_number = 42,
        .payload_kind = 1,
        .payload_plain_hash = "a" ** 64,
        .payload_cipher_hash = "b" ** 64,
        .event_signing_hash = "c" ** 64,
        .policy_id = "order_total.cap",
        .policy_params_json = "{\"cap\":25000}",
    };
    var inputs = try builder.build();
    defer inputs.deinit();

    // order_total.cap allows amount == cap (<=)
    var proof = try prove(25000, &inputs, .order_total_cap, 25000);
    defer proof.deinit();

    const wc_hex: [*:0]const u8 = @ptrCast(proof.witnessCommitmentHex().?.ptr);
    var result = try verifyHex(proof.proofBytes(), &inputs, wc_hex);
    defer result.deinit();

    try std.testing.expect(result.valid());
    try std.testing.expectEqualStrings("order_total.cap", result.policyId().?);
    try std.testing.expectEqual(@as(u64, 25000), result.policyLimit());
}
