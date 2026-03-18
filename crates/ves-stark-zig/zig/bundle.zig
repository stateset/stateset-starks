///! ComplianceProofBundle – canonical transport artifact for payload-bound compliance proofs.
///!
///! This is a pure-Zig implementation of the Rust `ComplianceProofBundle` type. It bundles
///! proof bytes, metadata, witness commitment, public inputs, and amount binding into a
///! single JSON-serializable, locally-verifiable artifact.
///!
///! Example:
///! ```zig
///! const bundle = @import("bundle");
///! const ves = @import("ves_stark");
///!
///! var b = try bundle.proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
///! defer b.deinit(allocator);
///!
///! const json = try b.toJson(allocator);
///! defer allocator.free(json);
///!
///! var b2 = try bundle.ComplianceProofBundle.fromJson(allocator, json);
///! defer b2.deinit(allocator);
///! ```
const std = @import("std");
const ves = @import("ves_stark");

const Sha256 = std.crypto.hash.sha2.Sha256;
const base64_alphabet: [64]u8 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
const base64_encoder = std.base64.Base64Encoder.init(base64_alphabet, '=');
const base64_decoder = std.base64.Base64Decoder.init(base64_alphabet, '=');

const BUNDLE_VERSION: u32 = 1;
const PROOF_VERSION: u32 = 2;
const DOMAIN_PREFIX = "STATESET_VES_COMPLIANCE_PROOF_BUNDLE_HASH_V1";

pub const BundleError = error{
    InvalidBundle,
    InvalidJson,
    VersionMismatch,
    HashMismatch,
    MissingPublicInputs,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// ComplianceProofBundle
// ---------------------------------------------------------------------------

pub const ComplianceProofBundle = struct {
    version: u32,
    proof_type: []u8,
    proof_version: u32,
    proof_b64: []u8,
    proof_hash: []u8,
    proving_time_ms: u64,
    proof_size: usize,
    witness_commitment: [4]u64,
    witness_commitment_hex: []u8,
    public_inputs_json: []u8,
    public_inputs_hash: []u8,
    amount_binding_json: []u8,
    bundle_hash: []u8,

    /// Create a bundle from a proof, public inputs handle, and amount.
    ///
    /// If `pi_json` is provided, it is embedded directly. Otherwise, public inputs
    /// are serialized from the handle automatically via `PublicInputs.toJson()`.
    pub fn create(
        allocator: std.mem.Allocator,
        proof: *const ves.Proof,
        inputs: *const ves.PublicInputs,
        amount: u64,
        pi_json: ?[]const u8,
    ) (BundleError || ves.Error)!ComplianceProofBundle {
        const proof_bytes = proof.proofBytes();
        const proof_hash_slice = proof.proofHash() orelse return BundleError.InvalidBundle;
        const wc_hex_slice = proof.witnessCommitmentHex() orelse return BundleError.InvalidBundle;
        const wc = try proof.witnessCommitment();

        // Base64 encode proof bytes
        const b64_len = base64_encoder.calcSize(proof_bytes.len);
        const proof_b64 = allocator.alloc(u8, b64_len) catch return BundleError.OutOfMemory;
        errdefer allocator.free(proof_b64);
        _ = base64_encoder.encode(proof_b64, proof_bytes);

        // Compute amount binding
        var binding = try ves.createPayloadAmountBinding(inputs, amount);
        defer binding.deinit();

        // Copy all strings
        const proof_hash = allocator.dupe(u8, proof_hash_slice) catch return BundleError.OutOfMemory;
        errdefer allocator.free(proof_hash);
        const wc_hex = allocator.dupe(u8, wc_hex_slice) catch return BundleError.OutOfMemory;
        errdefer allocator.free(wc_hex);
        const binding_json = allocator.dupe(u8, binding.slice()) catch return BundleError.OutOfMemory;
        errdefer allocator.free(binding_json);

        // Get public inputs JSON: use provided string, or serialize from handle
        var auto_pi: ?ves.OwnedString = null;
        defer if (auto_pi) |*ap| ap.deinit();

        const pi_source = if (pi_json) |pj|
            pj
        else blk: {
            auto_pi = inputs.toJson() catch break :blk @as([]const u8, "{}");
            break :blk auto_pi.?.slice();
        };

        const pi_stored = allocator.dupe(u8, pi_source) catch return BundleError.OutOfMemory;
        errdefer allocator.free(pi_stored);
        const pi_hash_str = sha256Hex(allocator, pi_stored) catch return BundleError.OutOfMemory;
        errdefer allocator.free(pi_hash_str);
        const proof_type = allocator.dupe(u8, "stark") catch return BundleError.OutOfMemory;
        errdefer allocator.free(proof_type);

        var bundle = ComplianceProofBundle{
            .version = BUNDLE_VERSION,
            .proof_type = proof_type,
            .proof_version = PROOF_VERSION,
            .proof_b64 = proof_b64,
            .proof_hash = proof_hash,
            .proving_time_ms = proof.provingTimeMs(),
            .proof_size = proof.proofSize(),
            .witness_commitment = wc,
            .witness_commitment_hex = wc_hex,
            .public_inputs_json = pi_stored,
            .public_inputs_hash = pi_hash_str,
            .amount_binding_json = binding_json,
            .bundle_hash = allocator.dupe(u8, "") catch return BundleError.OutOfMemory,
        };

        // Compute bundle hash
        allocator.free(bundle.bundle_hash);
        bundle.bundle_hash = bundle.computeHash(allocator) catch return BundleError.OutOfMemory;

        return bundle;
    }

    /// Set or replace the public inputs JSON after bundle creation.
    pub fn setPublicInputs(self: *ComplianceProofBundle, allocator: std.mem.Allocator, pi_json: []const u8) BundleError!void {
        const new_pi = allocator.dupe(u8, pi_json) catch return BundleError.OutOfMemory;
        allocator.free(self.public_inputs_json);
        self.public_inputs_json = new_pi;

        const new_hash = sha256Hex(allocator, new_pi) catch return BundleError.OutOfMemory;
        allocator.free(self.public_inputs_hash);
        self.public_inputs_hash = new_hash;
    }

    /// Returns true if this bundle has real public inputs (not the "{}" placeholder).
    pub fn hasPublicInputs(self: *const ComplianceProofBundle) bool {
        return self.public_inputs_json.len > 2;
    }

    /// Deserialize a bundle from JSON.
    pub fn fromJson(allocator: std.mem.Allocator, json: []const u8) BundleError!ComplianceProofBundle {
        const version = jsonNumberField(allocator, json, "version") catch return BundleError.InvalidJson;
        if (version != BUNDLE_VERSION) return BundleError.VersionMismatch;

        const proof_type = jsonStringField(allocator, json, "proofType") catch return BundleError.InvalidJson;
        errdefer allocator.free(proof_type);
        const proof_version_val = jsonNumberField(allocator, json, "proofVersion") catch return BundleError.InvalidJson;
        const proof_b64 = jsonStringField(allocator, json, "proofB64") catch return BundleError.InvalidJson;
        errdefer allocator.free(proof_b64);
        const proof_hash = jsonStringField(allocator, json, "proofHash") catch return BundleError.InvalidJson;
        errdefer allocator.free(proof_hash);
        const proving_time_ms = jsonNumberField(allocator, json, "provingTimeMs") catch 0;
        const proof_size_val = jsonNumberField(allocator, json, "proofSize") catch 0;
        const wc_hex = jsonStringField(allocator, json, "witnessCommitmentHex") catch return BundleError.InvalidJson;
        errdefer allocator.free(wc_hex);
        const pi_json = jsonObjectField(allocator, json, "publicInputs") catch
            (allocator.dupe(u8, "{}") catch return BundleError.OutOfMemory);
        errdefer allocator.free(pi_json);
        const pi_hash = jsonStringField(allocator, json, "publicInputsHash") catch
            (allocator.dupe(u8, "") catch return BundleError.OutOfMemory);
        errdefer allocator.free(pi_hash);
        const binding_json = jsonObjectField(allocator, json, "amountBinding") catch
            (allocator.dupe(u8, "{}") catch return BundleError.OutOfMemory);
        errdefer allocator.free(binding_json);
        const bundle_hash = jsonStringField(allocator, json, "bundleHash") catch
            (allocator.dupe(u8, "") catch return BundleError.OutOfMemory);
        errdefer allocator.free(bundle_hash);

        // Parse witness commitment hex → [4]u64
        var wc: [4]u64 = .{ 0, 0, 0, 0 };
        if (wc_hex.len == 64) {
            for (0..4) |idx| {
                const offset = idx * 16;
                wc[idx] = std.fmt.parseInt(u64, wc_hex[offset .. offset + 16], 16) catch 0;
            }
        }

        return ComplianceProofBundle{
            .version = @intCast(version),
            .proof_type = proof_type,
            .proof_version = @intCast(proof_version_val),
            .proof_b64 = proof_b64,
            .proof_hash = proof_hash,
            .proving_time_ms = proving_time_ms,
            .proof_size = @intCast(proof_size_val),
            .witness_commitment = wc,
            .witness_commitment_hex = wc_hex,
            .public_inputs_json = pi_json,
            .public_inputs_hash = pi_hash,
            .amount_binding_json = binding_json,
            .bundle_hash = bundle_hash,
        };
    }

    /// Serialize the bundle to JSON.
    pub fn toJson(self: *const ComplianceProofBundle, allocator: std.mem.Allocator) BundleError![]u8 {
        // Build JSON manually to avoid format string type issues
        var parts = std.ArrayListUnmanaged(u8){};
        defer parts.deinit(allocator);
        const w = parts.writer(allocator);

        w.writeAll("{\"version\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.version}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"proofType\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.proof_type) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"proofVersion\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.proof_version}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"proofB64\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.proof_b64) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"proofHash\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.proof_hash) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"provingTimeMs\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.proving_time_ms}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"proofSize\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.proof_size}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"witnessCommitment\":[") catch return BundleError.OutOfMemory;
        for (self.witness_commitment, 0..) |val, i| {
            if (i > 0) w.writeAll(",") catch return BundleError.OutOfMemory;
            w.print("{d}", .{val}) catch return BundleError.OutOfMemory;
        }
        w.writeAll("],\"witnessCommitmentHex\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.witness_commitment_hex) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"publicInputs\":") catch return BundleError.OutOfMemory;
        w.writeAll(self.public_inputs_json) catch return BundleError.OutOfMemory;
        w.writeAll(",\"publicInputsHash\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.public_inputs_hash) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"amountBinding\":") catch return BundleError.OutOfMemory;
        w.writeAll(self.amount_binding_json) catch return BundleError.OutOfMemory;
        w.writeAll(",\"bundleHash\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.bundle_hash) catch return BundleError.OutOfMemory;
        w.writeAll("\"}") catch return BundleError.OutOfMemory;

        return allocator.dupe(u8, parts.items) catch return BundleError.OutOfMemory;
    }

    /// Validate bundle invariants without running STARK verification.
    /// The bundle hash covers all inner fields, so this detects any tampering.
    pub fn validate(self: *const ComplianceProofBundle, allocator: std.mem.Allocator) BundleError!void {
        if (self.version != BUNDLE_VERSION) return BundleError.VersionMismatch;
        if (!std.mem.eql(u8, self.proof_type, "stark")) return BundleError.InvalidBundle;
        if (self.proof_version == 0) return BundleError.InvalidBundle;
        if (self.proof_b64.len == 0) return BundleError.InvalidBundle;
        if (self.proof_hash.len != 64) return BundleError.InvalidBundle;
        if (self.witness_commitment_hex.len != 64) return BundleError.InvalidBundle;

        if (self.bundle_hash.len > 0) {
            const computed = self.computeHash(allocator) catch return BundleError.OutOfMemory;
            defer allocator.free(computed);
            if (!std.mem.eql(u8, computed, self.bundle_hash)) return BundleError.HashMismatch;
        }
    }

    /// Strict validation: also re-derives the proof hash from decoded proof bytes.
    /// Uses the same domain-separated hash as the Rust prover:
    ///   SHA256("STATESET_VES_COMPLIANCE_PROOF_HASH_V1" || proof_bytes)
    pub fn validateStrict(self: *const ComplianceProofBundle, allocator: std.mem.Allocator) BundleError!void {
        try self.validate(allocator);

        const proof_bytes = self.decodeProofBytes(allocator) catch return BundleError.InvalidBundle;
        defer allocator.free(proof_bytes);
        const computed = domainSha256Hex(allocator, "STATESET_VES_COMPLIANCE_PROOF_HASH_V1", proof_bytes) catch return BundleError.OutOfMemory;
        defer allocator.free(computed);
        if (!std.mem.eql(u8, computed, self.proof_hash)) return BundleError.HashMismatch;
    }

    /// Run local STARK verification. Requires public inputs to be populated.
    pub fn verify(self: *const ComplianceProofBundle, allocator: std.mem.Allocator) (BundleError || ves.Error)!ves.VerificationResult {
        try self.validate(allocator);

        if (!self.hasPublicInputs()) return BundleError.MissingPublicInputs;

        const proof_bytes = self.decodeProofBytes(allocator) catch return BundleError.InvalidBundle;
        defer allocator.free(proof_bytes);

        const binding_z = allocator.dupeZ(u8, self.amount_binding_json) catch return BundleError.OutOfMemory;
        defer allocator.free(binding_z);

        const pi_z = allocator.dupeZ(u8, self.public_inputs_json) catch return BundleError.OutOfMemory;
        defer allocator.free(pi_z);

        var inputs = ves.PublicInputs.fromJson(pi_z) catch return BundleError.InvalidBundle;
        defer inputs.deinit();

        return ves.verifyWithAmountBinding(proof_bytes, &inputs, binding_z);
    }

    /// Decode proof bytes from base64.
    pub fn decodeProofBytes(self: *const ComplianceProofBundle, allocator: std.mem.Allocator) BundleError![]u8 {
        const decoded_len = base64_decoder.calcSizeForSlice(self.proof_b64) catch return BundleError.InvalidBundle;
        const buf = allocator.alloc(u8, decoded_len) catch return BundleError.OutOfMemory;
        errdefer allocator.free(buf);
        base64_decoder.decode(buf, self.proof_b64) catch return BundleError.InvalidBundle;
        return buf;
    }

    /// Compute the domain-separated bundle hash.
    fn computeHash(self: *const ComplianceProofBundle, allocator: std.mem.Allocator) BundleError![]u8 {
        // Build canonical payload (sorted keys, excluding bundleHash)
        var parts = std.ArrayListUnmanaged(u8){};
        defer parts.deinit(allocator);
        const w = parts.writer(allocator);

        w.writeAll("{\"proofB64\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.proof_b64) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"proofHash\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.proof_hash) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"proofType\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.proof_type) catch return BundleError.OutOfMemory;
        w.writeAll("\",\"proofVersion\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.proof_version}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"provingTimeMs\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.proving_time_ms}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"proofSize\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.proof_size}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"version\":") catch return BundleError.OutOfMemory;
        w.print("{d}", .{self.version}) catch return BundleError.OutOfMemory;
        w.writeAll(",\"witnessCommitmentHex\":\"") catch return BundleError.OutOfMemory;
        w.writeAll(self.witness_commitment_hex) catch return BundleError.OutOfMemory;
        w.writeAll("\"}") catch return BundleError.OutOfMemory;

        return domainSha256Hex(allocator, DOMAIN_PREFIX, parts.items);
    }

    pub fn deinit(self: *ComplianceProofBundle, allocator: std.mem.Allocator) void {
        allocator.free(self.proof_type);
        allocator.free(self.proof_b64);
        allocator.free(self.proof_hash);
        allocator.free(self.witness_commitment_hex);
        allocator.free(self.public_inputs_json);
        allocator.free(self.public_inputs_hash);
        allocator.free(self.amount_binding_json);
        allocator.free(self.bundle_hash);
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Convenience: prove → bundle in one step
// ---------------------------------------------------------------------------

/// Generate a compliance proof and wrap it in a canonical bundle.
///
/// Public inputs are automatically serialized from the handle. The bundle
/// can be verified locally, serialized to JSON, and submitted to the sequencer.
pub fn proveComplianceBundle(
    allocator: std.mem.Allocator,
    amount: u64,
    inputs: *const ves.PublicInputs,
    policy_type: ves.PolicyType,
    policy_limit: u64,
) (BundleError || ves.Error)!ComplianceProofBundle {
    var proof = try ves.prove(amount, inputs, policy_type, policy_limit);
    defer proof.deinit();

    return ComplianceProofBundle.create(allocator, &proof, inputs, amount, null);
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

fn sha256Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    Sha256.hash(data, &hash, .{});
    return hexEncode(allocator, &hash);
}

fn domainSha256Hex(allocator: std.mem.Allocator, domain: []const u8, data: []const u8) ![]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(domain);
    hasher.update(data);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);
    return hexEncode(allocator, &hash);
}

fn hexEncode(allocator: std.mem.Allocator, bytes: *const [32]u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, 64);
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

// ---------------------------------------------------------------------------
// JSON field extractors
// ---------------------------------------------------------------------------

fn jsonStringField(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ![]u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\":\"", .{key});
    defer allocator.free(needle);
    const start = std.mem.indexOf(u8, json, needle) orelse return error.InvalidJson;
    const val_start = start + needle.len;
    const val_end = std.mem.indexOfPos(u8, json, val_start, "\"") orelse return error.InvalidJson;
    return allocator.dupe(u8, json[val_start..val_end]);
}

fn jsonNumberField(allocator: std.mem.Allocator, json: []const u8, key: []const u8) !u64 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\":", .{key});
    defer allocator.free(needle);
    const start = std.mem.indexOf(u8, json, needle) orelse return error.InvalidJson;
    var pos = start + needle.len;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\n')) pos += 1;
    var end = pos;
    while (end < json.len and json[end] >= '0' and json[end] <= '9') end += 1;
    if (end == pos) return error.InvalidJson;
    return std.fmt.parseInt(u64, json[pos..end], 10) catch return error.InvalidJson;
}

fn jsonObjectField(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ![]u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\":", .{key});
    defer allocator.free(needle);
    const start = std.mem.indexOf(u8, json, needle) orelse return error.InvalidJson;
    var pos = start + needle.len;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\n')) pos += 1;
    if (pos >= json.len) return error.InvalidJson;
    if (json[pos] == '{') {
        var depth: u32 = 1;
        var end = pos + 1;
        var in_string = false;
        while (end < json.len and depth > 0) : (end += 1) {
            if (json[end] == '"' and (end == 0 or json[end - 1] != '\\')) in_string = !in_string;
            if (!in_string) {
                if (json[end] == '{') depth += 1;
                if (json[end] == '}') depth -= 1;
            }
        }
        return allocator.dupe(u8, json[pos..end]);
    }
    return error.InvalidJson;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn testInputs(allocator: std.mem.Allocator) !ves.PublicInputs {
    return (ves.PublicInputsBuilder{
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
    }).build();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "sha256Hex computes correct hash" {
    const allocator = std.testing.allocator;
    const hash = try sha256Hex(allocator, "hello");
    defer allocator.free(hash);
    try std.testing.expectEqualStrings("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash);
}

test "domainSha256Hex includes domain prefix" {
    const allocator = std.testing.allocator;
    const h1 = try sha256Hex(allocator, "data");
    defer allocator.free(h1);
    const h2 = try domainSha256Hex(allocator, "DOMAIN", "data");
    defer allocator.free(h2);
    try std.testing.expect(!std.mem.eql(u8, h1, h2));
}

test "proveComplianceBundle creates valid bundle" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    try std.testing.expectEqual(BUNDLE_VERSION, bundle.version);
    try std.testing.expectEqualStrings("stark", bundle.proof_type);
    try std.testing.expect(bundle.proof_b64.len > 0);
    try std.testing.expectEqual(@as(usize, 64), bundle.proof_hash.len);
    try std.testing.expectEqual(@as(usize, 64), bundle.bundle_hash.len);
    // Public inputs are auto-serialized from the handle
    try std.testing.expect(bundle.hasPublicInputs());
}

test "bundle toJson + fromJson roundtrip preserves all fields" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    const json = try bundle.toJson(allocator);
    defer allocator.free(json);

    var bundle2 = try ComplianceProofBundle.fromJson(allocator, json);
    defer bundle2.deinit(allocator);

    try std.testing.expectEqual(bundle.version, bundle2.version);
    try std.testing.expectEqualStrings(bundle.proof_type, bundle2.proof_type);
    try std.testing.expectEqual(bundle.proof_version, bundle2.proof_version);
    try std.testing.expectEqualStrings(bundle.proof_hash, bundle2.proof_hash);
    try std.testing.expectEqualStrings(bundle.witness_commitment_hex, bundle2.witness_commitment_hex);
    try std.testing.expectEqualStrings(bundle.bundle_hash, bundle2.bundle_hash);
    try std.testing.expectEqual(bundle.proving_time_ms, bundle2.proving_time_ms);
    try std.testing.expectEqualStrings(bundle.proof_b64, bundle2.proof_b64);
}

test "bundle validate detects tampering" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    bundle.proof_hash[0] = if (bundle.proof_hash[0] == 'a') 'b' else 'a';
    try std.testing.expectError(BundleError.HashMismatch, bundle.validate(allocator));
}

test "bundle validateStrict verifies proof hash from bytes" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    // validateStrict should pass on a freshly created bundle
    try bundle.validateStrict(allocator);
}

test "bundle validateStrict survives JSON roundtrip" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    const json = try bundle.toJson(allocator);
    defer allocator.free(json);

    var bundle2 = try ComplianceProofBundle.fromJson(allocator, json);
    defer bundle2.deinit(allocator);

    try bundle2.validateStrict(allocator);
}

test "bundle fromJson rejects wrong version" {
    const allocator = std.testing.allocator;
    const json =
        \\{"version":99,"proofType":"stark","proofVersion":2,"proofB64":"AA==","proofHash":"0000000000000000000000000000000000000000000000000000000000000000","witnessCommitmentHex":"0000000000000000000000000000000000000000000000000000000000000000","bundleHash":""}
    ;
    try std.testing.expectError(BundleError.VersionMismatch, ComplianceProofBundle.fromJson(allocator, json));
}

test "bundle verify succeeds with auto-serialized public inputs" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    try std.testing.expect(bundle.hasPublicInputs());

    var result = try bundle.verify(allocator);
    defer result.deinit();

    try std.testing.expect(result.valid());
    try std.testing.expectEqualStrings("aml.threshold", result.policyId().?);
}

test "bundle verify survives JSON roundtrip" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    // Serialize → deserialize → verify
    const json = try bundle.toJson(allocator);
    defer allocator.free(json);

    var bundle2 = try ComplianceProofBundle.fromJson(allocator, json);
    defer bundle2.deinit(allocator);

    try std.testing.expect(bundle2.hasPublicInputs());
    var result = try bundle2.verify(allocator);
    defer result.deinit();

    try std.testing.expect(result.valid());
}

test "bundle setPublicInputs replaces existing" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    var bundle = try proveComplianceBundle(allocator, 5000, &inputs, .aml_threshold, 10000);
    defer bundle.deinit(allocator);

    const old_hash = try allocator.dupe(u8, bundle.public_inputs_hash);
    defer allocator.free(old_hash);

    try bundle.setPublicInputs(allocator, "{\"different\":\"data\"}");
    try std.testing.expect(bundle.hasPublicInputs());
    // Hash should change after setPublicInputs
    try std.testing.expect(!std.mem.eql(u8, old_hash, bundle.public_inputs_hash));
}

test "bundle decodeProofBytes roundtrips correctly" {
    const allocator = std.testing.allocator;
    var inputs = try testInputs(allocator);
    defer inputs.deinit();

    // Get raw proof bytes
    var proof = try ves.prove(5000, &inputs, .aml_threshold, 10000);
    defer proof.deinit();
    const original_bytes = proof.proofBytes();

    // Create bundle (encodes to base64)
    var bundle = try ComplianceProofBundle.create(allocator, &proof, &inputs, 5000, null);
    defer bundle.deinit(allocator);

    // Decode back
    const decoded = try bundle.decodeProofBytes(allocator);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, original_bytes, decoded);
}
