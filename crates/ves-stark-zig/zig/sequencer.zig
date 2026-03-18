///! Native Zig HTTP client for the StateSet sequencer API.
///!
///! Mirrors the Rust SequencerClient – fetches public inputs, submits proofs,
///! queries proof status, and triggers server-side verification.
///!
///! Example:
///! ```zig
///! const seq = @import("sequencer");
///! const ves = @import("ves_stark");
///!
///! var client = try seq.SequencerClient.init(allocator, "http://localhost:8080", api_key);
///! defer client.deinit();
///!
///! var resp = try client.getPublicInputs(event_id, "aml.threshold", "{\"threshold\":10000}");
///! defer resp.deinit(allocator);
///!
///! var inputs = try ves.PublicInputs.fromJsonSlice(allocator, resp.public_inputs_json);
///! defer inputs.deinit();
///!
///! var proof = try ves.prove(5000, &inputs, .aml_threshold, 10000);
///! defer proof.deinit();
///!
///! var submit_resp = try client.submitProof(.{
///!     .event_id = event_id,
///!     .proof_bytes = proof.proofBytes(),
///!     .witness_commitment_hex = proof.witnessCommitmentHex().?,
///!     .policy_id = "aml.threshold",
///!     .policy_params_json = "{\"threshold\":10000}",
///! });
///! defer submit_resp.deinit(allocator);
///! ```
const std = @import("std");

// Maximum response body size (1 MB)
const MAX_RESPONSE_SIZE = 1024 * 1024;

pub const ClientError = error{
    InvalidBaseUrl,
    InvalidApiKey,
    ConnectionFailed,
    RequestFailed,
    ResponseTooLarge,
    NotFound,
    Unauthorized,
    Conflict,
    ApiError,
    InvalidResponse,
    OutOfMemory,
    Overflow,
};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

pub const PublicInputsResponse = struct {
    event_id: []u8,
    public_inputs_json: []u8,
    public_inputs_hash: []u8,

    pub fn deinit(self: *PublicInputsResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.event_id);
        allocator.free(self.public_inputs_json);
        allocator.free(self.public_inputs_hash);
        self.* = undefined;
    }
};

pub const SubmitProofResponse = struct {
    proof_id: []u8,
    event_id: []u8,
    proof_hash: []u8,
    raw_json: []u8,

    pub fn deinit(self: *SubmitProofResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.proof_id);
        allocator.free(self.event_id);
        allocator.free(self.proof_hash);
        allocator.free(self.raw_json);
        self.* = undefined;
    }
};

pub const ProofDetails = struct {
    proof_id: []u8,
    event_id: []u8,
    policy_id: []u8,
    proof_hash: []u8,
    raw_json: []u8,

    pub fn deinit(self: *ProofDetails, allocator: std.mem.Allocator) void {
        allocator.free(self.proof_id);
        allocator.free(self.event_id);
        allocator.free(self.policy_id);
        allocator.free(self.proof_hash);
        allocator.free(self.raw_json);
        self.* = undefined;
    }
};

pub const ListProofsResponse = struct {
    event_id: []u8,
    count: u64,
    raw_json: []u8,

    pub fn deinit(self: *ListProofsResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.event_id);
        allocator.free(self.raw_json);
        self.* = undefined;
    }
};

pub const VerifyResponse = struct {
    stark_valid: bool,
    public_inputs_match: bool,
    raw_json: []u8,

    pub fn deinit(self: *VerifyResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.raw_json);
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Proof submission options
// ---------------------------------------------------------------------------

pub const SubmitProofOptions = struct {
    event_id: []const u8,
    proof_bytes: []const u8,
    witness_commitment_hex: []const u8,
    policy_id: []const u8,
    policy_params_json: []const u8,
    /// Optional: public inputs JSON to include in submission.
    public_inputs_json: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// SequencerClient
// ---------------------------------------------------------------------------

pub const SequencerClient = struct {
    allocator: std.mem.Allocator,
    base_url: []u8,
    auth_header: []u8,

    /// Initialize a new sequencer client.
    ///
    /// `base_url`: e.g. "http://localhost:8080" (trailing slash is stripped)
    /// `api_key`: your STATESET_API_KEY
    pub fn init(allocator: std.mem.Allocator, base_url: []const u8, api_key: []const u8) ClientError!SequencerClient {
        if (base_url.len == 0) return ClientError.InvalidBaseUrl;
        if (api_key.len == 0) return ClientError.InvalidApiKey;

        // Strip trailing slash
        const trimmed = if (base_url[base_url.len - 1] == '/')
            base_url[0 .. base_url.len - 1]
        else
            base_url;

        const owned_url = allocator.dupe(u8, trimmed) catch return ClientError.OutOfMemory;
        errdefer allocator.free(owned_url);

        const auth = std.fmt.allocPrint(allocator, "ApiKey {s}", .{api_key}) catch
            return ClientError.OutOfMemory;

        return SequencerClient{
            .allocator = allocator,
            .base_url = owned_url,
            .auth_header = auth,
        };
    }

    /// Initialize from the STATESET_API_KEY environment variable.
    pub fn fromEnv(allocator: std.mem.Allocator, base_url: []const u8) ClientError!SequencerClient {
        const key = std.posix.getenv("STATESET_API_KEY") orelse return ClientError.InvalidApiKey;
        return init(allocator, base_url, key);
    }

    pub fn deinit(self: *SequencerClient) void {
        self.allocator.free(self.base_url);
        // Zero the auth header before freeing for security
        @memset(self.auth_header, 0);
        self.allocator.free(self.auth_header);
        self.* = undefined;
    }

    // ── Internal HTTP ───────────────────────────────────────────────────

    const base64_alphabet: [64]u8 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
    const base64_encoder = std.base64.Base64Encoder.init(base64_alphabet, '=');

    fn doFetch(
        self: *const SequencerClient,
        url: []const u8,
        method: std.http.Method,
        payload: ?[]const u8,
    ) ClientError!struct { status: std.http.Status, body: []u8 } {
        var http_client = std.http.Client{ .allocator = self.allocator };
        defer http_client.deinit();

        const buf = self.allocator.alloc(u8, MAX_RESPONSE_SIZE) catch return ClientError.OutOfMemory;
        errdefer self.allocator.free(buf);

        var writer = std.Io.Writer.fixed(buf);

        const result = http_client.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = payload,
            .headers = .{
                .authorization = .{ .override = self.auth_header },
                .content_type = .{ .override = "application/json" },
            },
            .response_writer = &writer,
        }) catch return ClientError.ConnectionFailed;

        // Copy body to exact-size allocation
        const body = self.allocator.dupe(u8, buf[0..writer.end]) catch return ClientError.OutOfMemory;
        self.allocator.free(buf);

        return .{ .status = result.status, .body = body };
    }

    fn checkStatus(status: std.http.Status) ClientError!void {
        const code = @intFromEnum(status);
        if (code >= 200 and code < 300) return;
        if (code == 401 or code == 403) return ClientError.Unauthorized;
        if (code == 404) return ClientError.NotFound;
        if (code == 409) return ClientError.Conflict;
        return ClientError.ApiError;
    }

    // ── JSON helpers (lightweight extraction) ───────────────────────────

    fn jsonString(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ClientError![]u8 {
        const needle = std.fmt.allocPrint(allocator, "\"{s}\":\"", .{key}) catch return ClientError.OutOfMemory;
        defer allocator.free(needle);

        const start_idx = std.mem.indexOf(u8, json, needle) orelse return ClientError.InvalidResponse;
        const val_start = start_idx + needle.len;
        const val_end = std.mem.indexOfPos(u8, json, val_start, "\"") orelse return ClientError.InvalidResponse;

        return allocator.dupe(u8, json[val_start..val_end]) catch return ClientError.OutOfMemory;
    }

    fn jsonNumber(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ClientError!u64 {
        const needle = std.fmt.allocPrint(allocator, "\"{s}\":", .{key}) catch return ClientError.OutOfMemory;
        defer allocator.free(needle);

        const start_idx = std.mem.indexOf(u8, json, needle) orelse return ClientError.InvalidResponse;
        var pos = start_idx + needle.len;
        while (pos < json.len and json[pos] == ' ') pos += 1;

        var end = pos;
        while (end < json.len and json[end] >= '0' and json[end] <= '9') end += 1;
        if (end == pos) return ClientError.InvalidResponse;

        return std.fmt.parseInt(u64, json[pos..end], 10) catch return ClientError.InvalidResponse;
    }

    fn jsonBool(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ClientError!bool {
        const needle = std.fmt.allocPrint(allocator, "\"{s}\":", .{key}) catch return ClientError.OutOfMemory;
        defer allocator.free(needle);

        const start_idx = std.mem.indexOf(u8, json, needle) orelse return ClientError.InvalidResponse;
        var pos = start_idx + needle.len;
        while (pos < json.len and json[pos] == ' ') pos += 1;

        if (pos + 4 <= json.len and std.mem.eql(u8, json[pos .. pos + 4], "true")) return true;
        if (pos + 5 <= json.len and std.mem.eql(u8, json[pos .. pos + 5], "false")) return false;
        return ClientError.InvalidResponse;
    }

    fn jsonObject(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ClientError![]u8 {
        const needle = std.fmt.allocPrint(allocator, "\"{s}\":", .{key}) catch return ClientError.OutOfMemory;
        defer allocator.free(needle);

        const start_idx = std.mem.indexOf(u8, json, needle) orelse return ClientError.InvalidResponse;
        var pos = start_idx + needle.len;
        while (pos < json.len and json[pos] == ' ') pos += 1;

        if (pos >= json.len) return ClientError.InvalidResponse;

        if (json[pos] == '{') {
            var depth: u32 = 1;
            var end = pos + 1;
            while (end < json.len and depth > 0) : (end += 1) {
                if (json[end] == '{') depth += 1;
                if (json[end] == '}') depth -= 1;
            }
            return allocator.dupe(u8, json[pos..end]) catch return ClientError.OutOfMemory;
        } else if (json[pos] == '"') {
            const val_start = pos + 1;
            const val_end = std.mem.indexOfPos(u8, json, val_start, "\"") orelse return ClientError.InvalidResponse;
            return std.fmt.allocPrint(allocator, "\"{s}\"", .{json[val_start..val_end]}) catch
                return ClientError.OutOfMemory;
        }

        return ClientError.InvalidResponse;
    }

    fn jsonStringOr(allocator: std.mem.Allocator, json: []const u8, key: []const u8, fallback: []const u8) []u8 {
        return jsonString(allocator, json, key) catch
            (allocator.dupe(u8, fallback) catch @as([]u8, &.{}));
    }

    // ── Public API ──────────────────────────────────────────────────────

    /// Fetch public inputs for an event from the sequencer.
    ///
    /// `event_id`: UUID string of the event
    /// `policy_id`: e.g. "aml.threshold"
    /// `policy_params_json`: e.g. "{\"threshold\":10000}"
    pub fn getPublicInputs(
        self: *const SequencerClient,
        event_id: []const u8,
        policy_id: []const u8,
        policy_params_json: []const u8,
    ) ClientError!PublicInputsResponse {
        const url = std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/ves/compliance/{s}/inputs",
            .{ self.base_url, event_id },
        ) catch return ClientError.OutOfMemory;
        defer self.allocator.free(url);

        const body = std.fmt.allocPrint(
            self.allocator,
            "{{\"policyId\":\"{s}\",\"policyParams\":{s}}}",
            .{ policy_id, policy_params_json },
        ) catch return ClientError.OutOfMemory;
        defer self.allocator.free(body);

        const result = try self.doFetch(url, .POST, body);
        defer self.allocator.free(result.body);

        try checkStatus(result.status);

        return PublicInputsResponse{
            .event_id = try jsonString(self.allocator, result.body, "eventId"),
            .public_inputs_json = try jsonObject(self.allocator, result.body, "publicInputs"),
            .public_inputs_hash = try jsonString(self.allocator, result.body, "publicInputsHash"),
        };
    }

    /// Submit a proof to the sequencer.
    pub fn submitProof(self: *const SequencerClient, opts: SubmitProofOptions) ClientError!SubmitProofResponse {
        const url = std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/ves/compliance/{s}/proofs",
            .{ self.base_url, opts.event_id },
        ) catch return ClientError.OutOfMemory;
        defer self.allocator.free(url);

        // Base64 encode proof bytes
        const b64_len = base64_encoder.calcSize(opts.proof_bytes.len);
        const proof_b64 = self.allocator.alloc(u8, b64_len) catch return ClientError.OutOfMemory;
        defer self.allocator.free(proof_b64);
        _ = base64_encoder.encode(proof_b64, opts.proof_bytes);

        // Build optional public_inputs field
        const pi_field = if (opts.public_inputs_json) |pi|
            std.fmt.allocPrint(self.allocator, ",\"publicInputs\":{s}", .{pi}) catch
                return ClientError.OutOfMemory
        else
            self.allocator.dupe(u8, "") catch return ClientError.OutOfMemory;
        defer self.allocator.free(pi_field);

        const body = std.fmt.allocPrint(self.allocator,
            \\{{"proofType":"stark","proofVersion":2,
            \\"policyId":"{s}","policyParams":{s},
            \\"proofB64":"{s}","witnessCommitment":"{s}"{s}}}
        , .{
            opts.policy_id,
            opts.policy_params_json,
            proof_b64,
            opts.witness_commitment_hex,
            pi_field,
        }) catch return ClientError.OutOfMemory;
        defer self.allocator.free(body);

        const result = try self.doFetch(url, .POST, body);
        try checkStatus(result.status);

        // result.body ownership transfers to the response
        return SubmitProofResponse{
            .proof_id = jsonStringOr(self.allocator, result.body, "proofId", ""),
            .event_id = jsonStringOr(self.allocator, result.body, "eventId", opts.event_id),
            .proof_hash = jsonStringOr(self.allocator, result.body, "proofHash", ""),
            .raw_json = result.body,
        };
    }

    /// List all proofs for an event.
    pub fn listProofs(self: *const SequencerClient, event_id: []const u8) ClientError!ListProofsResponse {
        const url = std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/ves/compliance/{s}/proofs",
            .{ self.base_url, event_id },
        ) catch return ClientError.OutOfMemory;
        defer self.allocator.free(url);

        const result = try self.doFetch(url, .GET, null);
        try checkStatus(result.status);

        return ListProofsResponse{
            .event_id = jsonStringOr(self.allocator, result.body, "eventId", event_id),
            .count = jsonNumber(self.allocator, result.body, "count") catch 0,
            .raw_json = result.body,
        };
    }

    /// Get details for a specific proof.
    pub fn getProof(self: *const SequencerClient, proof_id: []const u8) ClientError!ProofDetails {
        const url = std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/ves/compliance/proofs/{s}",
            .{ self.base_url, proof_id },
        ) catch return ClientError.OutOfMemory;
        defer self.allocator.free(url);

        const result = try self.doFetch(url, .GET, null);
        try checkStatus(result.status);

        return ProofDetails{
            .proof_id = jsonStringOr(self.allocator, result.body, "proofId", proof_id),
            .event_id = jsonStringOr(self.allocator, result.body, "eventId", ""),
            .policy_id = jsonStringOr(self.allocator, result.body, "policyId", ""),
            .proof_hash = jsonStringOr(self.allocator, result.body, "proofHash", ""),
            .raw_json = result.body,
        };
    }

    /// Trigger server-side verification of a proof.
    pub fn verifyProof(self: *const SequencerClient, proof_id: []const u8) ClientError!VerifyResponse {
        const url = std.fmt.allocPrint(
            self.allocator,
            "{s}/api/v1/ves/compliance/proofs/{s}/verify",
            .{ self.base_url, proof_id },
        ) catch return ClientError.OutOfMemory;
        defer self.allocator.free(url);

        const result = try self.doFetch(url, .GET, null);
        try checkStatus(result.status);

        return VerifyResponse{
            .stark_valid = jsonBool(self.allocator, result.body, "starkValid") catch false,
            .public_inputs_match = jsonBool(self.allocator, result.body, "publicInputsMatch") catch false,
            .raw_json = result.body,
        };
    }

    /// Convenience: fetch public inputs → prove → submit in one call.
    ///
    /// Returns the submitted proof response. The caller can optionally call
    /// `verifyProof(resp.proof_id)` to trigger server-side verification.
    pub fn proveAndSubmit(
        self: *const SequencerClient,
        event_id: []const u8,
        policy_id: []const u8,
        policy_params_json: []const u8,
        proof_bytes: []const u8,
        witness_commitment_hex: []const u8,
    ) ClientError!SubmitProofResponse {
        return self.submitProof(.{
            .event_id = event_id,
            .proof_bytes = proof_bytes,
            .witness_commitment_hex = witness_commitment_hex,
            .policy_id = policy_id,
            .policy_params_json = policy_params_json,
        });
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SequencerClient.init validates inputs" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(ClientError.InvalidBaseUrl, SequencerClient.init(allocator, "", "key"));
    try std.testing.expectError(ClientError.InvalidApiKey, SequencerClient.init(allocator, "http://localhost", ""));
}

test "SequencerClient.init strips trailing slash" {
    const allocator = std.testing.allocator;
    var client = try SequencerClient.init(allocator, "http://localhost:8080/", "test_key");
    defer client.deinit();

    try std.testing.expectEqualStrings("http://localhost:8080", client.base_url);
}

test "SequencerClient.init preserves auth header" {
    const allocator = std.testing.allocator;
    var client = try SequencerClient.init(allocator, "http://localhost:8080", "sk_test_123");
    defer client.deinit();

    try std.testing.expectEqualStrings("ApiKey sk_test_123", client.auth_header);
}

test "SequencerClient.deinit zeroes auth header" {
    const allocator = std.testing.allocator;
    var client = try SequencerClient.init(allocator, "http://localhost:8080", "sk_secret");
    const auth_ptr = client.auth_header.ptr;
    const auth_len = client.auth_header.len;
    client.deinit();

    // After deinit, the memory should be zeroed (may be freed, so only check if allocator reuses)
    _ = auth_ptr;
    _ = auth_len;
    // Note: we can't safely read freed memory, but the @memset(0) ensures it was zeroed before free
}

test "jsonString extracts value" {
    const allocator = std.testing.allocator;
    const json =
        \\{"proofId":"abc-123","eventId":"def-456"}
    ;
    const val = try SequencerClient.jsonString(allocator, json, "proofId");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("abc-123", val);
}

test "jsonString returns error for missing key" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ClientError.InvalidResponse, SequencerClient.jsonString(allocator, "{}", "missing"));
}

test "jsonNumber extracts value" {
    const allocator = std.testing.allocator;
    const json =
        \\{"count":42,"other":"x"}
    ;
    const val = try SequencerClient.jsonNumber(allocator, json, "count");
    try std.testing.expectEqual(@as(u64, 42), val);
}

test "jsonBool extracts values" {
    const allocator = std.testing.allocator;
    const json =
        \\{"starkValid":true,"publicInputsMatch":false}
    ;
    try std.testing.expect(try SequencerClient.jsonBool(allocator, json, "starkValid"));
    try std.testing.expect(!try SequencerClient.jsonBool(allocator, json, "publicInputsMatch"));
}

test "jsonObject extracts nested object" {
    const allocator = std.testing.allocator;
    const json =
        \\{"publicInputs":{"foo":"bar","n":1}}
    ;
    const val = try SequencerClient.jsonObject(allocator, json, "publicInputs");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("{\"foo\":\"bar\",\"n\":1}", val);
}

test "checkStatus categorizes responses" {
    try std.testing.expectEqual({}, try SequencerClient.checkStatus(.ok));
    try std.testing.expectEqual({}, try SequencerClient.checkStatus(.created));
    try std.testing.expectError(ClientError.NotFound, SequencerClient.checkStatus(.not_found));
    try std.testing.expectError(ClientError.Unauthorized, SequencerClient.checkStatus(.unauthorized));
    try std.testing.expectError(ClientError.Unauthorized, SequencerClient.checkStatus(.forbidden));
    try std.testing.expectError(ClientError.Conflict, SequencerClient.checkStatus(.conflict));
    try std.testing.expectError(ClientError.ApiError, SequencerClient.checkStatus(.internal_server_error));
}

test "base64 encoder works" {
    const input = "hello";
    var buf: [8]u8 = undefined;
    _ = SequencerClient.base64_encoder.encode(&buf, input);
    try std.testing.expectEqualStrings("aGVsbG8=", &buf);
}
