///! Example: generate and verify a STARK compliance proof using the VES STARK Zig client.
///!
///! Run modes:
///!   ./ves-stark-example                 — local prove + verify (no sequencer needed)
///!   ./ves-stark-example --sequencer URL — fetch inputs from sequencer, prove, submit, verify
const std = @import("std");
const ves = @import("ves_stark");
const seq = @import("sequencer");
const bun = @import("bundle");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== VES STARK Zig Client Example ===\n\n", .{});

    // Check for --sequencer flag
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var sequencer_url: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--sequencer") and i + 1 < args.len) {
            sequencer_url = args[i + 1];
            i += 1;
        }
    }

    if (sequencer_url) |url| {
        try runSequencerMode(allocator, url);
    } else {
        try runLocalMode(allocator);
    }
}

// ---------------------------------------------------------------------------
// Local mode: standalone prove + verify (no sequencer needed)
// ---------------------------------------------------------------------------

fn runLocalMode(allocator: std.mem.Allocator) !void {
    std.debug.print("[mode] Local prove + verify\n\n", .{});

    // ── 1. Build public inputs using the builder ────────────────────────

    const builder = ves.PublicInputsBuilder{
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

    var inputs = try builder.build();
    defer inputs.deinit();

    std.debug.print("[ok] Public inputs built (policy hash auto-computed)\n", .{});

    // ── 2. Generate proof ───────────────────────────────────────────────

    const amount: u64 = 5000;

    var proof = ves.prove(amount, &inputs, .aml_threshold, 10000) catch |e| {
        std.debug.print("[err] Proof generation failed: {}\n", .{e});
        if (ves.lastError()) |msg| std.debug.print("      {s}\n", .{msg});
        return e;
    };
    defer proof.deinit();

    std.debug.print("[ok] Proof generated\n", .{});
    std.debug.print("     size:       {} bytes\n", .{proof.proofSize()});
    std.debug.print("     time:       {} ms\n", .{proof.provingTimeMs()});
    if (proof.proofHash()) |h| std.debug.print("     hash:       {s}\n", .{h});
    if (proof.witnessCommitmentHex()) |wc| std.debug.print("     commitment: {s}\n", .{wc});

    // ── 3. Create payload amount binding ────────────────────────────────

    var binding = try ves.createPayloadAmountBinding(&inputs, amount);
    defer binding.deinit();
    std.debug.print("[ok] Amount binding: {s}\n", .{binding.slice()});

    // ── 4. Verify proof (hex variant – recommended) ─────────────────────

    const wc_hex = proof.witnessCommitmentHex() orelse return error.InvalidArg;
    const wc_hex_z: [*:0]const u8 = @ptrCast(wc_hex.ptr);

    var result = ves.verifyHex(proof.proofBytes(), &inputs, wc_hex_z) catch |e| {
        std.debug.print("[err] Verification failed: {}\n", .{e});
        if (ves.lastError()) |msg| std.debug.print("      {s}\n", .{msg});
        return e;
    };
    defer result.deinit();

    std.debug.print("[ok] Verification complete\n", .{});
    std.debug.print("     valid:      {}\n", .{result.valid()});
    std.debug.print("     time:       {} ms\n", .{result.verificationTimeMs()});
    if (result.policyId()) |pid| std.debug.print("     policy:     {s}\n", .{pid});
    std.debug.print("     limit:      {}\n", .{result.policyLimit()});

    if (result.valid()) {
        std.debug.print("\nProof is valid!\n", .{});
    } else {
        std.debug.print("\nProof is INVALID.\n", .{});
        if (result.err()) |msg| std.debug.print("  reason: {s}\n", .{msg});
    }

    // ── 5. Also verify with u64 commitment (for completeness) ───────────

    const commitment = try proof.witnessCommitment();

    var result2 = ves.verify(proof.proofBytes(), &inputs, &commitment) catch |e| {
        std.debug.print("[err] u64 verification failed: {}\n", .{e});
        return e;
    };
    defer result2.deinit();

    std.debug.print("[ok] u64-commitment verification: valid={}\n", .{result2.valid()});

    // ── 6. Create compliance proof bundle ────────────────────────────────

    std.debug.print("\n--- Bundle Demo ---\n\n", .{});

    var bundle = bun.proveComplianceBundle(allocator, 7500, &inputs, .aml_threshold, 10000) catch |e| {
        std.debug.print("[err] Bundle creation failed: {}\n", .{e});
        return e;
    };
    defer bundle.deinit(allocator);

    std.debug.print("[ok] Bundle created\n", .{});
    std.debug.print("     version:    {}\n", .{bundle.version});
    std.debug.print("     proof_hash: {s}\n", .{bundle.proof_hash});
    std.debug.print("     bundle_hash:{s}\n", .{bundle.bundle_hash});

    // Serialize to JSON
    const bundle_json = try bundle.toJson(allocator);
    defer allocator.free(bundle_json);

    std.debug.print("[ok] Bundle serialized ({} bytes JSON)\n", .{bundle_json.len});

    // Deserialize and validate
    var bundle2 = bun.ComplianceProofBundle.fromJson(allocator, bundle_json) catch |e| {
        std.debug.print("[err] Bundle deserialization failed: {}\n", .{e});
        return e;
    };
    defer bundle2.deinit(allocator);

    bundle2.validate(allocator) catch |e| {
        std.debug.print("[err] Bundle validation failed: {}\n", .{e});
        return e;
    };

    std.debug.print("[ok] Bundle roundtrip: deserialized and validated\n", .{});
    std.debug.print("     hashes match: {}\n", .{std.mem.eql(u8, bundle.bundle_hash, bundle2.bundle_hash)});

    // Local verification from deserialized bundle
    var vresult = bundle2.verify(allocator) catch |e| {
        std.debug.print("[err] Bundle verification failed: {}\n", .{e});
        if (ves.lastError()) |msg| std.debug.print("      {s}\n", .{msg});
        return e;
    };
    defer vresult.deinit();

    std.debug.print("[ok] Bundle locally verified: valid={}\n", .{vresult.valid()});

    // Strict validation (re-derives proof hash from decoded bytes)
    bundle2.validateStrict(allocator) catch |e| {
        std.debug.print("[err] Strict validation failed: {}\n", .{e});
        return e;
    };

    std.debug.print("[ok] Bundle strict validation passed\n", .{});
}

// ---------------------------------------------------------------------------
// Sequencer mode: fetch inputs → prove → submit → verify via sequencer
// ---------------------------------------------------------------------------

fn runSequencerMode(allocator: std.mem.Allocator, url: []const u8) !void {
    std.debug.print("[mode] Sequencer at {s}\n\n", .{url});

    // ── 1. Initialize sequencer client ──────────────────────────────────

    var client = seq.SequencerClient.fromEnv(allocator, url) catch |e| {
        if (e == seq.ClientError.InvalidApiKey) {
            std.debug.print("[err] Set STATESET_API_KEY environment variable\n", .{});
            return e;
        }
        std.debug.print("[err] Failed to create client: {}\n", .{e});
        return e;
    };
    defer client.deinit();

    std.debug.print("[ok] Sequencer client initialized\n", .{});

    // ── 2. Fetch public inputs ──────────────────────────────────────────

    const event_id = "00000000-0000-0000-0000-000000000001";
    const policy_params = "{\"threshold\":10000}";

    var pi_resp = client.getPublicInputs(event_id, "aml.threshold", policy_params) catch |e| {
        std.debug.print("[err] Failed to fetch public inputs: {}\n", .{e});
        return e;
    };
    defer pi_resp.deinit(allocator);

    std.debug.print("[ok] Public inputs fetched (hash={s})\n", .{pi_resp.public_inputs_hash});

    // ── 3. Parse and prove ──────────────────────────────────────────────

    var inputs = try ves.PublicInputs.fromJsonSlice(allocator, pi_resp.public_inputs_json);
    defer inputs.deinit();

    var proof = ves.prove(5000, &inputs, .aml_threshold, 10000) catch |e| {
        std.debug.print("[err] Proof generation failed: {}\n", .{e});
        if (ves.lastError()) |msg| std.debug.print("      {s}\n", .{msg});
        return e;
    };
    defer proof.deinit();

    std.debug.print("[ok] Proof generated ({} bytes, {} ms)\n", .{ proof.proofSize(), proof.provingTimeMs() });

    // ── 4. Submit to sequencer ──────────────────────────────────────────

    const wc_hex = proof.witnessCommitmentHex() orelse return error.InvalidArg;

    var submit_resp = client.submitProof(.{
        .event_id = event_id,
        .proof_bytes = proof.proofBytes(),
        .witness_commitment_hex = wc_hex,
        .policy_id = "aml.threshold",
        .policy_params_json = policy_params,
    }) catch |e| {
        std.debug.print("[err] Failed to submit proof: {}\n", .{e});
        return e;
    };
    defer submit_resp.deinit(allocator);

    std.debug.print("[ok] Proof submitted (id={s})\n", .{submit_resp.proof_id});

    // ── 5. Verify via sequencer ─────────────────────────────────────────

    var verify_resp = client.verifyProof(submit_resp.proof_id) catch |e| {
        std.debug.print("[err] Failed to verify proof: {}\n", .{e});
        return e;
    };
    defer verify_resp.deinit(allocator);

    std.debug.print("[ok] Server verification: stark_valid={}, inputs_match={}\n", .{
        verify_resp.stark_valid,
        verify_resp.public_inputs_match,
    });
}
