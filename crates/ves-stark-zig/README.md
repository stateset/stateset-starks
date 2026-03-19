# ves-stark-zig

C FFI bindings for the VES STARK proof system, with an idiomatic Zig wrapper.

## Overview

Exposes the VES STARK prover and verifier through a C-compatible FFI layer (Rust `staticlib`/`cdylib`), along with Zig modules that wrap the FFI into a native Zig API. Suitable for embedding in Zig, C, or C++ applications.

## Architecture

```
Rust (ves-stark-zig crate)     Zig wrapper modules
┌─────────────────────┐       ┌─────────────────────┐
│  C FFI layer        │──────▶│  ves_stark.zig       │
│  - Opaque handles   │       │  sequencer.zig       │
│  - Error codes      │       │  bundle.zig          │
│  - JSON I/O         │       │  batch.zig           │
└─────────────────────┘       └─────────────────────┘
```

## Build

```bash
# Build the Rust static library
cargo build --release -p ves-stark-zig

# Build Zig project (links the static library)
cd crates/ves-stark-zig
zig build
```

## Zig API

```zig
const ves = @import("ves_stark");

// Create public inputs and prove
var inputs = try ves.PublicInputs.fromJson(json_str);
defer inputs.deinit();

var proof = try ves.prove(5000, inputs, .aml_threshold, 10000);
defer proof.deinit();

// Verify
var result = try ves.verifyHex(proof.bytes(), inputs, witness_hex);
defer result.deinit();
```

## C FFI

### Error Codes

| Code | Name | Value |
|------|------|-------|
| `VES_OK` | Success | 0 |
| `VES_ERR_INVALID_ARG` | Invalid argument | -1 |
| `VES_ERR_PROOF_FAILED` | Proof generation failed | -2 |
| `VES_ERR_VERIFY_FAILED` | Verification failed | -3 |
| `VES_ERR_JSON` | JSON serialization error | -4 |
| `VES_ERR_NULL_PTR` | Null pointer | -5 |

### Opaque Handles

- `VesPublicInputs` — public inputs handle
- `VesProof` — proof handle
- `VesVerificationResult` — verification result handle

## Zig Modules

| Module | Description |
|--------|-------------|
| `ves_stark.zig` | Core prover/verifier with `PolicyType` enum, `Proof`, `PublicInputs`, `VerificationResult` |
| `sequencer.zig` | HTTP client for sequencer interaction |
| `bundle.zig` | Proof bundle utilities |
| `batch.zig` | Batch proof support (requires `batch` feature) |
| `example.zig` | Example usage |

## Features

| Feature | Description |
|---------|-------------|
| `batch` | Enable batch proof support via `ves-stark-batch` |

## License

MIT
