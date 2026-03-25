# ves-stark-verifier

[![crates.io](https://img.shields.io/crates/v/ves-stark-verifier.svg)](https://crates.io/crates/ves-stark-verifier)
[![license](https://img.shields.io/crates/l/ves-stark-verifier.svg)](../LICENSE)

STARK proof verification for VES compliance proofs.

## Overview

Stateless verifier for VES STARK proofs. Supports multiple verification modes including compliance proofs, agent authorization proofs, and amount-binding verification. Verification takes <5ms. Enforces proof size limits (10 MB) and version checking.

## Installation

```toml
[dependencies]
ves-stark-verifier = "0.3"
```

## Usage

```rust
use ves_stark_verifier::verify_compliance_proof_auto_bound_strict;

// Strict verification with automatic witness binding
let result = verify_compliance_proof_auto_bound_strict(
    &proof_bytes,
    &public_inputs,
)?;
assert!(result.valid);
```

## Verification Modes

| Mode | Description |
|------|-------------|
| Basic compliance | Verify proof against public inputs + witness commitment |
| Amount binding | Additional binding between proof and declared amount |
| Strict compliance | Enforces all binding checks |
| Agent authorization | Verifies agent auth receipt + intent hash binding |

## Key Types

| Type | Description |
|------|-------------|
| `ComplianceVerifier` | Stateless verifier (no setup needed) |
| `VerificationResult` | Outcome with timing information |
| `VerifierError` | Typed error variants |

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PROOF_SIZE` | 10 MB | Maximum accepted proof size |

## License

MIT
