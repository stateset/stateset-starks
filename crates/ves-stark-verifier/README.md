# ves-stark-verifier

STARK proof verification for VES compliance proofs.

## Overview

Stateless verifier for VES STARK proofs. Supports multiple verification modes including compliance proofs, agent authorization proofs, and amount-binding verification. Enforces proof size limits (10 MB) and version checking.

## Public API

```rust
use ves_stark_verifier::{ComplianceVerifier, VerificationResult};

let verifier = ComplianceVerifier::new();

// Basic verification
let result = verifier.verify(&proof_bytes, &public_inputs, &witness_commitment)?;

// With amount binding
let result = verifier.verify_with_amount_binding(
    &proof_bytes, &public_inputs, &amount_binding
)?;

// Agent authorization
let result = verifier.verify_agent_authorization(
    &proof_bytes, &public_inputs, &witness_commitment, &receipt
)?;
```

## Verification Modes

| Mode | Description |
|------|-------------|
| Basic compliance | Verify proof against public inputs + witness commitment |
| Amount binding | Additional binding between proof and declared amount |
| Strict compliance | Enforces all binding checks |
| Agent authorization | Verifies agent auth receipt + intent hash binding |
| Agent auth + amount | Agent authorization with amount binding |
| Agent auth + witness | Agent authorization with witness commitment binding |

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PROOF_SIZE` | 10 MB | Maximum accepted proof size |
| `PROOF_VERSION` | Current | Expected proof format version |

## Key Types

| Type | Description |
|------|-------------|
| `ComplianceVerifier` | Stateless verifier (no setup needed) |
| `VerificationResult` | Outcome with timing information |
| `VerifierError` | Typed error variants |

## License

MIT
