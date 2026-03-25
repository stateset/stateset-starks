# ves-stark-air

[![crates.io](https://img.shields.io/crates/v/ves-stark-air.svg)](https://crates.io/crates/ves-stark-air)
[![license](https://img.shields.io/crates/l/ves-stark-air.svg)](../LICENSE)

AIR (Algebraic Intermediate Representation) constraint definitions for VES STARK proofs.

## Overview

Defines the constraint system that enforces compliance rules inside STARK proofs. Each policy (AML threshold, order total cap, agent authorization) is expressed as a set of algebraic constraints over an execution trace.

- **157 transition constraints** + **80 boundary assertions**
- **Max constraint degree**: 9 (Rescue half-round transitions)
- **Trace**: 248 columns x 16 rows (minimum)
- **Requires**: blowup factor >= 16

## Installation

```toml
[dependencies]
ves-stark-air = "0.3"
```

## Proof Options

```rust
use ves_stark_air::ProofOptions;

let opts = ProofOptions::default();  // 82-bit security, ~17ms prove
let fast = ProofOptions::fast();     // Lower security for testing
let secure = ProofOptions::secure(); // ~128-bit security
```

## Modules

| Module | Description |
|--------|-------------|
| `compliance` | `ComplianceAir` — main AIR orchestrator |
| `policies` | Policy-specific constraints (`aml_threshold`, `order_total_cap`) |
| `policy` | `Policy`, `PolicyError`, `ComparisonType` abstractions |
| `rescue_air` | Rescue-Prime hash constraints (in-circuit) |
| `range_check` | Range proof validation constraints |
| `trace` | `TraceInfo`, `TRACE_WIDTH` — trace layout definitions |

## Constraint Summary

| Category | Count | Degree |
|----------|-------|--------|
| Round counter | 1 | 1 |
| Amount bit binary | 64 | 3 |
| Amount recomposition | 2 | 2 |
| Diff bit binary | 64 | 3 |
| Diff recomposition | 2 | 2 |
| Borrow binary | 2 | 3 |
| Subtraction | 2 | 2 |
| Rescue permutation | 12 | 9 |
| Rescue init binding | 8 | 2 |

## License

MIT
