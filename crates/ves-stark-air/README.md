# ves-stark-air

AIR (Algebraic Intermediate Representation) constraint definitions for VES STARK proofs.

## Overview

Defines the constraint system that enforces compliance rules inside STARK proofs. Each policy (AML threshold, order total cap, agent authorization) is expressed as a set of algebraic constraints over an execution trace.

- **Max constraint degree**: 10 (from Rescue half-round transitions)
- **Requires**: blowup factor >= 16
- **Framework**: Winterfell v0.10

## Modules

| Module | Description |
|--------|-------------|
| `compliance` | `ComplianceAir` — main AIR orchestrator |
| `policies` | Policy-specific constraints (`aml_threshold`, `order_total_cap`) |
| `policy` | `Policy`, `PolicyError`, `ComparisonType` abstractions |
| `rescue_air` | Rescue-Prime hash constraints (in-circuit) |
| `range_check` | Range proof validation constraints |
| `trace` | `TraceInfo`, `TRACE_WIDTH` — trace layout definitions |

## Public API

```rust
use ves_stark_air::{ComplianceAir, Policy, ProofOptions};
```

- `ComplianceAir` — constructs the AIR from public inputs and policy parameters
- `Policy` — policy type selection and parameter validation
- `ProofOptions` — proof configuration (blowup factor, field extension, query count)

## Constraint Degree Groups

| Group | Degree | Description |
|-------|--------|-------------|
| Structural | 2 | Flag transitions, step counters |
| Rescue | 10 | Half-round S-box (pow7) |
| Input binding | 2–3 | Hash input wiring |
| Output binding | 3–4 | Hash output wiring |

## License

MIT
