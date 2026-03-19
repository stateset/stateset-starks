# ves-stark-primitives

Cryptographic primitives for VES STARK proofs.

## Overview

Foundation crate providing the core field arithmetic, hash functions, and data types used across the entire VES STARK proof system.

- **Field**: Goldilocks (p = 2^64 - 2^32 + 1) — a 64-bit STARK-friendly prime field
- **Hash**: Rescue-Prime (7 rounds, 12-element state, alpha=7 S-box)
- **Framework**: Built on [Winterfell](https://github.com/novifinancial/winterfell) v0.10

## Modules

| Module | Description |
|--------|-------------|
| `field` | Goldilocks field arithmetic, `Felt` type alias, felt conversions |
| `hash` | Hash-to-field conversions (`Hash256` → field elements) |
| `rescue` | Rescue-Prime hash function and `RescueState` |
| `commerce_intent` | `CommerceIntent`, `CommerceExecution`, `CommerceAuthorizationReceipt` |
| `public_inputs` | `CompliancePublicInputs`, `PayloadAmountBinding`, `PolicyParams`, policy hash computation |

## Usage

```rust
use ves_stark_primitives::{
    field::Felt,
    hash::Hash256,
    rescue::RescueState,
    public_inputs::{CompliancePublicInputs, PolicyParams},
    commerce_intent::{CommerceIntent, CommerceExecution},
};
```

## License

MIT
