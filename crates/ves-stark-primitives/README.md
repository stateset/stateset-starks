# ves-stark-primitives

[![crates.io](https://img.shields.io/crates/v/ves-stark-primitives.svg)](https://crates.io/crates/ves-stark-primitives)
[![license](https://img.shields.io/crates/l/ves-stark-primitives.svg)](../LICENSE)

Cryptographic primitives for VES STARK proofs.

## Overview

Foundation crate providing the core field arithmetic, hash functions, and data types used across the entire VES STARK proof system.

- **Field**: Goldilocks (p = 2^64 - 2^32 + 1) — a 64-bit STARK-friendly prime field
- **Hash**: Rescue-Prime (7 rounds, 12-element state, alpha=7 S-box)
- **Framework**: Built on [Winterfell](https://github.com/facebook/winterfell) v0.10

## Installation

```toml
[dependencies]
ves-stark-primitives = "0.3"
```

## Modules

| Module | Description |
|--------|-------------|
| `field` | Goldilocks field arithmetic, `Felt` type alias, felt conversions |
| `hash` | Hash-to-field conversions (`Hash256` to field elements) |
| `rescue` | Rescue-Prime hash function and `RescueState` |
| `commerce_intent` | `CommerceIntent`, `CommerceExecution`, `CommerceAuthorizationReceipt` |
| `public_inputs` | `CompliancePublicInputs`, `PayloadAmountBinding`, `PolicyParams`, policy hash computation |

## Rescue-Prime Parameters

| Parameter | Value |
|-----------|-------|
| State width | 12 elements |
| Rate | 8 elements |
| Capacity | 4 elements |
| Rounds | 7 |
| S-box (alpha) | x^7 |
| MDS | 12x12 circulant matrix |

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
