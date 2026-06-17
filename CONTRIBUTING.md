# Contributing to StateSet STARK

This guide helps you understand the codebase structure and development practices.

## Architecture Overview

```
ves-stark (workspace)
├── ves-stark-primitives   # Cryptographic primitives (Rescue hash, field ops)
├── ves-stark-air          # Constraint system (AIR definitions)
├── ves-stark-prover       # Proof generation
├── ves-stark-verifier     # Proof verification
├── ves-stark-batch        # Batch/state transition proofs (Phase 2)
├── ves-stark-client       # HTTP integration
└── ves-stark-cli          # Command-line interface
```

## Development Workflow

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p ves-stark-prover

# Run with verbose output
cargo test --workspace -- --nocapture

# Run property-based tests (proptest)
cargo test --workspace -- proptest
```

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark group
cargo bench -- proof_generation

# Save baseline for comparison
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

### Fuzzing

Requires nightly Rust and cargo-fuzz:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_rescue_hash -- -max_total_time=60
cargo +nightly fuzz run fuzz_witness_validation
cargo +nightly fuzz run fuzz_proof_deserialization
cargo +nightly fuzz run fuzz_public_inputs
```

## Code Quality Standards

### Testing Requirements

1. **Unit Tests**: Every public function should have tests
2. **Property Tests**: Use proptest for functions with mathematical properties
3. **Integration Tests**: Full prove/verify cycles for each policy type
4. **Boundary Tests**: Test edge cases (0, MAX, threshold boundaries)

### Documentation Requirements

1. **Module Docs**: Every module should have `//!` documentation
2. **Public Items**: All public functions, structs, and constants need `///` docs
3. **Constraint Docs**: AIR constraints must document their soundness argument
4. **Crypto Docs**: Cryptographic constants must document their derivation

### Performance Guidelines

1. Avoid allocations in hot paths
2. Use field element operations over integer operations
3. Pre-compute constants where possible
4. Profile before optimizing

## Constraint System

### Adding a New Policy

1. Add policy definition in `ves-stark-air/src/policies/`
2. Implement `PolicyConstraints` trait
3. Add policy variant to `Policy` enum in `ves-stark-prover`
4. Add tests for boundary conditions
5. Update benchmarks

### Soundness Checklist

When modifying constraints, verify:

- [ ] Binary constraints: `b * (1 - b) = 0` for all bits
- [ ] Recomposition: `limb = Σ(bit[i] * 2^i)`
- [ ] Boundary constraints bind public inputs
- [ ] Transition constraints maintain consistency
- [ ] Witness commitment binds private data
- [ ] If you change constraint ordering or counts, the `debug_assert_eq!(idx, NUM_*_CONSTRAINTS)`
      at the end of each `evaluate_transition` must still hold (it runs in tests). Update the
      `NUM_*_CONSTRAINTS` constants and their `test_constraint_count` assertions deliberately.

### Batch AIR compile-time notes

`evaluate_transition` in `ves-stark-batch` is large and generic over the field, so under
`opt-level=3` (release/bench profiles) LLVM spends a long time optimizing it — historically 20-35
min for the whole crate. Mitigations already in place, which you should preserve and extend if you
add constraints:

- The big per-row constraint evaluators (`evaluate_merkle_constraints`, `evaluate_leaf_*`,
  `evaluate_compliance_binding_constraints`) and the IR-dense Rescue block
  (`evaluate_rescue_permutation_constraints`) are `#[inline(never)]` so they stay separate codegen
  units instead of being folded into one giant function.
- `[profile.bench]` uses `lto = false` + `codegen-units = 16` so those units optimize in parallel.
  **Any LTO setting forces a single serial codegen unit** and erases the benefit.

The residual cost is that the remaining body of `evaluate_merkle_constraints` (the structural +
accumulator-linkage constraints) is still one sizeable function. Splitting it further is the next
improvement, but do it only when you can **measure** the compile-time delta on a quiet machine —
correctness is cheap to verify (`cargo test -p ves-stark-batch` runs at `opt-level=0`), but a split
that isn't measured may not be worth the constraint-ordering risk. Verify proof outputs are
unchanged via the batch prove/verify roundtrip tests.

## Security Considerations

1. Never log or expose private witness data
2. Use constant-time operations for sensitive comparisons
3. Validate all inputs at system boundaries
4. Use domain separation in hash functions
5. Keep cryptographic dependencies up to date

## Release Checklist

- [ ] All tests pass (`cargo test --workspace`)
- [ ] Benchmarks show no regression
- [ ] Fuzz tests run for minimum 1 hour each
- [ ] Documentation is complete
- [ ] CHANGELOG is updated
- [ ] Version bumped in Cargo.toml
