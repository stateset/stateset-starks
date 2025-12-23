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
