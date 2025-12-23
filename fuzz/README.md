# VES STARK Fuzzing Infrastructure

This directory contains fuzz targets for testing the VES STARK proving system
using cargo-fuzz and libFuzzer.

## Prerequisites

Install cargo-fuzz:

```bash
cargo install cargo-fuzz
```

Requires nightly Rust:

```bash
rustup install nightly
```

## Fuzz Targets

### 1. `fuzz_rescue_hash`

Tests the Rescue-Prime hash function for:
- No panics on any input
- Deterministic output
- Valid field element outputs

```bash
cargo +nightly fuzz run fuzz_rescue_hash
```

### 2. `fuzz_witness_validation`

Tests witness creation and validation for:
- No panics on arbitrary inputs
- Correct validation logic (amount < threshold)
- Correct limb decomposition

```bash
cargo +nightly fuzz run fuzz_witness_validation
```

### 3. `fuzz_proof_deserialization`

Tests proof parsing and verification for:
- No panics on garbage input
- Graceful rejection of invalid proofs
- Memory safety during deserialization

```bash
cargo +nightly fuzz run fuzz_proof_deserialization
```

### 4. `fuzz_public_inputs`

Tests public input handling for:
- Correct serialization/deserialization
- Policy hash determinism
- Field element conversion

```bash
cargo +nightly fuzz run fuzz_public_inputs
```

## Running All Fuzz Targets

```bash
# Run each target for 60 seconds
for target in fuzz_rescue_hash fuzz_witness_validation fuzz_proof_deserialization fuzz_public_inputs; do
    echo "Fuzzing $target..."
    timeout 60s cargo +nightly fuzz run $target -- -max_total_time=60 || true
done
```

## CI Integration

Add to your CI pipeline:

```yaml
fuzzing:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@nightly
    - run: cargo install cargo-fuzz
    - run: |
        cd fuzz
        for target in fuzz_rescue_hash fuzz_witness_validation; do
          cargo +nightly fuzz run $target -- -max_total_time=60
        done
```

## Corpus Management

Fuzzing corpus is stored in `fuzz/corpus/<target_name>/`. To seed with
interesting inputs:

```bash
mkdir -p fuzz/corpus/fuzz_rescue_hash
echo -n "test input" > fuzz/corpus/fuzz_rescue_hash/seed1
```

## Reproducing Crashes

If a crash is found:

```bash
cargo +nightly fuzz run fuzz_rescue_hash fuzz/artifacts/fuzz_rescue_hash/crash-...
```

## Coverage

Generate coverage reports:

```bash
cargo +nightly fuzz coverage fuzz_rescue_hash
```
