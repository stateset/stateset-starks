# Changelog

All notable changes to the VES STARK proving system will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `scripts/rescue_constants.py`, `docs/rescue_constants.json`, and `docs/RESCUE_CONSTANTS.md` to export and audit frozen Rescue-Prime constants (digest pinned in tests/docs).
- `rust-toolchain.toml` and workspace-wide `rust-version` (MSRV) pinning to make CI/builds reproducible.
- Optional `witnessCommitment` field in canonical public inputs (hex64, representing 32 bytes) plus helpers to parse/encode it.
- Bound verification entrypoint `verify_compliance_proof_auto_bound` (and `ComplianceVerifier::verify_auto_bound`) which requires `witnessCommitment` in public inputs.
- `SetChainClient::{try_new, try_unauthenticated}` constructors to avoid panics on invalid inputs.
- Proof JSON now includes `witness_commitment_hex` for JS-safe transport.
- Node.js bindings now expose `witnessCommitmentHex` on proofs and a `verifyHex` API to avoid `u64` round-trip issues.
- `SECURITY.md` and `.github/dependabot.yml` for basic security reporting and dependency update automation.
- CI now uses the pinned Rust toolchain and includes smoke tests for Node.js and Python bindings.

### Changed
- **Breaking**: Corrected the Rescue-Prime `MDS_INV` constant to be a true inverse of `MDS` over Goldilocks. This changes Rescue permutation/hash outputs and invalidates proofs/commitments produced with the previous constants.
- Batch trace layout now keeps total width under Winterfell's 255-column limit by sharing only the base compliance columns needed for batch proofs.
- Updated docs to clarify witness binding and recommended verification flow when `witnessCommitment` is available.

### Fixed
- Compliance AIR now binds the final subtraction borrow at row 0 (where the comparison gadget is enforced), preventing inconsistent borrows across rows.
- Clippy now passes with `-D warnings` across all targets (libs, tests, benches).

### Security
- Sequencer client now validates `public_inputs` by parsing canonical JSON and verifying `public_inputs_hash` and `event_id` before returning typed inputs (`SequencerClient::get_public_inputs_validated`).

## [0.2.0] - 2025-12-22

### Added

#### Testing Infrastructure
- **Verifier Tests**: Expanded from 3 to 30+ comprehensive tests covering:
  - Verifier creation and configuration
  - Policy hash validation
  - Proof hash verification
  - Proof deserialization error handling
  - Edge cases (zero amounts, max values, boundary conditions)
  - Serialization round-trips
  - Error type coverage

- **Property-Based Testing**: Added proptest integration for:
  - Rescue-Prime hash determinism and field validity
  - Limb decomposition/recomposition correctness
  - Witness validation logic
  - Field element arithmetic properties

- **Batch Proof Integration Tests**: 26 new tests for Phase 2 batch proofs:
  - BatchMetadata creation and validation
  - BatchEventWitness construction
  - BatchWitnessBuilder workflow
  - BatchStateRoot transitions
  - EventMerkleTree operations
  - BatchVerifier functionality
  - Edge cases for empty batches and error handling

- **Fuzzing Infrastructure**: 4 fuzz targets using cargo-fuzz/libFuzzer:
  - `fuzz_rescue_hash`: Tests hash function robustness
  - `fuzz_witness_validation`: Tests witness creation safety
  - `fuzz_proof_deserialization`: Tests proof parsing safety
  - `fuzz_public_inputs`: Tests public input handling

#### Benchmarks
- Expanded to 8 benchmark groups with Criterion:
  - `proof_generation`: Single proof generation
  - `proof_generation_by_amount`: Performance across amount ranges
  - `verification`: Proof verification timing
  - `end_to_end`: Full prove/verify cycles
  - `witness_creation`: Witness construction benchmarks
  - `rescue_hash`: Hash function performance
  - `serialization`: Proof serialization/deserialization
  - `policy_comparison`: AML vs Order Total policy comparison

#### Documentation
- **Cryptographic Constants**: Comprehensive documentation for:
  - ALPHA (7) and ALPHA_INV with security rationale
  - MDS matrix derivation and diffusion properties
  - Round constants from nothing-up-my-sleeve derivation
  - Goldilocks prime field properties

- **Formal Constraint Specification**: Added soundness documentation for:
  - All 167 constraints with notation and purpose
  - Degree analysis for each constraint type
  - Security level documentation (~128-bit security)
  - Binary, range, and policy constraint descriptions

- **CONTRIBUTING.md**: Developer guide covering:
  - Architecture overview
  - Development workflow
  - Code quality standards
  - Constraint system guidelines
  - Security considerations
  - Release checklist

### Changed
- Test count increased from 140 to 249 (+78%)
- Improved module documentation throughout primitives crate
- Enhanced error messages for constraint validation

### Fixed
- Edge case handling in empty batch creation
- Error propagation in witness builder

## [0.1.0] - 2024-XX-XX

### Added
- Initial release of VES STARK proving system
- Rescue-Prime hash implementation over Goldilocks field
- AIR constraint system for compliance proofs
- AML threshold policy (amount < threshold)
- Order total cap policy (amount <= threshold)
- Winterfell-based prover and verifier
- HTTP client for sequencer integration
- CLI tool for proof generation and verification
- Basic test coverage (140 tests)
