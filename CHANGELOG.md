# Changelog

All notable changes to the VES STARK proving system will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
