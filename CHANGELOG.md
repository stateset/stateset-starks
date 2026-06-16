# Changelog

All notable changes to the VES STARK proving system will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Performance
- Rescue-Prime hashing precomputes the MDS / MDS⁻¹ matrices and round constants in `Felt` (Montgomery) form once instead of converting the constant `u64` values on every permutation. This removes ~2k Montgomery conversions per hash and measures ~8–9% faster on `rescue_hash` micro-benchmarks (47.7→43.9 µs single element, 48.6→44.0 µs full-rate), which propagates into faster trace generation and proving since Rescue is invoked for every Merkle node and leaf. Hash outputs are byte-for-byte identical (known-answer, integration, and batch prove/verify roundtrip tests all pass).
- The Rescue inverse S-box (`x^ALPHA_INV`, the dominant cost of each backward half-round) now uses a fixed addition chain (~72 field multiplications) instead of generic square-and-multiply over the 64-bit exponent (~99 multiplications) — the same proven sequence Winterfell's `Rp64_256` uses for Goldilocks. The chain's exponent is verified to equal `ALPHA_INV` exactly, cross-checked against generic exponentiation over field edge cases, and validated by the existing randomized proptests plus full integration and batch prove/verify roundtrips (outputs unchanged).

### Security
- Batch chain verification (`BatchVerifier::verify_chain`) now rejects chains whose batches do not all share the same tenant and store. Previously batches from unrelated tenants/stores could be stitched into a single "valid" chain via coincidental sequence numbers and state-root linkage.
- `BatchProofSubmission::validate()` now rejects proofs larger than `MAX_SUBMISSION_PROOF_SIZE` (10 MiB) before they are submitted to Set Chain. Such a proof exceeds the batch verifier's `MAX_BATCH_PROOF_SIZE` and could never verify, so it is now caught client-side instead of wasting an on-chain submission. A compile-time assertion (under the `batch` feature) keeps the submission limit locked to the verifier's limit.

### Testing
- Added adversarial coverage for batch-proof verification, asserting the batch STARK binds its public inputs: a valid proof presented with a forged `new_state_root`, `prev_state_root`, `all_compliant` flag, `policy_limit`, `batch_id`, or public-inputs accumulator is rejected, as is a bit-flipped proof. This guards the core soundness property behind on-chain state-root anchoring, which previously had essentially no negative-path tests on the batch path.
- Added end-to-end tests for `BatchVerifier::verify_chain` (previously exercised only via unit tests on its continuity helper): a two-batch chain where batch 2 links from batch 1's new state root and continues its sequence verifies successfully, while two individually-valid batches with broken state-root linkage are rejected with `InvalidStateChain`.
- Added a JSON transport round-trip test for batch proofs: a real proof serialized via `SerializableBatchProof::to_json` and recovered with `from_json` still verifies against the public inputs extracted from that JSON — the exact path the FFI/client transport (`ves_batch_prove_json` → `ves_batch_verify_json`) takes. Existing serialization tests only checked field fidelity with placeholder proof bytes.
- Added a completeness test for the canonical `PayloadAmountBinding` hash, asserting it changes when any committed field is perturbed (event_id, tenant_id, store_id, sequence_number, payload_kind, both payload hashes, event_signing_hash, amount). This guards against a regression silently dropping a field from the commitment, which would let a proof bound to one event be replayed for another.
- Added a `fuzz_batch_proof` libFuzzer target covering the batch untrusted-input surface (`SerializableBatchProof::from_json` and `verify_batch_proof`) — the most complex parser in the system and the path behind the `ves_batch_verify_json` FFI entry point. Both must return `Ok`/`Err` rather than panic on arbitrary input.

### Documentation
- Extended `docs/THREAT_MODEL.md` with batch-proof attack vectors and mitigations (batch public-input substitution, chain stitching across tenants/stores or broken state-root linkage, and oversized-proof resource exhaustion), so the canonical threat model reflects the batch verifier's actual security properties.

### Added
- `ves-stark-zig` FFI now exposes batch-proof accessors for raw proof bytes/size and previous/new state roots (`ves_batch_proof_bytes`, `ves_batch_proof_size`, `ves_batch_proof_prev_state_root`, `ves_batch_proof_new_state_root`) and batch-verification accessors for the error message and state roots (`ves_batch_verification_error`, `ves_batch_verification_prev_state_root`, `ves_batch_verification_new_state_root`), with matching C header declarations.

### Changed
- Every `unsafe extern "C"` function in `ves-stark-zig` now documents its pointer-safety contract (validity, NUL-termination, ownership/free rules), and the workspace is clippy-clean under both default and `--all-features` builds.
- Reduced `cargo bench` compile time for `ves-stark-batch`. The large per-row constraint evaluators (`evaluate_merkle_constraints`, `evaluate_leaf_hash_constraints`, `evaluate_leaf_binding_constraints`, `evaluate_compliance_binding_constraints`) are now `#[inline(never)]` so LLVM keeps them as separate optimization units instead of folding them into one giant `evaluate_transition`, and the `bench` profile uses `lto = false` + `codegen-units = 16` so those units are optimized in parallel across cores (verified: the batch crate now compiles multi-threaded rather than in a single serial unit). To address the remaining wall-clock floor, the IR-densest piece — the in-circuit Rescue permutation transitions (24 degree-7 `pow7` evaluations plus two 12×12 MDS multiplies, monomorphized over the extension field) — was extracted from `evaluate_merkle_constraints` into its own `#[inline(never)]` helper, `evaluate_rescue_permutation_constraints`, so it forms a separate codegen unit that optimizes in parallel with the rest. These changes are semantics-neutral (`inline` is only a hint; the extracted helper recomputes its inputs and preserves exact constraint ordering) — all batch tests pass and proof outputs are unchanged. Production `release` builds remain fully optimized (`lto = "fat"`, `codegen-units = 1`).

## [0.2.2] - 2026-03-19

### Added
- New `ves-stark-wasm` crate with browser/WebAssembly bindings for proof generation, verification, policy-hash helpers, and payload amount bindings.

### Fixed
- Client-side WASM proving and verification now work end-to-end on `wasm32-unknown-unknown` by using a wasm-safe wall-clock timer instead of `std::time::Instant`.
- WASM panic output now reports the underlying Rust panic to the browser console, making runtime failures diagnosable instead of surfacing only as `RuntimeError: unreachable`.
- Workspace `uuid` configuration now enables the `js` feature so wasm builds can use browser randomness correctly.

### Changed
- Workspace, npm, Python, and Rust crate release metadata are aligned on `0.2.2`.

## [0.2.1] - 2026-03-11

### Changed
- Batch state roots now bind the previous state root into the metadata hash, preventing valid batches from being re-anchored onto arbitrary history.
- Limit-based client helpers now support both `aml.threshold` and `order_total.cap` instead of serializing AML parameters unconditionally.
- Workspace, npm, Python, and Rust crate release metadata are aligned on `0.2.1`.

### Fixed
- Documentation now accurately distinguishes proving a private amount witness from proving payload-to-amount linkage, which remains an application-layer responsibility.
- Soundness and threat-model docs now match the enforced minimum blowup factor.

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
