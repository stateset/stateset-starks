# Changelog

All notable changes to the VES STARK proving system will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-09-05

### Commerce integrity hardening

- Confirmed amount/salt disclosure in proof transcripts; confidential commerce APIs
  now fail closed. Explicit `_disclosed` APIs and CLI disclosure acknowledgment are
  required for new integrity-only workflows. Legacy low-level APIs remain disclosing.
- Added domain-separated, scoped Ed25519 approvals with policy revision, nonce,
  expiration, key validity, and revocation checks. These signatures are not post-quantum.
- Added public refund transitions, exact amount-to-proof checks, and an optional
  SQLite ledger with atomic reservations, event/nonce consumption, and durable
  idempotent execution requests. Arithmetic is verified natively, not privately in AIR.
- Added batch composition verification with independent V2 event proofs and full
  Merkle/state-root reconstruction. Aggregate-only verification explicitly reports
  that payload binding was not checked; aggregate AIR/compression is unchanged.
- Added the signed-refund CLI lifecycle, crash/concurrency/tamper tests, and a
  synthetic optimized pilot with a signed-record verification baseline.
- Corrected stale security parameter documentation and withdrew confidentiality
  claims from historical whitepapers. A reviewed zero-knowledge backend, independent
  audit, real provider integration, and customer validation remain release gates.

## [0.7.0] - 2026-08-31

### Changed

- **The hash permutation is now canonical Rescue-Prime (Rescue-XLIX), not a variant.** The backward
  half-round previously applied the MDS *before* the inverse S-box (`MDS -> S-box⁻¹ -> +c`), which
  made the two MDS layers within a round adjacent — the effective linear layer was `MDS²` and the
  construction was non-standard, so published Rescue-Prime cryptanalysis did not transfer. It now
  applies `S-box⁻¹ -> MDS -> +c`, the same layer order as the forward half-round, matching textbook
  Rescue-Prime with these parameters (Goldilocks, width 12, 7 rounds, α=7). This removes the single
  largest unquantified soundness assumption in the system.

  The change touched the native permutation (`rescue.rs`) and both in-circuit AIR encodings (the
  per-event `compliance.rs` and the batch `merkle.rs` helper, rewritten to the degree-7 form
  `pow7(MDS_inv·(next − c)) = curr`). The trace builders drive off the native permutation, so they
  needed no change. Constraint counts and degrees are unchanged (157/76, degree 7). Round constants
  and the MDS matrix are unchanged, so `rescue_constants.json` and its pinned digest are unchanged.
  KAT vectors were regenerated from an independent Python computation and cross-checked by the
  from-spec reference in `rescue_kat_test.rs`; the full prove/verify suite (per-event + all batch
  roundtrips) confirms native and in-circuit agree.

  BREAKING: every proof and witness commitment changes; proofs from ≤0.6.0 no longer verify, and
  amount witness commitments (Rescue outputs) differ. Downstream must re-prove.

## [0.6.0] - 2026-08-31

### Fixed

- CI fuzz smoke job installed nothing: `taiki-e/install-action@cargo-fuzz` (shortcut-tag form,
  pinned to an old release) was a silent no-op, so `cargo fuzz` was absent and the job failed with
  `no such command: fuzz` — not a fuzzing crash. Switched all `install-action` uses to the
  canonical `@v2` + `tool:` form. This is why the v0.5.0 CI run showed the fuzz job red despite
  both defects being contained.

### Added

- **The proved amount is now bound to the event for `payload_kind == 2`.** This was the one open
  gap that changed what a verifier may conclude: a proof showed *some* compliant amount existed
  behind the commitment, not that it was the amount on the order. For V2 events the sequencer
  forms `payload_plain_hash = SHA-256(domain ‖ C ‖ restHash)` with `C` the salted witness
  commitment the circuit already proves, and the verifier recomputes it. No circuit change, no
  proving cost, no signed artifact, and 0.5.0 proofs are not invalidated; the `restHash` field
  applies to **per-event** proofs; batch proofs still carry the V1 guarantee for V2 events (an
  open item tracked in the design doc). The `restHash` field joins the canonical public inputs.
  Contract for the sequencer in
  `docs/AMOUNT_BINDING_DESIGN.md`; `ves_stark_primitives::payload_v2` is the reference
  implementation with a KAT from an independent Python computation. An earlier draft of the
  design used an unsalted leaf as a public input, which would have been brute-forceable — caught
  in review and replaced by reusing `C`.

## [0.5.0] - 2026-08-31

### Security

- **Contained a reachable panic on the verification path.** `cargo +nightly fuzz run
  fuzz_proof_deserialization` — the CI job added in 0.4.0, run for the first time — reaches
  `attempt to multiply with overflow` inside `winter-air-0.10.3`
  (`src/air/trace_info.rs:311`) with eleven bytes of proof input. The deserializer validates only
  the *lower* bound of the log2 trace-length byte and then evaluates `2_usize.pow(n)` for an `n`
  read straight from the input; there is no `MAX_TRACE_LENGTH` in the crate. Under
  `overflow-checks = true` this panics, which on a verification service is a denial of service.
  Both verifiers now wrap deserialization in `panic_guard::guard_untrusted`, returning a
  `DeserializationError` instead. Regression tests in `tests/untrusted_input_test.rs` run under
  both `overflow-checks` settings.
- **Closed an upstream allocation DoS on the verifier.** The same fuzz target reaches
  `Vec::with_capacity(num_elements)` in `winter-utils-0.10.2`
  (`src/serde/byte_reader.rs:194`), where `num_elements` is a length prefix never checked against
  the bytes remaining. A 39-byte proof requested ~72 PB; Rust aborts on allocation failure rather
  than unwinding, so this SIGABRTed in both debug and release and no `catch_unwind` could reach it.
  Still present in the latest upstream release (`winter-air 0.13.1`). Fixed in-repo without
  vendoring: `read_many` is a *provided* `ByteReader` method, so
  `ves_stark_primitives::bounded_reader::BoundedReader` overrides it to reject any declared count
  larger than the bytes remaining, before allocating. Both verifiers now parse via
  `deserialize_bounded` instead of `Proof::from_bytes`; the upstream deserializers are otherwise
  untouched. The regression test that had to be `#[ignore]`d because it killed the test binary is
  now live and passing, and the CI fuzz job is blocking again.

### Fixed

- `Cargo.toml` `repository` pointed at `stateset/stateset-stark`; the remote is `stateset-starks`.
- `docs/VERIFICATION.md` §11 claimed the untrusted-input surfaces "never panic". They did. The
  section now states what is contained, what is not, and how to mitigate the remainder.

### Added

- `ves_stark_verifier::ComplianceVerification`, a builder that expresses the same checks as the
  26 free verification functions as one readable call, and keeps their tripwire: `run()` refuses
  unless the caller chose `.amount_binding(..)` or explicitly `.witness_only()`. The free functions
  remain.
- `docs/AMOUNT_BINDING_DESIGN.md`: the design for binding the proved amount to the event payload
  *inside the circuit* — the one open gap that changes what a verifier may conclude. Recommends
  making the amount its own Rescue leaf of `payload_plain_hash` (one extra permutation, +14
  constraints) over hashing the payload in-circuit; the sequencer-side contract is specified and
  must land first.
- `docs/upstream/`: ready-to-file issue text for both Winterfell deserialization defects.
- Nightly workflow: 40-minute fuzz campaign per target with a persisted corpus, Miri over a real
  prove/verify cycle through the C ABI, and `cargo-deny` (licenses, bans, sources) with `deny.toml`.
- Property tests proving `BoundedReader` is observationally identical to upstream `SliceReader`
  except in the over-allocation region, where it must — and does — refuse instead.

### Changed

- The three monoliths are split. `ves-stark-zig` (1.7k lines, every `unsafe` block in the
  workspace) is now a module per section of the C API with helpers, error codes and handle types
  in `lib.rs`. `ves-stark-client::types` (2.9k) keeps the DTOs and moves bundles, submission and
  validation into `types/`. `ves-stark-cli` (2.3k) keeps the CLI definition, `main` and shared
  helpers and moves each command into `commands/`. No public path changed; the largest file in the
  workspace is now 1.3k lines, most of it tests.
- Release-build time investigated: `codegen-units = 4` was tried and measured *not* to help — with
  `lto = "fat"` the serial link dominates. Left at 1 with the finding recorded in the profile
  comment; `lto = "thin"` is the real lever and needs a prove-time benchmark before adoption.
- All five fuzz targets have now actually been run (previously none had been). `fuzz_rescue_hash`
  111k executions, `fuzz_public_inputs` 255k, `fuzz_witness_validation` 96k and `fuzz_batch_proof`
  985k are clean; `fuzz_proof_deserialization` reproduces the upstream allocation defect above.
- Fuzz targets that exercise a guarded boundary now assert the property that matters — *no panic
  escapes the library to its caller* — instead of tripping on a panic the library deliberately
  catches. `libfuzzer-sys` aborts before unwinding, which otherwise hides a working guard.
- `ves-stark-client::types` no longer carries a blanket `allow(missing_docs)`: all 91 transport
  fields are documented with what the wire contract requires — base64 vs hex encodings, which hash
  is reported versus recomputed, and where the `u64` commitment form is unsafe for JavaScript
  consumers.
- Node and Python packages moved from 0.2.3 to 0.4.0, ending the drift from the Rust crates. Both
  binding test suites verified against the bump.

## [0.4.0] - 2026-08-29

### Security

- **BREAKING — proof parameters are now secure by default.** `ProofOptions::security_level()`
  previously computed `queries*log2(blowup) + grinding + flat_extension_bonus`, a model with no
  term for the size of the field challenges are drawn from. Over 64-bit Goldilocks that term is
  the one that binds: with `FieldExtension::None` the real ceiling is about
  `64 - log2(max_degree * trace_len)` ≈ 40 bits for a 2^20 trace, and no number of FRI queries can
  raise it. The estimator now reports `min(query bound, algebraic bound)`, and no preset ships on
  the bare base field. Reported levels: `default()` 104 bits (was claimed 82), `secure()` 168 bits
  (variously claimed 100+, 128, and 190 in the same README), `fast()` 80 bits and now documented as
  development-only. `conjectured_security_level(trace_length)` gives the exact figure for a known
  trace. Proof bytes change; downstream must re-prove.
- Clients refuse to send an API key in cleartext. `Url::parse` accepted any scheme, so a mistyped
  `http://` production endpoint shipped the credential unencrypted and `ftp://`/`file://` were
  accepted outright. Only `https` is allowed now, with a carve-out for genuine loopback hosts so
  the documented `http://localhost:8080` development setup keeps working. Loopback detection parses
  IP literals rather than matching string prefixes — `127.0.0.1.evil.com` and `localhost.evil.com`
  are ordinary attacker-controlled domains.
- The `Authorization` header is marked sensitive, keeping the API key out of `reqwest`'s `Debug`
  output and any tracing or error dump that formats the client.
- Fixed an FFI defect found by the new tests: `ves_proof_bytes(NULL, &len)` and
  `ves_batch_proof_bytes(NULL, &len)` returned `NULL` while leaving `*out_len` untouched, handing a
  C caller a stale or uninitialized length next to a null pointer. Both now zero the out-parameter.
- `panic = "abort"` removed from the release profile. The verifier parses attacker-supplied bytes;
  under `abort` a reachable panic becomes process death, turning one malformed proof into a denial
  of service for a verification service.
- Updated dependencies to clear 8 RUSTSEC advisories, including four in `rustls-webpki` reachable
  through the client's TLS stack (name-constraint bypass on wildcard certificates, URI name
  constraints wrongly accepted, a reachable panic in CRL parsing, and a CRL authority bug). `pyo3`
  moved 0.24 → 0.29 for an out-of-bounds read and a missing `Sync` bound.

### Testing

- **Rescue now has known-answer tests and an independent reference implementation.** Every previous
  Rescue test was self-referential — determinism, order-sensitivity, `MDS x MDS_INV = I`, constants
  matching a JSON generated from those same constants — so none of them constrained the
  permutation's output. That is why the `MDS_INV` diffusion defect, which collapsed the permutation
  into twelve independent lanes and made the amount recoverable from a published commitment, passed
  the entire suite. `tests/rescue_kat_test.rs` adds a naive from-specification reimplementation
  (schoolbook `u128` arithmetic, no Montgomery form, no addition chain) checked against the
  optimized code, plus output vectors generated by a third implementation.
- Added the first tests for `ves-stark-zig`, which had none: 1739 lines, 48 `extern "C"` functions
  and every `unsafe` block in the workspace were previously uncovered. The new tests exercise null
  handling, allocate/borrow/free cycles, and the out-parameter ownership protocol, and run under
  Miri in CI.
- Documentation numbers are now machine-checked (`tests/docs_consistency_test.rs`). The
  salted-commitment change had freed four boundary assertions (80 → 76) while `SOUNDNESS.md` still
  described `AMOUNT[2..7] = 0` — a scheme in which the blinding salt is pinned to zero, i.e. one
  that does not hide. Constraint counts, assertion counts, and every quoted security level are now
  asserted against the code.

### Changed

- The permutation is documented as a Rescue **variant**, not textbook Rescue-Prime: the backward
  half-round applies `MDS -> S-box^-1 -> +c` where the specification applies the S-box first. The
  two MDS layers are consequently adjacent and compose, so the matrix mixing lanes between the two
  S-box layers is `MDS^2`. `MDS^2` is now asserted to retain the MDS property rather than assumed
  to. Published Rescue-Prime cryptanalysis does not transfer to this construction unchanged.
- All crates except the FFI surface are `#![forbid(unsafe_code)]`; all are `#![deny(missing_docs)]`
  and `#![deny(rustdoc::broken_intra_doc_links)]`.
- CI adds a Miri job for the FFI crate and a smoke run of every fuzz target. The fuzz targets live
  outside the workspace and were built by nothing, so they could bit-rot silently.
- `ves-stark-verifier` documents how to choose among its verification entry points, and why
  `verify_compliance_proof_strict` deliberately always errors.

### Fixed

- `cargo fmt --check` and `cargo clippy -D warnings` both failed on `master`, so the CI `check` job
  was red; the two most recent (and most safety-critical) commits landed without the gates passing.

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
- Added the equivalent completeness test for the `CommerceAuthorizationReceipt` hash (the agent-authorization binding), perturbing each of its 18 hashed fields (intent/tenant/store/agent/delegation/event ids, nonce, amount, currency, merchant, payee, sku/category sets, shipping country, timestamps, intent hash) and asserting the receipt hash changes. Previously only `nonce` and `sequence_number` sensitivity were tested.
- Added a completeness test for the `CommerceIntent` hash, which binds the authorization constraints themselves (spend cap, merchant/payee, allowed SKU/category scopes, expiry, nonce, identifiers). Perturbing each of its 14 fields must change the intent hash; previously only normalization-equivalence was tested. Since the receipt carries this intent hash, the guard extends transitively to the receipt binding.
- Added a completeness test for the sequencer-canonical `CompliancePublicInputs` hash — the per-event binding for the main compliance proof's public-input stream. Perturbing each committed field (event/tenant/store ids, sequence number, payload kind, the three payload hashes, policy id/params/hash, and the optional receipt/amount-binding hashes) must change the hash, while `witnessCommitment` is confirmed excluded. Previously only the witness-commitment exclusion was tested.
- Added a `fuzz_batch_proof` libFuzzer target covering the batch untrusted-input surface (`SerializableBatchProof::from_json` and `verify_batch_proof`) — the most complex parser in the system and the path behind the `ves_batch_verify_json` FFI entry point. Both must return `Ok`/`Err` rather than panic on arbitrary input.

- Added a test (`test_rescue_constants_json_matches_code`) that locks the published `docs/rescue_constants.json` audit artifact to the in-code Rescue constants (MDS, MDS⁻¹, round constants, dimensions, and embedded digest). Previously only the code constants were hash-tested, so the published reproducibility artifact could drift from the source of truth undetected.

### Documentation
- Extended `docs/THREAT_MODEL.md` with batch-proof attack vectors and mitigations (batch public-input substitution, chain stitching across tenants/stores or broken state-root linkage, and oversized-proof resource exhaustion), so the canonical threat model reflects the batch verifier's actual security properties.

### Added
- `ves-stark-zig` FFI now exposes batch-proof accessors for raw proof bytes/size and previous/new state roots (`ves_batch_proof_bytes`, `ves_batch_proof_size`, `ves_batch_proof_prev_state_root`, `ves_batch_proof_new_state_root`) and batch-verification accessors for the error message and state roots (`ves_batch_verification_error`, `ves_batch_verification_prev_state_root`, `ves_batch_verification_new_state_root`), with matching C header declarations.

### Changed
- Every `unsafe extern "C"` function in `ves-stark-zig` now documents its pointer-safety contract (validity, NUL-termination, ownership/free rules), and the workspace is clippy-clean under both default and `--all-features` builds.
- The proof-hash domain-separation tags are now defined once in `ves-stark-primitives` (`COMPLIANCE_PROOF_HASH_DOMAIN`, `BATCH_PROOF_HASH_DOMAIN`) and referenced by the prover, verifier, batch prover/verifier, Set Chain submission client, and the C FFI, instead of each hardcoding the literal. These tags must agree across crates — the prover computes a hash the verifier and on-chain submission path recompute — so a single source of truth removes a silent-drift risk. Hash outputs are unchanged (all prove/verify roundtrip and hash tests pass).
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
