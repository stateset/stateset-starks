# Verification Matrix

This document maps every claimed security property, threat-model vector, and
integrity invariant to the concrete, executable test(s) that verify it. It exists
to make the system **independently auditable**: a reviewer can confirm each claim
by name rather than reconstructing coverage from scratch.

Run the full evidence set with:

```bash
cargo test --workspace --all-features
```

Conventions: test locations are abbreviated — `air` = `crates/ves-stark-air/src/...`,
`prim` = `crates/ves-stark-primitives/src/...`, `batch` =
`crates/ves-stark-batch/src/...`, `it/*` = top-level `tests/*.rs`.

---

## 1. Per-event proof soundness

The proven statement is "the private `amount` satisfies the policy and is bound to
the public witness commitment." See `docs/SOUNDNESS.md` for the argument.

| Property | Mechanism | Tests |
|---|---|---|
| Valid amount always proves | range + subtraction gadget | `prop_valid_amount_always_proves_lt`, `prop_valid_amount_always_proves_lte` (it/property_test) |
| Invalid amount never proves | subtraction borrow boundary assertion | `prop_invalid_amount_never_proves_lt`, `prop_invalid_amount_never_proves_lte`, `test_amount_exceeds_threshold_rejected`, `test_amount_exceeds_cap_rejected` (it/adversarial_test) |
| Strict `<` vs `<=` boundary | comparison-type selection | `prop_boundary_equal_always_fails_lt`, `prop_boundary_equal_always_succeeds_lte`, `test_amount_equals_threshold_rejected_for_lt` |
| AIR semantics match native policy | reference cross-check | `prop_lt_semantics_match_native`, `prop_lte_semantics_match_native` |
| Range validity (u64 limbs) | binary + recomposition constraints | `test_binary_constraint`, `test_decompose_recompose`, `test_validate_limbs`, `test_range_check_data_invalid` (air) |

## 2. Threat-model vectors (`docs/THREAT_MODEL.md`)

| # | Vector | Mitigation | Tests |
|---|---|---|---|
| 1 | Non-binary bit manipulation | `b·(1−b)=0` per bit column | `test_binary_constraint` (air) |
| 2 | Subtraction gadget manipulation | limb subtraction + borrow binary + final-borrow=0 boundary | `test_amount_exceeds_threshold_rejected`, `prop_invalid_amount_never_proves_lt` |
| 3 | Commitment forgery | Rescue constraints + output-row boundary assertion | `test_tampered_witness_commitment_rejected`, `test_commitment_from_different_amount_rejected`, `test_zero_witness_commitment_rejected`, `prop_commitment_is_binding` |
| 4 | Policy mismatch | verifier rechecks `policy_hash` + id/params; AIR binds limit | `test_policy_id_mismatch_rejected`, `test_threshold_mismatch_rejected`, `test_higher_threshold_proof_fails_lower_verification` |
| 5 | V2 amount-to-payload binding: commitment not in payload hash rejected | verifier recomputes `SHA-256(domain ‖ C ‖ restHash)` | `test_commitment_not_in_payload_rejected`, `test_payload_hash_mismatch_rejected_v2`, `test_v2_requires_rest_hash`, `test_builder_witness_only_still_binds_v2`, `test_v2_honest_event_verifies`, `test_v1_events_unaffected` (it/payload_v2_binding_test); `kat_payload_plain_hash_v2` (prim/payload_v2) |
| Public-input substitution | inputs bound into trace via boundary assertions | `test_proof_with_different_event_id_rejected`, `test_payload_hash_mismatch_rejected`, `test_public_inputs_canonical_hash_commits_to_every_field` (prim) |
| 6 | Batch public-input substitution | batch AIR binds `BatchPublicInputs` | `test_batch_verifier_rejects_tampered_public_inputs`, `test_batch_verifier_rejects_bit_flipped_proof` (batch) |
| 7 | Batch chain stitching | `verify_chain` enforces tenant/store + sequence continuity + state-root linkage | `test_verify_chain_rejects_broken_state_root_linkage`, `test_chain_continuity_rejects_tenant_mismatch`, `test_chain_continuity_rejects_store_mismatch`, `test_sequence_continuity_check_with_gap` |
| 8 | Oversized-proof resource exhaustion | `MAX_BATCH_PROOF_SIZE` at verify; `MAX_SUBMISSION_PROOF_SIZE` at submit (const-asserted equal) | `test_verify_batch_proof_over_max_size_is_rejected`, `test_batch_proof_submission_validate_rejects_oversized_proof` (client) |

## 3. Commitment / binding completeness

Every hash that binds event metadata or authorization constraints into a proof has
a field-by-field completeness guard: perturbing **any** committed field must change
the hash. This catches the "silently dropped field → forgeable binding" class.

| Binding | Fields | Test |
|---|---|---|
| `CompliancePublicInputs` canonical hash (per-event) | 14 | `test_public_inputs_canonical_hash_commits_to_every_field` (prim) |
| `PayloadAmountBinding` hash (amount↔event) | 9 | `test_payload_amount_binding_hash_commits_to_every_field` (prim) |
| `CommerceAuthorizationReceipt` hash (execution) | 18 | `test_authorization_receipt_hash_commits_to_every_field` (prim) |
| `CommerceIntent` hash (authorization constraints) | 14 | `test_commerce_intent_hash_commits_to_every_field` (prim) |

## 4. Validation branch coverage (negative path)

The complement to §3: every multi-condition check from untrusted input to on-chain
anchoring rejects on **each** condition independently, so no single branch can
silently regress (e.g. dropping a spend-cap or context-binding check).

| Check | Branches | Test(s) |
|---|---|---|
| Delegated-authorization limits (`authorize_execution`) | amount/spend-cap, currency, merchant, payee, shipping country, SKU scope, category scope, expiry | `test_authorize_execution_rejects_remaining_violations`, `test_authorize_execution_rejects_expired_intent`, `test_authorize_execution_rejects_scope_violation`, `test_authorize_execution_rejects_merchant_mismatch` (prim) |
| Authorization-receipt context binding | event/tenant/store ids, sequence number | `test_validate_authorization_receipt_rejects_each_context_field` (prim) |
| Payload-amount-binding context | event/tenant/store ids, sequence, payload kind, 3 payload hashes | `test_validate_payload_amount_binding_rejects_each_context_field` (prim) |
| Batch event identity vs metadata | tenant id, store id | `test_batch_witness_tenant_store_mismatch`, `test_batch_witness_store_mismatch` (batch) |
| Policy parsing (`Policy::from_public_inputs`) | unknown id, missing threshold/cap/maxTotal/intentHash/budgetLimit | `test_from_public_inputs_rejects_invalid_policies` (air) |
| Registry-address config | missing 0x prefix, wrong length, non-hex, zero address | `test_set_chain_config_rejects_malformed_registry_address`, `test_set_chain_config_zero_registry_is_rejected` (client) |

## 5. Integrity / anti-drift invariants

Critical shared values are pinned or single-sourced, with tests preventing silent
divergence.

| Invariant | Test |
|---|---|
| Rescue constants unchanged (digest pinned) | `test_rescue_constants_hash` (prim) |
| Published `rescue_constants.json` matches code | `test_rescue_constants_json_matches_code` (prim) |
| MDS · MDS⁻¹ = identity | `test_mds_times_mds_inv_is_identity`, `test_mds_inv_times_mds_is_identity` (prim/rescue) |
| Inverse S-box addition chain == generic `x^ALPHA_INV` | `test_sbox_inv_addition_chain` (prim/rescue) |
| Batch policy-id strings match canonical `policy_ids` | `test_batch_policy_kind_ids_match_canonical_constants` (batch) |
| Proof-hash domain tags single-sourced in `ves-stark-primitives` | enforced by construction (`COMPLIANCE_PROOF_HASH_DOMAIN`, `BATCH_PROOF_HASH_DOMAIN`); prove/verify roundtrips would fail on drift |
| `SOUNDNESS.md` transition-constraint count matches the AIR | `soundness_doc_transition_constraint_count_matches_air` (it/docs_consistency_test) |
| `SOUNDNESS.md` boundary-assertion count matches the AIR | `soundness_doc_boundary_assertion_count_matches_air`, `test_air_assertions` (air) |
| `SOUNDNESS.md` does not claim the salt limbs are pinned to zero | `soundness_doc_does_not_claim_the_salt_limbs_are_pinned` |
| README security numbers equal what the estimator returns | `readme_security_levels_match_the_estimator` |
| Superseded (mutually contradictory) security claims removed | `readme_does_not_carry_superseded_security_claims` |
| Permutation described as canonical Rescue-Prime | `docs_describe_canonical_rescue_prime` |

## 6. Hash primitive correctness (Rescue)

The rest of the Rescue suite is self-referential — determinism, order-sensitivity,
`MDS x MDS_INV = I`, constants matching a JSON generated from those same
constants. None of it constrains the permutation's *output*, which is how a
defect that cancelled all cross-lane diffusion (and with it commitment hiding)
once passed the entire workspace. These tests close that class.

| Property | Test |
|---|---|
| Optimized permutation equals a naive from-spec reimplementation | `optimized_permutation_matches_independent_reference` (it/rescue_kat_test) |
| Agreement holds on structured edge cases (zero, all-ones, p-1) | `reference_agreement_on_edge_case_states` |
| Permutation output pinned to externally generated vectors | `kat_permutation_of_zero_state` |
| Merkle 2-to-1 compression output pinned | `kat_hash_pair` |
| Sponge output pinned across the rate boundary (len 0/1/8/9) | `kat_hash_across_input_lengths` |
| Lane-mixing layer `MDS` is MDS (canonical Rescue-Prime) | `mds_matrix_is_mds` |
| Permutation is canonical Rescue-Prime, docs say so | `docs_describe_canonical_rescue_prime` (it/docs_consistency_test) |
| MDS + inverse MDS are the audited Rp64_256 matrices | `mds_matrix_is_the_audited_rp64_256_mds` (it/rescue_kat_test) |
| State width, round count, S-box exponents match Rp64_256 | `structural_params_match_rp64_256` |
| Round constants are our own (documented divergence) | `round_constants_are_our_own_not_rp64_256` |
| Permutation diffuses across lanes | `diffusion_regression` tests (prim/rescue) |

## 7. Proof parameter soundness

The reported security level is `min(query bound, algebraic bound)`. The algebraic
bound is set by the challenge field and is what binds over 64-bit Goldilocks.

| Property | Test |
|---|---|
| Security is capped by the challenge field, not raised by query count | `test_security_is_capped_by_challenge_field_not_query_count` (air/options) |
| Extension field raises the cap rather than adding a flat bonus | `test_extension_field_raises_the_cap_it_is_not_an_additive_bonus` |
| Longer traces are strictly less sound | `test_security_decreases_as_trace_grows` |
| No shipped preset uses the bare base field | `test_no_preset_uses_the_bare_base_field` |
| `default()` clears the documented security floor | `test_default_is_secure_by_default`, `default_preset_clears_the_documented_security_floor` |
| A query-starved config is still reported weak | `test_query_starved_config_is_still_reported_weak` |
| The assumed max trace length really bounds every AIR's trace | `assumed_max_trace_length_bounds_every_real_trace` (it/docs_consistency_test) |

## 8. Credential and transport handling

| Property | Test |
|---|---|
| API key is never sent in cleartext to a non-loopback host | `http_to_remote_host_is_rejected` (client/transport_policy) |
| Loopback development endpoints still work | `http_to_loopback_is_accepted` |
| Lookalike hosts (`127.0.0.1.evil.com`) are not treated as loopback | `lookalike_hosts_are_not_treated_as_loopback` |
| Non-HTTP schemes rejected | `non_http_schemes_are_rejected` |
| Authorization header is redacted in `Debug` output | `auth_header_is_marked_sensitive_and_redacted_in_debug` |

## 9. FFI memory safety (`ves-stark-zig`)

This crate holds every `unsafe` block in the workspace; the other ten are
`#![forbid(unsafe_code)]`. These tests run under Miri in CI.

| Property | Test |
|---|---|
| NULL handles are rejected, never dereferenced | `null_pointers_are_rejected_not_dereferenced` |
| Proof accessors tolerate a NULL handle | `proof_accessors_tolerate_a_null_handle` |
| Verification accessors tolerate a NULL handle | `verification_accessors_tolerate_a_null_handle` |
| A NULL handle zeroes the out-length (no stale length beside a NULL pointer) | `batch_proof_bytes_zeroes_out_len_on_null_handle` |
| Freeing NULL is a no-op | `freeing_null_is_a_no_op` |
| Allocate/borrow/free cycle is balanced | `public_inputs_round_trip_allocates_and_frees_cleanly` |
| Repeated cycles do not corrupt allocator state | `repeated_round_trips_do_not_corrupt_allocator_state` |
| Malformed input fails closed with a retrievable message | `invalid_json_returns_null_and_records_an_error` |
| Well-formed but wrong JSON is rejected | `structurally_valid_but_wrong_json_is_rejected` |
| Out-parameter string protocol hands over ownership correctly | `compute_policy_hash_writes_an_owned_string` |
| Hash helper rejects NULL arguments | `compute_policy_hash_rejects_null_arguments` |

## 10. Transport & serialization

| Property | Test |
|---|---|
| Real batch proof survives JSON round-trip and verifies | `test_batch_proof_survives_json_round_trip_and_verifies` (batch) |
| Serialized batch proof binary round-trip preserves fields | `test_binary_round_trip` (batch/serialization) |
| Malformed/tampered serialized proofs rejected | `test_binary_deserialization_rejects_*`, `test_json_deserialization_rejects_*`, `test_*_rejects_tampered_*` (batch/serialization) |

## 11. Robustness (no panic on untrusted input)

The untrusted-input surfaces return `Ok`/`Err` rather than unwinding into the
caller. Two caveats, both upstream in Winterfell and both found by the fuzz
targets below — see `docs/THREAT_MODEL.md` for the full write-up:

- **Contained.** `winter-air` overflows on a malformed log2 trace-length byte.
  The verifiers wrap deserialization in `guard_untrusted`, so this surfaces as a
  `DeserializationError`. Locked in by `tests/untrusted_input_test.rs`.
- **Contained.** `winter-utils` sizes a `Vec` from an unchecked length prefix,
  so a 39-byte proof could request a ~72 PB allocation and abort the process.
  The verifiers parse through `bounded_reader::deserialize_bounded`, whose
  `read_many` rejects a count the input cannot hold before allocating.

Continuous fuzzing (libFuzzer, `fuzz/`) plus example-based rejection tests:

| Surface | Fuzz target / tests |
|---|---|
| Rescue hash | `fuzz_rescue_hash` |
| Public-input parsing | `fuzz_public_inputs` |
| Single-proof deserialization + verify | `fuzz_proof_deserialization`; `test_empty_proof_bytes_rejected`, `test_garbage_proof_bytes_rejected`, `test_truncated_proof_rejected`, `test_bit_flipped_proof_rejected` |
| Witness validation | `fuzz_witness_validation` |
| Batch proof JSON deserialization + verify | `fuzz_batch_proof` |
| No panic escapes the library boundary | `fuzzer_crash_input_is_rejected_not_panicked_on`, `malformed_headers_are_rejected_not_panicked_on`, `no_short_input_of_any_length_panics`, `extreme_thresholds_do_not_panic` (it/untrusted_input_test) |
| Unbounded allocation rejected before allocating | `oversized_declared_allocation_is_rejected_not_attempted` (it/untrusted_input_test), `declared_length_beyond_input_is_rejected_before_allocating` (prim/bounded_reader) |
| `BoundedReader` identical to upstream `SliceReader` except the over-allocation region | `agrees_with_slice_reader_except_where_upstream_would_over_allocate`, `never_panics_and_bounds_allocation`, `huge_declared_counts_are_invalid_value` (it/bounded_reader_prop_test) |
| Verifier builder refuses to pick the weaker statement silently | `run_without_a_binding_choice_is_refused`, `strict_alone_is_still_refused`, `witness_only_requires_the_field` (verifier/builder) |
| Full FFI prove/verify cycle under Miri (nightly) | `miri_full_prove_verify_cycle` (zig) — `#[ignore]` natively, run by `.github/workflows/nightly.yml` |

Run fuzzers with `cargo +nightly fuzz run <target>`.

## 12. CI gates (every PR)

`fmt --check`, `clippy --all-features -D warnings`, `test --all-features`,
`cargo audit`, `cargo +nightly miri test -p ves-stark-zig`, a 60s smoke run of
every fuzz target, `doc -D warnings`, `check --benches`, and `llvm-cov`
coverage — see `.github/workflows/ci.yml`. Nightly (`nightly.yml`): a 40-minute
fuzz campaign per target with a persisted corpus, Miri over a full FFI prove/verify
cycle, and `cargo-deny` license/ban/source policy.

---

## Out of scope for this matrix

- **Formal/external soundness audit** of the AIR and verifier. These tests
  demonstrate the intended properties hold behaviorally; they do not constitute a
  machine-checked proof of soundness. An independent ZK audit remains recommended
  before relying on the system to anchor value at scale.
- **Performance figures.** See `cargo bench --bench stark_bench`; numbers are
  environment-dependent and not asserted here.
