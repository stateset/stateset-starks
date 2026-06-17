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
| 5 | Public-input substitution | inputs bound into trace via boundary assertions | `test_proof_with_different_event_id_rejected`, `test_payload_hash_mismatch_rejected`, `test_public_inputs_canonical_hash_commits_to_every_field` (prim) |
| 6 | Batch public-input substitution | batch AIR binds `BatchPublicInputs` | `test_batch_verifier_rejects_tampered_public_inputs`, `test_batch_verifier_rejects_bit_flipped_proof` (batch) |
| 7 | Batch chain stitching | `verify_chain` enforces tenant/store + sequence continuity + state-root linkage | `test_verify_chain_rejects_broken_state_root_linkage`, `test_chain_continuity_rejects_tenant_mismatch`, `test_chain_continuity_rejects_store_mismatch`, `test_sequence_continuity_check_with_gap` |
| 8 | Oversized-proof resource exhaustion | `MAX_BATCH_PROOF_SIZE` at verify; `MAX_SUBMISSION_PROOF_SIZE` at submit (const-asserted equal) | `test_verify_batch_proof_over_max_size_is_rejected`, `test_batch_proof_submission_validate_rejects_oversized_proof` (client) |

## 3. Commitment / binding completeness

Every hash that binds event metadata or authorization constraints into a proof has
a field-by-field completeness guard: perturbing **any** committed field must change
the hash. This catches the "silently dropped field → forgeable binding" class.

| Binding | Fields | Test |
|---|---|---|
| `CompliancePublicInputs` canonical hash (per-event) | 13 | `test_public_inputs_canonical_hash_commits_to_every_field` (prim) |
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

## 6. Transport & serialization

| Property | Test |
|---|---|
| Real batch proof survives JSON round-trip and verifies | `test_batch_proof_survives_json_round_trip_and_verifies` (batch) |
| Serialized batch proof binary round-trip preserves fields | `test_binary_round_trip` (batch/serialization) |
| Malformed/tampered serialized proofs rejected | `test_binary_deserialization_rejects_*`, `test_json_deserialization_rejects_*`, `test_*_rejects_tampered_*` (batch/serialization) |

## 7. Robustness (no panic on untrusted input)

The untrusted-input surfaces never panic — they return `Ok`/`Err`. Continuous
fuzzing (libFuzzer, `fuzz/`) plus example-based rejection tests:

| Surface | Fuzz target / tests |
|---|---|
| Rescue hash | `fuzz_rescue_hash` |
| Public-input parsing | `fuzz_public_inputs` |
| Single-proof deserialization + verify | `fuzz_proof_deserialization`; `test_empty_proof_bytes_rejected`, `test_garbage_proof_bytes_rejected`, `test_truncated_proof_rejected`, `test_bit_flipped_proof_rejected` |
| Witness validation | `fuzz_witness_validation` |
| Batch proof JSON deserialization + verify | `fuzz_batch_proof` |

Run fuzzers with `cargo +nightly fuzz run <target>`.

## 8. CI gates (every PR)

`fmt --check`, `clippy --all-features -D warnings`, `test --all-features`,
`doc -D warnings`, `bench --no-run`, and `llvm-cov` coverage — see
`.github/workflows/ci.yml`.

---

## Out of scope for this matrix

- **Formal/external soundness audit** of the AIR and verifier. These tests
  demonstrate the intended properties hold behaviorally; they do not constitute a
  machine-checked proof of soundness. An independent ZK audit remains recommended
  before relying on the system to anchor value at scale.
- **Performance figures.** See `cargo bench --bench stark_bench`; numbers are
  environment-dependent and not asserted here.
