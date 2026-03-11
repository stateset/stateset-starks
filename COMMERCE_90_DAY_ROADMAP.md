# 90-Day Roadmap: StateSet STARK for Intelligent Commerce

## Objective
Build an STARK-native commerce platform layer that turns event-level policy checks and batch state transitions into a global, privacy-preserving fraud/compliance runtime.

This roadmap assumes the current stack is the foundation:
- `ves-stark-air`
- `ves-stark-prover`
- `ves-stark-verifier`
- `ves-stark-batch`
- `ves-stark-client`
- `ves-stark-primitives`

and adds a commerce-oriented extension surface.

## North-Star Outcomes (End of 90 Days)
1. New commerce event types are proven with policy-specific zk-STARK attestations.
2. End-to-end ingestion → proof generation → batch verification → submission works for two live policy families.
3. Sequence + policy + witness continuity is enforceable across batches.
4. Fraud/compliance enforcement moves from ad-hoc checks to verifiable proofs.
5. Clear path for global commerce expansion (regional policy packs, additional policies).

---

## Proposed Crate Set

### New/expanded crates
1. `ves-stark-commerce-domain`
   - Canonical event types (`payment`, `payout`, `refund`, `dispute`) and IDs.
   - Versioned payload schema and `payload_kind` registry.
   - Conversion to/from `CompliancePublicInputs` and batch metadata views.

2. `ves-stark-commerce-policies`
   - Extended policy implementations and policy IDs.
   - First policies:
     - `amount.less_than`
     - `amount.less_than_or_equal`
     - `merchant.daily_cap`
     - `merchant.velocity_count`
     - `merchant.refund_ratio`
   - Policy registry + deserialization + validation rules.

3. `ves-stark-commerce-attestation`
   - Event intake and canonicalization boundary.
   - Verifies source signatures/attestations and maps raw event records into canonical STARK public inputs.
   - Produces signed `event_commitments`, `witness_commitment`, and `policy_id/params`.

4. `ves-stark-commerce-state`
   - Commerce-specific batch semantics:
     - tenant/store scope sequencing,
     - optional regional settlement windows,
     - anti-duplication helpers.
   - Pre-built batch builders for multi-event submission.

5. `ves-stark-commerce-sdk`
   - Unified user-facing API for app/dev teams:
     - prove event, prove batch, verify event, verify batch chain.
   - Opinionated defaults for proof options, timeouts, batch sizing.

6. `ves-stark-commerce-policy-compiler` (optional in 90 days)
   - JSON policy DSL → policy objects + compatibility checks.
   - Helps product/policy teams publish new policy packs safely.

### No-new-crate phase (stabilization)
- `ves-stark-air`: add policy hook points for new policy types.
- `ves-stark-batch`: add optional structured event metadata fields and stronger chain validators.
- `ves-stark-client`: expose commerce batch submission + verify APIs (set-chain + optional webhooks).

---

## 90-Day Execution Plan

## Days 1-14: Foundation & Threat-Model Alignment
### Goals
- Define commerce trust boundary and canonical input contract.
- Lock policy and payload versioning.

### Deliverables
1. `ves-stark-commerce-domain`
   - `CommerceEvent`, `CommerceEventType`, `PolicyRef`, `PolicyVersion`.
   - Canonical hash inputs for event + policy.
2. `ves-stark-commerce-policies`
   - Add 3 baseline policies and tests:
     - amount thresholds (`<`, `<=`),
     - merchant daily cap,
     - refund ratio rule.
3. `docs/` update: trust boundary, threat model updates, policy assumptions.
4. End-to-end schema tests:
   - input malformed / unknown policy / old policy version handling.

### Success criteria
- A new event payload for at least one domain can be transformed into `CompliancePublicInputs` reliably.
- Invalid policy/version is rejected deterministically.

---

## Days 15-30: Policy Execution + Attestation Integration
### Goals
- Move from “policy in code only” to “policy-bound proof data from attested intake”.

### Deliverables
1. `ves-stark-commerce-attestation`
   - Trusted ingest pipeline:
     - decode, validate, and assert required canonical fields,
     - verify external signatures where present,
     - emit witness commitment.
2. Policy binding hardening in prover path:
   - Ensure generated proof inputs are always bound to policy IDs and hashes.
3. `ves-stark-verifier` guardrails:
   - require policy continuity checks in optional verify mode.
4. Shared fixtures for positive/negative event proofs.

### Success criteria
- At least one production-like event feed can be transformed and proven from ingestion stage.
- Replay and payload-tamper tests pass for commerce inputs.

---

## Days 31-45: Batch-First Commerce Mode
### Goals
- Prove and verify cross-event integrity in practical batch flows.

### Deliverables
1. `ves-stark-commerce-state`
   - Batch builder from commerce events with tenant/store scoping.
2. `BatchWitness` extension wrappers:
   - enforce event-kind policy homogeneity per batch,
   - enforce tenant/store partitioning by default.
3. `ves-stark-batch` enhancements:
   - stronger sequence continuity checks in witness validation (in addition to verifier-chain checks),
   - batch metadata helper constructors for commerce.
4. Integration example:
   - 50 events, one batch, one policy pack.

### Success criteria
- Batch prover emits proof with deterministic `event_tree_root` and `new_state_root`.
- Verifier rejects bad sequence, mixed policy, wrong policy hash, and altered commitment.

---

## Days 46-60: Fraud-Prevention Primitives
### Goals
- Convert anti-fraud policy into verifiable primitives and batch observability.

### Deliverables
1. Add policy families:
   - `velocity_count` (events/tenant in window),
   - `duplicate_signature_reject` or `idempotency_token_unique` helper constraints.
2. Off-chain helper crate integration:
   - risk signal pre-processor outputs bounded claims for STARK policies.
3. `ves-stark-client` features:
   - submission helpers for compliance+fraud modes,
   - chain-verification helpers for operators.
4. Detection dashboards for:
   - reject reason taxonomy,
   - proof generation latency,
   - verifier failure rates.

### Success criteria
- 2 anti-fraud policies integrated, each with negative/positive proof test suites.
- Rejection reasons are deterministic and machine-consumable.

---

## Days 61-75: Global Commerce Readiness
### Goals
- Support multi-region governance and policy versioning.

### Deliverables
1. Policy pack registry for region/vertical:
   - `region.us`, `region.eu`, `region.apac` policy groups.
2. Multi-key rollover support:
   - active policy version in proof metadata.
3. International fields:
   - currency, FX-rate band, jurisdiction tags in event domain schema.
4. Settlement-level invariants:
   - per-tenant per-window cap enforcement in batch metadata.

### Success criteria
- Same event can be routed to different region packs with explicit policy selection.
- A policy version mismatch produces explicit hard fail before proof verification.

---

## Days 76-90: Production Hardening & Launch Prep
### Goals
- Stability, observability, and operational runbooks.

### Deliverables
1. `ves-stark-commerce-sdk`
   - one-command local flow:
     - ingest -> prove event -> batch -> verify chain -> submit.
2. Migration guide:
   - from current manual compliance checks to STARK-backed enforcement.
3. Performance tuning:
   - optimize batch size defaults,
   - benchmark proof time vs batch size,
   - profile trace width and constraint hotspots.
4. Security review checklist:
   - payload binding, policy replay, continuity, witness commitments, key management.

### Success criteria
- 2-hour ops playbook for rollback/replay recovery.
- P95 event prove path and batch verify latency under internal SLO targets.
- “Ready for staging global commerce pilot” gate passed.

---

## Milestone Matrix

### M1 (Day 14)
- Canonical commerce event + policies + ingestion boundary

### M2 (Day 30)
- Policy-bound single-event proofs from trusted attested payload

### M3 (Day 45)
- Batch proof flow proven end-to-end

### M4 (Day 60)
- Anti-fraud policy families active

### M5 (Day 90)
- Globalized policy packs + production-grade SDK + runbooks

---

## Resource Plan

### Suggested roles
- 1 Core ZK engineer (AIR/prover/verifier changes)
- 1 Backend engineer (ingestion + attestations)
- 1 Product/Policy engineer (policy design + governance)
- 1 SRE/Platform engineer (SDK + observability)
- 1 QA/reliability engineer

### Dependency risks
- Policy explosion without good registry governance
- Ingestion trust assumptions not enforced (most common risk)
- Wrongness in cross-region semantics if policy versions are not explicit

---

## Immediate Next Step (this week)
1. Create `ves-stark-commerce-domain` and `ves-stark-commerce-policies` scaffolding.
2. Add 2 policy extensions and 1 conversion pipeline from raw event → `CompliancePublicInputs`.
3. Add end-to-end integration test for one policy and one batch path.


