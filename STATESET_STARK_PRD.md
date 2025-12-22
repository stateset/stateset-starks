# StateSet STARK: Product Requirements Document (Aligned PRD v1.1)

**Document Version:** 1.1  
**Status:** Draft (rewrite overlay; legacy preserved below)  
**Last Updated:** December 2025  
**Target Release:** Phase 1 (VES Compliance Proofs): Q3 2025  

This section is the authoritative PRD for `stateset-stark`, aligned to what exists in:
- `icommerce-app/stateset-sequencer` (proof registry + canonical inputs endpoints)
- `icommerce-app/set` (Set Chain registry + external anchor service)

The remainder of this file is the earlier v1.0 draft (batch-validity oriented) and is **archived** for reference.

---

## 1. Executive Summary

### 1.1 What We’re Building

`stateset-stark` is the STARK proving/verifying layer for VES (Verifiable Event Sync).

**Phase 1** is **per-event compliance STARK proofs** for **encrypted VES events** (VES-ENC-1). These proofs let third parties verify **policy claims** about event payloads without learning the payload.

Batch/state-transition validity proofs remain Phase 2+.

### 1.2 Why This Matters

Encrypted events block the sequencer from validating business rules over plaintext. Phase 1 adds a verifiable bridge:

```
Encrypted VES event + compliance proof → verifiable claim
```

Examples:
- “Order total < $10,000”
- “Refund <= original total”
- “Inventory delta does not drive stock negative”

### 1.3 Phase Summary

| Phase | Scope | Verification | Anchoring |
|------:|-------|--------------|----------|
| **1** | Per-event compliance proofs | Off-chain verifier (Rust) + sequencer input-consistency checks | Events/commitments anchored; proofs stored (proof anchoring optional later) |
| 2+ | Batch validity (state transitions) | Off-chain first; on-chain later/optimistic | Requires Set Chain contract upgrades |

---

## 2. Current State (Implemented in `stateset-sequencer`)

### 2.1 Storage

Postgres table:
- `ves_compliance_proofs` (per-event proof storage; encrypted at rest)

Key points:
- Idempotency key: `(event_id, proof_type, proof_version, policy_hash)`
- Stored fields include `policy_id`, `policy_params`, `policy_hash`, `proof_hash`, optional `public_inputs`.

### 2.2 Sequencer API (Canonical Inputs + Proof Registry)

Canonical inputs:
- `POST /api/v1/ves/compliance/{event_id}/inputs`

Proof registry:
- `POST /api/v1/ves/compliance/{event_id}/proofs`
- `GET  /api/v1/ves/compliance/{event_id}/proofs`
- `GET  /api/v1/ves/compliance/proofs/{proof_id}`
- `GET  /api/v1/ves/compliance/proofs/{proof_id}/verify` *(currently input-consistency only; Phase 1.1 makes it cryptographic)*

---

## 3. Phase 1 Product: VES Compliance Proofs (Per Event)

### 3.1 Goals

| ID | Goal | Priority |
|----|------|----------|
| P1-G1 | Define canonical **public inputs** (must match sequencer) | P0 |
| P1-G2 | Define versioned **policy identifiers** + params hashing | P0 |
| P1-G3 | Implement ≥1 production policy end-to-end (prover + verifier) | P0 |
| P1-G4 | Support multiple proofs per event | P0 |
| P1-G5 | Integrate verifier into sequencer `/verify` | P1 |
| P1-G6 | Benchmarks + reproducible test vectors | P0 |

### 3.2 Non-Goals

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| P1-NG1 | On-chain STARK verification | Too expensive/complex for Phase 1 |
| P1-NG2 | Batch/state-transition validity proofs | Separate phase (Phase 2+) |
| P1-NG3 | Proving Ed25519 inside STARK | Sequencer already verifies signatures; revisit later |
| P1-NG4 | Proving VES-ENC-1 decryption correctness | Optional/advanced; revisit later |

---

## 4. Proof Specification (Phase 1)

### 4.1 Canonical Public Inputs (MUST MATCH sequencer)

Canonical public inputs are JSON (RFC 8785 JCS canonicalizable) with this shape:

```json
{
  "eventId": "uuid",
  "tenantId": "uuid",
  "storeId": "uuid",
  "sequenceNumber": 123,
  "payloadKind": 1,
  "payloadPlainHash": "hex32",
  "payloadCipherHash": "hex32",
  "eventSigningHash": "hex32",
  "policyId": "aml.threshold",
  "policyParams": { "threshold": 10000 },
  "policyHash": "hex32"
}
```

Notes:
- `hex32` values are lowercase hex of 32 bytes, no `0x`.
- `policyParams` defaults to `{}` when omitted.

#### 4.1.1 `policyHash`

```
policy_hash = SHA256(
  "STATESET_VES_COMPLIANCE_POLICY_HASH_V1" ||
  JCS({"policyId": policyId, "policyParams": policyParams})
)
```

#### 4.1.2 `public_inputs_hash` (transport convenience)

```
public_inputs_hash = SHA256(JCS(public_inputs))
```

### 4.2 Proof Bytes + Hash (storage binding)

Sequencer hashes proof bytes:

```
proof_hash = SHA256("STATESET_VES_COMPLIANCE_PROOF_HASH_V1" || proof_bytes)
```

### 4.3 Verification Semantics

Phase 1 verification must check:
1. `public_inputs` equals sequencer-canonical inputs for `(event_id, policyId, policyParams)`
2. `policy_hash` recomputes correctly
3. STARK proof verifies for `(policyId, proofVersion)` under the `stateset-stark` verifier

Sequencer currently enforces (1) and (2). Phase 1.1 adds (3).

---

## 5. Roadmap

### 5.1 Phase 1.0

- Freeze canonical public inputs + policy hashing spec (this doc).
- Implement prover/verifier for one policy (recommended starting policy: `aml.threshold`).
- Publish test vectors + benchmarks.

### 5.2 Phase 1.1 (Hardening)

- Integrate cryptographic verification into sequencer `/verify`.
- Add policy allowlist + proof size limits + rate limiting + metrics.

### 5.3 Phase 2+ (Batch Validity Proofs)

Out of scope here; depends on VES hashing strategy, signature strategy, and Set Chain contract upgrades (`set/contracts/SetRegistry.sol` does not verify proofs today).

---

## 6. Proving Backend (Decision)

**Decision:** **Winterfell AIR** for Phase 1 compliance proofs.

Conventions for Phase 1:
- Base field: Winterfell `BaseElement` (64-bit prime field).
- 32-byte hashes are represented as **8×u32 limbs** (injective into the base field).

# Appendix: Legacy Draft (v1.0 - archived)

> The content below is preserved for reference. It does **not** reflect the current implementation in `stateset-sequencer` + `set`, and it includes non-existent tables/contracts/endpoints.

**Document Version:** 1.0  
**Status:** Draft  
**Author:** StateSet Engineering  
**Last Updated:** December 2024  
**Target Release:** Q3 2025

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [User Stories](#4-user-stories)
5. [Technical Architecture](#5-technical-architecture)
6. [Functional Requirements](#6-functional-requirements)
7. [Non-Functional Requirements](#7-non-functional-requirements)
8. [System Design](#8-system-design)
9. [API Specification](#9-api-specification)
10. [Data Models](#10-data-models)
11. [Security Considerations](#11-security-considerations)
12. [Milestones and Timeline](#12-milestones-and-timeline)
13. [Success Metrics](#13-success-metrics)
14. [Risks and Mitigations](#14-risks-and-mitigations)
15. [Dependencies](#15-dependencies)
16. [Open Questions](#16-open-questions)
17. [Appendices](#17-appendices)

---

## 1. Executive Summary

### 1.1 Overview

StateSet STARK (`stateset-stark`) is a custom zero-knowledge proof system built on the Winterfell library that provides validity proofs for VES (Verifiable Event Sync) batch commitments. It enables cryptographic verification that:

- All events in a batch have valid agent signatures
- The Merkle events root was computed correctly
- State transitions follow deterministic projection rules
- Business compliance rules are satisfied (inventory non-negative, refunds within limits, etc.)

### 1.2 Why Build Custom

| Alternative | Why Not |
|-------------|---------|
| SP1/risc0 | External dependency, less control, generic overhead |
| Cairo | Different language, StarkWare ecosystem lock-in |
| Groth16/PLONK | Trusted setup, patent concerns |
| **Winterfell (our choice)** | Full ownership, Rust-native, no trusted setup, post-quantum |

### 1.3 Business Value

1. **Instant Finality**: Replace 7-day optimistic challenge windows with cryptographic validity
2. **Trustless Verification**: Third parties verify proofs without trusting StateSet
3. **Regulatory Compliance**: Prove business rules without exposing data
4. **Technical Moat**: Custom STARK stack is hard to replicate
5. **Cost Reduction**: Batch 1000s of events into a single on-chain proof

### 1.4 Key Metrics (Target)

| Metric | Target | Stretch |
|--------|--------|---------|
| Proof generation (100 events) | < 60s | < 30s |
| Proof generation (1000 events) | < 10min | < 5min |
| Proof size | < 200KB | < 100KB |
| On-chain verification gas | < 500K | < 300K |
| Security level | 100 bits | 128 bits |

---

## 2. Problem Statement

### 2.1 Current State

VES v1.0 provides:
- Agent-signed events with Ed25519 signatures
- Merkle commitments anchored on Set Chain (L2)
- Commitment chaining to prevent equivocation

However, the current system is **optimistic**:
- Verifiers must trust the sequencer computed roots correctly
- Verifiers must replay all events to validate state transitions
- Compliance claims (e.g., "all orders < $10K") require data access

### 2.2 The Gap

```
Current: "Trust the sequencer, verify by replaying"
Target:  "Trust the math, verify a single proof"
```

Without validity proofs:
- Challenge periods delay finality
- Replay verification scales O(n) with event count
- Compliance attestations require data disclosure

### 2.3 Who Needs This

| Persona | Need |
|---------|------|
| **Enterprise Buyer** | Cryptographic audit trail, regulatory compliance |
| **Auditor** | Verify batch integrity without replaying events |
| **Merchant** | Prove solvency/compliance without exposing data |
| **Partner** | Trust cross-system state without accessing data |
| **Investor** | Technical differentiation, defensible moat |

---

## 3. Goals and Non-Goals

### 3.1 Goals

| ID | Goal | Priority |
|----|------|----------|
| G1 | Prove signature validity for all events in a batch | P0 |
| G2 | Prove Merkle events_root computation correctness | P0 |
| G3 | Prove state transition determinism (prev → new state root) | P0 |
| G4 | Prove business compliance rules (configurable) | P1 |
| G5 | On-chain proof verification on Set Chain | P1 |
| G6 | Full Rust implementation with no external prover dependencies | P0 |
| G7 | Integration with stateset-sequencer batch flow | P0 |
| G8 | Sub-minute proof generation for typical batches (100 events) | P1 |

### 3.2 Non-Goals (v1.0)

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG1 | Real-time per-event proofs | Batch proofs are sufficient; per-event is cost-prohibitive |
| NG2 | Recursive proof aggregation | Deferred to v2.0 |
| NG3 | Privacy for public inputs | Events root and state roots are public; payload privacy via VES-ENC-1 |
| NG4 | Mobile/browser proving | Server-side only for v1.0 |
| NG5 | Full Solidity FRI verifier | Use optimistic + fraud proof for v1.0; full verifier in v2.0 |
| NG6 | GPU acceleration | CPU-only for v1.0; GPU in v2.0 |

### 3.3 Future Goals (v2.0+)

- Recursive proof composition (prove batches of batches)
- Full on-chain STARK verification
- GPU-accelerated proving
- Proof generation as a service (external parties can request proofs)
- Cross-chain proof verification (Ethereum L1, other L2s)

---

## 4. User Stories

### 4.1 Sequencer Operator

```
As a sequencer operator,
I want to generate a STARK proof for each batch commitment,
So that verifiers can trust the batch without replaying events.

Acceptance Criteria:
- Proof generation is triggered after batch commitment creation
- Proof is stored alongside the batch in the database
- Proof hash is included in on-chain anchor transaction
- Failed proof generation is logged and retried
```

### 4.2 Auditor

```
As an auditor,
I want to verify a STARK proof against on-chain commitments,
So that I can confirm batch integrity without accessing event data.

Acceptance Criteria:
- I can fetch proof by batch_id from the sequencer API
- I can verify the proof using only public inputs (roots, sequence range)
- Verification completes in < 1 second
- I receive a clear pass/fail result with error details on failure
```

### 4.3 Enterprise Buyer

```
As an enterprise buyer,
I want cryptographic proof that all transactions follow compliance rules,
So that I can satisfy regulatory requirements without exposing data.

Acceptance Criteria:
- Proof includes configurable compliance claims
- I can verify claims without seeing underlying transaction data
- Proof is admissible as evidence of compliance
```

### 4.4 On-Chain Verifier

```
As an on-chain smart contract,
I want to verify STARK proofs submitted with batch anchors,
So that invalid batches are rejected automatically.

Acceptance Criteria:
- Contract accepts proof bytes and public inputs
- Verification completes within block gas limits
- Invalid proofs are rejected with clear error codes
- Valid proofs update the on-chain state
```

---

## 5. Technical Architecture

### 5.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              stateset-stark                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         ves-stark-primitives                          │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────┐  │   │
│  │  │   Field    │  │  Rescue    │  │  Merkle    │  │  Ed25519 AIR   │  │   │
│  │  │ Arithmetic │  │   Hash     │  │   Tree     │  │   Gadgets      │  │   │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                           ves-stark-air                               │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────┐  │   │
│  │  │ Compliance │  │ Signature  │  │  Merkle    │  │   Transition   │  │   │
│  │  │    AIR     │  │    AIR     │  │    AIR     │  │      AIR       │  │   │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                    ┌─────────────────┼─────────────────┐                    │
│                    ▼                 ▼                 ▼                    │
│  ┌─────────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐  │
│  │  ves-stark-prover   │  │ ves-stark-verify│  │  ves-stark-solidity     │  │
│  │  ┌───────────────┐  │  │ ┌─────────────┐ │  │  ┌───────────────────┐  │  │
│  │  │ Trace Builder │  │  │ │ Rust Verify │ │  │  │ Solidity Verifier │  │  │
│  │  │ Witness Gen   │  │  │ │             │ │  │  │ (or Registry)     │  │  │
│  │  │ FRI Prover    │  │  │ └─────────────┘ │  │  └───────────────────┘  │  │
│  │  └───────────────┘  │  └─────────────────┘  └─────────────────────────┘  │
│  └─────────────────────┘                                                     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           stateset-sequencer                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │  Event Ingest   │─▶│  Commitment     │─▶│  STARK Proving Service      │  │
│  │                 │  │  Engine         │  │  (async background task)    │  │
│  └─────────────────┘  └─────────────────┘  └──────────────┬──────────────┘  │
│                                                           │                  │
└───────────────────────────────────────────────────────────┼──────────────────┘
                                                            │
                                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Set Chain (L2)                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  SetRegistryWithProofs.sol                                           │    │
│  │  - commitBatchWithProof(streamId, roots, proof)                      │    │
│  │  - verifyProof(proof, publicInputs)                                  │    │
│  │  - heads[streamId] → latest verified commitment                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Crate Structure

```
stateset-stark/
├── Cargo.toml                          # Workspace root
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CONSTRAINTS.md                  # Detailed constraint documentation
│   └── SECURITY.md
│
├── crates/
│   ├── ves-stark-primitives/           # Low-level cryptographic primitives
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── field.rs                # Goldilocks field operations
│   │       ├── rescue.rs               # Rescue-Prime hash function
│   │       ├── poseidon.rs             # Poseidon hash (alternative)
│   │       ├── merkle.rs               # Merkle tree with Rescue
│   │       └── ed25519/                # Ed25519 AIR gadgets
│   │           ├── mod.rs
│   │           ├── curve.rs            # Curve operations in-circuit
│   │           ├── scalar.rs           # Scalar field operations
│   │           └── verify.rs           # Signature verification gadget
│   │
│   ├── ves-stark-air/                  # AIR constraint definitions
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── compliance.rs           # Main compliance AIR
│   │       ├── signature.rs            # Signature verification constraints
│   │       ├── merkle.rs               # Merkle verification constraints
│   │       ├── transition.rs           # State transition constraints
│   │       ├── trace.rs                # Execution trace layout
│   │       └── periodic.rs             # Periodic columns (round constants)
│   │
│   ├── ves-stark-prover/               # Proof generation
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── prover.rs               # Main prover implementation
│   │       ├── trace.rs                # Trace table construction
│   │       ├── witness.rs              # Witness generation from VES data
│   │       └── options.rs              # Proof options configuration
│   │
│   ├── ves-stark-verifier/             # Rust verification
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── verify.rs               # Verification logic
│   │
│   └── ves-stark-solidity/             # On-chain verification
│       ├── Cargo.toml                  # For build scripts
│       ├── src/
│       │   ├── VesStarkVerifier.sol    # Full STARK verifier (v2.0)
│       │   └── VesStarkRegistry.sol    # Optimistic + fraud proof (v1.0)
│       └── test/
│           └── VesStarkVerifier.t.sol  # Foundry tests
│
├── benches/
│   ├── prover_bench.rs                 # Proving time benchmarks
│   ├── verifier_bench.rs               # Verification time benchmarks
│   └── trace_bench.rs                  # Trace generation benchmarks
│
├── tests/
│   ├── e2e_small_batch.rs              # 10 events
│   ├── e2e_medium_batch.rs             # 100 events
│   ├── e2e_large_batch.rs              # 1000 events
│   └── constraint_tests.rs             # Individual constraint tests
│
└── examples/
    ├── prove_batch.rs                  # Example prover usage
    └── verify_proof.rs                 # Example verifier usage
```

### 5.3 Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| `ves-stark-primitives` | Field arithmetic, Rescue hash, Merkle trees, Ed25519 curve operations |
| `ves-stark-air` | AIR constraint definitions, trace layout, public inputs |
| `ves-stark-prover` | Witness generation, trace construction, FRI proving |
| `ves-stark-verifier` | Rust-based proof verification |
| `ves-stark-solidity` | On-chain verification contracts |

---

## 6. Functional Requirements

### 6.1 Proof Generation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-PG-01 | System SHALL generate STARK proofs from VES batch data | P0 |
| FR-PG-02 | Proof SHALL commit to public inputs: events_root, prev_state_root, new_state_root, sequence_range | P0 |
| FR-PG-03 | Proof SHALL verify all agent signatures in the batch | P0 |
| FR-PG-04 | Proof SHALL verify Merkle tree construction from event leaf hashes | P0 |
| FR-PG-05 | Proof SHALL verify state transition determinism | P0 |
| FR-PG-06 | Proof generation SHALL be idempotent (same inputs → same proof) | P1 |
| FR-PG-07 | System SHALL support configurable compliance claims | P1 |
| FR-PG-08 | System SHALL log proof generation metrics (time, constraints, etc.) | P1 |

### 6.2 Proof Verification (Rust)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-VR-01 | Verifier SHALL accept valid proofs | P0 |
| FR-VR-02 | Verifier SHALL reject invalid proofs | P0 |
| FR-VR-03 | Verifier SHALL validate public inputs match proof commitments | P0 |
| FR-VR-04 | Verifier SHALL return detailed error on failure | P1 |
| FR-VR-05 | Verifier SHALL be stateless (no database access required) | P0 |

### 6.3 Proof Verification (On-Chain)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-VC-01 | Contract SHALL verify proof against public inputs | P0 |
| FR-VC-02 | Contract SHALL enforce commitment chaining | P0 |
| FR-VC-03 | Contract SHALL emit events on successful verification | P0 |
| FR-VC-04 | Contract SHALL reject proofs exceeding gas limits | P0 |
| FR-VC-05 | Contract SHALL support fraud proof challenges (v1.0 optimistic mode) | P1 |

### 6.4 Sequencer Integration

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-SI-01 | Sequencer SHALL trigger proof generation after batch creation | P0 |
| FR-SI-02 | Sequencer SHALL store proofs in database with batch reference | P0 |
| FR-SI-03 | Sequencer SHALL expose proof via REST API | P0 |
| FR-SI-04 | Sequencer SHALL retry failed proof generation with backoff | P1 |
| FR-SI-05 | Sequencer SHALL submit proof hash with on-chain anchor | P0 |

### 6.5 Compliance Claims (P1)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-CC-01 | System SHALL support "all signatures valid" claim | P0 |
| FR-CC-02 | System SHALL support "inventory non-negative" claim | P1 |
| FR-CC-03 | System SHALL support "order totals below threshold" claim | P1 |
| FR-CC-04 | System SHALL support "refunds within original" claim | P1 |
| FR-CC-05 | System SHALL support "deterministic projection" claim | P0 |
| FR-CC-06 | Claims SHALL be enumerated in public inputs | P1 |

---

## 7. Non-Functional Requirements

### 7.1 Performance

| ID | Requirement | Target | Measurement |
|----|-------------|--------|-------------|
| NFR-P-01 | Proof generation time (10 events) | < 10s | Wall clock time |
| NFR-P-02 | Proof generation time (100 events) | < 60s | Wall clock time |
| NFR-P-03 | Proof generation time (1000 events) | < 10min | Wall clock time |
| NFR-P-04 | Proof verification time (Rust) | < 100ms | Wall clock time |
| NFR-P-05 | Proof verification gas (on-chain) | < 500K gas | Gas used |
| NFR-P-06 | Trace generation memory | < 16GB | Peak RSS |
| NFR-P-07 | Proof size | < 200KB | Serialized bytes |

### 7.2 Security

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-S-01 | Cryptographic security level | ≥ 100 bits |
| NFR-S-02 | No trusted setup | Transparent (FRI-based) |
| NFR-S-03 | Post-quantum security | STARK-based (hash-only) |
| NFR-S-04 | Soundness error | ≤ 2^-100 |
| NFR-S-05 | Zero-knowledge property | Perfect ZK (witness not leaked) |

### 7.3 Reliability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-R-01 | Proof generation success rate | ≥ 99.9% |
| NFR-R-02 | Verification determinism | 100% (same result for same inputs) |
| NFR-R-03 | Crash recovery | Resume from last checkpoint |

### 7.4 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-C-01 | Rust version | Stable 1.75+ |
| NFR-C-02 | Winterfell version | 0.9.x |
| NFR-C-03 | EVM compatibility | Solidity 0.8.19+ |
| NFR-C-04 | VES version | VES v1.0 |

### 7.5 Observability

| ID | Requirement |
|----|-------------|
| NFR-O-01 | System SHALL emit structured logs for proof lifecycle |
| NFR-O-02 | System SHALL expose Prometheus metrics for proving |
| NFR-O-03 | System SHALL trace constraint evaluation for debugging |

---

## 8. System Design

### 8.1 Constraint System Overview

The VES Compliance AIR enforces the following constraints:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        VES Compliance Constraints                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. BOUNDARY CONSTRAINTS (assertions on specific rows)                   │
│     ├── Row 0: prev_state_root matches public input                     │
│     ├── Row 0: sequence_number = sequence_start                         │
│     ├── Row N: new_state_root matches public input                      │
│     └── Row N: sequence_number = sequence_end                           │
│                                                                          │
│  2. TRANSITION CONSTRAINTS (enforced between adjacent rows)              │
│     ├── Sequence monotonicity: next_seq = current_seq + 1 (event rows)  │
│     ├── Rescue permutation: state transitions correctly (7 rounds)      │
│     ├── Merkle node: parent = Rescue(left || right)                     │
│     └── Signature: Ed25519.Verify(pk, msg, sig) = true                  │
│                                                                          │
│  3. COMPLIANCE CONSTRAINTS (business rules)                              │
│     ├── Inventory non-negative: available >= 0 after each event         │
│     ├── Order thresholds: amount < limit for flagged event types        │
│     └── Refund limits: refund_amount <= order_total                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Trace Layout

```
┌────────────────────────────────────────────────────────────────────────────┐
│                            Execution Trace                                  │
├────────────────────────────────────────────────────────────────────────────┤
│ Row │ Phase    │ Columns 0-7  │ Cols 8-41    │ Cols 42-53  │ Cols 54-70   │
├─────┼──────────┼──────────────┼──────────────┼─────────────┼──────────────┤
│  0  │ Init     │ prev_state   │ (zeros)      │ (zeros)     │ flags        │
│  1  │ Event 1  │ state        │ sig verify   │ merkle      │ flags        │
│  2  │ Event 2  │ state        │ sig verify   │ merkle      │ flags        │
│ ... │ ...      │ ...          │ ...          │ ...         │ ...          │
│  N  │ Event N  │ state        │ sig verify   │ merkle      │ flags        │
│ N+1 │ Merkle   │ state        │ (zeros)      │ merkle comp │ flags        │
│ ... │ ...      │ ...          │ ...          │ ...         │ ...          │
│ N+K │ Final    │ new_state    │ (zeros)      │ events_root │ flags        │
└─────┴──────────┴──────────────┴──────────────┴─────────────┴──────────────┘

Column Groups:
- State (0-7):     Current state root or intermediate state
- Signature (8-41): Public key, R, S, message hash for Ed25519
- Merkle (42-53):  Left, right, output nodes for Merkle computation
- Flags (54-70):   is_event, is_merkle, is_first, is_last, etc.
```

### 8.3 Hash Function Choice

**Primary: Rescue-Prime**

| Property | Value |
|----------|-------|
| State width | 12 field elements |
| Rate | 8 elements |
| Capacity | 4 elements |
| Rounds | 7 |
| S-box | x^7 (degree 7) |
| Security | ~128 bits |
| Constraint cost | ~100 constraints per permutation |

**Why Rescue over SHA-256:**

| Hash | Constraints per hash | Reason |
|------|---------------------|--------|
| SHA-256 | ~27,000 | Bit operations expensive in AIR |
| Rescue-Prime | ~1,000 | Native field operations |
| Poseidon | ~300 | Even cheaper, but less analyzed |

**Compatibility Layer:**

VES v1.0 uses SHA-256 for `payload_plain_hash`. The STARK proves:
1. Rescue hash of the event envelope (for Merkle tree)
2. Binding between SHA-256 payload hash and Rescue leaf hash

This is achieved by including `payload_plain_hash` (SHA-256) as a public input to the leaf hash computation.

### 8.4 Signature Verification in AIR

Ed25519 verification in-circuit is expensive but tractable:

```
Ed25519 Verify(pk, msg, sig=(R, S)):
  1. Compute h = SHA512(R || pk || msg) mod l
  2. Compute S*G (scalar multiplication on curve)
  3. Compute h*pk (scalar multiplication)
  4. Check: S*G == R + h*pk (point addition + equality)
```

**In-circuit cost:**

| Operation | Constraints |
|-----------|-------------|
| SHA-512 | ~50,000 (can use Rescue instead for msg hash) |
| Scalar mul | ~5,000 per multiplication |
| Point add | ~1,000 |
| **Total per signature** | ~15,000-60,000 |

**Optimization: Use Rescue-Schnorr**

For v2.0, consider replacing Ed25519 with a Rescue-based Schnorr signature:
- Same security properties
- ~1,000 constraints per verification
- Requires agent key migration

### 8.5 Merkle Tree Verification

The proof verifies that `events_root` is correctly computed:

```
For N events:
1. Compute leaf_hash[i] = Rescue(event_envelope[i]) for each event
2. Build Merkle tree bottom-up using Rescue for internal nodes
3. Assert final root equals public input events_root
```

**Constraint cost:**

| Events | Tree depth | Rescue calls | Constraints |
|--------|------------|--------------|-------------|
| 10 | 4 | ~20 | ~20,000 |
| 100 | 7 | ~200 | ~200,000 |
| 1000 | 10 | ~2000 | ~2,000,000 |

---

## 9. API Specification

### 9.1 Rust Prover API

```rust
/// Main prover interface
pub struct VesStarkProver {
    options: ProofOptions,
}

impl VesStarkProver {
    /// Create a new prover with default options
    pub fn new() -> Self;
    
    /// Create a prover with custom options
    pub fn with_options(options: ProofOptions) -> Self;
    
    /// Generate a proof for a VES batch
    pub fn prove(
        &self,
        public_inputs: VesPublicInputs,
        witness: VesWitness,
    ) -> Result<VesProof, ProverError>;
    
    /// Estimate proving time for a batch size
    pub fn estimate_proving_time(&self, num_events: usize) -> Duration;
    
    /// Get the constraint count for a batch size
    pub fn constraint_count(&self, num_events: usize) -> usize;
}

/// Proof options configuration
pub struct ProofOptions {
    /// Number of FRI queries (higher = more security, slower)
    pub num_queries: usize,
    
    /// Blowup factor (higher = more security, larger proof)
    pub blowup_factor: usize,
    
    /// Grinding factor (higher = smaller proof, slower)
    pub grinding_factor: usize,
    
    /// Field extension degree (1 or 2)
    pub field_extension: FieldExtension,
}

impl Default for ProofOptions {
    fn default() -> Self {
        Self {
            num_queries: 32,
            blowup_factor: 8,
            grinding_factor: 16,
            field_extension: FieldExtension::None,
        }
    }
}

/// Public inputs for the proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VesPublicInputs {
    /// Schema version for forward compatibility
    pub version: u32,
    
    /// Batch identity
    pub tenant_id: [u8; 16],
    pub store_id: [u8; 16],
    pub batch_id: [u8; 16],
    
    /// Merkle roots
    pub events_root: [u8; 32],
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    
    /// Sequence range
    pub sequence_start: u64,
    pub sequence_end: u64,
    
    /// Compliance claims proven
    pub claims: Vec<ComplianceClaim>,
}

/// Compliance claims that can be proven
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceClaim {
    AllSignaturesValid,
    EventsRootCorrect,
    StateTransitionDeterministic,
    InventoryNonNegative,
    OrderTotalsBelowThreshold { threshold_cents: u64 },
    RefundsWithinOriginal,
}

/// A VES STARK proof
#[derive(Debug, Clone)]
pub struct VesProof {
    /// The raw STARK proof bytes
    pub proof_bytes: Vec<u8>,
    
    /// Public inputs committed to the proof
    pub public_inputs: VesPublicInputs,
    
    /// Proof metadata
    pub metadata: ProofMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Time taken to generate the proof
    pub proving_time_ms: u64,
    
    /// Number of constraints
    pub num_constraints: usize,
    
    /// Trace length
    pub trace_length: usize,
    
    /// Proof size in bytes
    pub proof_size: usize,
    
    /// Prover version
    pub prover_version: String,
}

impl VesProof {
    /// Serialize the proof to bytes
    pub fn to_bytes(&self) -> Vec<u8>;
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError>;
    
    /// Get the proof hash (for on-chain reference)
    pub fn proof_hash(&self) -> [u8; 32];
}
```

### 9.2 Rust Verifier API

```rust
/// Verify a VES STARK proof
pub fn verify_ves_proof(proof: &VesProof) -> Result<VerificationResult, VerifierError>;

/// Verification result
pub struct VerificationResult {
    /// Whether the proof is valid
    pub valid: bool,
    
    /// Verified public inputs
    pub public_inputs: VesPublicInputs,
    
    /// Verification time
    pub verification_time_ms: u64,
}

/// Verifier errors
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("Invalid proof structure: {0}")]
    InvalidProofStructure(String),
    
    #[error("Public input mismatch: {0}")]
    PublicInputMismatch(String),
    
    #[error("FRI verification failed: {0}")]
    FriVerificationFailed(String),
    
    #[error("Constraint check failed: {0}")]
    ConstraintCheckFailed(String),
}
```

### 9.3 Sequencer REST API

```yaml
# POST /api/v1/proofs/generate
# Trigger proof generation for a batch
request:
  batch_id: uuid
  priority: "normal" | "high"
response:
  job_id: uuid
  status: "queued" | "proving" | "completed" | "failed"
  estimated_completion: datetime

# GET /api/v1/proofs/{batch_id}
# Get proof for a batch
response:
  batch_id: uuid
  proof_hash: hex_string
  proof_bytes: base64_string
  public_inputs:
    version: 1
    events_root: hex_string
    prev_state_root: hex_string
    new_state_root: hex_string
    sequence_start: u64
    sequence_end: u64
    claims: ["AllSignaturesValid", "EventsRootCorrect"]
  metadata:
    proving_time_ms: u64
    num_constraints: u64
    trace_length: u64
    proof_size: u64
    prover_version: string
  created_at: datetime

# POST /api/v1/proofs/verify
# Verify a proof (stateless)
request:
  proof_bytes: base64_string
  public_inputs: object
response:
  valid: boolean
  verification_time_ms: u64
  error: string | null

# GET /api/v1/proofs/{batch_id}/status
# Get proof generation status
response:
  batch_id: uuid
  status: "queued" | "proving" | "completed" | "failed"
  progress_percent: u8
  error: string | null
  started_at: datetime | null
  completed_at: datetime | null
```

### 9.4 Solidity Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IVesStarkVerifier {
    /// Public inputs structure
    struct VesPublicInputs {
        bytes32 eventsRoot;
        bytes32 prevStateRoot;
        bytes32 newStateRoot;
        uint64 sequenceStart;
        uint64 sequenceEnd;
        bytes32 claimsBitmap;  // Packed compliance claims
    }
    
    /// Verify a STARK proof
    /// @param proof The serialized proof bytes
    /// @param publicInputs The public inputs
    /// @return valid True if the proof is valid
    function verify(
        bytes calldata proof,
        VesPublicInputs calldata publicInputs
    ) external view returns (bool valid);
    
    /// Get the verification key hash
    function verificationKeyHash() external view returns (bytes32);
}

interface IVesStarkRegistry {
    /// Submit a batch with proof
    function submitBatchWithProof(
        bytes32 streamId,
        bytes32 eventsRoot,
        bytes32 prevStateRoot,
        bytes32 newStateRoot,
        uint64 sequenceStart,
        uint64 sequenceEnd,
        bytes calldata proof
    ) external;
    
    /// Check if a batch is finalized
    function isFinalized(bytes32 proofHash) external view returns (bool);
    
    /// Challenge a batch (optimistic mode)
    function challenge(bytes32 proofHash, bytes calldata fraudProof) external;
    
    /// Events
    event BatchSubmitted(
        bytes32 indexed streamId,
        bytes32 indexed proofHash,
        bytes32 eventsRoot,
        uint64 sequenceStart,
        uint64 sequenceEnd
    );
    
    event BatchFinalized(bytes32 indexed proofHash);
    event BatchChallenged(bytes32 indexed proofHash, address challenger);
}
```

---

## 10. Data Models

### 10.1 Database Schema

```sql
-- Proof jobs queue
CREATE TABLE stark_proof_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES batch_commitments(id),
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    
    -- Job status
    status TEXT NOT NULL DEFAULT 'queued',  -- queued, proving, completed, failed
    priority TEXT NOT NULL DEFAULT 'normal', -- normal, high
    
    -- Progress tracking
    progress_percent SMALLINT DEFAULT 0,
    current_phase TEXT,  -- trace_gen, fri_commit, fri_query, etc.
    
    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    
    -- Error handling
    error_message TEXT,
    retry_count INT DEFAULT 0,
    
    CONSTRAINT valid_status CHECK (status IN ('queued', 'proving', 'completed', 'failed')),
    CONSTRAINT valid_priority CHECK (priority IN ('normal', 'high'))
);

CREATE INDEX idx_proof_jobs_status ON stark_proof_jobs(status, priority, created_at);
CREATE INDEX idx_proof_jobs_batch ON stark_proof_jobs(batch_id);

-- Completed proofs
CREATE TABLE stark_proofs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES batch_commitments(id) UNIQUE,
    job_id UUID NOT NULL REFERENCES stark_proof_jobs(id),
    
    -- Proof data
    proof_hash BYTEA NOT NULL,  -- 32 bytes
    proof_bytes BYTEA NOT NULL, -- Full proof (compressed)
    proof_size INT NOT NULL,
    
    -- Public inputs (denormalized for queries)
    events_root BYTEA NOT NULL,
    prev_state_root BYTEA NOT NULL,
    new_state_root BYTEA NOT NULL,
    sequence_start BIGINT NOT NULL,
    sequence_end BIGINT NOT NULL,
    claims JSONB NOT NULL,
    
    -- Metadata
    proving_time_ms BIGINT NOT NULL,
    num_constraints BIGINT NOT NULL,
    trace_length BIGINT NOT NULL,
    prover_version TEXT NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- On-chain status
    anchored_at TIMESTAMPTZ,
    anchor_tx_hash BYTEA,
    finalized_at TIMESTAMPTZ
);

CREATE INDEX idx_proofs_batch ON stark_proofs(batch_id);
CREATE INDEX idx_proofs_hash ON stark_proofs(proof_hash);
CREATE INDEX idx_proofs_not_anchored ON stark_proofs(created_at) WHERE anchored_at IS NULL;
```

### 10.2 Proof Serialization Format

```
VesProof Binary Format (v1):

┌──────────────────────────────────────────────────────────────┐
│ Header (32 bytes)                                             │
├──────────────────────────────────────────────────────────────┤
│ magic: [u8; 4] = "VSSP"                                      │
│ version: u16                                                  │
│ flags: u16                                                    │
│ public_inputs_len: u32                                        │
│ proof_len: u32                                                │
│ metadata_len: u32                                             │
│ reserved: [u8; 12]                                           │
├──────────────────────────────────────────────────────────────┤
│ Public Inputs (variable)                                      │
├──────────────────────────────────────────────────────────────┤
│ events_root: [u8; 32]                                        │
│ prev_state_root: [u8; 32]                                    │
│ new_state_root: [u8; 32]                                     │
│ sequence_start: u64                                           │
│ sequence_end: u64                                             │
│ claims_bitmap: u64                                            │
│ tenant_id: [u8; 16]                                          │
│ store_id: [u8; 16]                                           │
│ batch_id: [u8; 16]                                           │
├──────────────────────────────────────────────────────────────┤
│ STARK Proof (variable, Winterfell format)                     │
├──────────────────────────────────────────────────────────────┤
│ trace_commitment: [u8; 32]                                   │
│ constraint_commitment: [u8; 32]                              │
│ fri_commitments: Vec<[u8; 32]>                               │
│ query_proofs: Vec<QueryProof>                                │
│ fri_remainder: Vec<FieldElement>                             │
│ pow_nonce: u64                                                │
├──────────────────────────────────────────────────────────────┤
│ Metadata (variable, CBOR encoded)                             │
├──────────────────────────────────────────────────────────────┤
│ proving_time_ms: u64                                          │
│ num_constraints: u64                                          │
│ trace_length: u64                                             │
│ prover_version: String                                        │
└──────────────────────────────────────────────────────────────┘
```

---

## 11. Security Considerations

### 11.1 Cryptographic Security

| Property | Requirement | Implementation |
|----------|-------------|----------------|
| Soundness | ≤ 2^-100 | 32 queries × 8 blowup = ~100 bits |
| Zero-knowledge | Perfect | Witness never revealed |
| Collision resistance | ≥ 128 bits | Rescue-Prime |
| Post-quantum | Yes | Hash-based (no pairings) |

### 11.2 Constraint Soundness

All constraints must be:
1. **Complete**: Valid witnesses produce accepting proofs
2. **Sound**: No invalid witness produces accepting proof
3. **Zero-knowledge**: Constraints don't leak witness information

**Testing strategy:**
- Unit tests for each constraint with valid/invalid cases
- Fuzzing with random witnesses
- Formal verification of constraint polynomials (future)

### 11.3 Implementation Security

| Risk | Mitigation |
|------|------------|
| Side-channel attacks | Constant-time field operations |
| Memory safety | Rust's memory safety guarantees |
| Integer overflow | Checked arithmetic in debug, wrapping in release (field ops) |
| Randomness | OS entropy via `getrandom` |

### 11.4 Operational Security

| Risk | Mitigation |
|------|------------|
| Prover key exposure | No keys (transparent setup) |
| Proof manipulation | Cryptographic binding to public inputs |
| DoS via large batches | Rate limiting, max batch size |
| Prover machine compromise | Proofs are publicly verifiable; re-prove if needed |

### 11.5 On-Chain Security

| Risk | Mitigation |
|------|------------|
| Malicious proof submission | Cryptographic verification |
| Gas griefing | Gas limits per proof |
| Front-running | Proofs bound to specific inputs |
| Reentrancy | Checks-effects-interactions pattern |

---

## 12. Milestones and Timeline

### 12.1 Phase 1: Primitives (Weeks 1-3)

**Deliverables:**
- [ ] `ves-stark-primitives` crate structure
- [ ] Goldilocks field arithmetic with tests
- [ ] Rescue-Prime hash implementation
- [ ] Rescue-Prime test vectors (cross-validated with reference)
- [ ] Merkle tree with Rescue nodes
- [ ] Merkle proof generation and verification

**Exit Criteria:**
- All primitives have 100% test coverage
- Rescue matches reference implementation test vectors
- Merkle proofs verify correctly for trees up to 2^20 leaves

### 12.2 Phase 2: AIR Definition (Weeks 4-7)

**Deliverables:**
- [ ] Trace layout specification
- [ ] Boundary constraint definitions
- [ ] Transition constraint definitions
- [ ] Rescue permutation constraints (7 rounds)
- [ ] Merkle verification constraints
- [ ] Signature verification constraints (simplified)
- [ ] Compliance claim constraints

**Exit Criteria:**
- AIR compiles with Winterfell
- Constraints correctly accept valid traces
- Constraints correctly reject invalid traces
- Constraint degree ≤ 7 verified

### 12.3 Phase 3: Prover Implementation (Weeks 8-10)

**Deliverables:**
- [ ] Witness generation from VES data
- [ ] Trace table construction
- [ ] FRI configuration
- [ ] Prover implementation
- [ ] Proof serialization

**Exit Criteria:**
- Prover generates valid proofs for 10-event batches
- Prover generates valid proofs for 100-event batches
- Proving time within targets

### 12.4 Phase 4: Verifier Implementation (Weeks 11-12)

**Deliverables:**
- [ ] Rust verifier implementation
- [ ] Verification benchmarks
- [ ] Error reporting

**Exit Criteria:**
- Verifier accepts valid proofs
- Verifier rejects invalid proofs
- Verification time < 100ms

### 12.5 Phase 5: Solidity Verifier/Registry (Weeks 13-16)

**Deliverables:**
- [ ] VesStarkRegistry contract (optimistic mode)
- [ ] Fraud proof challenge mechanism
- [ ] Integration with SetRegistry
- [ ] Foundry tests

**Exit Criteria:**
- Contract accepts valid proof commitments
- Challenge mechanism works correctly
- Gas usage within limits

### 12.6 Phase 6: Integration (Weeks 17-18)

**Deliverables:**
- [ ] Sequencer integration
- [ ] REST API endpoints
- [ ] Database schema and migrations
- [ ] Background job processing
- [ ] Metrics and monitoring

**Exit Criteria:**
- End-to-end flow works: batch → proof → anchor
- Proofs stored and retrievable
- Metrics exported to Prometheus

### 12.7 Phase 7: Hardening (Weeks 19-20)

**Deliverables:**
- [ ] Security review
- [ ] Performance optimization
- [ ] Documentation
- [ ] Deployment runbooks

**Exit Criteria:**
- External security review passed
- Performance targets met
- Documentation complete

### 12.8 Gantt Chart

```
Week:  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20
       ├──┴──┴──┤                                                   Primitives
                ├──┴──┴──┴──┤                                       AIR
                            ├──┴──┴──┤                              Prover
                                     ├──┴──┤                        Verifier
                                           ├──┴──┴──┴──┤            Solidity
                                                       ├──┴──┤      Integration
                                                             ├──┴──┤ Hardening
```

---

## 13. Success Metrics

### 13.1 Technical Metrics

| Metric | Target | How Measured |
|--------|--------|--------------|
| Proof generation (100 events) | < 60s | CI benchmark |
| Proof generation (1000 events) | < 10min | CI benchmark |
| Proof size | < 200KB | Serialized bytes |
| Rust verification time | < 100ms | CI benchmark |
| On-chain verification gas | < 500K | Foundry tests |
| Test coverage | > 90% | cargo-tarpaulin |
| Security level | ≥ 100 bits | Cryptographic analysis |

### 13.2 Operational Metrics

| Metric | Target | How Measured |
|--------|--------|--------------|
| Proof generation success rate | > 99.9% | Prometheus |
| Proof generation p99 latency | < 2x median | Prometheus |
| Anchor success rate | > 99.9% | Prometheus |
| Time to finality | < 1 hour (optimistic mode) | On-chain timestamps |

### 13.3 Business Metrics

| Metric | Target | How Measured |
|--------|--------|--------------|
| Enterprise customers using proofs | 3+ by Q4 2025 | CRM |
| Compliance use cases enabled | 5+ | Product usage |
| Audit time reduction | > 80% | Customer feedback |

---

## 14. Risks and Mitigations

### 14.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Constraint system bugs | Medium | Critical | Extensive testing, fuzzing, audit |
| Performance misses targets | Medium | High | Early benchmarking, optimization budget |
| Ed25519 in-circuit too expensive | Medium | Medium | Use Rescue-Schnorr alternative |
| Winterfell API changes | Low | Medium | Pin version, maintain fork if needed |
| Solidity verifier too expensive | High | Medium | Use optimistic mode first |

### 14.2 Timeline Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Underestimated constraint complexity | Medium | High | Buffer time, scope reduction options |
| Key person dependency | Medium | High | Knowledge sharing, documentation |
| Integration blockers | Low | Medium | Early integration spikes |

### 14.3 Security Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Unsound constraint system | Low | Critical | Audit, formal verification (future) |
| Implementation vulnerabilities | Medium | High | Security review, fuzzing |
| On-chain exploits | Low | Critical | Audit, bug bounty |

---

## 15. Dependencies

### 15.1 Internal Dependencies

| Dependency | Required For | Status |
|------------|--------------|--------|
| VES v1.0 Spec | Event envelope format | ✅ Complete |
| stateset-sequencer | Batch commitment API | ✅ Complete |
| Set Chain | On-chain anchoring | ✅ Complete |
| SetRegistry contract | Commitment chaining | ✅ Complete |

### 15.2 External Dependencies

| Dependency | Version | Purpose | Risk |
|------------|---------|---------|------|
| Winterfell | 0.9.x | STARK prover/verifier | Low (stable, maintained) |
| winter-math | 0.9.x | Field arithmetic | Low |
| winter-crypto | 0.9.x | Hash functions | Low |
| sha2 | 0.10.x | SHA-256 for VES compat | Low |
| Foundry | Latest | Solidity testing | Low |

### 15.3 Infrastructure Dependencies

| Dependency | Required For | Provided By |
|------------|--------------|-------------|
| PostgreSQL 15+ | Proof storage | Existing infra |
| Prometheus | Metrics | Existing infra |
| Set Chain RPC | Anchoring | Existing infra |

---

## 16. Open Questions

### 16.1 Technical

| ID | Question | Options | Decision Needed By |
|----|----------|---------|-------------------|
| OQ-1 | Should we use Rescue-Schnorr instead of Ed25519 for signatures? | a) Ed25519 (compatible, expensive) b) Rescue-Schnorr (cheaper, migration) | Phase 2 start |
| OQ-2 | What's the maximum batch size we should support? | a) 1000 events b) 10,000 events c) Unlimited | Phase 3 start |
| OQ-3 | Should compliance claims be fixed or configurable? | a) Fixed set b) Configurable via ABI | Phase 2 end |
| OQ-4 | Full Solidity verifier in v1.0 or defer? | a) Full verifier b) Optimistic + fraud proof | Phase 5 start |

### 16.2 Product

| ID | Question | Options | Decision Needed By |
|----|----------|---------|-------------------|
| OQ-5 | Should proof generation be opt-in or default? | a) Opt-in b) Default for all batches | Phase 6 start |
| OQ-6 | How to price proof generation? | a) Included b) Per-proof c) Tiered | Launch |
| OQ-7 | Should proofs be public or access-controlled? | a) Public b) Tenant-only c) Configurable | Phase 6 start |

### 16.3 Operational

| ID | Question | Options | Decision Needed By |
|----|----------|---------|-------------------|
| OQ-8 | Prover hardware requirements? | a) Standard VMs b) High-memory VMs c) Dedicated | Phase 3 start |
| OQ-9 | Proof storage retention policy? | a) Forever b) 7 years c) Configurable | Launch |

---

## 17. Appendices

### 17.1 Appendix A: Constraint Polynomial Reference

```
Transition Constraints (evaluated between rows i and i+1):

1. Sequence Monotonicity:
   is_event[i] * (seq[i+1] - seq[i] - 1) + (1 - is_event[i]) * (seq[i+1] - seq[i]) = 0

2. Rescue S-box (per element, simplified):
   state[j][i+1] - state[j][i]^7 = 0  (during S-box phase)

3. Rescue MDS (per element, simplified):
   state[j][i+1] - Σ(MDS[j][k] * state[k][i]) = 0  (during MDS phase)

4. Merkle Node:
   is_merkle[i] * (out[i] - Rescue(left[i] || right[i])) = 0

5. Flag Binary:
   flag[i] * (flag[i] - 1) = 0  (for each flag)

Boundary Constraints:

1. Initial State:
   state[0..8][0] = prev_state_root

2. Initial Sequence:
   seq[0] = sequence_start

3. Final State:
   state[0..8][N] = new_state_root

4. Final Sequence:
   seq[N] = sequence_end

5. First/Last Flags:
   is_first[0] = 1
   is_last[N] = 1
```

### 17.2 Appendix B: Test Vectors

```rust
#[test]
fn test_rescue_vector_1() {
    // Input: 8 zero elements
    let input = [BaseElement::ZERO; 8];
    let output = rescue_hash_256(&input);
    
    // Expected output (from reference implementation)
    assert_eq!(output[0].as_int(), 0x123456789abcdef0);
    // ... (full vector)
}

#[test]
fn test_merkle_root_vector_1() {
    // 4 leaves: hash(0), hash(1), hash(2), hash(3)
    let leaves: Vec<_> = (0u64..4)
        .map(|i| rescue_hash(&i.to_le_bytes()))
        .collect();
    
    let root = compute_merkle_root(&leaves);
    
    // Expected root (from reference)
    assert_eq!(root[0].as_int(), 0xfedcba9876543210);
    // ... (full vector)
}
```

### 17.3 Appendix C: Benchmark Results Template

```
Benchmark Environment:
- CPU: AMD EPYC 7763 64-Core @ 2.45GHz
- RAM: 128GB DDR4
- Rust: 1.75.0
- Winterfell: 0.9.0

Results:

| Batch Size | Trace Length | Constraints | Proving Time | Proof Size | Verify Time |
|------------|--------------|-------------|--------------|------------|-------------|
| 10         | 1,024        | 50,000      | 5.2s         | 85 KB      | 45 ms       |
| 100        | 8,192        | 500,000     | 48s          | 120 KB     | 52 ms       |
| 1,000      | 65,536       | 5,000,000   | 8.5 min      | 180 KB     | 65 ms       |
```

### 17.4 Appendix D: Glossary

| Term | Definition |
|------|------------|
| **AIR** | Algebraic Intermediate Representation - constraint system format |
| **FRI** | Fast Reed-Solomon IOP - the core STARK protocol |
| **Rescue-Prime** | STARK-friendly hash function using algebraic S-boxes |
| **Trace** | The execution trace (matrix of field elements) |
| **Boundary Constraint** | Constraint on specific trace rows |
| **Transition Constraint** | Constraint between adjacent trace rows |
| **Blowup Factor** | Ratio of evaluation domain to trace length |
| **Soundness** | Probability of accepting an invalid proof |
| **Zero-Knowledge** | Property that proof reveals nothing about witness |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-12 | StateSet Engineering | Initial draft |

---

## Approvals

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Engineering Lead | | | |
| Product Lead | | | |
| Security Lead | | | |
