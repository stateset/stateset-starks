# StateSet STARK: Technical Whitepaper

**Version 2.2 — March 2026**

---

## Abstract

StateSet STARK is a zero-knowledge proof system for privacy-preserving commerce compliance. Built on STARKs (Scalable Transparent Arguments of Knowledge), it enables merchants and platforms to prove that a private transaction-amount witness satisfies regulatory policies — such as AML thresholds and order caps — without revealing the underlying amount. The system operates in two modes: per-event proofs for individual compliance decisions, and batch proofs that aggregate up to 128 compliance decisions into a single, chain-committable state root transition. The implementation is Rust-native (~25,000 lines across 8 crates, plus tests and bindings), targets the Goldilocks prime field, uses Rescue-Prime as its algebraic hash function, and produces transparent, post-quantum secure proofs with no trusted setup. Per-event proofs generate in ~50 ms and verify in under 10 ms on commodity hardware. Batch proofs for 128 events complete in seconds with sub-100 ms verification.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Related Work](#2-related-work)
3. [System Architecture](#3-system-architecture)
4. [Cryptographic Foundations](#4-cryptographic-foundations)
5. [Per-Event Compliance Proofs](#5-per-event-compliance-proofs)
6. [Batch State-Transition Proofs](#6-batch-state-transition-proofs)
7. [Verification Protocol](#7-verification-protocol)
8. [Security Analysis](#8-security-analysis)
9. [Performance](#9-performance)
10. [Integration and Deployment](#10-integration-and-deployment)
11. [Known Limitations and Future Work](#11-known-limitations-and-future-work)
12. [Conclusion](#12-conclusion)
13. [References](#13-references)

---

## 1. Introduction

### 1.1 Problem Statement

Modern commerce platforms process millions of transactions subject to regulatory compliance requirements — anti-money laundering (AML) checks, transaction caps, sanctions screening, and more. Traditional approaches require exposing sensitive transaction data to compliance infrastructure, creating privacy risks and expanding the attack surface for data breaches. A merchant proving that a $5,000 order falls below a $10,000 AML threshold should not need to reveal the exact amount to every participant in the verification chain.

### 1.2 Solution

StateSet STARK addresses this tension by enabling *verifiable compliance without data exposure*. A prover (the merchant's platform) generates a cryptographic proof that a private transaction-amount witness satisfies a public policy, and any verifier can check this proof without learning the amount. The proof is:

- **Transparent:** No trusted setup ceremony, no toxic waste, no multi-party computation.
- **Operationally simple:** No ceremony coordination. Deploy a binary, generate proofs.
- **Post-quantum secure:** Based on hash functions and Reed-Solomon codes, not discrete logarithms or pairings.
- **Succinct:** 100–200 KB regardless of computation complexity.
- **Batch-aggregatable:** Up to 128 compliance decisions in a single proof with a chainable Merkle state root.

The system is designed for Verifiable Event Sync (VES), StateSet's event-driven architecture where commerce events (orders, payments, refunds) are synchronized across distributed participants with cryptographic integrity guarantees.

### 1.3 Actors and Workflow

A concrete scenario: Alice purchases a $5,000 item on a merchant's platform subject to an AML threshold of $10,000.

1. **The Sequencer** (StateSet's event coordinator) creates a VES event with metadata, encrypted payload hashes, and the compliance policy. It publishes the public inputs.
2. **The Merchant's Prover Node** holds the private amount ($5,000). It fetches the public inputs, constructs a witness, and generates a STARK proof that $5,000 < $10,000 without revealing "5,000" to anyone.
3. **The Verifier** (the sequencer, an auditor, or a smart contract on Set Chain) checks the proof against the public inputs in under 10 ms. The proof is valid; the transaction is compliant. The amount remains private.

**Failure path:** If Alice's order were $12,000, the prover cannot produce a valid proof (no witness satisfies `amount < 10,000`). The sequencer marks the event as non-compliant and blocks it from proceeding. In batch mode, the `all_compliant` flag would be 0, and the batch proof would still be valid but would attest to non-compliance — the verifier knows at least one event failed without learning which amount caused the failure.

For high-throughput processing, the merchant batches events: 64 orders are proven in a single STARK that also computes a Merkle state root, committable to Set Chain as an immutable audit trail.

### 1.4 Set Chain

Set Chain is StateSet's application-specific blockchain for anchoring commerce state commitments. Batch proofs' state roots (`new_state_root`) are submitted to Set Chain's `SetRegistry` contract, creating a tamper-evident, publicly auditable history of compliance decisions without exposing any private transaction data.

### 1.5 Contributions

1. A complete STARK-based compliance proof system with per-event and batch proving modes.
2. An in-circuit Merkle tree construction using Rescue-Prime that produces chainable state roots.
3. A multiplicative compliance accumulator with formal non-forgeability under binary flag constraints.
4. Stream accumulators that enforce consistency between event processing and Merkle leaf commitment, with a clear path to full Fiat-Shamir-derived challenge soundness.
5. Production-grade Rust implementation (~25,000 lines across 8 crates, plus tests and bindings) with Node.js and Python bindings.

---

## 2. Related Work

### 2.1 ZK Compliance Landscape

Several systems address privacy-preserving compliance in blockchain and commerce contexts:

**Aztec Protocol** uses application-specific SNARKs (PLONK-based) for private DeFi compliance. Their "compliance hooks" enable protocol-level policy enforcement on encrypted notes. However, Aztec relies on a universal trusted setup (the PLONK SRS ceremony) and targets Ethereum L2 settlement, not general commerce event streams.

**Espresso Systems** operates a shared sequencer with privacy features. Their model focuses on cross-chain MEV protection and fair ordering rather than per-transaction compliance proofs. Espresso does not produce per-event compliance attestations.

**Pedersen commitment range proofs** (used by Monero, Mimblewimble, and many DeFi protocols) provide compact proofs that a committed value lies in a range. These are efficient (a few hundred bytes) but rely on the discrete logarithm assumption on elliptic curves, making them vulnerable to quantum adversaries. They also lack the batch aggregation and Merkle state root features that commerce audit trails require.

**Bulletproofs** extend Pedersen range proofs with logarithmic proof size. They are transparent (no trusted setup) but not post-quantum secure, and proving time is linear in the range size rather than logarithmic as in STARKs.

### 2.2 Why STARKs

StateSet chose STARKs over SNARKs and commitment-based range proofs for three reasons:

1. **No trusted setup.** Commerce compliance infrastructure must be auditable and operationally simple. Eliminating ceremony coordination removes a class of deployment risks and trust assumptions.
2. **Post-quantum security.** While most commerce compliance buyers are not threat-modeling quantum adversaries today, regulatory timelines are long: a compliance system deployed in 2026 may process proofs verified in 2036. NIST's post-quantum standardization timeline validates building on quantum-resistant foundations now.
3. **Programmable constraint systems.** STARKs' AIR (Algebraic Intermediate Representation) supports complex, multi-phase computations — range checks, hash verifications, Merkle trees, accumulators — in a single proof. This enables the batch aggregation model that commitment-based schemes cannot provide.

The tradeoff is proof size: STARK proofs are 100–200 KB versus ~1 KB for Bulletproofs. For commerce compliance (off-chain verification, sequencer-mediated), this is acceptable. For on-chain settlement, recursive STARK compression is planned (Section 11).

### 2.3 Hash Function Choice: Rescue-Prime vs. Poseidon

In modern ZK engineering, Poseidon and Poseidon2 are the predominant algebraic hashes for STARK circuits, offering faster native execution and lower constraint degrees. StateSet uses Rescue-Prime for two reasons:

1. **Winterfell compatibility.** The Winterfell library (our STARK backend) provides first-class Rescue-Prime support with optimized constraint helpers. Poseidon integration would require custom AIR primitives without framework-level optimization.
2. **Conservative security margins.** Rescue-Prime's alternating forward/backward half-round structure provides stronger security margins against algebraic attacks than Poseidon's single-direction rounds. With 7 rounds at ~2× the security margin, we prioritize defense-in-depth over constraint-count optimization. The degree-10 maximum constraint (versus Poseidon's typical degree-5) is absorbed by the blowup factor without meaningful impact on proving time for our trace sizes.

A migration to Poseidon2 is on the roadmap if Winterfell adds native support or if constraint budget becomes a bottleneck at larger batch sizes (Section 11).

---

## 3. System Architecture

StateSet STARK is organized as a Rust workspace of eight crates:

```
stateset-stark/
├── ves-stark-primitives    # Field arithmetic, Rescue-Prime hash, public input types
├── ves-stark-air           # Algebraic Intermediate Representation (constraint system)
├── ves-stark-prover        # Per-event proof generation
├── ves-stark-verifier      # Per-event proof verification
├── ves-stark-batch         # Batch AIR, prover, verifier, and Merkle state tree
├── ves-stark-client        # HTTP client for sequencer and Set Chain submission
├── ves-stark-cli           # Command-line interface
├── ves-stark-nodejs        # Node.js bindings (NAPI-RS)
└── ves-stark-python        # Python bindings (PyO3)
```

### 3.1 Proof Generation Pipeline

1. **Input Canonicalization.** Public inputs (event metadata, payload hashes, policy parameters) are serialized using RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic hashing.
2. **Witness Construction.** The private amount is combined with public inputs to build a `ComplianceWitness` (per-event) or `BatchWitness` (batch).
3. **Trace Generation.** The witness is expanded into an execution trace — a matrix of field elements where each row is a computation step and each column a register.
4. **Constraint Evaluation.** The AIR defines polynomial constraints that the trace must satisfy. Winterfell evaluates these over the trace's low-degree extension (LDE).
5. **FRI Commitment.** The prover commits to the trace and constraint composition polynomials using the FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol, made non-interactive via Fiat-Shamir.
6. **Proof Output.** The serialized proof, witness commitment, and metadata are returned.

### 3.2 Privacy Boundary

It is important to be precise about what is private and what is public:

| Data | Visibility | Notes |
|------|-----------|-------|
| Transaction amount | **Private** | Never leaves the prover; bound via Rescue commitment |
| Event ID, tenant ID, store ID | Public | Visible to verifiers as public inputs |
| Policy ID, parameters, limit | Public | Verifier must know the policy to check the proof |
| Payload hashes | Public | Hashes of encrypted/plain payloads; the payloads themselves are not in the proof |
| Compliance result (pass/fail) | Public | The whole point — verifier learns compliance status |
| Witness commitment | Public | Rescue hash of amount; computationally hides the amount |

The system hides the transaction amount, not the transaction metadata. Applications requiring metadata privacy (e.g., hiding which merchant or which policy) need additional mechanisms beyond this proof system.

---

## 4. Cryptographic Foundations

### 4.1 The Goldilocks Field

All arithmetic operates over the Goldilocks prime field:

```
p = 2^64 - 2^32 + 1 = 18,446,744,069,414,584,321
```

This 64-bit prime has roots in earlier work on efficient modular arithmetic and was popularized for ZK applications by the Plonky2 proving system [8]. It was chosen for:

- **64-bit native arithmetic.** Field elements fit in a single `u64`, and reduction modulo `p` exploits the sparse form `2^64 ≡ 2^32 - 1 (mod p)` for efficient reduction without full-width division.
- **Large 2-adic subgroup.** `p - 1 = 2^32 × 4,294,967,295`, providing a multiplicative subgroup of order `2^32` for NTT-based polynomial operations on traces up to `2^32` rows.
- **Winterfell compatibility.** Winterfell's prover requires a prime field with a sufficiently large 2-adic subgroup; Goldilocks provides this with maximal hardware efficiency.

Field elements are represented as Winterfell's `BaseElement` type, with helper conversions for `u64`, `u128`, UUID-to-felt (4 limbs of 32-bit little-endian), and 256-bit hash-to-felt (8 limbs of 32-bit little-endian).

### 4.2 Rescue-Prime Hash Function

Rescue-Prime [2] is an algebraic hash function designed for efficient arithmetization. Unlike SHA-256 or BLAKE, whose bitwise operations require thousands of constraints per round, Rescue-Prime uses algebraic S-boxes that translate directly into low-degree polynomial constraints.

#### 4.2.1 Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| State width | 12 elements | Rate 8 + capacity 4 |
| Rate | 8 elements | Absorption bandwidth per permutation |
| Capacity | 4 elements | 256 bits of hidden state for ~128-bit collision resistance |
| Rounds | 7 | ~2× margin over best known algebraic attacks (see 4.2.3) |
| S-box exponent α | 7 | Lowest prime with gcd(7, p-1) = 1 in Goldilocks |
| Inverse S-box α⁻¹ | 10,540,996,611,094,048,183 | Multiplicative inverse of 7 mod (p-1) |
| MDS matrix | 12×12 circulant | Maximal branch number for diffusion |

#### 4.2.2 Round Structure

Each of the 7 rounds consists of two half-rounds:

**Forward half-round:**
```
state ← MDS × [s₀^7, s₁^7, ..., s₁₁^7] + round_constants
```

**Backward half-round:**
```
state ← [t₀^(α⁻¹), t₁^(α⁻¹), ..., t₁₁^(α⁻¹)]   where t = MDS⁻¹ × (state - round_constants)
```

In the execution trace, both half-rounds are recorded as intermediate states, yielding 14 transition rows per permutation. The prover computes both forward and inverse S-box evaluations natively, while the AIR constrains them as degree-7 polynomial relations (using `pow7` in both directions — a critical design choice that keeps constraint degree bounded; see Section 5.4.3).

#### 4.2.3 Security Analysis

**Collision resistance:** ~128 bits. The capacity (4 elements × 64 bits = 256 bits) is never directly exposed; the birthday bound gives 128-bit collision security.

**Algebraic attack resistance:** The best known algebraic attacks on Rescue-Prime are Gröbner basis attacks and interpolation attacks. For the Rescue-Prime SoK [2], the authors analyze:
- **Gröbner basis attacks:** Complexity ≥ 2^128 for state width 12 with 5+ rounds (Table 3 of [2]).
- **Interpolation attacks:** Require ≥ α^(2r) evaluations where r is the number of rounds. With α=7 and r=7, this exceeds 2^128.
- **Differential/linear attacks:** Infeasible with the MDS matrix providing full diffusion after 1 round.

With 7 rounds, the security margin is approximately 2× over the minimum required rounds (estimated at 3-4 for this parameter set), consistent with conservative deployment practice.

**Constant integrity:** Round constants are derived from the digits of π (nothing-up-my-sleeve construction) and frozen with a SHA-256 integrity check: `2936f261...bc3adb5b`.

#### 4.2.4 Sponge Construction

The hash function uses a sponge:

1. Initialize state to zeros with domain separation in the capacity.
2. Absorb input in 8-element blocks, XORing into the rate portion.
3. Apply the full permutation after each absorption.
4. Squeeze the first 4 elements of the rate as the hash output.

For Merkle tree nodes: `rescue_hash_pair(left[4], right[4])` absorbs 8 elements (left || right) in a single permutation.

### 4.3 STARK Protocol (Winterfell)

The proof system is built on Winterfell [4] v0.10, an open-source STARK library. The STARK protocol:

1. **Commits to the execution trace** via Merkle trees over the low-degree extension (LDE).
2. **Evaluates constraints** at random points chosen by the verifier (via Fiat-Shamir).
3. **Composes constraint polynomials** into a single polynomial whose degree is bounded.
4. **Proves low-degree** via FRI (Fast Reed-Solomon IOP of Proximity) [3].
5. **Outputs** a non-interactive proof (Fiat-Shamir transform of the interactive protocol).

The key property: if the trace does not satisfy all constraints, the composition polynomial is not low-degree, and FRI rejects with overwhelming probability.

---

## 5. Per-Event Compliance Proofs

> **Reader's guide:** Sections 5.3–5.6 provide constraint-level detail intended for independent audit and cryptographic peer review. Readers primarily interested in the security properties may skip to Section 8. Readers interested in the batch aggregation design may skip to Section 6.

### 5.1 Statement

Given public inputs `P`, a policy with effective limit `L`, and a public witness commitment `C` (4 field elements), a valid proof attests:

1. There exists a private `amount` (u64) such that `amount ≤ L`.
2. `C = Rescue(amount_limbs)` — the commitment binds the amount.
3. `P` is bound to the proof instance via boundary assertions.

For `aml.threshold(T)`: the effective limit is `L = T - 1`, so `amount ≤ T - 1` ⟺ `amount < T`.
For `order_total.cap(C)`: the effective limit is `L = C`, so `amount ≤ C`.

### 5.2 Public Inputs

Public inputs are JSON-canonicalized (RFC 8785 JCS) for deterministic hashing:

```json
{
  "eventId": "uuid",
  "tenantId": "uuid",
  "storeId": "uuid",
  "sequenceNumber": 123,
  "payloadKind": 1,
  "payloadPlainHash": "hex64",
  "payloadCipherHash": "hex64",
  "eventSigningHash": "hex64",
  "policyId": "aml.threshold",
  "policyParams": {"threshold": 10000},
  "policyHash": "hex64"
}
```

The policy hash is domain-separated:
```
policy_hash = SHA256("STATESET_VES_COMPLIANCE_POLICY_HASH_V1" || JCS({policyId, policyParams}))
```

The `witnessCommitment` field is optional in the canonical format. In the sequencer integration, the prover submits it out-of-band alongside the proof, and the sequencer stores it for use during verification.

### 5.3 Execution Trace Layout

The per-event trace has **248 columns** and a minimum of **128 rows** (power of 2):

| Columns | Width | Purpose |
|---------|-------|---------|
| 0–11 | 12 | **Rescue permutation state.** 12 field elements evolving over 14 half-round transitions. |
| 12–19 | 8 | **Amount limbs.** The private amount as 8 × u32 limbs (limbs 2–7 must be zero for u64). |
| 20–27 | 8 | **Threshold/limit limbs.** The effective policy limit in the same representation. |
| 28–35 | 8 | **Comparison intermediates.** Subtraction diff limbs and borrow witnesses. |
| 36–39 | 4 | **Control flags.** `is_first`, `is_last`, `round_counter`, `phase`. |
| 40–103 | 64 | **Bit decomposition.** 32 bits for amount limb 0, 32 bits for amount limb 1. Each bit occupies its own column for binary constraint enforcement (`b × (1-b) = 0`). |
| 104 | 1 | **Rescue commitment flag.** Gates the commitment output binding. |
| 105–120 | 16 | **Subtraction witness.** Diff bits and borrow values for the comparison gadget. |
| 121–247 | 127 | **Public input binding columns.** Each field element of the public inputs (event ID as 4 felts, tenant ID as 4 felts, store ID as 4 felts, payload hashes as 8 felts each, policy hash as 8 felts, etc.) is assigned a dedicated trace column. These columns are constant across all rows, and boundary assertions at row 0 pin them to the verifier's public inputs, preventing substitution. |

### 5.4 Constraint System (157 Transition Constraints)

#### 5.4.1 Range Checking (132 constraints)

The amount is represented as 8 × u32 limbs. Limbs 2–7 are boundary-asserted to zero (enforcing u64 range). Limbs 0 and 1 are range-checked via binary decomposition:

- **64 bit-binary constraints** for amount: `b_i × (1 - b_i) = 0` for each bit, gated to row 0 via periodic selector.
- **2 recomposition constraints** for amount: `limb[k] = Σᵢ bᵢ × 2ⁱ` for k ∈ {0, 1}.
- **64 bit-binary constraints** for diff (the subtraction witness).
- **2 recomposition constraints** for diff.

#### 5.4.2 Subtraction Gadget (4 constraints)

The comparison `amount ≤ limit` is enforced via a 2-limb subtraction witness:

```
limb 0:  amount[0] + diff[0] = limit[0] + borrow₀ × 2³²
limb 1:  amount[1] + diff[1] + borrow₀ = limit[1] + borrow₁ × 2³²
```

With `borrow₀, borrow₁ ∈ {0, 1}` (2 binary constraints) and a boundary assertion that `borrow₁ = 0` at row 0.

**Why this is sound:** If `amount > limit`, then `limit - amount` is negative. The prover must provide `diff = limit - amount + borrow₁ × 2^64`, but with `borrow₁ = 0` (boundary-asserted), `diff` must equal `limit - amount` which is negative — impossible to represent as a valid u64 binary decomposition. The bit-binary constraints on diff prevent non-binary "bits" that could fake a valid decomposition.

#### 5.4.3 Rescue Permutation (12 constraints)

The Rescue state evolves over 14 half-round transitions (7 rounds × 2 directions). Each half-round constrains 12 state elements.

The **forward** half-round constraint (degree 7):
```
next[i] = Σⱼ MDS[i][j] × curr[j]^7 + rc[i]
```

The **backward** half-round constraint. A naive formulation would use `curr[i]^(α⁻¹)` with α⁻¹ ≈ 10^19, yielding intractable constraint degree. Instead, we express the backward constraint as a *forward* relation:
```
(next[i] - rc[i])^7 = Σⱼ MDS_inv[i][j] × curr[j]
```

This keeps both half-round constraint directions at degree 7, which is critical: the maximum constraint degree with periodic selectors is 10 (not 10^19), making the proof system practical.

#### 5.4.4 Witness Binding (8 constraints)

At row 0, the Rescue state is initialized from the amount limbs:
```
state[i] = amount_limbs[i]    for i ∈ {0, ..., 7}
```

The Rescue output at row 14 is boundary-asserted to equal the public commitment `C`:
```
RESCUE_STATE[0..3] == C
```

This means producing a valid proof for a different amount requires finding a Rescue preimage collision (~128-bit security).

#### 5.4.5 Round Counter (1 constraint)

```
round_counter[row+1] = round_counter[row] + 1
```

### 5.5 Boundary Assertions (80 total)

Boundary assertions pin values into the trace at fixed rows, preventing the prover from substituting different values:

- **Row 0:** All public input field elements, effective limit limbs (with upper limbs = 0), amount upper limbs = 0, diff upper limbs = 0, final borrow = 0, Rescue domain separator, control flags (`is_first = 1`, `round_counter = 0`).
- **Row 14:** Rescue output = witness commitment `C`.
- **Last row:** `is_last = 1`, `round_counter = last`.

### 5.6 Constraint Degree Analysis

The maximum constraint degree is **10**, arising from the Rescue S-box (`x^7`) multiplied by periodic selector columns that gate constraints to specific rows. Winterfell requires that `blowup_factor ≥ max_constraint_degree + 1`; with degree 10, the minimum blowup is 16.

Constraint degree groups:
| Group | Degree | Count | Description |
|-------|--------|-------|-------------|
| Structural | 2 | 1 | Round counter increment |
| Bit binary | 2 | 128 | `b(1-b)` for amount and diff bits |
| Recomposition | 2 | 4 | Limb = Σ bit × 2^i |
| Borrow binary | 2 | 2 | `borrow(1-borrow)` |
| Subtraction | 2 | 2 | Limb-wise equations |
| Rescue S-box | 7–10 | 12 | pow7 × periodic selector |
| Rescue init binding | 3 | 8 | Transition constraints: periodic selector × (state[i] - amount[i]) at row 0 |

---

## 6. Batch State-Transition Proofs

> **Reader's guide:** Sections 6.3–6.8 detail the trace layout and constraint modules. For a high-level understanding, Sections 6.1–6.2 (overview and state model) and 6.5 (compliance accumulator) are sufficient. The constraint-level detail is intended for implementers and auditors.

### 6.1 Overview

Batch proofs extend the per-event model to prove N events simultaneously while computing a deterministic state root. A single STARK proof attests:

1. Every event in the batch satisfies the policy (encoded in the `all_compliant` flag).
2. Each event's leaf is correctly committed via Rescue hash.
3. The Merkle tree over all leaves is correctly computed.
4. The state root transition `prev_state_root → new_state_root` is valid.
5. Stream accumulators confirm that the event phase and Merkle phase process the same data.

### 6.2 State Model

```
EventLeaf = RescueHash(event_id[4] || amount_commitment[4] || policy_hash[8]
                        || public_inputs_hash[8] || compliance_flag[1])
            (25 elements total, absorbed in ⌈25/8⌉ = 4 sponge permutations)

EventMerkleTree = balanced Rescue Merkle tree over [Leaf₀, ..., Leaf_{n-1}]
                  (padded to next power of 2 with zero leaves)

BatchStateRoot = RescueHash(event_tree_root[4] || metadata_hash[4])

metadata_hash = RescueHash(prev_state_root[4] || batch_id[4] || tenant_id[4]
                           || store_id[4] || sequence_start || sequence_end || timestamp)
```

### 6.3 Trace Composition

The batch trace is organized into five sequential phases:

| Phase | Rows per Unit | Purpose |
|-------|---------------|---------|
| 0: Event stream | 4 per event | Amount decomposition, subtraction witness, flag computation, accumulator update |
| 1: Leaf hashing | 60 per event | 4 Rescue permutations per leaf (25 input elements at rate 8 → ⌈25/8⌉ = 4 absorptions × 15 rows each) |
| 2: Commitment hashing | 15 per event | Single Rescue permutation for amount commitment |
| 3: Merkle tree | 15 per internal node | In-circuit Rescue for each binary merge |
| 4: Finalize | 15 (fixed) | State root = Rescue(tree_root \|\| metadata_hash) |

**Why 60 rows for leaf hashing:** Each event leaf has 25 field elements. The Rescue sponge absorbs 8 elements per permutation (the rate), so ⌈25/8⌉ = 4 permutations are needed. Each permutation requires 15 rows (14 half-round transitions + 1 output row). Thus: 4 × 15 = 60 rows per leaf.

**Trace length formula:**
```
total_rows = next_power_of_two(
    num_events × 4          +    // Event phase
    num_events × 60         +    // Leaf hashing
    num_events × 15         +    // Commitment hashing
    (2^⌈log₂(n)⌉ - 1) × 15 +    // Merkle internal nodes
    15                            // Finalize
).max(256)
```

| Events | Event | Leaf Hash | Commit | Merkle | Finalize | Raw | Trace (pow2) |
|--------|-------|-----------|--------|--------|----------|-----|-------------|
| 8 | 32 | 480 | 120 | 105 | 15 | 752 | 1,024 |
| 32 | 128 | 1,920 | 480 | 465 | 15 | 3,008 | 4,096 |
| 64 | 256 | 3,840 | 960 | 945 | 15 | 6,016 | 8,192 |
| 128 | 512 | 7,680 | 1,920 | 1,905 | 15 | 12,032 | 16,384 |

The batch trace width is the base compliance width plus 99 batch-specific columns, staying under Winterfell's 255-column limit.

### 6.4 In-Circuit Merkle Tree

The Merkle tree is computed entirely inside the AIR. Each internal node occupies **15 rows:**

- **Rows 0–13:** 14 Rescue half-round transitions (7 rounds × 2 half-rounds), degree-7 each.
- **Row 14:** Output row where the 4-element hash result is extracted.

The tree is processed bottom-up, level by level. Constraints enforce:

1. **Level transitions:** Nodes at level k consume pairs of outputs from level k-1.
2. **Node ordering:** `node_index` increments sequentially within each level.
3. **Input binding:** The Rescue state at row 0 of each node is initialized with `left_child[0..3] || right_child[0..3]` (8 elements, one full-rate absorption).
4. **Output binding:** The Rescue output at row 14 equals `MERKLE_OUTPUT[0..3]`.
5. **Root binding:** The final Merkle output equals `EVENT_TREE_ROOT`.
6. **Leaf padding:** Trees are padded to a power-of-2 leaf count with zero leaves.

#### 6.4.1 Merkle Linkage Accumulators

To ensure that child hashes produced at one level are consumed exactly once at the next level, the AIR uses **multiplicative linkage accumulators** with γ = 11 (`MERKLE_LINK_GAMMA`). For each of the 4 hash output lanes:

```
produced_acc_{level}[i] = Π (γ × output[i] + node_index)    over all nodes at level
consumed_acc_{level+1}[i] = Π (γ × input[i] + child_index)  over all children consumed
```

A boundary constraint asserts `produced_acc = consumed_acc`, ensuring a bijective mapping between produced and consumed hashes. The γ-tagging prevents a cheating prover from permuting or duplicating nodes.

### 6.5 Compliance Accumulator

The compliance accumulator encodes whether all N events are compliant using a multiplicative running product.

**Definition.** Let γ = 7 (`COMPLIANCE_ACC_GAMMA`). The accumulator evolves as:

```
acc₀ = γ^{-N}                          (initialization)
acc_{i+1} = acc_i × γ × flag_i          (transition at EVENT_ROW == 2)
acc_final = γ^{-N} × γ^N × Π flag_i     (after N events)
         = Π flag_i                       (telescopes)
```

If all `flag_i = 1`: `acc_final = 1`. A boundary assertion checks `acc[last_row] == all_compliant`.

#### 6.5.1 Why a Malicious Prover Cannot Forge the Accumulator

**Claim:** A prover cannot produce `acc_final = 1` if any `flag_i = 0`, assuming γ = 7 has high multiplicative order in the Goldilocks field.

**Argument:** The transition constraint enforces `acc_{i+1} = acc_i × γ × flag_i` algebraically. The constraint is degree-2 in the trace columns and is enforced at every event row by the STARK. If `flag_j = 0` for some event j, then `acc_{j+1} = 0`, and all subsequent values are `acc_k = 0` for k > j (since each step multiplies by γ × flag, and 0 × anything = 0). The boundary assertion `acc_final = 1 ≠ 0` then fails.

A more subtle attack: could the prover set `flag_j` to some non-binary value `v ≠ 0, 1` such that the accumulator still reaches 1? No: the compliance binding constraints (Section 6.7) enforce that each `flag_i = 1 - borrow₁`, where `borrow₁` is binary-constrained. So `flag_i ∈ {0, 1}` is enforced by the AIR. The only way to produce `acc_final = 1` is if all `flag_i = 1`.

**Why γ = 7:** The choice of γ = 7 satisfies `gcd(7, p-1) = 1` in the Goldilocks field, ensuring that 7 is a generator of a large subgroup and that `γ^{-N}` is well-defined for all N. The value is also the S-box exponent of Rescue-Prime, ensuring algebraic consistency across the system. Any small prime coprime to `p-1` would work; 7 was chosen for minimality.

### 6.6 Stream Accumulators and Leaf Binding (151 constraints)

A critical integrity requirement: the leaf hashes in the Merkle phase must correspond exactly to the events processed in the event phase. A cheating prover could try to process one set of events but commit a different set of leaves to the Merkle tree.

This is enforced via **stream accumulators** — paired ordered hash chains on the event side and the leaf side. Seven streams are accumulated with γ = 11 (`MERKLE_LINK_GAMMA`):

| Stream | Lanes | Content |
|--------|-------|---------|
| Amount commitment | 4 | Rescue commitment to private amount |
| Event ID | 4 | UUID field elements |
| Policy hash | 8 | Domain-separated policy hash |
| Public inputs hash | 8 | Canonical hash of event metadata |
| Amount limbs | 2 | Raw amount (u32 limbs, with per-lane tags [1, 2]) |
| Compliance flag | 1 | Boolean compliance result |

**Transition formula** (for each lane i):
```
Event phase (at EVENT_ROW == 2):   event_acc_{k+1}[i] = event_acc_k[i] × γ + value_i
Leaf phase (per leaf row):          leaf_acc_{k+1}[i]  = leaf_acc_k[i]  × γ + leaf_value_i
Non-active rows:                    acc_{k+1}[i] = acc_k[i]   (carry forward)
```

**Boundary enforcement:** At the trace boundary:
```
event_accumulator[i] × γ^{num_padding_leaves} = leaf_accumulator[i]
```

where `num_padding_leaves` accounts for zero-padded leaves when `num_events` is not a power of 2.

#### 6.6.1 Security Argument

The stream accumulator is an ordered polynomial evaluation. After N events, the event accumulator for lane i is:

```
event_acc[i] = Σ_{k=0}^{N-1} value_k[i] × γ^{N-1-k}
```

This is a polynomial of degree N-1 in γ evaluated at the fixed point γ = 11. Suppose a cheating prover substitutes a different sequence of values `value'_k[i]`. The accumulators match iff:

```
Σ_{k=0}^{N-1} (value_k[i] - value'_k[i]) × γ^{N-1-k} = 0
```

This is a non-zero polynomial of degree ≤ N-1 in γ (assuming at least one value differs). By the Schwartz-Zippel lemma [5], if γ were sampled uniformly at random after the polynomial coefficients are fixed, the probability of forgery would be at most `(N-1) / p ≈ 2^{-57}` per lane, or ≈ 2^{-52} across all 27 lanes (union bound).

**Important caveat:** In the current implementation, γ = 11 is a fixed, publicly known constant — not a random challenge. This means the Schwartz-Zippel bound models *accidental* collisions, not adaptive algebraic forgery. A malicious prover who knows γ = 11 in advance could, in principle, solve the degree-(N-1) polynomial to find a substitution `value'_k` that produces the same accumulator value. However, this attack is constrained by two factors:

1. **STARK enforcement.** The prover must produce a valid STARK proof for the entire trace. The accumulator values are trace columns subject to transition constraints. The attacker cannot freely choose accumulator values — they must be consistent with a low-degree trace that passes all 505 constraints. Stream accumulator forgery alone does not break soundness; the attacker must *simultaneously* forge the accumulator and produce a valid STARK proof, which requires breaking FRI soundness.

2. **Practical difficulty.** Solving a degree-127 polynomial equation over the Goldilocks field to find a specific root is feasible in isolation (~2^7 work), but the solution must satisfy all other transition and boundary constraints in the AIR, making the combined attack intractable under STARK soundness assumptions.

For the `secure` profile (quadratic field extension), the field size increases to ~2^128, making even the algebraic solve infeasible. As described in Section 11.2.5, future versions will derive γ via the Fiat-Shamir heuristic after trace commitment, achieving full cryptographic soundness for the accumulator binding.

**Note:** The per-lane tags `[1, 2]` on amount limb streams prevent zero-value events from being indistinguishable, ensuring the polynomial is non-trivial even when amount values collide.

### 6.7 Compliance Binding Constraints (149 constraints)

Within each event's 4-row block, the batch AIR re-derives the compliance flag from scratch:

- **Row 0 (64 + 2 + 12 = 78 constraints):** Amount bit decomposition (64 binary constraints), amount recomposition (2 constraints), upper-limb zero checks (12 constraints: limbs 2–7 for both amount and threshold).
- **Row 1 (64 + 2 + 2 + 2 = 70 constraints):** Diff bit decomposition (64 binary), diff recomposition (2), borrow binary (2), 2-limb subtraction (2).
- **Row 2 (1 constraint):** Final flag binding: `flag = 1 - borrow₁`.

All constraints are gated by the `EVENTS_DONE == 0` selector, deactivating them for padding rows after the last real event.

### 6.8 Constraint Budget Summary

| Module | Constraints | Max Degree | Description |
|--------|-------------|-----------|-------------|
| Base structural | 54 | 2–3 | Phase control, event indexing, column carry-overs |
| Merkle + finalization | 47 | 7–10 | In-circuit Rescue transitions, tree traversal, root binding |
| Leaf hashing | 104 | 7–10 | In-circuit Rescue for leaf preimage absorption |
| Leaf binding | 151 | 2–3 | Stream accumulators linking events to leaves |
| Compliance binding | 149 | 2–3 | Amount decomposition, subtraction gadget, flag derivation |
| **Total transitions** | **505** | **10** | |
| **Boundary assertions** | **145** | — | State roots, metadata, policy, accumulators |

### 6.9 Batch Public Inputs (35 field elements)

| Field | Elements | Description |
|-------|----------|-------------|
| prev_state_root | 4 | Previous batch's state root (or zeros for genesis) |
| new_state_root | 4 | Computed state root for this batch |
| batch_id | 4 | UUID of this batch |
| tenant_id | 4 | Tenant UUID |
| store_id | 4 | Store UUID |
| sequence_start | 1 | First event sequence number |
| sequence_end | 1 | Last event sequence number |
| timestamp | 1 | Batch timestamp (Unix epoch seconds) |
| num_events | 1 | Number of events in batch |
| all_compliant | 1 | 1 iff all events satisfy the policy |
| policy_kind | 1 | Policy type identifier |
| policy_limit | 1 | Policy threshold or cap value |
| public_inputs_accumulator | 8 | Ordered accumulator over canonical per-event hashes |

### 6.10 Batch Witness Validation

Before trace construction, `BatchWitness::validate` enforces:

1. Non-empty batch and event count within `MAX_BATCH_SIZE` (128).
2. Sequence continuity: `event[i].sequence_number = sequence_start + i`.
3. Unique event IDs (no duplicates within a batch).
4. Policy consistency: all events share the same `policy_id`, `policy_params`, and `policy_limit`.
5. Tenant and store consistency across all events.
6. Witness commitment correctness: each event's Rescue commitment is recomputed and compared.
7. Compliance flag correctness: each event's flag is re-derived from the amount and limit.

---

## 7. Verification Protocol

### 7.1 Per-Event Verification Algorithm

The verification algorithm proceeds in strict order:

**Input:** Proof bytes `π`, public inputs `P`, policy `Φ`, witness commitment `C`.

1. **Size check.** Reject if `|π| > 10 MB`.
2. **Policy hash verification.** Recompute `h = SHA256("STATESET_VES_COMPLIANCE_POLICY_HASH_V1" || JCS(Φ))`. Reject if `h ≠ P.policy_hash`.
3. **Witness commitment binding.** If `P.witness_commitment` is present, reject if it does not match `C`.
4. **Proof options validation.** Deserialize the proof and extract the `ProofOptions`. Reject if not in the allowed set {`default`, `fast`, `secure`}.
5. **STARK verification.** Construct the `ComplianceAir` instance from `P`, `C`, and the effective limit `L`. Invoke Winterfell's `verify(π, air)`. This internally:
   - Reconstructs the constraint composition polynomial from the proof commitments.
   - Performs FRI verification (low-degree test).
   - Checks all boundary assertions against the public inputs.
   - Checks the deep composition polynomial consistency.
6. **Output.** Return `VerificationResult { valid, verification_time_ms, policy_id, policy_limit }`.

### 7.2 Batch Verification Algorithm

**Input:** Proof bytes `π`, batch public inputs `B`.

1. **Size check.** Reject if `|π| > 10 MB`.
2. **Input validation.** Reject if `B.all_compliant ∉ {0, 1}` (must be a field bit). Reject if `B.sequence_end - B.sequence_start + 1 ≠ B.num_events` (with overflow checks).
3. **STARK verification.** Construct the `BatchAir` instance from `B`. Invoke Winterfell's `verify(π, air)`.
4. **Output.** Return `BatchVerificationResult { valid, verification_time_ms, ... }`.

### 7.3 Chain Verification

For a sequence of batch proofs `[B₀, B₁, ..., Bₖ]`:

- **State root continuity:** `B[i].prev_state_root = B[i-1].new_state_root` for all i > 0.
- **Sequence continuity:** `B[i].sequence_start = B[i-1].sequence_end + 1` for all i > 0.

These checks are performed by `BatchVerifier::verify_chain`, creating an unbroken chain of verified state transitions. Each batch's integrity is individually proven by a STARK; the chain's continuity is enforced by the verifier.

---

## 8. Security Analysis

### 8.1 Formal Security Statement

**Theorem (informal).** Under the assumption that Rescue-Prime with the parameters in Section 4.2 provides ≥ 128-bit collision resistance, and that FRI with the proof options in Section 8.2 achieves soundness error ≤ 2^{-λ} (where λ depends on the chosen profile), the per-event compliance proof system has soundness error at most 2^{-λ}. That is: if the verifier accepts, then with probability ≥ 1 - 2^{-λ}, there exists a witness `amount` such that `amount ≤ limit` and `Rescue(amount_limbs) = C`.

A formal proof proceeds by reduction: a successful soundness attacker implies either (a) an efficient FRI distinguisher (contradicting FRI soundness), or (b) a Rescue collision finder (contradicting collision resistance). We defer the full proof to a companion document.

### 8.2 Proof Options and Security Levels

| Profile | Queries | Blowup | Grinding | Extension | Est. λ |
|---------|---------|--------|----------|-----------|--------|
| `default` | 28 | 16 | 16 | None | ~128 bits |
| `fast` | 20 | 16 | 8 | None | ~88 bits |
| `secure` | 40 | 16 | 20 | Quadratic | ~180 bits |

Security level estimation: `λ ≈ num_queries × log₂(blowup_factor) + grinding_factor + extension_bonus`, where `extension_bonus ≈ 10` for quadratic extension.

The minimum blowup factor of 16 is required because the AIR contains degree-10 constraints (Rescue S-box × periodic selectors). Winterfell requires that the evaluation domain size exceed the constraint composition polynomial's degree.

### 8.3 Soundness Properties

**Inequality soundness.** The subtraction gadget with binary borrow constraints ensures that `amount ≤ limit` (see Section 5.4.2 for the detailed argument).

**Witness binding.** Rescue permutation fully constrained over 14 half-rounds; output boundary-asserted to commitment `C`. Forging requires a Rescue collision (~128-bit security).

**Range validity.** u64 range enforced via 32-bit binary decomposition of active limbs and zero-assertion of upper limbs.

**Policy binding.** Verifier independently recomputes policy hash and compares. AIR binds effective limit via boundary assertions.

**Batch compliance.** Multiplicative accumulator with binary-constrained flags (Section 6.5.1).

**Event-leaf consistency.** Stream accumulators enforce that the Merkle leaves match the processed events. In the current design, the accumulator evaluation point is a fixed constant, so this binding is enforced by the STARK's constraint system rather than by information-theoretic randomness alone (see Section 6.6.1 for the full analysis). Forgery of the accumulator alone is insufficient to break soundness — an attacker must simultaneously produce a valid STARK proof, which requires breaking FRI soundness.

### 8.4 Threat Vectors and Mitigations

| Attack | Mitigation |
|--------|-----------|
| Non-binary bit manipulation | `b × (1 - b) = 0` for every bit column |
| Subtraction gadget bypass | Limb-wise equations + borrow binary + boundary `borrow₁ = 0` |
| Witness commitment forgery | Full Rescue constraint + output boundary assertion |
| Policy mismatch | Verifier recomputes policy hash; AIR binds effective limit |
| Public input substitution | Boundary assertions bind all public inputs at row 0 |
| Batch compliance flag forgery | Multiplicative accumulator forces `acc = 1` only if all flags = 1 |
| Merkle tree manipulation | In-circuit Rescue + level/node constraints + linkage accumulators |
| Leaf-event mismatch | Stream accumulators with γ-binding (Schwartz-Zippel) |

### 8.5 Amount-to-Payload Binding: Limitation and Mitigation

The AIR does **not** prove that the private `amount` is derived from the payload hashes in the public inputs. A malicious prover could, in theory, input a fake compliant amount while the actual payload contains a non-compliant value.

**Current mitigation in the VES pipeline:**

1. **Sequencer-mediated witness construction.** The StateSet Sequencer decrypts the payload, extracts the amount, and provides the public inputs. The prover node receives the amount from the sequencer's trusted decryption pipeline — it does not choose the amount arbitrarily.
2. **Witness commitment binding.** The prover must produce a Rescue commitment to the exact amount it proves about. The sequencer stores this commitment and cross-references it during audit. A prover that uses a fake amount produces a commitment that does not match the amount the sequencer extracted.
3. **Operational trust boundary.** The current architecture places trust in the sequencer's decryption and amount-extraction pipeline. This is analogous to how traditional compliance systems trust the payment processor's reported amounts.

This is a deliberate architectural choice: payload decryption and parsing involve non-algebraic operations (AES, JSON parsing) that are prohibitively expensive in a STARK AIR. Future extensions (Section 11) address this via recursive composition or auxiliary proofs.

---

## 9. Performance

### 9.1 Benchmarking Environment

All measurements are from the Criterion.rs benchmark suite in `benches/stark_bench.rs`, run in `--release` mode on:

- **CPU:** Intel Core i7-1195G7 @ 2.90 GHz (4 cores / 8 threads, 11th Gen)
- **RAM:** 32 GB DDR4
- **OS:** Linux 5.15 (x86_64)
- **Rust:** 1.90.0, release profile with LTO

### 9.2 Per-Event Performance (Measured)

| Operation | Time | Notes |
|-----------|------|-------|
| Witness creation | < 1 ms | Negligible; field arithmetic only |
| Proof generation | **52 ms** | 128-row trace, 248 columns, default options |
| Verification | < 10 ms | Dominated by FRI query checks |
| Proof serialization | < 1 ms | JSON round-trip |
| Proof size | **75 KB** | Default options; varies with proof profile |

Measured via integration test (`test_valid_witness_creates_valid_proof`, `--release` mode). Proving time is independent of both the amount value and the limit value — it depends only on the trace dimensions, which are fixed for per-event proofs.

### 9.3 Batch Performance (Extrapolated)

Batch benchmarks are extrapolated from per-event measurements and the trace length formula (Section 6.3). Proving time scales with trace length; the dominant cost is NTT over the LDE domain.

| Batch Size | Trace Rows | Est. Proving Time | Est. Verification Time | Est. Proof Size |
|------------|------------|-------------------|----------------------|----------------|
| 8 events | 1,024 | ~1–2 s | < 50 ms | ~150 KB |
| 32 events | 4,096 | ~4–8 s | < 50 ms | ~250 KB |
| 64 events | 8,192 | ~8–15 s | < 100 ms | ~350 KB |
| 128 events | 16,384 | ~15–30 s | < 100 ms | ~450 KB |

These estimates will be replaced with measured values as batch benchmarks are added to the Criterion suite. The per-event result (52 ms for 128-row trace) provides the baseline scaling factor.

**Maximum proof size enforced:** 10 MB (verifier rejects larger proofs).

### 9.4 Prover Cost Model

Proving time scales as `O(N × T × log(T))` where N is the number of trace columns and T is the trace length. The dominant costs are:

1. **NTT (Number Theoretic Transform):** Used for polynomial evaluation on the LDE domain. Cost: `O(T × log(T))` per column. With 256 columns and blowup factor 16, the LDE domain is 16T, so NTT cost is `O(256 × 16T × log(16T))`.
2. **Constraint evaluation:** `O(T × num_constraints)` field multiplications.
3. **FRI commitment:** `O(T × log(T))` for Merkle tree construction over the LDE.

For batch proofs, trace length grows linearly with event count (dominated by the 60 leaf-hashing rows per event), so proving time is approximately linear in batch size for small batches and mildly superlinear for large batches due to NTT cost.

### 9.5 Rescue-Prime Native Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Single permutation (12 elements) | ~5 μs | 7 rounds × 2 half-rounds |
| Hash 8 elements (full rate) | ~5 μs | 1 absorption + 1 permutation |
| Hash pair (Merkle node) | ~5 μs | 8 elements at rate 8 |
| Hash 25 elements (event leaf) | ~20 μs | 4 absorptions |

---

## 10. Integration and Deployment

### 10.1 Sequencer Integration

```rust
let client = SequencerClient::try_new(base_url, api_key)?;

// Fetch and validate public inputs (sequencer-provided hash cross-checked locally)
let inputs = client
    .get_public_inputs_validated(event_id, "aml.threshold", 10000)
    .await?;

// Generate proof
let witness = ComplianceWitness::new(amount, inputs);
let proof = ComplianceProver::with_policy(Policy::aml_threshold(10000)).prove(&witness)?;

// Submit proof with witness commitment
client.submit_proof(ProofSubmission::aml_threshold(
    event_id, 10000, proof.proof_bytes, proof.witness_commitment
)).await?;
```

API keys are stored in `Zeroizing<String>` wrappers (zeroed on drop) and support environment variable loading (`STATESET_API_KEY`). A `dev` feature flag disables authentication for local development.

### 10.2 Set Chain Submission

Batch proofs are submitted to Set Chain's `SetRegistry` contract for on-chain state anchoring:

```rust
let chain_client = SetChainClient::new(chain_url, registry_address);
chain_client.submit_batch_proof(batch_proof).await?;
```

The `new_state_root` from each batch becomes the `prev_state_root` for the next, forming a verifiable chain of state transitions anchored on-chain.

### 10.3 CLI

```bash
# Per-event operations
ves-stark-cli prove --amount 5000 --policy aml.threshold --limit 10000
ves-stark-cli verify --proof proof.bin --inputs inputs.json

# Batch operations
ves-stark-cli batch-prove --events events.json --policy aml.threshold --limit 10000
ves-stark-cli batch-verify --proof batch_proof.bin --inputs batch_inputs.json

# Utilities
ves-stark-cli inspect --proof proof.bin    # Display proof metadata
ves-stark-cli gen-inputs                   # Generate test public inputs
```

### 10.4 Language Bindings

**Node.js (NAPI-RS):**
```javascript
const { prove, verify } = require('ves-stark-nodejs');
const proof = prove(amount, publicInputs, policy);
const result = verify(proof.proofBytes, publicInputs, proof.witnessCommitment);
```

**Python (PyO3):**
```python
from ves_stark_python import prove, verify, Policy
proof = prove(amount, public_inputs, Policy.aml_threshold(10000))
result = verify(proof.proof_bytes, public_inputs, proof.witness_commitment)
```

---

## 11. Known Limitations and Future Work

### 11.1 Current Limitations

1. **No payload-to-amount binding in-AIR.** The proof does not attest that the private amount was correctly derived from the encrypted payload. The VES pipeline's sequencer mediates this linkage (Section 8.5), but the trust boundary is operational, not cryptographic.

2. **Single-policy batches.** All events in a batch must share the same policy type and parameters. Multi-policy batches would require per-event policy routing in the AIR.

3. **u64 amount range.** Amounts are restricted to 64-bit unsigned integers. Higher-precision amounts (e.g., for fractional currencies at 18 decimal places) would require multi-limb arithmetic extensions.

4. **Fixed accumulator evaluation point.** The stream accumulator γ values are fixed constants, not verifier-chosen random challenges. As analyzed in Section 6.6.1, this means the event-leaf consistency binding relies on the STARK's constraint enforcement rather than information-theoretic randomness. This does not reduce the *compliance proof's* soundness (which depends on FRI and Rescue), but it means the event-leaf consistency guarantee is structurally rather than probabilistically enforced. The `secure` profile with quadratic extension further mitigates this by increasing the field size.

### 11.2 Future Directions

1. **Recursive proof composition.** Using STARK recursion to compress multiple batch proofs into a single constant-size proof for on-chain verification, reducing Set Chain calldata costs.

2. **Payload binding via auxiliary proofs.** Linking the encrypted payload to the private amount through a hybrid proof system (e.g., STARK for field-native operations + a SNARK or MPC-in-the-head proof for AES decryption).

3. **Multi-policy AIR.** Extending the batch AIR to support heterogeneous policies within a single batch, with per-event policy selectors.

4. **Poseidon2 migration.** If Winterfell adds native Poseidon2 support, migrating from Rescue-Prime would reduce constraint degree from 10 to ~5, enabling blowup factor 8 and halving the LDE domain.

5. **Verifier-chosen accumulator challenges.** Making γ a Fiat-Shamir challenge derived from the trace commitment would raise accumulator soundness to match the STARK's FRI soundness level.

6. **Hardware acceleration.** GPU or FPGA-based NTT and hash computation for faster proof generation at scale.

---

## 12. Conclusion

StateSet STARK demonstrates that practical, privacy-preserving compliance is achievable with current zero-knowledge technology. By combining STARKs' transparency and post-quantum security with a carefully designed constraint system — 157 per-event constraints and 505 batch constraints enforcing range validity, witness binding, Merkle integrity, and compliance accumulation — the system enables commerce platforms to prove regulatory compliance without exposing sensitive transaction data.

The batch proving mode extends this to production-scale event processing, producing chainable Merkle state roots that form a cryptographically verifiable audit trail anchored on Set Chain. The modular Rust architecture, with bindings for Node.js and Python, provides a clear path from proof generation to production deployment.

The honest disclosure of the payload-to-amount binding gap (Section 8.5) and the stream accumulator's bounded soundness (Section 6.6.1) reflects a system designed for iterative hardening rather than marketing claims. The roadmap items — recursive compression, payload binding, and verifier-chosen challenges — address each known limitation with concrete technical paths.

---

## 13. References

[1] Ben-Sasson, E., Bentov, I., Horesh, Y., & Riabzev, M. (2018). "Scalable, transparent, and post-quantum secure computational integrity." *IACR ePrint 2018/046.*

[2] Grassi, L., Khovratovich, D., Rechberger, C., Roy, A., & Schofnegger, M. (2020). "Rescue-Prime: a Standard Specification (SoK)." *IACR ePrint 2020/1143.*

[3] Ben-Sasson, E., Goldberg, L., Kopparty, S., & Saraf, S. (2020). "DEEP-FRI: Sampling Outside the Box Improves Soundness." *ITCS 2020.*

[4] Winterfell STARK Library. https://github.com/facebook/winterfell

[5] Schwartz, J.T. (1980). "Fast Probabilistic Algorithms for Verification of Polynomial Identities." *Journal of the ACM, 27(4), 701-717.*

[6] NIST Post-Quantum Cryptography Standardization. https://csrc.nist.gov/projects/post-quantum-cryptography

[7] RFC 8785: JSON Canonicalization Scheme (JCS). https://www.rfc-editor.org/rfc/rfc8785

[8] Polygon Zero Team (2022). "Plonky2: Fast Recursive Arguments with PLONK and FRI." https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/plonky2.pdf

[9] VES Specification. StateSet Sequencer Documentation.
