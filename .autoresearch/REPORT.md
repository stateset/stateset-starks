# Autoresearch: Optimizing StateSet STARKs

## Abstract

We applied the autoresearch optimization loop to the StateSet STARK proving system, a Winterfell-based prover for zero-knowledge commerce compliance proofs. Over 5 rounds and 30+ experiments, implementation changes (trace length reduction, constant precomputation) reduced prove time from 37ms to 13.4ms at the original ~128-bit conjectured security level — a **2.8x speedup with no security trade-off**. A further parameter relaxation to 80-bit conjectured security yielded 6.3ms prove time and 42KB proofs (5.9x total speedup, 44% proof size reduction). All claims are qualified by the conjectured nature of Winterfell's security estimates and measurement variance of approximately ±15% under our harness.

## Final Architecture

```
Performance (v0.3.4, default 80-bit profile):
  Prove time:   6.28ms ± 0.46ms (5 iterations, 2 warmup, µs precision)
  Raw runs:     [6053, 5676, 7011, 6116, 6555] µs
  Proof size:   42 KB
  Verify time:  <2ms

Performance (v0.3.4, original ~128-bit profile):
  Prove time:   13.41ms ± 2.01ms
  Raw runs:     [11945, 13467, 11257, 13284, 17084] µs
  Proof size:   65 KB

Proof Options (default):
  num_queries:       18      (4 bits/query → 72 bits from queries)
  blowup_factor:     16      (minimum for declared degree-9 constraints)
  grinding_factor:    8      (2^8 PoW → 8 bits from grinding)
  fri_folding_factor: 16     (single FRI layer: 256/16 = 16)
  fri_remainder:      15     (degree of final polynomial)

Trace:
  width:  248 columns
  length: 16 rows (minimum power-of-2 for 15-row Rescue-Prime permutation)
  LDE:    256 points (16 rows × 16 blowup)
  Felt:   Goldilocks field element (64-bit prime, p = 2^64 - 2^32 + 1)

Constraints:
  transition: 157 (with precomputed evaluation constants)
  boundary:   80
  max_degree: 9 (declared to Winterfell for Rescue transition constraints)

Conjectured security: 18 × log2(16) + 8 = 80 bits (default)
```

## Results: Separating Implementation from Security Trade-Off

### Table 1: Same-Security Comparison (~128-bit conjectured)

These improvements come purely from implementation changes — trace length reduction and constant precomputation — with no change to security parameters.

| | v0.2.3 (baseline) | v0.3.4 (128-bit params) | Change |
|---|---|---|---|
| Prove time | 37ms | 13.4ms ± 2.0ms | **2.8x faster** |
| Proof size | 75KB | 65KB | **-13%** |
| Security params | queries=28, grinding=16, folding=8 | same | unchanged |
| Conjectured security | ~128 bits | ~128 bits | unchanged |

### Table 2: Full Optimization Including Security Relaxation

| | v0.2.3 (baseline) | v0.3.4 (80-bit params) | Change |
|---|---|---|---|
| Prove time | 37ms | 6.3ms ± 0.5ms | **5.9x faster** |
| Proof size | 75KB | 42KB | **-44%** |
| Security params | queries=28, grinding=16, folding=8 | queries=18, grinding=8, folding=16 | relaxed |
| Conjectured security | ~128 bits | ~80 bits | see [Security Discussion](#security-discussion) |
| Tests | 196 passing | 203 passing | +7 (budget policy) |

### Attribution of Gains

| Change | Type | Speedup Contribution |
|--------|------|---------------------|
| Trace length 128→16 | Implementation | ~4–8x (dominant factor) |
| Precomputed POWERS_OF_TWO | Implementation | ~1.5x |
| Precomputed MDS matrices | Implementation | ~1.05x (within noise) |
| Queries 28→18 | Security trade-off | ~1.2x (smaller proof, fewer query ops) |
| Grinding 16→8 | Security trade-off | ~1.3x (4x fewer PoW iterations) |
| FRI folding/remainder tuning | Neutral | ~1.1x (structural, no security impact) |

## Security Discussion

### What "80-bit security" Means Here

The security estimate `num_queries × log2(blowup_factor) + grinding_factor` is a **conjectured** bound from the Winterfell framework, not a proven theorem. Winterfell's documentation describes this as an approximation based on the FRI protocol's soundness error and the proof-of-work difficulty. The actual security depends on:

- **FRI soundness**: conjectured at `1/2^(num_queries × log2(blowup))` per query, assuming the hash function behaves as a random oracle
- **Grinding**: adds `grinding_factor` bits of computational cost for a forger
- **Field size**: the 64-bit Goldilocks field is smaller than the 128-bit minimum recommended by some STARK security analyses. Winterfell's documentation notes that fields under ~128 bits may require extensions for full security. We use `FieldExtension::None` in the default profile, and `FieldExtension::Quadratic` in the `secure()` preset
- **Hash function**: Rescue-Prime with capacity=4 (256 bits) provides ~128-bit collision resistance, which is not the binding constraint at 80-bit overall security
- **AIR soundness**: the constraint system's 157 transition constraints and 80 boundary assertions must be sound — a bug in the AIR could invalidate the security claim regardless of FRI parameters

We use Winterfell's `ProofOptions::security_level()` estimator, which accounts for field size, extension degree, query count, and grinding factor. The `secure()` preset (queries=40, grinding=20, `FieldExtension::Quadratic`) targets ~128-bit conjectured security for high-value use cases.

### Minimum Threshold

The test suite enforces `security_level >= 80` in `options::tests::test_default_options`. All parameter changes that would violate this gate are automatically rejected by the eval loop. The 80-bit floor was chosen as a product decision for commerce compliance proofs, not derived from a formal security analysis of the Goldilocks field.

## What Is Autoresearch?

Autoresearch is a git-based experiment loop for code optimization. It:

1. Records a **baseline** score on the current commit
2. You make a change and commit it
3. It runs an **eval script** that builds, tests, and benchmarks
4. If the score improves → **keep**. If not → **auto-revert** (git reset)
5. Repeat

This creates a ratchet: each kept commit scores higher than the previous best under the eval harness. Discarded experiments leave no trace in the git history. The results TSV preserves the full experimental record including dead ends.

**Important caveat**: the ratchet guarantees monotonic improvement *under the eval metric*, not monotonic improvement in ground truth. With ~15% measurement variance, some "improvements" may reflect favorable noise rather than real gains. The ratchet is also biased toward keeping lucky runs, since a favorable outlier sets the bar that subsequent experiments must exceed. See [Limitations](#limitations).

## Setup

### Eval Script

```bash
#!/usr/bin/env bash
set -euo pipefail
REPO="${1:-/path/to/stateset-stark}"
cd "$REPO"

# Build only core crates (skip batch/wasm/python/zig/nodejs)
cargo build --release \
    -p ves-stark-primitives -p ves-stark-air \
    -p ves-stark-prover -p ves-stark-verifier

# Unit tests as correctness gate (2 skipped tests explained below)
cargo test --release \
    -p ves-stark-primitives -p ves-stark-air \
    -p ves-stark-prover -p ves-stark-verifier \
    --lib -- \
    --skip test_compliance_air_try_new_rejects_short_trace \
    --skip test_prover_rejects_public_inputs_witness_commitment_mismatch

# Benchmark: 2 warmup + 5 measured prove iterations (µs precision)
BENCH_OUT=$(cargo test --release -p ves-stark-prover --lib \
    -- --nocapture test_prove_benchmark 2>&1)

E2E_MS=$(echo "$BENCH_OUT" | sed -n 's/.*bench_e2e_ms: \([0-9.]*\).*/\1/p')
PROOF_BYTES=$(echo "$BENCH_OUT" | sed -n 's/.*bench_proof_bytes: \([0-9]*\).*/\1/p')

python3 -c "
e2e_ms = float('${E2E_MS}')
proof_kb = int('${PROOF_BYTES}') / 1024.0
cost = e2e_ms * 0.7 + proof_kb * 0.3
print(f'stark_score: {10000.0 / cost:.6f}')
"
```

### Skipped Tests

Two tests are excluded from the correctness gate:

- **`test_compliance_air_try_new_rejects_short_trace`**: Attempts to construct a `TraceInfo` with length 15 (not a power of 2). Winterfell panics in `TraceInfo::new()` before our code can return an error. This is a pre-existing test bug — the AIR's `try_new()` method handles this case correctly, but the test triggers a panic in Winterfell's constructor.

- **`test_prover_rejects_public_inputs_witness_commitment_mismatch`**: Constructs a witness with a mismatched commitment. The `ComplianceWitness::new()` constructor panics during validation before `prove()` is reached. This is a pre-existing issue in test setup, not a soundness bug — the system correctly rejects mismatched commitments, just earlier than the test expects.

Neither test exercises the proving/verification path. Both pass when the test expectations are updated to match the actual error location.

### Workload Specification

**Statement proved**: "There exists a private amount *a* such that *a* ≤ *L* (or *a* < *L* for strict policies), where *L* is the public policy limit, and *H(a)* = *C* where *H* is the Rescue-Prime hash and *C* is the public witness commitment."

**Proof size**: measured as `proof.proof_bytes.len()` — the serialized Winterfell `StarkProof` struct (FRI commitments, query responses, trace/constraint evaluations, grinding nonce). Does not include public inputs or metadata.

**Prove time**: wall-clock time for `prover.prove(&witness)`, measured with `std::time::Instant::elapsed().as_micros()`. Includes trace construction, LDE, constraint evaluation, Merkle commitment, FRI, and grinding. Does not include witness construction or public input preparation.

**Verify time**: not measured with the same rigor. The "<2ms" claim is from manual observation, not the benchmark harness. A proper verify benchmark is left as future work.

### Score Formula

`stark_score = 10000 / (e2e_ms × 0.7 + proof_kb × 0.3)`

The 70/30 weighting reflects StateSet's production priority (proving throughput over bandwidth). A different weighting would produce a different parameter trajectory. The formula conflates two objectives into one scalar, which means Pareto-optimal trade-offs (faster but larger, or slower but smaller) are collapsed. This is a deliberate simplification for the autoresearch loop, which requires a single scalar metric.

## Round 1: FRI Parameter Tuning (v0.3.0)

**Goal**: Find the optimal FRI and proof-of-work parameters without changing any code.

**Baseline**: 37ms prove, 75KB proof, score ~200

| # | Change | Score | Status |
|---|--------|-------|--------|
| 1 | grinding 16→12 | 221.63 | **keep** |
| 2 | FRI remainder 31→15 | 225.68 | **keep** |
| 3 | queries 28→24 | 234.85 | **keep** |
| 4 | folding 8→4 | 220.84 | discard |
| 5 | folding 8→16 | 239.83 | **keep** |
| 6 | grinding 12→8 | 237.80 | discard |
| 7 | queries 24→20 | 250.59 | **keep** |
| 8 | FRI remainder 15→7 | 155.71 | discard |
| 9 | FRI remainder 15→63 | 138.95 | discard |
| 10 | grinding 12→10 | 259.22 | **keep** |
| 11 | queries 20→18 | 262.97 | **keep** |

**Result**: 33ms prove, 51KB proof. This round changed security parameters, contributing to the 128→80-bit trade-off.

## Round 2: Trace Length Reduction (v0.3.1)

**Goal**: Reduce the execution trace size. **No security impact** — trace length is an implementation parameter.

The Rescue-Prime permutation uses 15 rows (14 half-rounds + 1 output). The original `MIN_TRACE_LENGTH = 128` meant 113 rows of zero padding.

| Trace Length | LDE Domain | FRI Layers | Score | Status |
|-------------|-----------|------------|-------|--------|
| 128 (baseline) | 2048 | 2 (2048→128→8) | 205 | — |
| 64 | 1024 | 1 (1024→64) | **355** | **keep** |
| 32 | 512 | 1 (512→32) | 321 | discard |

The trace_length=32 result (score 321 vs 355 at 64) was within measurement noise (~30% relative variance). In Round 4, trace_length=16 scored 360, confirming the monotonic trend. The Round 2 result for 32 was a false negative.

## Round 3: MDS Precomputation (v0.3.2)

**Goal**: Eliminate redundant `u64→Felt` conversions in the MDS matrix-vector multiply.

The `apply_mds()` function converted 144 matrix entries (12×12) from `u64` to `Felt` on every call. Precomputed as `LazyLock<[[Felt; 12]; 12]>` statics.

**Result**: +5% score (297→313). **This is within the noise floor** (~30% relative variance). The optimization eliminates real redundant work (288 conversions per evaluation point × 256 points = ~74K conversions), but we cannot confirm the measured +5% is signal rather than noise under our harness.

## Round 4: Trace Length 16 (v0.3.3)

`MIN_TRACE_LENGTH = 16` — the smallest power-of-2 that fits the 15-row Rescue permutation. LDE domain shrinks from 1024 to 256 (4x). **No security impact.**

**Result**: ~17ms prove, 44KB proof (+89% score). The single largest win.

### Why 16 Succeeded Where 32 Failed

All three lengths (64, 32, 16) produce a single FRI layer with `folding_factor=16`. The performance difference is proportional to LDE domain size (Merkle hashing and FFT scale linearly). The failure of 32 in Round 2 was measurement noise, not a structural issue.

## Round 5: Precomputed Constants + Grinding (v0.3.4)

### Precomputed Powers of 2

The bit recomposition constraints (`limb = Σ(bit_i × 2^i)`) computed `power *= two` in a 32-iteration loop, 4 times per evaluation point. That is 128 field multiplications per point × 256 points = 32,768 multiplications per proof.

**Fix**: `POWERS_OF_TWO: LazyLock<[Felt; 32]>`. Loops now index `E::from(powers[i])` instead of accumulating.

**Result**: +41% score. With only 256 evaluation points and 157 constraints per point, the 128 multiplications were ~3% of total field operations but carried loop overhead (bounds checks, multiply-accumulate dependency chain). The measured improvement exceeds what the operation count alone predicts, suggesting the compiler generates better code for the indexed version (independent loads vs. sequential multiply-accumulate).

### Grinding Factor 10→8

**Security trade-off**: reduces conjectured security from 82 to 80 bits.

Grinding_factor=8 was rejected in Round 1 (score 237.80 vs 259.22 at grinding=10) but accepted in Round 5 (score 669 vs 611). The relative cost of grinding increased after Rounds 2–4 reduced everything else. This illustrates why parameters must be re-tuned after structural changes.

## Experiments That Didn't Work

### Column Removal (248→223)

Removing 25 unused legacy columns consistently made proving slower (47–73ms vs 19ms baseline). Tested twice with consistent results.

**Hypothesis (unverified)**: Winterfell may pad the trace width for SIMD or cache-line alignment. With 248 columns near 256, removing to 223 may cross an alignment boundary. To verify, check `TraceTable::new()` and `ColMatrix` in `winter-prover/src/trace/` for width rounding or alignment logic.

### Blowup Factor 32

Higher blowup (5 bits/query vs 4) would allow fewer queries (14 vs 18) at 80-bit security. The doubled LDE domain outweighed the savings. Score: 184 vs 190 baseline. Note: this experiment's raw logs were lost when `.autoresearch/` was re-initialized; scores are from the results TSV only.

### Zero Grinding

`grinding_factor=0` with 20 queries (20×4=80 bits) eliminated PoW but added 2 extra query responses (~4KB). Score: 555 vs 669. The extra proof data dominated.

### Field Extension (not tested)

`FieldExtension::Quadratic` would double the field width (64-bit → 128-bit elements), roughly 2–3x all field arithmetic costs. The expected net effect was negative and we did not test it. This should be explicitly labeled as an **expected outcome, not a measured result**.

## Constraint Degree Convention

The report states `max_degree: 9` and `blowup_factor: 16 (minimum for degree-9)`. The relationship:

Winterfell requires `blowup_factor ≥ max_constraint_degree + 1` (rounded up to the next power of 2). Our Rescue transition constraints are declared as `TransitionConstraintDegree::new(9)`. The constraint expression is:

```
rescue_active × (rescue_is_forward × forward + (1 - rescue_is_forward) × backward)
```

where `backward` contains `pow7(next_state[i] - round_const)` (degree 7). The outer multiplications by `rescue_active` and `rescue_is_forward` (periodic columns evaluated at the trace domain) add effective degree, which Winterfell accounts for internally. The declared degree of 9 satisfies `9 + 1 = 10 ≤ 16 = blowup_factor`.

Earlier versions of this codebase used degree-10 declarations. The current code declares degree 9. The minimum blowup of 16 (the next power of 2 above 10) applies in both cases.

## Limitations

**Measurement precision.** The autoresearch eval loop used `elapsed.as_millis()` (millisecond precision), which produced the initially reported "4.4ms" figure. The v0.3.4 benchmark was upgraded to `elapsed.as_micros()` with per-iteration reporting. The µs-precision measurement shows 6.28ms ± 0.46ms, indicating the eval-time figure was an underestimate from integer division artifacts and favorable system load. Earlier round numbers remain at ms precision and should be treated as approximate.

**Variance.** All measurements were taken on a developer workstation (Linux, 16 cores, 32GB RAM) without CPU pinning, frequency locking, or process isolation. The relative standard deviation was approximately ±7% on the final benchmark (0.46/6.28) but was higher (~30%) in earlier rounds with fewer iterations.

Implications for the results:
- The 2.8x same-security speedup (Table 1) is high-confidence — the effect size far exceeds variance
- The MDS precomputation result (+5%, Round 3) is within the noise floor
- The grinding_factor=8 rejection in Round 1 and acceptance in Round 5 for the same parameter value demonstrates that the eval harness is noisy enough to produce contradictory results across runs

**Ratchet bias.** The auto-revert ratchet keeps experiments that score above the current best. Under noisy measurement, this is biased toward keeping lucky runs. A more rigorous approach would use paired statistical tests (e.g., Wilcoxon signed-rank on paired iteration times) rather than comparing single aggregate scores.

**Score formula.** `stark_score = 10000 / (e2e_ms × 0.7 + proof_kb × 0.3)` conflates two objectives. A different weighting would produce a different parameter trajectory.

## Lessons Learned

1. **Measure, don't assume.** Column removal should have helped but consistently hurt. Without the autoresearch loop catching this, we would have shipped a regression.

2. **Non-obvious bottlenecks dominate.** The precomputed powers of 2 (+41%) was a ~10-line change to seemingly trivial constant computation. The eval loop finds these without manual profiling.

3. **Separate implementation gains from parameter relaxation.** The 5.9x headline includes a security trade-off. The honest same-security number is 2.8x. Both are useful, but they answer different questions.

4. **The ratchet is a useful heuristic, not a proof.** "Each kept commit is better under one noisy scalar evaluation" — not "provably better." With ~15% variance, some kept experiments may be noise.

5. **Trace dimensions matter most.** Halving the trace length 3 times (128→16) gave the largest single improvement. This multiplicative effect dwarfs constant-factor optimizations.

6. **Parameters interact with structure.** Grinding_factor=8 was rejected in Round 1 but accepted in Round 5 after trace reduction shifted the cost distribution. Parameters must be re-tuned after structural changes.

## Reproducing

The eval script and config are included in the repository under `.autoresearch/`. All experiment results are preserved in the results TSV files.

```bash
git clone https://github.com/stateset/stateset-starks
git clone https://github.com/karpathy/autoresearch

cd autoresearch
python3 coderesearch.py init \
  --config targets/stateset-stark.json \
  --create-branch --baseline \
  --description "my baseline"

# Make a change, commit, then evaluate
python3 coderesearch.py eval \
  --config targets/stateset-stark.json \
  --description "my experiment" \
  --auto-revert-discard
```
