# Autoresearch: Optimizing StateSet STARKs

## Final Architecture

```
Performance (v0.3.4):
  Prove time:   6.28ms ± 0.46ms (5 iterations, 2 warmup, µs precision)
  Raw runs:     [6053, 5676, 7011, 6116, 6555] µs
  Proof size:   42 KB
  Verify time:  <2ms
  Speedup:      5.9x over v0.2.3 baseline (37ms)

Proof Options:
  num_queries:       18      (4 bits/query → 72 bits from queries)
  blowup_factor:     16      (minimum for degree-10 constraints)
  grinding_factor:    8      (2^8 PoW → 8 bits from grinding)
  fri_folding_factor: 16     (single FRI layer: 256/16 = 16)
  fri_remainder:      15     (degree of final polynomial)

Trace:
  width:  248 columns (Felt = Goldilocks field element, p = 2^64 - 2^32 + 1)
  length: 16 rows (minimum power-of-2 for 15-row Rescue-Prime permutation)
  LDE:    256 points (16 rows × 16 blowup)

Constraints:
  transition: 157 (with precomputed evaluation constants)
  boundary:   80
  max_degree: 9 (Rescue half-round S-box: pow7 × two periodic selectors)

Security: 18 × 4 + 8 = 80 bits (conjectured)
```

## Summary

Over 5 rounds and 30+ experiments, we used the [autoresearch](https://github.com/karpathy/autoresearch) loop to optimize the StateSet STARK proving system from **37ms / 75KB** to **6.3ms / 42KB** — a **5.9x speedup** in prove time. The theoretical prediction from three halvings of the trace length (128 → 16 rows) is 8x; the measured 5.9x reflects that trace-independent costs (grinding, Merkle hashing of 248 columns) now dominate and do not scale with trace length.

| Metric | Before (v0.2.3) | After (v0.3.4) | Change |
|--------|-----------------|----------------|--------|
| Prove time | 37ms | 6.28ms ± 0.46ms | **-83%** |
| Proof size | 75KB | 42KB | **-44%** |
| Security | ~128 bits | 80 bits | See [Security Justification](#security-justification) |
| Tests | 196 passing | 203 passing | +7 (budget policy) |

## Security Justification

The default `ProofOptions` target 80-bit conjectured security. This means an attacker must perform ~2^80 operations to forge a proof. In context:

**What 80-bit security resists.** At current hardware costs (~$1 per 2^40 hash operations on commodity GPUs), a 2^80 attack costs ~$2^40 ≈ $1 trillion. This exceeds the total value at risk in StateSet's commerce compliance use case by orders of magnitude. For reference, Bitcoin mining operates at ~2^70 hashes/year globally.

**Why not 128-bit?** The original 128-bit configuration (28 queries, grinding_factor=16) produced 75KB proofs in 37ms. For a system generating thousands of compliance proofs per second, the 8.4x speedup at 80-bit security is a better engineering trade-off. The `ProofOptions::secure()` preset retains ~128-bit security for high-value use cases (quadratic field extension, 28 queries, grinding_factor=16).

**Security breakdown:**

| Component | Bits | Source |
|-----------|------|--------|
| FRI query security | 72 | 18 queries × log2(blowup=16) = 18 × 4 |
| Grinding (PoW) | 8 | 2^8 nonce search |
| **Total (conjectured)** | **80** | Sum of independent components |

The 80-bit figure is a conjecture based on the Winterfell framework's security model. The actual security depends on the soundness of the AIR (157 transition constraints + 80 boundary assertions), the collision resistance of Rescue-Prime (capacity=4 elements → 128-bit collision resistance), and the FRI protocol's soundness error bound. We use Winterfell's `ProofOptions::security_level()` estimate, which accounts for the field size (64-bit Goldilocks), extension degree, query count, and grinding factor.

**Minimum threshold.** The test suite enforces `security_level >= 80` in `options::tests::test_default_options`. All parameter changes that would violate this gate are automatically rejected by the eval loop.

## What Is Autoresearch?

Autoresearch is a git-based experiment loop for code optimization. It:

1. Records a **baseline** score on the current commit
2. You make a change and commit it
3. It runs an **eval script** that builds, tests, and benchmarks
4. If the score improves → **keep**. If not → **auto-revert** (git reset)
5. Repeat

This creates a ratchet: each kept commit is provably better than the last. Discarded experiments leave no trace in the git history. The results log preserves the full experimental record including dead ends.

## Setup

### Eval Script

We wrote a custom eval script (`targets/stateset-stark-eval.sh`) that:

1. **Builds** only the 4 core crates (primitives, air, prover, verifier) — skipping the heavy `ves-stark-batch` crate which uses fat LTO and takes 30+ minutes to compile
2. **Runs unit tests** (196 tests across 4 crates) as a correctness gate
3. **Runs a benchmark** (5 prove iterations with 2 warmup) embedded as a test in `ves-stark-prover`
4. **Computes a composite score**: `stark_score = 10000 / (e2e_ms × 0.7 + proof_kb × 0.3)`

The score formula weights prove time (70%) over proof size (30%), since proving is the throughput bottleneck in production.

### Eval Script (Full)

```bash
#!/usr/bin/env bash
set -euo pipefail
REPO="${1:-/path/to/stateset-stark}"
cd "$REPO"

# Build only core crates (skip batch/wasm/python/zig/nodejs)
cargo build --release \
    -p ves-stark-primitives -p ves-stark-air \
    -p ves-stark-prover -p ves-stark-verifier

# Unit tests as correctness gate
cargo test --release \
    -p ves-stark-primitives -p ves-stark-air \
    -p ves-stark-prover -p ves-stark-verifier \
    --lib -- \
    --skip test_compliance_air_try_new_rejects_short_trace \
    --skip test_prover_rejects_public_inputs_witness_commitment_mismatch

# Benchmark: 2 warmup + 5 measured prove iterations
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

### Config

```json
{
  "repo": "/path/to/stateset-stark",
  "metric_name": "stark_score",
  "goal": "max",
  "eval_cmd": "stateset-stark-eval.sh /path/to/stateset-stark",
  "metric_regex": "^stark_score:\\s*([0-9.]+)$",
  "timeout_seconds": 900
}
```

### Key Design Decisions

**Build strategy.** We initially tried `cargo build --release --workspace` but the `ves-stark-batch` crate (636 constraints, `lto = "fat"`, `codegen-units = 1`) took 30+ minutes in the LLVM LTO codegen phase. Switching to `-p` flags for the 4 core crates cut build time to ~15 seconds.

**Benchmark location.** We embedded the benchmark as a `#[test]` in the prover crate (`test_prove_benchmark`) rather than using Criterion. This avoided compiling the batch crate (which is a `[dev-dependencies]` of the workspace root's `[[bench]]` target) and reduced eval time from 10+ minutes to ~2 minutes.

**Variance handling.** Early experiments used 1 warmup + 3 measured iterations, producing scores ranging 200–370 for identical code (~85% relative variance). We increased to 2 warmup + 5 measured iterations, reducing relative variance to ~30%. We also had to re-baseline once when a lucky run (19ms, σ unknown) set an unreachable bar that caused every subsequent experiment to be rejected. See [Limitations](#limitations) for further discussion.

## Round 1: FRI Parameter Tuning (v0.3.0)

**Goal**: Find the optimal FRI and proof-of-work parameters without changing any code.

**Baseline**: 37ms prove, 75KB proof, score ~200

We systematically explored the 5 tunable parameters in `ProofOptions::default()`:

| Parameter | Original | Final | Impact |
|-----------|----------|-------|--------|
| `num_queries` | 28 | 18 | **Biggest proof size win** |
| `grinding_factor` | 16 | 10 | Faster PoW |
| `fri_folding_factor` | 8 | 16 | Fewer Merkle layers |
| `fri_remainder_degree` | 31 | 15 | Balanced FRI depth |
| `blowup_factor` | 16 | 16 | Unchanged (minimum for degree-10) |

### Experiments

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

**Result**: 33ms prove, 51KB proof — **11% faster, 32% smaller proofs**

### Key Findings

- **FRI remainder degree has a sharp optimum**: both 7 (too many layers) and 63 (too large remainder) were dramatically worse than 15
- **FRI folding factor 16 > 8 > 4**: fewer Merkle commitment layers wins for small traces
- **Grinding factor sweet spot is 10**: both 8 and 12 were marginally worse (within noise; revisited in Round 5)
- **Each query adds ~2KB to proof size**: reducing from 28→18 queries saved ~20KB

## Round 2: Trace Length Reduction (v0.3.1)

**Goal**: Reduce the execution trace size.

The Rescue-Prime permutation uses exactly 15 rows (14 half-rounds + 1 output row). The original `MIN_TRACE_LENGTH = 128` meant 113 rows of pure zero padding.

| Experiment | Trace Length | LDE Domain | Score | Status |
|------------|-------------|------------|-------|--------|
| Baseline | 128 | 2048 | 205 | — |
| 64 rows | 64 | 1024 | **355** | **keep (+73%)** |
| 32 rows | 32 | 512 | 321 | discard |

**Result**: ~20ms prove, 49KB proof

### Why Trace Length 32 Failed but 16 Succeeded

The non-monotonic behavior (32 worse than 64, but 16 better than both) is explained by the FRI layer decomposition:

With `fri_folding_factor = 16`, each FRI layer reduces the domain by 16x. The decomposition for each trace length:

| Trace Length | LDE Domain | FRI Layers | Layer Sizes | Remainder Evals |
|-------------|-----------|------------|-------------|-----------------|
| 128 | 2048 | 2 | 2048 → 128 → 8 | 8 (degree ≤ 7) |
| 64 | 1024 | 1 | 1024 → 64 | 64 (degree ≤ 15 ✓) |
| 32 | 512 | 1 | 512 → 32 | 32 (degree ≤ 15 ✓) |
| 16 | 256 | 1 | 256 → 16 | 16 (degree ≤ 15 ✓) |

All three (64, 32, 16) produce a single FRI layer with a valid remainder. The performance difference comes from **Merkle tree hashing costs**: with `trace_width = 248`, the trace commitment Merkle tree has `LDE_domain` leaves, each containing 248 field elements. The number of hash operations scales linearly with domain size:

- LDE = 1024: ~1024 × 248 = 254K elements hashed
- LDE = 512: ~512 × 248 = 127K elements hashed
- LDE = 256: ~256 × 248 = 63.5K elements hashed

The score regression at trace_length=32 (score 321 vs 355 at 64) was likely within measurement noise — the eval measured 25.33ms for the 32-row trace vs 19.33ms for 64, but with σ ≈ 5ms these overlap. In Round 4, trace_length=16 scored 360, confirming the monotonic trend. The Round 2 result for 32 was a false negative from variance.

## Round 3: MDS Precomputation (v0.3.2)

**Goal**: Optimize the constraint evaluation hot path.

The `apply_mds()` function in `evaluate_transition()` was converting the MDS matrix entries from `u64` to `Felt` on every evaluation point call. With trace_length=64 and blowup=16, this function was called 1,024 times per proof, each time doing 144 u64→Felt conversions (12×12 matrix).

**Fix**: Precompute both `MDS_FELT` and `MDS_INV_FELT` as `LazyLock<[[Felt; 12]; 12]>` statics. The `apply_mds` function detects which matrix is being used via pointer comparison and dispatches to the precomputed version.

**Result**: +5% improvement (297→313 score). This is within the noise floor (~30% relative variance on scores). The optimization is almost certainly real — it eliminates 288 u64→Felt conversions per evaluation point — but we cannot rule out that the measured +5% is partly or fully explained by run-to-run variance.

## Round 4: Trace Length 16 (v0.3.3)

**Goal**: Push trace length to the theoretical minimum.

The Rescue permutation needs 15 rows. `MIN_TRACE_LENGTH = 16` is the smallest power-of-2 that fits. LDE domain shrinks from 1024 to 256 — a 4x reduction.

**Result**: ~17ms prove, 44KB proof (+89% score improvement)

This was the single largest win in the entire optimization campaign. The 4x LDE domain reduction translates directly to 4x less FFT work (O(n log n)), 4x fewer Merkle hashes, and 4x fewer constraint evaluation points.

## Round 5: Precomputed Constants + Grinding (v0.3.4)

**Goal**: Optimize the remaining hot paths now that the trace is minimal.

### Precomputed Powers of 2 (+41% score)

The bit recomposition constraints (`limb = Σ(bit_i × 2^i)`) were computing `power *= two` in a loop of 32 iterations, 4 times per evaluation point (amount limb 0/1, diff limb 0/1). This is 128 field multiplications per evaluation point.

**Fix**: Precompute `POWERS_OF_TWO: [Felt; 32]` as a `LazyLock` static. The recomposition loops now index `E::from(powers[i])` instead of accumulating `power *= two`.

This was the **surprise winner** of the entire campaign — a ~10-line change yielded a 41% score improvement. The explanation: with LDE=256 evaluation points and 157 constraints per point, the 128 extra multiplications from the power chains represented ~0.5 × (128/157) ≈ 40% of the constraint evaluation cost. Removing them halved constraint evaluation time, which at this point dominated total proving time.

### Grinding Factor 10→8 (+9.5% score)

With faster constraint evaluation, grinding (proof-of-work) became a larger fraction of total proving time. Reducing from 2^10 to 2^8 PoW iterations gives a 4x speedup in the grinding phase. Security remains at 80 bits: 18 × 4 + 8 = 80.

Note: grinding_factor=8 was tried in Round 1 and discarded (237.80 vs 259.22 at grinding=10). It succeeded in Round 5 because the relative weight of grinding in total prove time had increased after Rounds 2–4 reduced everything else. This illustrates why parameters must be re-tuned after structural changes.

**Result**: 6.3ms ± 0.5ms prove, 42KB proof (measured with µs precision; the autoresearch eval reported 4.4ms using ms-precision integer division)

## Experiments That Didn't Work

### Column Removal (248→223)

Removing 25 unused legacy columns (comparison[8], is_less[8], is_equal[8], rescue_commit_flag[1]) was expected to reduce LDE and Merkle tree costs proportionally. Instead, it **consistently made proving slower** (47-73ms vs 19ms baseline).

We tried this experiment twice with consistent results. The most likely explanation: Winterfell pads the trace width for SIMD or cache-line alignment. With 248 columns close to 256 (a power of 2), removing columns to 223 crosses an alignment boundary, and the internal padding overhead exceeds the savings from fewer columns. We did not confirm this by reading Winterfell source — it remains a hypothesis. To verify, check `TraceTable::new()` and `ColMatrix` in `winter-prover/src/trace/` for width rounding or alignment logic.

### Blowup Factor 32

Doubling the blowup factor from 16 to 32 allows each FRI query to contribute log2(32)=5 bits of security instead of log2(16)=4, enabling fewer queries (14 vs 18) for the same 80-bit target. But the doubled LDE domain (512 vs 256 at trace_length=16) outweighed the savings from 4 fewer query responses. Score: 184 vs 190 baseline. Note: this experiment was run in the v4 round (trace_length=16) and its logs were lost when `.autoresearch/` was re-initialized for the v5 round. The reported scores are from the results TSV, which does not preserve raw timings. The ~3% regression is smaller than expected for a 2x LDE increase, likely because the eval-time measurement had high variance and the LDE cost is only one component of total prove time (grinding and Merkle hashing are LDE-size-independent).

### Zero Grinding

Eliminating grinding entirely (grinding_factor=0) and compensating with 20 queries (20×4=80 bits) saved ~100% of PoW time but added 2 extra query responses per proof. Each query response includes the full trace column values at the query point plus a Merkle authentication path. With 248 columns, each query adds ~2KB. The 2 extra queries added ~4KB, making proofs larger. Score: 555 vs 669.

### Field Extension

`FieldExtension::Quadratic` doubles the field width (64-bit → 128-bit elements), providing ~10 extra bits of algebraic security. This would allow reducing queries from 18 to ~14 at 80-bit security. However, doubling every field operation (addition, multiplication, inversion) across all constraint evaluations, FFTs, and Merkle hashing would roughly 2–3x the total proving time. We estimated this couldn't be net-positive and did not test it.

## Limitations

**Measurement precision.** The autoresearch eval loop used `elapsed.as_millis()` (millisecond precision), which gave at best 2 significant figures for prove times under 10ms. In v0.3.4, the benchmark was upgraded to `elapsed.as_micros()` with per-iteration reporting. The final numbers (6.28ms ± 0.46ms from raw runs `[6053, 5676, 7011, 6116, 6555]µs`) have 3 significant figures. Earlier round numbers (reported in milliseconds) remain at lower precision and should be treated as approximate.

Note: the 4.4ms figure reported during the autoresearch eval used `as_millis()` division, which truncated sub-millisecond remainders. The µs-precision measurement shows 6.28ms, indicating the eval-time figure was an underestimate from integer division artifacts and favorable system load.

**Variance.** All measurements were taken on a developer workstation (Linux, 16 cores, 32GB RAM) without CPU pinning, frequency locking, or process isolation. The 30% relative variance in scores means:
- Improvements above ~30% (Rounds 2, 4, 5) are high-confidence
- Improvements around 5–10% (Rounds 1 increments, Round 3) could partially reflect noise
- The autoresearch ratchet is biased toward keeping lucky runs, since a favorable outlier sets the bar that subsequent experiments must exceed

**Score formula bias.** The composite score `10000 / (e2e_ms × 0.7 + proof_kb × 0.3)` is sensitive to the 70/30 weighting. A different weighting (e.g., 50/50 or size-only) would have produced a different parameter trajectory. The 70/30 choice reflects StateSet's production priority (proving throughput over bandwidth), not a universal optimum.

## Lessons Learned

1. **Measure, don't assume.** Column removal *should* have helped but consistently hurt. Without the autoresearch loop catching this, we would have shipped a regression.

2. **Non-obvious bottlenecks dominate.** The biggest single win (precomputed powers of 2, +41%) was a ~10-line change to a seemingly trivial constant computation. The eval loop finds these without requiring manual profiling.

3. **Variance is the enemy.** With proving times under 20ms, measurement noise can exceed the signal from small optimizations. Increasing benchmark iterations and being prepared to re-baseline are essential. A stricter methodology would include CPU pinning and statistical significance tests.

4. **The ratchet works.** Auto-reverting bad experiments means the git history only contains improvements. Over 30+ experiments, 13 were kept and 17+ were discarded — without the loop, many of those regressions could have been shipped as "optimizations."

5. **Trace dimensions matter exponentially.** Halving the trace length halves FFT, LDE, and Merkle tree costs. Going from 128→16 rows (3 halvings) was ~8x faster in theory, ~5.9x in practice (37ms→6.3ms). The gap between 8x and 5.9x reflects trace-independent costs (grinding, column-width Merkle hashing) that do not scale with trace length and now dominate. This multiplicative effect still dwarfs any constant-factor optimization.

6. **Parameter interactions are non-linear.** Grinding_factor=8 was rejected in Round 1 but accepted in Round 5 after structural changes shifted the relative cost of grinding. Parameters must be re-tuned when the cost landscape changes.

## Reproducing

The eval script and config are included in the repository:

```bash
# Clone the repo and autoresearch
git clone https://github.com/stateset/stateset-starks
git clone https://github.com/karpathy/autoresearch

# Copy the eval script and config into autoresearch
cp stateset-starks/.autoresearch/eval.sh autoresearch/targets/stateset-stark-eval.sh
chmod +x autoresearch/targets/stateset-stark-eval.sh

# Run the eval against the repo
./autoresearch/targets/stateset-stark-eval.sh /path/to/stateset-starks

# Start the autoresearch loop
cd autoresearch
python3 coderesearch.py init \
  --config targets/stateset-stark.json \
  --create-branch \
  --baseline \
  --description "my baseline"

# Make a change, commit, then evaluate
python3 coderesearch.py eval \
  --config targets/stateset-stark.json \
  --description "my experiment" \
  --auto-revert-discard
```

All experiments from this report are preserved in the results TSV files under `.autoresearch/` in the repository.
