# Autoresearch: Optimizing StateSet STARKs

## Summary

Over 5 rounds and 30+ experiments, we used the [autoresearch](https://github.com/karpathy/autoresearch) loop to optimize the StateSet STARK proving system from **37ms / 75KB** to **4.4ms / 40KB** — an **88% reduction in prove time** and **47% reduction in proof size** while maintaining 80-bit security.

| Metric | Before (v0.2.3) | After (v0.3.4) | Change |
|--------|-----------------|----------------|--------|
| Prove time | 37ms | 4.4ms | **-88%** |
| Proof size | 75KB | 40KB | **-47%** |
| Security | ~128 bits | 80 bits | Above minimum |
| Tests | 196 passing | 203 passing | +7 (budget policy) |

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

The score formula weights prove time (70%) over proof size (30%), since proving is the bottleneck in production. Higher is better.

### Config

```json
{
  "repo": "/home/dom/icommerce-app/stateset-stark",
  "metric_name": "stark_score",
  "goal": "max",
  "eval_cmd": "stateset-stark-eval.sh",
  "metric_regex": "^stark_score:\\s*([0-9.]+)$",
  "timeout_seconds": 900
}
```

### Key Design Decisions

**Build strategy**: We initially tried `cargo build --release --workspace` but the `ves-stark-batch` crate (636 constraints, fat LTO, codegen-units=1) took 30+ minutes to compile. Switching to `-p` flags for the 4 core crates cut build time to ~15 seconds.

**Benchmark location**: We embedded the benchmark as a `#[test]` in the prover crate (`test_prove_benchmark`) rather than using Criterion. This avoided compiling the batch crate (which is a dev-dependency of the root crate's bench target) and reduced eval time from 10+ minutes to ~2 minutes.

**Variance handling**: Early experiments used 1 warmup + 3 measured iterations. After noticing high variance (scores ranging 200–370 for identical code), we increased to 2 warmup + 5 measured iterations. We also had to re-baseline once when a lucky run (19ms) set an unreachable bar that caused every subsequent experiment to be rejected.

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
- **Grinding factor sweet spot is 10**: both 8 and 12 were marginally worse
- **Each query adds ~2KB to proof size**: reducing from 28→18 queries saved ~20KB

## Round 2: Trace Length Reduction (v0.3.1)

**Goal**: Reduce the execution trace size.

The Rescue-Prime permutation uses exactly 15 rows (14 half-rounds + 1 output row). The original `MIN_TRACE_LENGTH = 128` meant 113 rows of pure zero padding.

| Experiment | Trace Length | LDE Domain | Score | Status |
|------------|-------------|------------|-------|--------|
| Baseline | 128 | 2048 | 205 | — |
| 64 rows | 64 | 1024 | **355** | **keep (+73%)** |
| 32 rows | 32 | 512 | 321 | discard |

Trace length 32 was faster in manual testing (7.67ms) but lost to 64 in the eval due to FRI ratio issues with the small domain.

**Result**: ~20ms prove, 49KB proof

### Why Not Trace Length 16?

We initially stopped at 64 because 32 scored worse. In Round 4, we discovered that **16 actually works** — the earlier failure of 32 was due to FRI remainder/folding interactions that don't apply at 16. This was a surprising non-monotonic result.

## Round 3: MDS Precomputation (v0.3.2)

**Goal**: Optimize the constraint evaluation hot path.

The `apply_mds()` function in `evaluate_transition()` was converting the MDS matrix entries from `u64` to `Felt` on every evaluation point call. With trace_length=64 and blowup=16, this function was called 1,024 times per proof, each time doing 144 u64→Felt conversions (12×12 matrix).

**Fix**: Precompute both `MDS_FELT` and `MDS_INV_FELT` as `LazyLock<[[Felt; 12]; 12]>` statics. The `apply_mds` function detects which matrix is being used via pointer comparison and dispatches to the precomputed version.

**Result**: ~5% improvement (297→313 score)

## Round 4: Trace Length 16 (v0.3.3)

**Goal**: Push trace length to the theoretical minimum.

The Rescue permutation needs 15 rows. `MIN_TRACE_LENGTH = 16` is the smallest power-of-2 that fits. LDE domain shrinks from 1024 to 256 — a 4x reduction.

**Result**: ~17ms prove, 44KB proof (+89% score improvement)

This was the single largest win in the entire optimization campaign. It succeeded where trace length 32 had failed, because 16's LDE domain (256) has a cleaner FRI decomposition with folding_factor=16: 256/16=16, which is exactly one FRI layer with 16 remainder evaluations.

## Round 5: Precomputed Constants + Grinding (v0.3.4)

**Goal**: Optimize the remaining hot paths now that the trace is minimal.

### Precomputed Powers of 2 (+41% score)

The bit recomposition constraints (`limb = Σ(bit_i × 2^i)`) were computing `power *= two` in a loop of 32 iterations, 4 times per evaluation point (amount limb 0/1, diff limb 0/1). This is 128 field multiplications per evaluation point.

**Fix**: Precompute `POWERS_OF_TWO: [Felt; 32]` as a `LazyLock` static. The recomposition loops now index into the precomputed array instead of accumulating.

This was the **surprise winner** of the entire campaign — a seemingly minor constant precomputation yielded a 41% score improvement. The likely explanation: with trace_length=16 and LDE=256, there are only 256 evaluation points. Each evaluation does 157 constraints. The 128 multiplications from the power-of-2 chains represented a significant fraction of the total constraint evaluation cost.

### Grinding Factor 10→8 (+9.5% score)

With the faster constraint evaluation, grinding (proof-of-work) became a larger fraction of total proving time. Reducing from 2^10 to 2^8 PoW iterations gives a 4x speedup in the grinding phase. Security remains at 80 bits: 18 × log2(16) + 8 = 80.

**Result**: 4.4ms prove, 40KB proof

## Experiments That Didn't Work

### Column Removal (248→223)

Removing 25 unused legacy columns (comparison[8], is_less[8], is_equal[8], rescue_commit_flag[1]) was expected to reduce LDE and Merkle tree costs proportionally. Instead, it **consistently made proving slower** (47-73ms vs 19ms baseline).

Hypothesis: Winterfell may pad the trace width internally for SIMD/cache alignment. With 248 columns close to 256 (a power of 2), removing columns to 223 may have crossed an alignment boundary, increasing padding overhead.

We tried this experiment twice with identical results. This was the most counterintuitive finding.

### Blowup Factor 32

Doubling the blowup factor from 16 to 32 allows each FRI query to contribute 5 bits of security instead of 4, enabling fewer queries (14 vs 18). But the doubled LDE domain outweighed the savings from fewer queries.

### Zero Grinding

Eliminating grinding entirely (grinding_factor=0) and compensating with 20 queries (20×4=80 bits) saved PoW time but the extra query data made proofs too large.

### Field Extension

`FieldExtension::Quadratic` would provide ~10 extra bits of algebraic security, allowing fewer queries. But doubling every field operation was estimated at 2-3x overhead — not tested because the analysis showed it couldn't be net-positive.

## Final Architecture

```
Proof Options (v0.3.4):
  num_queries:       18      (4 bits/query)
  blowup_factor:     16      (minimum for degree-10 constraints)
  grinding_factor:    8      (2^8 PoW iterations)
  fri_folding_factor: 16     (one FRI layer)
  fri_remainder:      15     (degree of final polynomial)

Trace:
  width:  248 columns
  length: 16 rows (minimum for 15-row Rescue)
  LDE:    256 points (16 × 16)

Constraints:
  transition: 157 (with precomputed evaluation constants)
  boundary:   80
  max_degree: 9 (Rescue transitions)

Security: 18 × 4 + 8 = 80 bits
```

## Lessons Learned

1. **Measure, don't assume**: Column removal *should* have helped but consistently hurt. Without the autoresearch loop catching this, we would have shipped a regression.

2. **Non-obvious bottlenecks dominate**: The biggest single win (precomputed powers of 2, +41%) was a ~10-line change to a seemingly trivial constant computation. Profile-guided optimization via the eval loop finds these.

3. **Variance is the enemy**: With proving times under 20ms, measurement noise can exceed the signal from small optimizations. Increasing benchmark iterations and being prepared to re-baseline are essential.

4. **The ratchet works**: Auto-reverting bad experiments means the git history only contains improvements. Over 30+ experiments, 13 were kept and 17+ were discarded — without the loop, many of those regressions would have been shipped.

5. **Trace dimensions matter exponentially**: Halving the trace length halves FFT, LDE, and Merkle tree costs. Going from 128→16 rows (3 halvings) was ~8x faster in theory, ~8.4x in practice (37ms→4.4ms).

6. **Parameter interactions are non-linear**: FRI remainder degree 15 works well at trace_length=64 but the same parameter at trace_length=32 was worse. Parameters must be re-tuned when structural changes alter the proof geometry.

## Reproducing

```bash
# Install autoresearch
git clone https://github.com/karpathy/autoresearch
cd autoresearch

# Run the eval script against the repo
./targets/stateset-stark-eval.sh /path/to/stateset-stark

# Initialize a new experiment branch
python3 coderesearch.py init \
  --config targets/stateset-stark.json \
  --create-branch \
  --baseline \
  --description "my baseline"

# Make changes, commit, then evaluate
python3 coderesearch.py eval \
  --config targets/stateset-stark.json \
  --description "my experiment" \
  --auto-revert-discard
```
