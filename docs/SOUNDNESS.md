# VES-STARK Soundness Analysis

This document provides a formal soundness analysis of the VES-STARK constraint system.

## Soundness Definition

A proof system is **sound** if:

> For any computationally bounded adversary A, the probability that A produces a proof that verifies but the claimed statement is false is negligible.

In our context: If the verifier accepts a proof, then with overwhelming probability:
- The prover knows an amount value
- That amount satisfies `amount < threshold` (or `amount <= cap`)

## Constraint System Overview (Current)

### Constraint Categories

| Category | Count | Degree | Purpose |
|----------|-------|--------|---------|
| Round counter | 1 | 1 | Trace length enforcement |
| Amount consistency | 8 | 1 | Amount constant across rows |
| Threshold consistency | 8 | 1 | Threshold constant across rows |
| Public input binding | 47 | 1 | Public inputs constant across rows |
| Amount bit binary (limbs 0-1) | 64 | 2 | `b * (1-b) = 0` for all bits |
| Amount bit consistency (limbs 0-1) | 64 | 1 | Bits constant across rows |
| Amount recomposition (limbs 0-1) | 2 | 1 | `limb = sum(bit[i] * 2^i)` |
| Diff bit binary (limbs 0-1) | 64 | 2 | `b * (1-b) = 0` for all bits |
| Diff bit consistency (limbs 0-1) | 64 | 1 | Bits constant across rows |
| Diff recomposition (limbs 0-1) | 2 | 1 | `diff = sum(bit[i] * 2^i)` |
| Borrow consistency (limbs 0-1) | 2 | 1 | Borrows constant across rows |
| Borrow binary (limbs 0-1) | 2 | 2 | `b * (1-b) = 0` for borrows |
| Subtraction constraints (limbs 0-1) | 2 | 1 | Enforce `threshold - amount = diff + borrow` |
| Rescue permutation transitions | 12 | 9 | Rescue-Prime rounds |
| Rescue init binding | 8 | 2 | Bind amount limbs to Rescue state |
| **Total** | **350** | max 9 | |

### Boundary Assertions

| Assertion | Row | Column | Value | Purpose |
|-----------|-----|--------|-------|---------|
| is_first | 0 | FLAG_IS_FIRST | 1 | Mark first row |
| is_last | last | FLAG_IS_LAST | 1 | Mark last row |
| limit_low | 0 | THRESHOLD_START | limit & 0xFFFFFFFF | Bind effective policy limit |
| limit_high | 0 | THRESHOLD_START+1 | limit >> 32 | Bind effective policy limit |
| upper_amount_limbs | 0 | AMOUNT_START+2..8 | 0 | Amount fits in u64 |
| upper_limit_limbs | 0 | THRESHOLD_START+2..8 | 0 | Limit fits in u64 |
| upper_diff_limbs | 0 | DIFF_START+2..8 | 0 | Diff fits in u64 |
| final_borrow | last | BORROW_START+1 | 0 | Enforce amount <= limit |
| rescue_domain | 0 | RESCUE_STATE+8..12 | 8, 0...0 | Domain separator + padding |
| rescue_init | 0 | RESCUE_STATE+0..7 | amount_limbs | Initialize hash |
| rescue_output | 14 | RESCUE_STATE+0..3 | commitment | Hash output matches |
| public_inputs | 0 | PUBLIC_INPUTS_* | value | Bind public inputs to trace |

## Soundness Arguments

### 1. Range Validity

**Claim**: Amount limbs 0-1 and diff limbs 0-1 are valid u32 (value < 2^32); limbs 2-7 are boundary-asserted to 0.

**Proof**:
1. For limbs 0-1, there exist 32 trace columns `b[i][0..31]`
2. Binary constraints enforce: `b[i][j] * (1 - b[i][j]) = 0` for all j
3. This means each `b[i][j]` is exactly 0 or 1 in the field
4. Recomposition constraint: `L[i] = sum(b[i][j] * 2^j for j in 0..32)`
5. If all bits are 0 or 1, the sum is at most `2^32 - 1`
6. Therefore `L[i] < 2^32` for i in {0,1}
7. Limbs 2-7 are boundary-asserted to 0, which is a valid u32

**Security**: Breaking requires finding non-binary field element satisfying `x * (1-x) = 0`, which has only solutions {0, 1} in any field.

### 2. Subtraction Correctness

**Claim**: The subtraction gadget correctly enforces `amount <= limit` (where `limit` is the policy's effective limit).

**Proof** (Two-limb subtraction with borrows):

For limbs 0-1 (u64 amounts), the prover supplies `diff[0..1]` and `borrow[0..1]` such that:

1. **Limb 0**:
   ```
   amount0 + diff0 - limit0 - borrow0 * 2^32 = 0
   ```
2. **Limb 1**:
   ```
   amount1 + diff1 + borrow0 - limit1 - borrow1 * 2^32 = 0
   ```
3. **Range and binary checks**:
   - `diff0` and `diff1` are range-checked via bit decomposition
   - `borrow0` and `borrow1` are constrained to {0,1}
4. **Final borrow must be zero**:
   - Boundary assertion enforces `borrow1 = 0` at the last row

If `borrow1 = 0`, the subtraction does not underflow, which implies `amount <= limit`.
For strict policies (AML threshold), the AIR uses `limit = threshold - 1`, so `amount <= limit`
is equivalent to `amount < threshold`.

### 3. Witness Commitment Binding

**Claim**: The witness commitment cryptographically binds the amount to the proof.

**Proof**:

1. **Initialization**: Row 0 boundary assertion sets:
   ```
   rescue_state[0..8] = amount_limbs[0..8]  (rate portion)
   rescue_state[8] = 8  (domain separator: input length)
   rescue_state[9..12] = 0  (capacity padding)
   ```

2. **Permutation**: Rows 0-13 constrain 7 rounds of Rescue-Prime:
   - Forward half-round: `S-box(x) = x^7`, then MDS, then add constants
   - Backward half-round: `MDS^{-1}`, then `S-box^{-1}`, then add constants
   - Constraints verify each transformation

3. **Output**: Row 14 boundary assertion sets:
   ```
   rescue_state[0..4] = witness_commitment[0..4]
   ```

4. **Soundness**: For adversary to produce valid proof with wrong commitment:
   - Must find `amount_limbs'` such that `Rescue(amount_limbs') = commitment` where `commitment = Rescue(amount_limbs)` for true amount
   - This is a preimage attack on Rescue-Prime
   - Rescue capacity (256 bits) provides ~128-bit preimage resistance

**Conclusion**: Commitment binding has ~128-bit security.

### 4. Policy Binding

**Claim**: Proof is bound to the specific policy parameters.

**Proof**:

1. **Policy hash**: Public inputs include `policy_hash = SHA256(domain || JCS(policy_id, params))`

2. **Threshold in boundary assertions**: The actual threshold value is asserted:
   ```
   T[THRESHOLD_START][0] = threshold_low
   T[THRESHOLD_START+1][0] = threshold_high
   ```

3. **Verification**: Verifier checks:
   - `policy_hash` matches recomputed hash from policy_id and params
   - Threshold in policy matches threshold in assertions

4. **Binding**: Changing policy parameters would:
   - Change `policy_hash` (hash collision required)
   - Or change boundary assertion values (would fail verification)

**Conclusion**: Policy binding has ~128-bit security (SHA256 collision resistance).

## Security Levels

### Computational Soundness

The STARK protocol provides computational soundness:

| Parameter | Value | Security |
|-----------|-------|----------|
| Field size | 2^64 | ~64-bit algebraic |
| FRI proximity | 1/8 | |
| Query count | 80 | 2^-80 soundness error |
| Combined | | ~80-bit computational |

### Statistical Soundness

For a verifier accepting an invalid proof:

```
Pr[accept invalid] <= 2^(-80) + negl(lambda)
```

Where `lambda` is the security parameter and `negl` is negligible.

## Attack Complexity Summary

| Attack | Complexity | Mitigation |
|--------|------------|------------|
| Forge range proof | Find non-binary solution to `x(1-x)=0` | Impossible in field |
| Forge subtraction | Find valid diff/borrow for wrong amount <= limit | 2^64 field operations |
| Forge commitment | Rescue preimage attack | 2^128 operations |
| Policy substitution | SHA256 collision | 2^128 operations |
| Proof forgery | Break FRI soundness | 2^80 operations |

## Formal Security Statement

**Theorem** (Soundness): The VES-STARK proof system is computationally sound with soundness error at most `2^(-80)` against adversaries running in time `T < 2^80`.

**Proof sketch**:
1. AIR constraints form a correct encoding of the compliance statement
2. Binary decomposition ensures valid range (unconditional soundness)
3. Subtraction gadget correctly enforces `amount <= limit`
4. Rescue permutation constraints bind commitment (128-bit security)
5. STARK protocol provides 80-bit computational soundness
6. Combined: proof accepted implies valid witness with overwhelming probability

## Constraint Verification Checklist

For each constraint category, verify:

- [ ] **Binary constraints**: `b * (1-b) = 0` for amount bits, diff bits, and borrows
- [ ] **Recomposition**: `limb = sum(bit * 2^i)` for amount/diff limbs 0-1
- [ ] **Subtraction gadget**: Enforce limb-wise subtraction with borrows and `borrow1 = 0`
- [ ] **Rescue initialization**: State correctly initialized from amount
- [ ] **Rescue rounds**: All 14 half-rounds constrained
- [ ] **Rescue output**: Output matches commitment
- [ ] **Boundary assertions**: All public inputs bound
- [ ] **Consistency**: All values constant where required

## References

1. Ben-Sasson et al., "Scalable, transparent, and post-quantum secure computational integrity" (STARK paper)
2. StarkWare, "ethSTARK Documentation"
3. Grassi et al., "Rescue-Prime: A Standard Specification"
4. Winterfell library security documentation
