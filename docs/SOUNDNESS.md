# VES-STARK Soundness Analysis

This document provides a formal soundness analysis of the VES-STARK constraint system.

## Soundness Definition

A proof system is **sound** if:

> For any computationally bounded adversary A, the probability that A produces a proof that verifies but the claimed statement is false is negligible.

In our context: If the verifier accepts a proof, then with overwhelming probability:
- The prover knows an amount value
- That amount satisfies `amount < threshold` (or `amount <= cap`)

## Constraint System Overview (V2)

### Constraint Categories

| Category | Count | Degree | Purpose |
|----------|-------|--------|---------|
| Round counter | 1 | 1 | Trace length enforcement |
| Amount consistency | 8 | 1 | Amount constant across rows |
| Threshold consistency | 8 | 1 | Threshold constant across rows |
| Comparison consistency | 8 | 1 | Comparison values constant |
| Binary (limbs 0-7) | 256 | 2 | `b * (1-b) = 0` for all bits |
| Bit consistency | 256 | 1 | Bits constant across rows |
| Recomposition | 8 | 1 | `limb = sum(bit[i] * 2^i)` |
| Comparison gadget | 96 | 2 | Lexicographic comparison |
| Rescue S-box | 168 | 7 | Forward/inverse S-box |
| Rescue MDS | 168 | 1 | Linear mixing |
| **Total** | **~990** | max 7 | |

### Boundary Assertions

| Assertion | Row | Column | Value | Purpose |
|-----------|-----|--------|-------|---------|
| is_first | 0 | FLAG_IS_FIRST | 1 | Mark first row |
| is_last | last | FLAG_IS_LAST | 1 | Mark last row |
| threshold_low | 0 | THRESHOLD_START | threshold & 0xFFFFFFFF | Bind public threshold |
| threshold_high | 0 | THRESHOLD_START+1 | threshold >> 32 | Bind public threshold |
| comparison_result | last | COMPARISON_END-1 | 1 | Prove amount < threshold |
| upper_limbs | 0 | AMOUNT_START+2..8 | 0 | Amount fits in u64 |
| rescue_init | 0 | RESCUE_STATE | amount_limbs | Initialize hash |
| rescue_output | 14 | RESCUE_STATE | commitment | Hash output matches |

## Soundness Arguments

### 1. Range Validity

**Claim**: Each amount limb is a valid u32 (value < 2^32).

**Proof**:
1. For each limb `L[i]`, there exist 32 trace columns `b[i][0..31]`
2. Binary constraints enforce: `b[i][j] * (1 - b[i][j]) = 0` for all j
3. This means each `b[i][j]` is exactly 0 or 1 in the field
4. Recomposition constraint: `L[i] = sum(b[i][j] * 2^j for j in 0..32)`
5. If all bits are 0 or 1, the sum is at most `2^32 - 1`
6. Therefore `L[i] < 2^32`

**Security**: Breaking requires finding non-binary field element satisfying `x * (1-x) = 0`, which has only solutions {0, 1} in any field.

### 2. Comparison Correctness

**Claim**: The comparison gadget correctly computes `amount < threshold`.

**Proof** (Lexicographic comparison from high to low limb):

For each limb pair `(A[i], T[i])` from i=7 down to i=0:

1. **is_less propagation**:
   ```
   is_less[i] = is_less[i+1] OR (is_equal[i+1] AND A[i] < T[i])
   ```
   Constrained by: `is_less[i] = is_less[i+1] + is_equal[i+1] * limb_less[i] * (1 - is_less[i+1])`

2. **is_equal propagation**:
   ```
   is_equal[i] = is_equal[i+1] AND (A[i] == T[i])
   ```
   Constrained by: `is_equal[i] = is_equal[i+1] * (1 - limb_less[i]) * (1 - limb_greater[i])`

3. **limb_less witness**: `diff[i] = T[i] - A[i] - 1` when `A[i] < T[i]`
   - Range proof on `diff[i]` ensures it's a valid u32
   - If `diff[i]` is valid u32 and `diff[i] = T[i] - A[i] - 1`, then `A[i] < T[i]`

4. **Boundary assertion**: `is_less[0] = 1` at last row

**Conclusion**: The comparison result is sound because:
- Base case: `is_less[8] = 0, is_equal[8] = 1` (start of comparison)
- Inductive: Each step correctly propagates less/equal status
- Final: `is_less[0] = 1` required for valid proof

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
| Forge comparison | Find valid diff for wrong comparison | 2^64 field operations |
| Forge commitment | Rescue preimage attack | 2^128 operations |
| Policy substitution | SHA256 collision | 2^128 operations |
| Proof forgery | Break FRI soundness | 2^80 operations |

## Formal Security Statement

**Theorem** (Soundness): The VES-STARK V2 proof system is computationally sound with soundness error at most `2^(-80)` against adversaries running in time `T < 2^80`.

**Proof sketch**:
1. AIR constraints form a correct encoding of the compliance statement
2. Binary decomposition ensures valid range (unconditional soundness)
3. Comparison gadget correctly implements lexicographic comparison
4. Rescue permutation constraints bind commitment (128-bit security)
5. STARK protocol provides 80-bit computational soundness
6. Combined: proof accepted implies valid witness with overwhelming probability

## Constraint Verification Checklist

For each constraint category, verify:

- [ ] **Binary constraints**: `b * (1-b) = 0` for all 256 bits
- [ ] **Recomposition**: `limb = sum(bit * 2^i)` for all 8 limbs
- [ ] **Comparison gadget**: Correct propagation of is_less/is_equal
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
