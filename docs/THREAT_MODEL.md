# VES-STARK Threat Model

This document defines the threat model for the VES (Verifiable Encrypted State) STARK proof system used for compliance verification.

## System Overview

VES-STARK enables zero-knowledge proofs of policy compliance for encrypted transaction data. The system proves statements like "the encrypted amount is less than threshold X" without revealing the actual amount.

### Components

1. **Prover**: Generates STARK proofs from private witness data
2. **Verifier**: Validates proofs against public inputs
3. **Public Inputs**: Policy parameters, event metadata, hashes
4. **Private Witness**: The actual amount being proven compliant

## Adversary Model

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| Malicious Prover | Full control over witness and trace generation | Forge proof for non-compliant amount |
| External Attacker | Can observe and modify proofs in transit | Tamper with proofs or public inputs |
| Malicious Verifier | Can choose verification parameters | Accept invalid proofs |

### Adversary Goals

1. **Proof Forgery**: Create a valid proof for an amount that violates the policy (amount >= threshold)

2. **Witness Manipulation**: Change the committed amount after proof generation while maintaining proof validity

3. **Policy Bypass**: Generate a proof against one policy but have it verify against a different policy

4. **Public Input Tampering**: Modify public inputs (threshold, event metadata) to make an invalid proof verify

5. **Replay Attacks**: Reuse a proof for a different transaction/event

## Security Properties

### Required Properties (Must Hold)

| Property | Definition | Enforcement |
|----------|------------|-------------|
| **Soundness** | If verifier accepts, prover knows valid witness (amount < threshold) | AIR constraints, FRI protocol |
| **Knowledge Binding** | Witness commitment cryptographically binds the private amount | Rescue-Prime hash commitment |
| **Policy Binding** | Proof is bound to specific policy ID and parameters | Policy hash in public inputs |
| **Range Validity** | All limbs are provably valid u32 values (< 2^32) | Binary decomposition constraints |
| **Comparison Integrity** | Comparison result is correctly computed from limbs | Lexicographic comparison constraints |

### Desired Properties

| Property | Definition | Status |
|----------|------------|--------|
| **Zero Knowledge** | Proof reveals nothing about amount beyond compliance | Provided by STARK protocol |
| **Non-Malleability** | Cannot modify proof without detection | Merkle commitments in FRI |
| **Replay Protection** | Proof bound to specific event | Event ID in public inputs |

## Attack Vectors and Mitigations

### 1. Non-Binary Bit Manipulation

**Attack**: Malicious prover sets "bit" columns to non-binary values (e.g., 0.5) that sum to correct limb but represent different actual values.

**Mitigation**: Binary constraints `b * (1 - b) = 0` for every bit column in AIR.

### 2. Fake Limb Values

**Attack**: Prover uses field elements >= 2^32 as "limb" values to bypass comparison.

**Mitigation**: Binary decomposition of all 8 limbs (256 bits total) ensures each limb is a valid u32.

### 3. Comparison Gadget Manipulation

**Attack**: Prover provides incorrect comparison intermediate values to claim amount < threshold when amount >= threshold.

**Mitigation**: Full comparison gadget constraints:
- `is_less[i]` and `is_equal[i]` propagation constraints
- `diff[i]` range proofs for each limb comparison
- Final boundary assertion that `is_less[0] = 1`

### 4. Hash Commitment Forgery

**Attack**: Prover provides arbitrary commitment value unrelated to actual amount.

**Mitigation**: Full Rescue-Prime permutation constraints verify:
- Initial state is amount_limbs + domain separator
- All 7 rounds are correctly computed
- Final state matches commitment

### 5. Policy Mismatch

**Attack**: Generate proof with threshold=1000000, verify with threshold=1000.

**Mitigation**:
- Policy hash binds policy_id + parameters
- Verifier validates policy hash
- Threshold embedded in boundary assertions

### 6. Public Input Substitution

**Attack**: Use public inputs from different event with same threshold.

**Mitigation**:
- Event ID, tenant ID, store ID in public inputs
- Payload hashes bind to specific encrypted data
- All public inputs contribute to proof verification

## Trust Assumptions

### Trusted

1. **Winterfell Library**: Correct implementation of STARK protocol
2. **Rescue-Prime Parameters**: Cryptographically secure (standard parameters)
3. **Goldilocks Field**: p = 2^64 - 2^32 + 1 provides ~64-bit security
4. **Verifier Implementation**: Correctly validates all constraints

### Untrusted

1. **Prover**: May attempt to forge proofs
2. **Witness Data**: Must be verified through constraints
3. **Network**: Proofs may be tampered in transit (integrity via proof hash)
4. **Public Input Sources**: Must be validated by verifier

## Security Parameters

| Parameter | Value | Security Implication |
|-----------|-------|---------------------|
| Field size | 64 bits (Goldilocks) | ~64-bit algebraic security |
| FRI security | 128 bits | Computational soundness |
| Rescue capacity | 256 bits | ~128-bit collision resistance |
| Trace blowup | 8x | Trade-off: size vs security |
| Query count | 80 | Statistical soundness |

## Proof Version Compatibility

| Version | AIR Structure | Status |
|---------|---------------|--------|
| V1 | Legacy (167 constraints, partial range proofs) | Deprecated |
| V2 | Full security (990+ constraints, full permutation) | Current |

**Migration**: V1 proofs are rejected. All clients must regenerate proofs.

## Incident Response

### If Soundness Vulnerability Discovered

1. Immediately notify all verifier deployments
2. Reject all proofs until patch deployed
3. Require proof regeneration from all provers
4. Conduct security audit of similar constraint patterns

### If Side-Channel Leak Discovered

1. Assess information leakage severity
2. If amount revealed: treat as privacy breach
3. Update prover to constant-time operations
4. Regenerate affected proofs if necessary

## References

- [STARK Protocol](https://eprint.iacr.org/2018/046)
- [Rescue-Prime](https://eprint.iacr.org/2020/1143)
- [Winterfell Library](https://github.com/facebook/winterfell)
- [Goldilocks Field](https://cr.yp.to/papers.html#goldilocks)
