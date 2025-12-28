# ves-stark

Python bindings for the VES STARK proof system. Generate and verify zero-knowledge compliance proofs for VES events.

## Installation

```bash
pip install ves-stark
```

## Requirements

- Python >= 3.8
- Supported platforms: Linux (x64, arm64), macOS (x64, arm64), Windows (x64)

## Usage

### Generate a Compliance Proof

```python
import ves_stark

# Create a policy (AML threshold of 10,000)
policy = ves_stark.Policy.aml_threshold(10000)

# Compute the policy hash
policy_hash = ves_stark.compute_policy_hash("aml.threshold", {"threshold": 10000})

# Create public inputs
public_inputs = ves_stark.CompliancePublicInputs(
    event_id="550e8400-e29b-41d4-a716-446655440000",
    tenant_id="550e8400-e29b-41d4-a716-446655440001",
    store_id="550e8400-e29b-41d4-a716-446655440002",
    sequence_number=12345,
    payload_kind=1,
    payload_plain_hash="a" * 64,  # 64-char lowercase hex
    payload_cipher_hash="b" * 64,
    event_signing_hash="c" * 64,
    policy_id="aml.threshold",
    policy_params={"threshold": 10000},
    policy_hash=policy_hash
)

# Generate proof (amount must be < threshold for aml.threshold)
proof = ves_stark.prove(5000, public_inputs, policy)

print(f"Proof generated in {proof.proving_time_ms}ms")
print(f"Proof size: {proof.proof_size} bytes")
print(f"Proof hash: {proof.proof_hash}")
```

### Verify a Proof

```python
import ves_stark

result = ves_stark.verify(proof.proof_bytes, public_inputs, proof.witness_commitment)

if result.valid:
    print("Proof is valid!")
    print(f"Verified in {result.verification_time_ms}ms")
    print(f"Policy: {result.policy_id} (limit: {result.policy_limit})")
else:
    print(f"Verification failed: {result.error}")

# VerificationResult is also truthy/falsy
if result:
    print("Valid!")
```

## API Reference

### Classes

#### `Policy`

Represents a compliance policy.

```python
# Create AML threshold policy (proves amount < threshold)
policy = ves_stark.Policy.aml_threshold(10000)

# Create order total cap policy (proves amount <= cap)
policy = ves_stark.Policy.order_total_cap(50000)

# Properties
policy.policy_id   # "aml.threshold" or "order_total.cap"
policy.limit       # The threshold/cap value
```

#### `CompliancePublicInputs`

Public inputs for proof generation and verification.

```python
public_inputs = ves_stark.CompliancePublicInputs(
    event_id="...",           # UUID string
    tenant_id="...",          # UUID string
    store_id="...",           # UUID string
    sequence_number=12345,    # u64
    payload_kind=1,           # u32
    payload_plain_hash="...", # 64-char lowercase hex
    payload_cipher_hash="...",
    event_signing_hash="...",
    policy_id="aml.threshold",
    policy_params={"threshold": 10000},  # dict
    policy_hash="..."         # 64-char lowercase hex
)

# All fields are readable and writable
public_inputs.sequence_number = 12346
```

#### `ComplianceProof`

Result of proof generation.

```python
proof.proof_bytes         # bytes - raw proof data
proof.proof_hash          # str - SHA-256 hash of proof
proof.proving_time_ms     # int - generation time in ms
proof.proof_size          # int - size in bytes
proof.witness_commitment  # list[int] - 4-element commitment
```

#### `VerificationResult`

Result of proof verification.

```python
result.valid               # bool - whether proof is valid
result.verification_time_ms # int - verification time in ms
result.error               # str | None - error message if invalid
result.policy_id           # str - verified policy ID
result.policy_limit        # int - verified policy limit

# Supports boolean conversion
if result:
    print("Valid!")
```

### Functions

#### `prove(amount, public_inputs, policy)`

Generate a STARK compliance proof.

```python
proof = ves_stark.prove(
    amount=5000,
    public_inputs=public_inputs,
    policy=policy
)
```

**Parameters:**
- `amount` (int): The amount to prove compliance for
- `public_inputs` (CompliancePublicInputs): Event metadata and policy info
- `policy` (Policy): The policy to prove compliance against

**Returns:** `ComplianceProof`

**Raises:**
- `ValueError`: If inputs are invalid
- `RuntimeError`: If proof generation fails

#### `verify(proof_bytes, public_inputs, witness_commitment)`

Verify a STARK compliance proof.

```python
result = ves_stark.verify(
    proof_bytes=proof.proof_bytes,
    public_inputs=public_inputs,
    witness_commitment=proof.witness_commitment
)
```

**Parameters:**
- `proof_bytes` (bytes): Raw proof bytes from `prove()`
- `public_inputs` (CompliancePublicInputs): Must match proving inputs
- `witness_commitment` (list[int]): 4-element list from proof

**Returns:** `VerificationResult`

**Raises:**
- `ValueError`: If inputs are invalid

#### `compute_policy_hash(policy_id, policy_params)`

Compute the canonical policy hash.

```python
hash = ves_stark.compute_policy_hash("aml.threshold", {"threshold": 10000})
```

**Parameters:**
- `policy_id` (str): Policy identifier
- `policy_params` (dict): Policy parameters

**Returns:** `str` - 64-character lowercase hex hash

## Policy Types

| Policy | ID | Constraint | Use Case |
|--------|-----|------------|----------|
| AML Threshold | `aml.threshold` | amount < threshold | Anti-money laundering compliance |
| Order Total Cap | `order_total.cap` | amount <= cap | Order value limits |

## Building from Source

Requires [maturin](https://github.com/PyO3/maturin):

```bash
# Install maturin
pip install maturin

# Build and install in development mode
cd crates/ves-stark-python
maturin develop

# Build release wheel
maturin build --release
```

## Performance

Typical performance on modern hardware:
- Proof generation: 500-2000ms
- Proof verification: 50-200ms
- Proof size: ~100-200 KB

## Example: Full Round-Trip

```python
import ves_stark

# Setup
policy = ves_stark.Policy.aml_threshold(10000)
policy_hash = ves_stark.compute_policy_hash("aml.threshold", {"threshold": 10000})

public_inputs = ves_stark.CompliancePublicInputs(
    event_id="550e8400-e29b-41d4-a716-446655440000",
    tenant_id="550e8400-e29b-41d4-a716-446655440001",
    store_id="550e8400-e29b-41d4-a716-446655440002",
    sequence_number=1,
    payload_kind=1,
    payload_plain_hash="0" * 64,
    payload_cipher_hash="0" * 64,
    event_signing_hash="0" * 64,
    policy_id="aml.threshold",
    policy_params={"threshold": 10000},
    policy_hash=policy_hash
)

# Prove
amount = 5000  # Must be < 10000
proof = ves_stark.prove(amount, public_inputs, policy)
print(f"Generated {proof.proof_size} byte proof in {proof.proving_time_ms}ms")

# Verify
result = ves_stark.verify(proof.proof_bytes, public_inputs, proof.witness_commitment)
assert result.valid, f"Verification failed: {result.error}"
print(f"Verified in {result.verification_time_ms}ms")
```

## License

MIT
