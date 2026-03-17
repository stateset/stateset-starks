# @stateset/ves-stark

Node.js bindings for the VES STARK proof system. Generate and verify zero-knowledge compliance proofs for VES events.

## Installation

```bash
npm install @stateset/ves-stark
```

## Requirements

- Node.js >= 14
- Supported platforms: Linux (x64, arm64), macOS (x64, arm64), Windows (x64)

## Usage

### Generate a Compliance Proof

```javascript
const {
  prove,
  computePolicyHash,
  createAmlThresholdParams,
  createAgentAuthorizationParams,
} = require('@stateset/ves-stark');

// Create policy parameters
const policyParams = createAmlThresholdParams(10000n);

// Compute the policy hash
const policyHash = computePolicyHash('aml.threshold', policyParams);

// Create public inputs
const publicInputs = {
  eventId: '550e8400-e29b-41d4-a716-446655440000',
  tenantId: '550e8400-e29b-41d4-a716-446655440001',
  storeId: '550e8400-e29b-41d4-a716-446655440002',
  sequenceNumber: 12345n,
  payloadKind: 1,
  payloadPlainHash: 'a'.repeat(64),  // 64-char lowercase hex
  payloadCipherHash: 'b'.repeat(64),
  eventSigningHash: 'c'.repeat(64),
  policyId: 'aml.threshold',
  policyParams: policyParams,
  policyHash: policyHash
};

// Generate proof (amount must be < threshold for aml.threshold)
const proof = prove(5000n, publicInputs, 'aml.threshold', 10000n);

console.log(`Proof generated in ${proof.provingTimeMs}ms`);
console.log(`Proof size: ${proof.proofSize} bytes`);
console.log(`Proof hash: ${proof.proofHash}`);
console.log(`Witness commitment (hex): ${proof.witnessCommitmentHex}`);
```

### Verify a Proof

```javascript
const {
  createPayloadAmountBinding,
  verifyHex,
  verifyWithAmountBinding,
} = require('@stateset/ves-stark');

const publicInputsBound = {
  ...publicInputs,
  witnessCommitment: proof.witnessCommitmentHex,
};

// Use the hex form to avoid u64 round-trip issues in JavaScript.
const result = verifyHex(proof.proofBytes, publicInputsBound, proof.witnessCommitmentHex);

if (result.valid) {
  console.log('Proof is valid!');
  console.log(`Verified in ${result.verificationTimeMs}ms`);
  console.log(`Policy: ${result.policyId} (limit: ${result.policyLimit}n)`);
} else {
  console.error(`Verification failed: ${result.error}`);
}
```

`verify()` and `verifyHex()` now bind the supplied witness commitment into the public inputs before
verification, so local verification is witness-bound by default.

For payload-to-amount binding, derive a canonical binding artifact and verify against it directly:

```javascript
const amountBinding = createPayloadAmountBinding(publicInputs, 5000n);
const boundResult = verifyWithAmountBinding(proof.proofBytes, publicInputs, amountBinding);
```

### Agent Authorization Policy

```javascript
const intentHash = '11'.repeat(32);
const policyParams = createAgentAuthorizationParams(20000n, intentHash);
const policyHash = computePolicyHash('agent.authorization.v1', policyParams);

const agentPublicInputs = {
  ...publicInputs,
  policyId: 'agent.authorization.v1',
  policyParams,
  policyHash,
};

const proof = prove(12500n, agentPublicInputs, 'agent.authorization.v1', 20000n);
```

If you also have the canonical authorization receipt, use `verifyAgentAuthorizationHex(...)` to
derive the payload amount binding from the receipt and verify the stronger receipt-bound
statement.

## API Reference

### `prove(amount, publicInputs, policyType, policyLimit)`

Generate a STARK compliance proof.

**Parameters:**
- `amount` (bigint): The amount to prove compliance for
- `publicInputs` (JsCompliancePublicInputs): Public inputs including event metadata
- `policyType` (string): Policy type - `"aml.threshold"`, `"order_total.cap"`, or `"agent.authorization.v1"`
- `policyLimit` (bigint): The policy limit value

**Returns:** `JsComplianceProof`
- `proofBytes` (Buffer): Raw proof bytes
- `proofHash` (string): SHA-256 hash of proof
- `provingTimeMs` (number): Generation time in milliseconds
- `proofSize` (number): Size in bytes
- `witnessCommitment` (string[]): 4-element decimal commitment array
- `witnessCommitmentHex` (string): 64-character lowercase hex commitment (recommended)

### `verify(proofBytes, publicInputs, witnessCommitment)`

Verify a STARK compliance proof.

**Parameters:**
- `proofBytes` (Buffer): Raw proof bytes from `prove()`
- `publicInputs` (JsCompliancePublicInputs): Must match proving inputs and
  include `witnessCommitment` when using canonical bound verification
- `witnessCommitment` (string[]): 4-element decimal array from proof

**Returns:** `JsVerificationResult`
- `valid` (boolean): Whether proof is valid
- `verificationTimeMs` (number): Verification time in milliseconds
- `error` (string | null): Error message if invalid
- `policyId` (string): Verified policy ID
- `policyLimit` (bigint): Verified policy limit

### `verifyHex(proofBytes, publicInputs, witnessCommitmentHex)`

Verify a STARK compliance proof using the witness commitment hex string.

**Parameters:**
- `proofBytes` (Buffer): Raw proof bytes from `prove()`
- `publicInputs` (JsCompliancePublicInputs): Must match proving inputs and
  include `witnessCommitment` when using canonical bound verification
- `witnessCommitmentHex` (string): 64-character lowercase hex commitment (recommended)

**Returns:** `JsVerificationResult`

### `verifyAgentAuthorization(proofBytes, publicInputs, witnessCommitment, receipt)`

Verify an `agent.authorization.v1` proof against a canonical authorization receipt, deriving the
payload amount binding from `receipt.amount`.

### `verifyAgentAuthorizationHex(proofBytes, publicInputs, witnessCommitmentHex, receipt)`

Verify an `agent.authorization.v1` proof against a canonical authorization receipt using the hex
commitment form, deriving the payload amount binding from `receipt.amount`.

### `verifyWithAmountBinding(proofBytes, publicInputs, amountBinding)`

Verify a proof against a canonical payload-derived amount binding.

### `verifyAgentAuthorizationWithAmountBinding(proofBytes, publicInputs, amountBinding, receipt)`

Verify an `agent.authorization.v1` proof against both a payload-derived amount binding and a
canonical authorization receipt. This is equivalent to the receipt-based helpers when the binding
matches `receipt.amount`, but keeps the artifact explicit.

### `computePolicyHash(policyId, policyParams)`

Compute the canonical policy hash.

**Parameters:**
- `policyId` (string): Policy identifier (e.g., `"aml.threshold"`)
- `policyParams` (object): Policy parameters

**Returns:** `string` - 64-character lowercase hex hash

### `createAmlThresholdParams(threshold)`

Create policy parameters for AML threshold policy.

**Parameters:**
- `threshold` (bigint): The threshold value

**Returns:** `{ threshold: bigint }`

### `createOrderTotalCapParams(cap)`

Create policy parameters for order total cap policy.

**Parameters:**
- `cap` (bigint): The cap value

**Returns:** `{ cap: bigint }`

### `createAgentAuthorizationParams(maxTotal, intentHash)`

Create policy parameters for the delegated agent authorization policy.

**Parameters:**
- `maxTotal` (bigint): The delegated maximum total
- `intentHash` (string): 64-character commerce intent hash

**Returns:** `{ maxTotal: bigint, intentHash: string }`

### `createPayloadAmountBinding(publicInputs, amount)`

Create a canonical payload amount binding artifact for the supplied public inputs and extracted
amount.

## Policy Types

| Policy | ID | Constraint | Use Case |
|--------|-----|------------|----------|
| AML Threshold | `aml.threshold` | amount < threshold | Anti-money laundering compliance |
| Order Total Cap | `order_total.cap` | amount <= cap | Order value limits |
| Agent Authorization | `agent.authorization.v1` | amount <= maxTotal | Delegated commerce execution |

## TypeScript Support

Full TypeScript definitions are included. Import types:

```typescript
import {
  prove,
  verify,
  computePolicyHash,
  JsCompliancePublicInputs,
  JsComplianceProof,
  JsVerificationResult
} from '@stateset/ves-stark';
```

## Building from Source

```bash
# Install dependencies
npm install

# Build release binary
npm run build

# Build debug binary
npm run build:debug
```

## Performance

Typical performance on modern hardware:
- Proof generation: 500-2000ms
- Proof verification: 50-200ms
- Proof size: ~100-200 KB

## License

MIT
