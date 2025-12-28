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
const { prove, computePolicyHash, createAmlThresholdParams } = require('@stateset/ves-stark');

// Create policy parameters
const policyParams = createAmlThresholdParams(10000);

// Compute the policy hash
const policyHash = computePolicyHash('aml.threshold', policyParams);

// Create public inputs
const publicInputs = {
  eventId: '550e8400-e29b-41d4-a716-446655440000',
  tenantId: '550e8400-e29b-41d4-a716-446655440001',
  storeId: '550e8400-e29b-41d4-a716-446655440002',
  sequenceNumber: 12345,
  payloadKind: 1,
  payloadPlainHash: 'a'.repeat(64),  // 64-char lowercase hex
  payloadCipherHash: 'b'.repeat(64),
  eventSigningHash: 'c'.repeat(64),
  policyId: 'aml.threshold',
  policyParams: policyParams,
  policyHash: policyHash
};

// Generate proof (amount must be < threshold for aml.threshold)
const proof = prove(5000, publicInputs, 'aml.threshold', 10000);

console.log(`Proof generated in ${proof.provingTimeMs}ms`);
console.log(`Proof size: ${proof.proofSize} bytes`);
console.log(`Proof hash: ${proof.proofHash}`);
```

### Verify a Proof

```javascript
const { verify } = require('@stateset/ves-stark');

const result = verify(proof.proofBytes, publicInputs, proof.witnessCommitment);

if (result.valid) {
  console.log('Proof is valid!');
  console.log(`Verified in ${result.verificationTimeMs}ms`);
  console.log(`Policy: ${result.policyId} (limit: ${result.policyLimit})`);
} else {
  console.error(`Verification failed: ${result.error}`);
}
```

## API Reference

### `prove(amount, publicInputs, policyType, policyLimit)`

Generate a STARK compliance proof.

**Parameters:**
- `amount` (number): The amount to prove compliance for
- `publicInputs` (JsCompliancePublicInputs): Public inputs including event metadata
- `policyType` (string): Policy type - `"aml.threshold"` or `"order_total.cap"`
- `policyLimit` (number): The policy limit value

**Returns:** `JsComplianceProof`
- `proofBytes` (Buffer): Raw proof bytes
- `proofHash` (string): SHA-256 hash of proof
- `provingTimeMs` (number): Generation time in milliseconds
- `proofSize` (number): Size in bytes
- `witnessCommitment` (number[]): 4-element commitment array

### `verify(proofBytes, publicInputs, witnessCommitment)`

Verify a STARK compliance proof.

**Parameters:**
- `proofBytes` (Buffer): Raw proof bytes from `prove()`
- `publicInputs` (JsCompliancePublicInputs): Must match proving inputs
- `witnessCommitment` (number[]): 4-element array from proof

**Returns:** `JsVerificationResult`
- `valid` (boolean): Whether proof is valid
- `verificationTimeMs` (number): Verification time in milliseconds
- `error` (string | null): Error message if invalid
- `policyId` (string): Verified policy ID
- `policyLimit` (number): Verified policy limit

### `computePolicyHash(policyId, policyParams)`

Compute the canonical policy hash.

**Parameters:**
- `policyId` (string): Policy identifier (e.g., `"aml.threshold"`)
- `policyParams` (object): Policy parameters

**Returns:** `string` - 64-character lowercase hex hash

### `createAmlThresholdParams(threshold)`

Create policy parameters for AML threshold policy.

**Parameters:**
- `threshold` (number): The threshold value

**Returns:** `{ threshold: number }`

### `createOrderTotalCapParams(cap)`

Create policy parameters for order total cap policy.

**Parameters:**
- `cap` (number): The cap value

**Returns:** `{ cap: number }`

## Policy Types

| Policy | ID | Constraint | Use Case |
|--------|-----|------------|----------|
| AML Threshold | `aml.threshold` | amount < threshold | Anti-money laundering compliance |
| Order Total Cap | `order_total.cap` | amount <= cap | Order value limits |

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
