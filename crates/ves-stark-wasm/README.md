# ves-stark-wasm

WebAssembly bindings for the VES STARK proof system. Generate and verify zero-knowledge compliance proofs directly in the browser.

## Build

```bash
wasm-pack build crates/ves-stark-wasm --target web
```

Or for bundler targets (webpack, etc.):

```bash
wasm-pack build crates/ves-stark-wasm --target bundler
```

## Usage

### Proof Generation

```javascript
import init, {
  prove,
  createAmlThresholdParams,
  computePolicyHash,
} from 'ves-stark-wasm';

await init();

const policyParams = createAmlThresholdParams(10000);
const policyHash = computePolicyHash('aml.threshold', policyParams);

const publicInputs = {
  eventId: '550e8400-e29b-41d4-a716-446655440000',
  tenantId: '550e8400-e29b-41d4-a716-446655440001',
  storeId: '550e8400-e29b-41d4-a716-446655440002',
  sequenceNumber: 12345,
  payloadKind: 1,
  payloadPlainHash: 'a'.repeat(64),
  payloadCipherHash: 'b'.repeat(64),
  eventSigningHash: 'c'.repeat(64),
  policyId: 'aml.threshold',
  policyParams: policyParams,
  policyHash: policyHash,
};

const proof = prove(5000, publicInputs, 'aml.threshold', 10000);
```

### Proof Verification

```javascript
import { verifyHex, verifyWithAmountBinding, createPayloadAmountBinding } from 'ves-stark-wasm';

// Basic verification with witness commitment
const result = verifyHex(proof.proofBytes, publicInputs, proof.witnessCommitmentHex);

// With payload-to-amount binding
const amountBinding = createPayloadAmountBinding(publicInputs, 5000);
const boundResult = verifyWithAmountBinding(proof.proofBytes, publicInputs, amountBinding);
```

### Agent Authorization

```javascript
import { createAgentAuthorizationParams, computePolicyHash, prove } from 'ves-stark-wasm';

const intentHash = '11'.repeat(32);
const params = createAgentAuthorizationParams(20000, intentHash);
const hash = computePolicyHash('agent.authorization.v1', params);

const proof = prove(12500, agentPublicInputs, 'agent.authorization.v1', 20000);
```

## API Reference

| Function | Description |
|----------|-------------|
| `prove(amount, publicInputs, policyType, policyLimit)` | Generate a STARK proof |
| `verifyHex(proofBytes, publicInputs, witnessCommitmentHex)` | Verify proof with hex witness commitment |
| `verifyWithAmountBinding(proofBytes, publicInputs, amountBinding)` | Verify with payload-to-amount binding |
| `computePolicyHash(policyId, policyParams)` | Compute canonical policy hash (64-char hex) |
| `createAmlThresholdParams(threshold)` | Create AML threshold policy params |
| `createOrderTotalCapParams(cap)` | Create order total cap policy params |
| `createAgentAuthorizationParams(maxTotal, intentHash)` | Create agent authorization policy params |
| `createPayloadAmountBinding(publicInputs, amount)` | Create canonical amount binding artifact |

## Policy Types

| Policy | ID | Constraint | Use Case |
|--------|-----|------------|----------|
| AML Threshold | `aml.threshold` | amount < threshold | Anti-money laundering compliance |
| Order Total Cap | `order_total.cap` | amount <= cap | Order value limits |
| Agent Authorization | `agent.authorization.v1` | amount <= maxTotal | Delegated commerce execution |

## When to Use

- **Use this** for browser applications or any WASM runtime
- **Use `ves-stark-nodejs`** for server-side Node.js where native performance is preferred

## License

MIT
