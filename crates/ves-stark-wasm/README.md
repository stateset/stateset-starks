# ves-stark-wasm

Browser/WebAssembly bindings for the VES STARK proof system.

## Exposed API

- `prove(amount, publicInputs, policyType, policyLimit)`
- `verifyHex(proofBytes, publicInputs, witnessCommitmentHex)`
- `verifyWithAmountBinding(proofBytes, publicInputs, amountBinding)`
- `computePolicyHash(policyId, policyParams)`
- `createAmlThresholdParams(threshold)`
- `createOrderTotalCapParams(cap)`
- `createAgentAuthorizationParams(maxTotal, intentHash)`
- `createPayloadAmountBinding(publicInputs, amount)`

## Build

```bash
cargo build -p ves-stark-wasm --target wasm32-unknown-unknown --release
```
