# ves-stark-client

HTTP client for submitting VES STARK proofs to the StateSet sequencer and anchoring batch proofs to the Set Chain L2.

## Overview

Provides two clients:

- **`SequencerClient`** — submits individual compliance/authorization proofs to the VES sequencer, retrieves public inputs, and handles x402 payment intents
- **`SetChainClient`** — anchors batch STARK proofs to the Set Chain L2 via the SetRegistry contract

## Usage

```rust
use ves_stark_client::{SequencerClient, ClientError};

// Connect to sequencer
let client = SequencerClient::new("http://localhost:8080", "ss_dev_admin_key_local")?;

// Submit a compliance proof
let bundle = ComplianceProofBundle { proof, public_inputs, witness_commitment };
client.submit_compliance_proof(&bundle).await?;
```

### Set Chain Anchoring

```rust
use ves_stark_client::{SetChainClient, SetChainConfig};

let config = SetChainConfig::local(); // localhost:8545
let chain_client = SetChainClient::new(config)?;

// Anchor batch proof
chain_client.anchor_batch_proof(&batch_submission).await?;
```

### Batch Submissions (feature-gated)

```rust
// Enable with: ves-stark-client = { features = ["batch"] }
use ves_stark_client::BatchSubmissionBuilder;

let submission = BatchSubmissionBuilder::new()
    .proof(batch_proof)
    .public_inputs(public_inputs)
    .build()?;
```

## Features

| Feature | Description |
|---------|-------------|
| `batch` | Enable `ves-stark-batch` integration and `BatchSubmissionBuilder` |
| `dev` | Development API key handling |

## Set Chain Configs

| Config | RPC URL | Description |
|--------|---------|-------------|
| `SetChainConfig::local()` | `http://localhost:8545` | Local Anvil |
| `SetChainConfig::testnet()` | Testnet RPC | Set Chain testnet |
| `SetChainConfig::mainnet()` | Mainnet RPC | Set Chain mainnet |

## Key Types

| Type | Description |
|------|-------------|
| `SequencerClient` | Sequencer API client |
| `SetChainClient` | Set Chain L2 client |
| `ComplianceProofBundle` | Proof + public inputs + witness commitment |
| `AgentAuthorizationProofBundle` | Agent auth proof bundle |
| `BatchProofSubmission` | Batch proof for anchoring |
| `BatchProofResponse` / `BatchProofStatus` | Anchoring response types |

## License

MIT
