# ves-stark-cli

CLI tool for VES STARK proof generation and verification.

## Installation

```bash
cargo install --path crates/ves-stark-cli
```

Binary name: `ves-stark`

## Commands

### `prove` — Generate a compliance proof

```bash
ves-stark prove \
  --amount 5000 \
  --policy aml.threshold \
  --limit 10000 \
  --public-inputs inputs.json
```

### `verify` — Verify a proof

```bash
ves-stark verify \
  --proof proof.bin \
  --public-inputs inputs.json \
  --witness-commitment <hex>
```

### `batch-prove` — Generate a batch proof for multiple events

```bash
ves-stark batch-prove \
  --events events.json
```

### `inspect` — Inspect proof metadata

```bash
ves-stark inspect --proof proof.bin
```

### `test-data` — Generate test data for development

```bash
ves-stark test-data --policy aml.threshold --limit 10000
```

### `sequencer-sim` — Simulate sequencer interaction

```bash
ves-stark sequencer-sim --url http://localhost:8080
```

## Supported Policies

| Policy | Flag | Description |
|--------|------|-------------|
| AML Threshold | `aml.threshold` | Amount must be below threshold |
| Order Total Cap | `order_total.cap` | Amount must not exceed cap |
| Agent Authorization | `agent.authorization.v1` | Amount within authorized limit with intent binding |

## Features

| Feature | Description |
|---------|-------------|
| `dev` | Enable development mode (sequencer connectivity) |

## License

MIT
