# ves-stark-cli

> **Integrity only:** proof bytes can disclose witness amounts. This documentation describes the 0.8.0 checkout, not a guarantee of registry availability. See [the security advisory](../../docs/SECURITY_ADVISORY_AMOUNT_DISCLOSURE.md).

[![crates.io](https://img.shields.io/crates/v/ves-stark-cli.svg)](https://crates.io/crates/ves-stark-cli)
[![license](https://img.shields.io/crates/l/ves-stark-cli.svg)](../LICENSE)

CLI tool for VES STARK proof generation and verification.

## Installation

```bash
cargo install ves-stark-cli
```

Binary name: `ves-stark`

## Commands

### `commerce prove` / `commerce verify` — Business-context cap proofs

From the repository root, prove the sample $42.42 refund against a $50 cap:

```bash
printf '4242\n' | cargo run -p ves-stark-cli -- commerce prove --allow-amount-disclosure \
  --request crates/ves-stark-cli/examples/refund-request.json \
  --amount-file - \
  --output-dir commerce-demo

cargo run -p ves-stark-cli -- commerce verify --allow-amount-disclosure --allow-unsigned-approval \
  --proof commerce-demo/proof.json \
  --approval commerce-demo/approval.json
```

`commerce prove` runs at trusted intake, which knows the actual amount. It writes
`proof.json` and a separate `approval.json` containing the request and payload
commitment. In production, retain/authenticate the approval through your approval
system; the verifier must retrieve it independently of the proof sender.
The generated approval file is unsigned. Accepting both files from an untrusted
sender does not establish that the proved amount is the transaction's real amount.

Use a protected amount file or pipe in production. The amount is not echoed by the CLI or included as a plaintext field in cap JSON.
However, proof bytes can disclose it; this is not a confidentiality guarantee. The command supports integer amounts only and
uses the request's explicit currency scale. The output directory must be new,
and its parent must exist. An I/O failure may leave an incomplete directory;
only a successful exit means both artifacts were written.

Both commands emit JSON on stdout when successful; failures exit nonzero and
write diagnostics to stderr. Verification also accepts `--proof -` for stdin.
Request and approval inputs must name files and are limited to 16 KiB; amount
input is limited to 64 bytes. Proof JSON is bounded before deserialization.
Verification requires `--approval` and never derives it from the proof. Signed
verification requires `--authority`; the old externally trusted unsigned-file flow
requires explicit `--allow-unsigned-approval`. Every commerce proving/verification
operation requires `--allow-amount-disclosure`. Successful cap reports include
`zeroKnowledge: false`.

Supported operations are `order`, `payment`, `refund`, and `payout`.
See the [commerce API contract](../ves-stark-commerce/README.md) for the exact
statement and the ledger/replay responsibilities of the integration.

### Signed approvals and durable refunds

`commerce sign-approval` signs intake-approved context using a protected Ed25519
seed file and scoped authority configuration. `commerce capture-import`,
`refund-prove`, `refund-apply`, `refund-pending`, and `refund-complete` implement a
local disclosed refund lifecycle with atomic reservations and durable execution
requests. See the [refund pilot](../../docs/REFUND_PILOT.md) for complete commands,
JSON schemas, key trust, and provider idempotency requirements. None of these
commands sends money to a payment provider.

### `prove` — Generate a compliance proof

```bash
ves-stark prove \
  --amount 5000 \
  --policy aml.threshold \
  --limit 10000 \
  --inputs inputs.json
```

### `verify` — Verify a proof

```bash
ves-stark verify \
  --proof proof.bin \
  --inputs inputs.json \
  --witness-commitment-hex <hex> \
  --limit 10000
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

### `gen-inputs` — Generate public inputs for development

```bash
ves-stark gen-inputs --policy aml.threshold --limit 10000
```

### `sequencer` — Simulate event processing locally

```bash
ves-stark sequencer --num-events 16 --batch-size 8
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
