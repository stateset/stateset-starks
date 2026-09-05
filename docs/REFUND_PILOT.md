# Disclosed refund pilot

## Supported outcome

A trusted capture feed establishes a captured balance. Intake prepares a refund
against its current state and signs an approval. An independent operator verifies
the signature, approved context, STARK cap, and disclosed accounting, then reserves
the refund in a durable ledger and queues a provider execution request.

This pilot is **not zero knowledge**. Amounts, balances, and transitions are public.
Refund arithmetic is checked by the verifier with exact checked u64 operations;
there is no new private state-transition AIR. The STARK binds the amount commitment
and transition hash into the approved event. Re-proving public addition inside an
AIR would add cost without hiding any data in this workflow.

## Guarantees and assumptions

| Property | Enforcement |
|---|---|
| Refund amount <= remaining captured balance | Cap STARK plus exact amount commitment check |
| New refunded total = old total + refund | Checked native arithmetic; transition hash bound into request |
| Capture/currency/scale/tenant/store continuity | Exact before/after state validation |
| Approval authenticity | Domain-separated Ed25519 signature, strict verification |
| Key authorization | Independently configured key ID, tenant/store, policy version, key validity and revocation |
| Fresh approval | Trusted current time within approval and key intervals; expiry is exclusive |
| No double reservation | SQLite BEGIN IMMEDIATE, expected predecessor hash, unique event and nonce |
| Crash consistency | Balance, consumption record, and outbox insert in one FULL-synchronous transaction |
| Execution retry | Stable tenant/store/event-derived provider idempotency key |
| Proof confidentiality | Unsupported; explicit disclosure acknowledgment required |

Ed25519 approvals are classical signatures, not post-quantum signatures. The
end-to-end approval protocol therefore does not claim post-quantum security.

All u64 JSON values must be handled with exact integer arithmetic. JavaScript
integrations must use a lossless JSON parser for values above 2^53-1; ordinary
JSON.parse/Number cannot preserve them. This pilot is implemented in Rust.

Trusted assumptions: capture ingestion authenticity and completeness, local database
integrity, key distribution and revocation freshness, current time, and a payment
provider that actually honors idempotency keys. The example does not contact a
payment service and does not demonstrate customer demand or production throughput.
The capture version enforces per-capture state continuity, not global event-stream
sequence continuity. Registering a capture never overwrites an existing record.

## Run the synthetic rehearsal

```sh
cargo run -p ves-stark-commerce --features ledger --example refund_pilot -- /tmp/new-refund-pilot.db
```

Use a new database path. The pilot performs ten synthetic $5 refunds against a
$100 capture, rejects replay, reopens the database, and simulates provider
completion. It prints per-event proof size and timings, plus p95 values and build
mode. Debug timings are diagnostic, not production performance claims.

The signed-record baseline measures signature plus disclosed transition checking.
It excludes STARK verification and is not a second payment/ledger implementation.
Both approaches still trust the source capture and approval authority. When that
trust already suffices, the signed-record baseline can be the preferable product.
Use measurements to justify proof cost rather than assuming cryptography adds value.

### Recorded optimized rehearsal (2026-09-05)

The [raw measurements](benchmarks/refund-pilot-2026-09-05.json) come from ten
sequential synthetic refunds on a shared, busy development host, using:

```sh
cargo run --profile bench -p ves-stark-commerce --features ledger --example refund_pilot --offline -- /tmp/stateset-refund-pilot-final.db
```

The bench profile is optimized, but is not the production release profile. With
only ten samples, the nearest-rank p95 is the maximum observed sample.

| Measurement | Observed result |
|---|---:|
| Proof generation p95 | 51.426 ms |
| Proof-path verification p95 | 7.409 ms |
| Signed-record baseline verification p95 | 0.411 ms |
| Proof size | 58,688–63,500 bytes |
| Ledger reservation latency range | 17.008–4,227.885 ms |
| Final refunded amount | 5,000 minor units |
| Pending executions after simulated completion | 0 |

Reservation includes verification and durable database work. Several multi-second
reservations make storage latency an explicit follow-up; this run does not isolate
its cause. These measurements establish a reproducible local rehearsal, not an
SLO, a capacity estimate, or evidence that the proof is worth its added cost.

## CLI integration

```sh
# Trusted operator imports capture.json (RefundState schema).
ves-stark commerce capture-import --state capture.json --ledger refunds.db

# Intake obtains the amount from a protected file or stdin.
ves-stark commerce refund-prove --allow-amount-disclosure \
  --ledger refunds.db --tenant-id TENANT_UUID --store-id STORE_UUID \
  --capture-id capture-123 --event-id REFUND_UUID --sequence-number 1 \
  --amount-file amount.txt --output-dir refund-1

# Intake signs only after authenticating the source amount and current state.
ves-stark commerce sign-approval --approval refund-1/approval.json \
  --authority trusted-authority.json --secret-key-file protected-seed.hex \
  --expires-at EXPIRY_UNIX_SECONDS --output signed-approval.json

# Operator independently configures the authority and current ledger.
ves-stark commerce refund-apply --allow-amount-disclosure \
  --ledger refunds.db --proof refund-1/proof.json \
  --approval signed-approval.json --authority trusted-authority.json

ves-stark commerce refund-pending --ledger refunds.db
# After provider confirmation, using the listed idempotency key on every attempt:
ves-stark commerce refund-complete --ledger refunds.db \
  --idempotency-key EXECUTION_KEY --provider-reference PROVIDER_REFUND_ID
```

`ApprovalAuthority` JSON contains `keyId`, raw 32-byte `publicKey` array, `tenantId`,
`storeId`, `policyVersion`, `notBefore`, `expiresAt`, and `revoked`. The seed file
contains a 32-byte Ed25519 seed in hex; use protected storage and never commit it.
This seed is not a transaction amount. Never accept the authority file from the
same untrusted channel as the proof. The CLI uses the system clock.

Pending requests are delivered at least once. Multiple workers may observe the
same request; the payment provider must deduplicate by the stable key. Marking
completion locally does not execute a payment. A permanently failed refund stays
reserved until an explicit, audited compensating workflow is implemented; do not
release funds merely because a provider call timed out.

## Acceptance and remaining release gates

Automated coverage includes changed signatures/context, expiry/revocation, integer
overflow, concurrent refunds, replayed events/nonces, transaction rollback, process
restart, and repeated provider acknowledgments. CLI subprocess tests cover the
complete local flow with bounded inputs and independently supplied authority keys.

Before a real customer rollout:

1. Connect an authenticated capture feed and idempotent payment provider; test
   provider timeout/retry and reconciliation with real sandbox credentials.
2. Define expected key rotation/revocation latency, durable backup/recovery, clock
   policy, monitoring, and compensation for permanent execution failures.
3. Benchmark optimized builds at actual concurrency and event volume against the
   signed-record baseline; include storage, proof transport, and operational cost.
4. Have an independent operator/customer verify the same records and identify the
   trust reduction or operational benefit they require. No demand is established
   by the synthetic pilot alone.
5. Complete external security review. Confidential use additionally requires every
   gate in the [amount disclosure advisory](SECURITY_ADVISORY_AMOUNT_DISCLOSURE.md).
