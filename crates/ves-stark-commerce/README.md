# Commerce integrity proofs

**Confidential proofs are unavailable. Proof bytes can disclose amounts and salts.**
Read the [security advisory](../../docs/SECURITY_ADVISORY_AMOUNT_DISCLOSURE.md).
`prepare_cap_proof`, `verify_cap_proof`, and `CommerceApproval::verify` reject
confidentiality by default. Disclosed data workflows use the explicitly named
`prepare_cap_proof_disclosed`, `verify_cap_proof_disclosed`, and
`CommerceApproval::verify_disclosed` APIs.

The crate supports per-event order, payment, refund, and payout caps. The canonical
request binds operation, reference, currency/scale, event/tenant/store, sequence,
and inclusive cap. An optional `stateTransitionHash` binds disclosed accounting.
Amounts use exact u64 integer units. Validate supported currency codes and scales
against application policy; the crate validates syntax, not a currency registry.

## Signed approvals and refund accounting

- `approval::SignedApproval`: domain-separated Ed25519 approval with nonce,
  policy version, validity interval, and a key ID resolved against an independently
  trusted tenant/store-scoped `ApprovalAuthority`. Revoked keys are rejected.
- `refund::prove_refund_disclosed`: prepares public before/after refund accounting
  and a context-bound cap STARK. Exact accounting is checked natively, not privately
  in the AIR. The public amount is matched to the STARK commitment using zero salt.
- `ledger::RefundLedger` (feature `ledger`): durable SQLite reservation with
  expected-state comparison, atomic event/nonce consumption, and a transactional
  execution queue. Provider execution requires stable-key idempotency.

See [the refund pilot contract](../../docs/REFUND_PILOT.md) for guarantees,
assumptions, CLI examples, restart behavior, and production acceptance gates.

```sh
cargo run -p ves-stark-commerce --example refund_cap
cargo run -p ves-stark-commerce --features ledger --example refund_pilot -- /tmp/new-refund-pilot.db
cargo test -p ves-stark-commerce --all-features
```

## Per-event cap API

```rust,ignore
let prepared = prepare_cap_proof_disclosed(actual_amount, &approved_request)?;
let approval = prepared.approval();
// Authenticate/store or sign the approval at trusted intake.
let proof = prepared.prove()?;
approval.verify_disclosed(&proof)?;
```

Preparation belongs at intake that knows the actual transaction amount. Never
accept both an unsigned approval and proof from an untrusted sender. V2 binding
protects the relationship to an authenticated commitment, not the truth of an
arbitrary source record. Standalone claims use zero cipher/signing hash placeholders;
they are not encrypted or signed VES events. Signed approvals are a separate protocol.

`CommerceProof` omits plaintext amount and salt JSON fields but its transcript can
reveal both. Apply transport limits before JSON deserialization. API signatures and
local serialization do not establish provenance or prevent replay by themselves.
The ledger enforces replay protection for its refund workflow; standalone cap
verification does not consume an event.
