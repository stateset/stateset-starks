# Amount disclosure in proof transcripts

Status: **confirmed; confidentiality is not implemented**. Date: 2026-09-05.

## Impact

The current per-event prover exposes enough public out-of-domain trace evaluations
to recover the witness amount. This affects salted and unsalted commitments and
V1 and V2 payloads. Salt protects the commitment in isolation, not the transcript.
Do not publish these proofs expecting to keep amounts or witness salts secret.
Historical proofs cannot be made confidential retroactively.

The trace contains `amount_limb` only at row zero, with zero padding elsewhere.
The first-row selector has the same support, so their interpolated polynomials
satisfy `amount_column(z) = amount_limb * first_row_selector(z)`. Both evaluations
are in the public proof. Division recovers each limb; the salt columns have the
same structure. Other deterministic trace columns also preclude claiming zero
knowledge. This is not a soundness forgery: proving an invalid cap and disclosing
a valid witness are distinct properties.

Reproduce with synthetic data:

```sh
cargo test -p ves-stark-prover --test privacy_capability -- --nocapture
```

This test intentionally demonstrates disclosure under explicit `AllowDisclosure`
and checks that a confidentiality requirement fails. A green result does not mean
confidentiality is fixed. The original diagnostic recovered `1099511632018` from
a freshly generated salted V2 proof using only public proof bytes.

## Containment and compatibility

- `SUPPORTS_ZERO_KNOWLEDGE` is false.
- `ProofPrivacy::Confidential` is the default requirement and returns an error.
- Commerce `prepare_cap_proof`, `verify_cap_proof`, and `CommerceApproval::verify`
  reject confidentiality by default. The explicitly named `_disclosed` alternatives
  remain available for integrity-only applications.
- Commerce proving/verification CLI commands require `--allow-amount-disclosure`.
- `ComplianceProver::prove_with_privacy` and `ComplianceVerification::privacy`
  enforce explicit requirements. Legacy low-level `prove`, free verification
  functions, and language bindings remain integrity-only compatibility APIs and
  can still emit/accept disclosing proofs. Do not infer confidentiality from their
  historical names or from successful verification.
- Signing an approval, encrypting an event payload, setting a larger FRI security
  level, or removing `amountBindingHash` does not repair transcript privacy.

## Required work before enabling confidential proofs

1. Select a reviewed zero-knowledge proving construction, including trace,
   composition-polynomial, and commitment masking; alternatively integrate a
   backend that supplies those guarantees. Randomizing a few padding rows is
   not a reviewed zero-knowledge construction.
2. Specify the complete leakage model, transcript simulator/security argument,
   public metadata, proof-size/timing leakage, and commitment domain separation.
3. Version the proof format/backend and verifier allowlist. Reject old proofs on
   any confidential endpoint; never select guarantees from untrusted metadata.
4. Add independent transcript analysis and adversarial tests for amount, salt,
   bit-decomposition, and Rescue-state recovery across every supported profile.
5. Obtain an independent cryptographic audit before changing the capability flag.

The above work remains a release blocker; this repository does not claim that it
has been completed. The disclosed refund pilot is suitable for testing accounting
and integration with synthetic or intentionally public data.

Upstream also documents the missing zero-knowledge construction:
[Winterfell issue #9](https://github.com/facebook/winterfell/issues/9).
