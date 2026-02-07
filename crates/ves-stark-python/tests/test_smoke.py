import uuid
from typing import Optional

import ves_stark


def _hex_zeros(byte_len: int) -> str:
    return "00" * byte_len


def _mk_public_inputs(*, witness_commitment: Optional[str] = None) -> ves_stark.CompliancePublicInputs:
    policy_id = "aml.threshold"
    policy_params = {"threshold": 10_000}
    policy_hash = ves_stark.compute_policy_hash(policy_id, policy_params)

    return ves_stark.CompliancePublicInputs(
        event_id=str(uuid.UUID(int=1)),
        tenant_id=str(uuid.UUID(int=2)),
        store_id=str(uuid.UUID(int=3)),
        sequence_number=1,
        payload_kind=1,
        payload_plain_hash=_hex_zeros(32),
        payload_cipher_hash=_hex_zeros(32),
        event_signing_hash=_hex_zeros(32),
        policy_id=policy_id,
        policy_params=policy_params,
        policy_hash=policy_hash,
        witness_commitment=witness_commitment,
    )


def test_compute_policy_hash_smoke() -> None:
    h = ves_stark.compute_policy_hash("aml.threshold", {"threshold": 10_000})
    assert isinstance(h, str)
    assert len(h) == 64
    int(h, 16)  # Valid hex


def test_prove_verify_bound_smoke() -> None:
    policy = ves_stark.Policy.aml_threshold(10_000)
    inputs = _mk_public_inputs()

    proof = ves_stark.prove(5_000, inputs, policy)
    assert len(proof.witness_commitment) == 4
    assert isinstance(proof.witness_commitment_hex, str)
    assert len(proof.witness_commitment_hex) == 64

    # Bound verification: canonical public inputs carry the witness commitment.
    inputs_bound = _mk_public_inputs(witness_commitment=proof.witness_commitment_hex)
    ok = ves_stark.verify(proof.proof_bytes, inputs_bound, proof.witness_commitment)
    assert ok.valid, ok.error

    # Negative test: mismatch between public_inputs.witnessCommitment and provided witness commitment must fail.
    wrong = proof.witness_commitment_hex[:-1] + ("1" if proof.witness_commitment_hex.endswith("0") else "0")
    inputs_wrong = _mk_public_inputs(witness_commitment=wrong)
    bad = ves_stark.verify(proof.proof_bytes, inputs_wrong, proof.witness_commitment)
    assert not bad.valid
    assert bad.error
