/* eslint-disable no-console */

const assert = require('assert')

const ves = require('..')

function hexZeros(bytes) {
  return '00'.repeat(bytes)
}

const policyType = 'aml.threshold'
const policyLimit = 10_000
const policyParams = ves.createAmlThresholdParams(policyLimit)
const policyHash = ves.computePolicyHash(policyType, policyParams)

const publicInputsBase = {
  eventId: '00000000-0000-0000-0000-000000000001',
  tenantId: '00000000-0000-0000-0000-000000000002',
  storeId: '00000000-0000-0000-0000-000000000003',
  sequenceNumber: 1,
  payloadKind: 1,
  payloadPlainHash: hexZeros(32),
  payloadCipherHash: hexZeros(32),
  eventSigningHash: hexZeros(32),
  policyId: policyType,
  policyParams,
  policyHash,
}

const amount = 5_000

const proof = ves.prove(amount, publicInputsBase, policyType, policyLimit)

assert.ok(Buffer.isBuffer(proof.proofBytes), 'expected proofBytes to be a Buffer')
assert.strictEqual(typeof proof.proofHash, 'string')
assert.strictEqual(proof.proofHash.length, 64)
assert.strictEqual(Array.isArray(proof.witnessCommitment), true)
assert.strictEqual(proof.witnessCommitment.length, 4)
assert.strictEqual(typeof proof.witnessCommitmentHex, 'string')
assert.strictEqual(proof.witnessCommitmentHex.length, 64)

// Bound verification: require canonical public inputs to carry the witness commitment.
const publicInputsBound = {
  ...publicInputsBase,
  witnessCommitment: proof.witnessCommitmentHex,
}

const ok = ves.verifyHex(proof.proofBytes, publicInputsBound, proof.witnessCommitmentHex)
assert.strictEqual(ok.valid, true, ok.error || 'verification failed')

// Negative test: mismatch between public_inputs.witnessCommitment and provided witness commitment must fail.
const wrongWitnessCommitmentHex =
  proof.witnessCommitmentHex.slice(0, -1) + (proof.witnessCommitmentHex.endsWith('0') ? '1' : '0')

const publicInputsWrong = {
  ...publicInputsBound,
  witnessCommitment: wrongWitnessCommitmentHex,
}

const bad = ves.verifyHex(proof.proofBytes, publicInputsWrong, proof.witnessCommitmentHex)
assert.strictEqual(bad.valid, false)
assert.ok(bad.error && bad.error.length > 0, 'expected an error message')

console.log('ok')

