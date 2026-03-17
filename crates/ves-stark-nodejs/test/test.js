/* eslint-disable no-console */

const assert = require('assert')

const ves = require('..')

function hexZeros(bytes) {
  return '00'.repeat(bytes)
}

const policyType = 'aml.threshold'
const policyLimit = 10_000n
const policyParams = ves.createAmlThresholdParams(policyLimit)
const policyHash = ves.computePolicyHash(policyType, policyParams)

const publicInputsBase = {
  eventId: '00000000-0000-0000-0000-000000000001',
  tenantId: '00000000-0000-0000-0000-000000000002',
  storeId: '00000000-0000-0000-0000-000000000003',
  sequenceNumber: 1n,
  payloadKind: 1,
  payloadPlainHash: hexZeros(32),
  payloadCipherHash: hexZeros(32),
  eventSigningHash: hexZeros(32),
  policyId: policyType,
  policyParams,
  policyHash,
}

const amount = 5_000n

const proof = ves.prove(amount, publicInputsBase, policyType, policyLimit)

assert.ok(Buffer.isBuffer(proof.proofBytes), 'expected proofBytes to be a Buffer')
assert.strictEqual(typeof proof.proofHash, 'string')
assert.strictEqual(proof.proofHash.length, 64)
assert.strictEqual(Array.isArray(proof.witnessCommitment), true)
assert.strictEqual(proof.witnessCommitment.length, 4)
assert.strictEqual(typeof proof.witnessCommitmentHex, 'string')
assert.strictEqual(proof.witnessCommitmentHex.length, 64)
assert.strictEqual(typeof proof.witnessCommitment[0], 'string')

// Bound verification: require canonical public inputs to carry the witness commitment.
const publicInputsBound = {
  ...publicInputsBase,
  witnessCommitment: proof.witnessCommitmentHex,
}

const okWithNumbers = ves.verify(proof.proofBytes, publicInputsBound, proof.witnessCommitment)
assert.strictEqual(okWithNumbers.valid, true, okWithNumbers.error || 'verification failed')
assert.strictEqual(typeof okWithNumbers.policyLimit, 'bigint')
assert.strictEqual(okWithNumbers.policyLimit, policyLimit)

const ok = ves.verifyHex(proof.proofBytes, publicInputsBound, proof.witnessCommitmentHex)
assert.strictEqual(ok.valid, true, ok.error || 'verification failed')
assert.strictEqual(typeof ok.policyLimit, 'bigint')
assert.strictEqual(ok.policyLimit, policyLimit)

// Negative test: mismatch between public_inputs.witnessCommitment and provided witness commitment must fail.
const wrongWitnessCommitmentHex =
  proof.witnessCommitmentHex.slice(0, -1) + (proof.witnessCommitmentHex.endsWith('0') ? '1' : '0')

const publicInputsWrong = {
  ...publicInputsBound,
  witnessCommitment: wrongWitnessCommitmentHex,
}

assert.throws(
  () => ves.verifyHex(proof.proofBytes, publicInputsWrong, proof.witnessCommitmentHex),
  /Failed to bind witness commitment to public inputs/
)

const capPolicyType = 'order_total.cap'
const capPolicyLimit = 10_000n
const capPolicyParams = ves.createOrderTotalCapParams(capPolicyLimit)
const capPolicyHash = ves.computePolicyHash(capPolicyType, capPolicyParams)

const capInputsBase = {
  ...publicInputsBase,
  policyId: capPolicyType,
  policyParams: capPolicyParams,
  policyHash: capPolicyHash,
}

const capProof = ves.prove(capPolicyLimit, capInputsBase, capPolicyType, capPolicyLimit)
const capInputsBound = {
  ...capInputsBase,
  witnessCommitment: capProof.witnessCommitmentHex,
}
const capOk = ves.verifyHex(capProof.proofBytes, capInputsBound, capProof.witnessCommitmentHex)
assert.strictEqual(capOk.valid, true, capOk.error || 'cap verification failed')
assert.strictEqual(capOk.policyLimit, capPolicyLimit)

const authPolicyType = 'agent.authorization.v1'
const authPolicyLimit = 20_000n
const authIntentHash = '11'.repeat(32)
const authPolicyParams = ves.createAgentAuthorizationParams(authPolicyLimit, authIntentHash)
const authPolicyHash = ves.computePolicyHash(authPolicyType, authPolicyParams)

const authInputsBase = {
  ...publicInputsBase,
  policyId: authPolicyType,
  policyParams: authPolicyParams,
  policyHash: authPolicyHash,
}

const authProof = ves.prove(12_500n, authInputsBase, authPolicyType, authPolicyLimit)
const authInputsBound = {
  ...authInputsBase,
  witnessCommitment: authProof.witnessCommitmentHex,
}
const authOk = ves.verifyHex(
  authProof.proofBytes,
  authInputsBound,
  authProof.witnessCommitmentHex
)
assert.strictEqual(authOk.valid, true, authOk.error || 'agent authorization verification failed')
assert.strictEqual(authOk.policyLimit, authPolicyLimit)

console.log('ok')
