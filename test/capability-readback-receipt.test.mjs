import assert from 'node:assert/strict'
import test from 'node:test'

import { createReadbackReceipt } from '../lib/capability-readback-receipt.mjs'
import {
  embeddedCapabilityProjection,
  PINNED_EMBEDDED_DIGEST,
  PINNED_EMBEDDED_MANIFEST,
  projectCapabilityManifest,
  STABLE_ACTIONS,
} from '../lib/capability-manifest.mjs'
import {
  canonicalJson,
  sha256Digest,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'

const EMBEDDED = embeddedCapabilityProjection()
const SUPPLIED = projectCapabilityManifest(structuredClone(PINNED_EMBEDDED_MANIFEST))
const GENERATION = 1
const OBSERVED_AT_MS = 1_787_166_400_000
const RECEIPT_KEYS = ['actions', 'contract', 'digest', 'generation', 'observedAtMs', 'product', 'receiptDigest', 'source', 'status']

function input(mutate) {
  const value = { runtimeMode: 'EMBEDDED', projection: EMBEDDED, generation: GENERATION, observedAtMs: OBSERVED_AT_MS }
  mutate?.(value)
  return value
}

function externalInput(mutate) {
  const value = { runtimeMode: 'EXTERNAL', projection: SUPPLIED, generation: GENERATION, observedAtMs: OBSERVED_AT_MS }
  mutate?.(value)
  return value
}

function denied(value, code) {
  assert.throws(() => createReadbackReceipt(value), (error) => error.code === code)
}

function resealed(projection) {
  const body = Object.fromEntries(Object.entries(projection).filter(([key]) => key !== 'projectionDigest'))
  projection.projectionDigest = sha256Digest(body)
  return projection
}

function receiptBody(receipt) {
  return Object.fromEntries(Object.entries(receipt).filter(([key]) => key !== 'receiptDigest'))
}

function assertExactReceipt(receipt, source) {
  assert.deepEqual(Object.keys(receipt).sort(), RECEIPT_KEYS)
  assert.equal(receipt.source, source)
  assert.deepEqual(receipt.product, { id: 'superset-bi-agent', version: 'v0.16.0' })
  assert.deepEqual(receipt.contract, { id: 'superset-bi-agent.external', version: '2.0.0' })
  assert.equal(receipt.digest, PINNED_EMBEDDED_DIGEST)
  assert.deepEqual(receipt.actions.map((action) => action.action), STABLE_ACTIONS)
  assert.deepEqual(receipt.actions, EMBEDDED.actions)
  assert.equal(receipt.generation, GENERATION)
  assert.equal(receipt.observedAtMs, OBSERVED_AT_MS)
  assert.equal(receipt.status, 'READY')
  assert.equal(receipt.receiptDigest, sha256Digest(receiptBody(receipt)))
  assert(Object.isFrozen(receipt))
  assert(Object.isFrozen(receipt.product))
  assert(Object.isFrozen(receipt.contract))
  assert(Object.isFrozen(receipt.actions))
  assert(receipt.actions.every((action) => Object.isFrozen(action)))
}

test('a valid EMBEDDED receipt binds the embedded projection source and the exact pinned digest', () => {
  const receipt = createReadbackReceipt(input())
  assertExactReceipt(receipt, 'embedded')
  const again = createReadbackReceipt(input())
  assert.equal(canonicalJson(receipt), canonicalJson(again))
  assert.equal(again.receiptDigest, receipt.receiptDigest)
})

test('a valid EXTERNAL receipt binds the supplied projection source and the exact pinned digest', () => {
  const receipt = createReadbackReceipt(externalInput())
  assertExactReceipt(receipt, 'supplied')
  assert.equal(receipt.digest, PINNED_EMBEDDED_DIGEST)
  assert.equal(receipt.source, 'supplied')
})

test('same inputs with reordered object keys yield identical receipt bytes and digest', () => {
  const base = createReadbackReceipt(input())
  const reorderedInput = createReadbackReceipt({ observedAtMs: OBSERVED_AT_MS, generation: GENERATION, projection: EMBEDDED, runtimeMode: 'EMBEDDED' })
  assert.equal(reorderedInput.receiptDigest, base.receiptDigest)
  assert.equal(canonicalJson(reorderedInput), canonicalJson(base))
  const projectionKeys = ['projectionDigest', 'actions', 'digest', 'contract', 'freshness', 'source', 'product', 'schemaVersion']
  const shuffledProjection = Object.fromEntries(projectionKeys.map((key) => [key, EMBEDDED[key]]))
  const viaShuffled = createReadbackReceipt(input((value) => { value.projection = shuffledProjection }))
  assert.equal(viaShuffled.receiptDigest, base.receiptDigest)
  assert.equal(canonicalJson(viaShuffled), canonicalJson(base))
})

test('receipts are deterministic and inputs are not mutated', () => {
  const projection = structuredClone(EMBEDDED)
  const before = canonicalJson({ runtimeMode: 'EMBEDDED', projection, generation: GENERATION, observedAtMs: OBSERVED_AT_MS })
  const first = createReadbackReceipt(input((value) => { value.projection = projection }))
  const second = createReadbackReceipt(input((value) => { value.projection = projection }))
  assert.equal(first.receiptDigest, second.receiptDigest)
  assert.equal(canonicalJson(first), canonicalJson(second))
  assert.equal(canonicalJson(projection), canonicalJson(EMBEDDED))
  assert.equal(canonicalJson({ runtimeMode: 'EMBEDDED', projection, generation: GENERATION, observedAtMs: OBSERVED_AT_MS }), before)
})

test('runtime mode must bind to the projection source; mismatches and foreign modes deny', () => {
  denied(input((value) => { value.projection = SUPPLIED }), 'KS_DSH_RECEIPT_MODE_SOURCE_MISMATCH')
  denied(externalInput((value) => { value.projection = EMBEDDED }), 'KS_DSH_RECEIPT_MODE_SOURCE_MISMATCH')
  denied(input((value) => { value.runtimeMode = 'embedded' }), 'KS_DSH_RECEIPT_MODE_INVALID')
  denied(input((value) => { value.runtimeMode = 'EXTERNAL-FORGE' }), 'KS_DSH_RECEIPT_MODE_INVALID')
  denied(input((value) => { value.runtimeMode = 42 }), 'KS_DSH_RECEIPT_MODE_INVALID')
  denied(input((value) => { value.runtimeMode = null }), 'KS_DSH_RECEIPT_MODE_INVALID')
})

test('generation must be a safe integer >= 1; zero and gap-shaped values deny', () => {
  for (const generation of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, null, undefined, '1', true]) {
    denied(input((value) => { value.generation = generation }), 'KS_DSH_RECEIPT_GENERATION_INVALID')
  }
  assert.doesNotThrow(() => createReadbackReceipt(input((value) => { value.generation = Number.MAX_SAFE_INTEGER })))
  assert.doesNotThrow(() => createReadbackReceipt(input((value) => { value.generation = 2 })))
})

test('observedAtMs must be a bounded positive safe integer; invalid times deny', () => {
  for (const observedAtMs of [0, -1, 1.5, NaN, Infinity, '2026-08-23T00:00:00Z', null, 8_640_000_000_000_000]) {
    denied(input((value) => { value.observedAtMs = observedAtMs }), 'KS_DSH_RECEIPT_OBSERVED_AT_INVALID')
  }
  assert.doesNotThrow(() => createReadbackReceipt(input((value) => { value.observedAtMs = 1 })))
})

test('projection, action, and authority drift deny', () => {
  const driftedAuthority = structuredClone(EMBEDDED)
  driftedAuthority.actions[2].authority = 'source-write'
  denied(input((value) => { value.projection = driftedAuthority }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
  const driftedCapability = structuredClone(EMBEDDED)
  driftedCapability.actions[0].capabilityId = 'bi.status.read-v2'
  denied(input((value) => { value.projection = driftedCapability }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
  const driftedDigest = structuredClone(EMBEDDED)
  driftedDigest.digest = `sha256:${'0'.repeat(64)}`
  denied(input((value) => { value.projection = driftedDigest }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
  const driftedContract = structuredClone(EMBEDDED)
  driftedContract.contract = { id: 'superset-bi-agent.external', version: '3.0.0' }
  denied(input((value) => { value.projection = driftedContract }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
  const missingAction = structuredClone(EMBEDDED)
  missingAction.actions = missingAction.actions.slice(0, 5)
  denied(input((value) => { value.projection = missingAction }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
  const staleSchema = structuredClone(EMBEDDED)
  staleSchema.schemaVersion = 'kaleidosphere.dsh/capability-projection/v0'
  denied(input((value) => { value.projection = staleSchema }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
})

test('a reordered or re-digested forged projection denies despite a self-consistent seal', () => {
  const reordered = structuredClone(EMBEDDED)
  reordered.actions = [...reordered.actions].reverse()
  resealed(reordered)
  assert.equal(reordered.projectionDigest, sha256Digest(Object.fromEntries(Object.entries(reordered).filter(([key]) => key !== 'projectionDigest'))))
  denied(input((value) => { value.projection = reordered }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
  const forged = structuredClone(EMBEDDED)
  forged.actions[1].nonMutating = false
  const body = Object.fromEntries(Object.entries(forged).filter(([key]) => key !== 'projectionDigest'))
  forged.projectionDigest = sha256Digest(body)
  assert.equal(forged.projectionDigest, sha256Digest(body))
  denied(input((value) => { value.projection = forged }), 'KS_DSH_RECEIPT_PROJECTION_DRIFT')
  const brokenSeal = structuredClone(EMBEDDED)
  brokenSeal.projectionDigest = sha256Digest({ ...body, note: 'forged' })
  denied(input((value) => { value.projection = brokenSeal }), 'KS_DSH_RECEIPT_PROJECTION_TAMPERED')
})

test('unknown fields, claims, credentials, paths, URLs, free text, and executables deny', () => {
  const cases = [
    (value) => { value.note = 'operator approved' },
    (value) => { value.receiptId = 'ks-readback-0001' },
    (value) => { value.claims = { authority: 'full-mutation' } },
    (value) => { value.credentials = { password: 'hunter2' } },
    (value) => { value.path = '/etc/passwd' },
    (value) => { value.url = 'https://example.internal/callback' },
    (value) => { value.callback = () => {} },
    (value) => { value.freeText = 'please expedite' },
  ]
  for (const mutate of cases) denied(input(mutate), 'KS_DSH_RECEIPT_SURFACE_INVALID')
  const claimed = structuredClone(EMBEDDED)
  claimed.note = 'claims full mutation'
  denied(input((value) => { value.projection = claimed }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
  denied(input((value) => { delete value.observedAtMs }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
  denied(input((value) => { delete value.projection }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
})

test('projection surface violations deny', () => {
  for (const projection of [null, undefined, 42, 'projection', [EMBEDDED]]) {
    denied(input((value) => { value.projection = projection }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
  }
  const noDigest = structuredClone(EMBEDDED)
  delete noDigest.projectionDigest
  denied(input((value) => { value.projection = noDigest }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
  const extraFreshness = structuredClone(EMBEDDED)
  extraFreshness.freshness.strict = true
  denied(input((value) => { value.projection = extraFreshness }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
  const notAnArray = structuredClone(EMBEDDED)
  notAnArray.actions = { ...notAnArray.actions[0] }
  denied(input((value) => { value.projection = notAnArray }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
  const keylessAction = structuredClone(EMBEDDED)
  delete keylessAction.actions[0].nonMutating
  denied(input((value) => { value.projection = keylessAction }), 'KS_DSH_RECEIPT_SURFACE_INVALID')
})

test('the receipt carries only the closed binding fields; no ids, notes, paths, URLs, or executables remain', () => {
  const receipt = createReadbackReceipt(input())
  assert.deepEqual(Object.keys(receipt).sort(), RECEIPT_KEYS)
  assert.deepEqual(Object.keys(receipt.product), ['id', 'version'])
  assert.deepEqual(Object.keys(receipt.contract), ['id', 'version'])
  for (const action of receipt.actions) {
    assert.deepEqual(Object.keys(action).sort(), ['action', 'authority', 'capabilityId', 'digest', 'nonMutating'])
  }
  const text = canonicalJson(receipt)
  for (const forbidden of ['://', '/', '=', 'http', 'password', 'callback', 'note', 'id:']) {
    assert(!text.includes(forbidden), forbidden)
  }
})