import assert from 'node:assert/strict'
import test from 'node:test'

import {
  ATTESTATION_SCHEMA,
  CONTRACT_VERSION,
  embeddedCapabilityProjection,
  EMBEDDED_PROVENANCE,
  PINNED_CAPABILITIES,
  PINNED_EMBEDDED_DIGEST,
  PINNED_EMBEDDED_MANIFEST,
  PROJECTION_SCHEMA,
  PRODUCT_VERSION,
  projectCapabilityManifest,
  resolveCapabilityManifest,
  STABLE_ACTIONS,
} from '../lib/capability-manifest.mjs'
import {
  canonicalJson,
  capabilityAttestationV2,
  sha256Digest,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import {
  EXTERNAL_INTENT_CAPABILITY_MAP,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-intent-evidence-bridge.mjs'

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/
const TRUSTED_ACTIONS = ['trusted-apply', 'trusted-readback', 'trusted-rollback']

function supplied(mutate) {
  const manifest = structuredClone(PINNED_EMBEDDED_MANIFEST)
  mutate?.(manifest)
  return manifest
}

function resealed(mutate) {
  return supplied((manifest) => {
    mutate(manifest)
    const body = Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== 'attestation'))
    manifest.attestation = { algorithm: 'sha256-canonical-json', digest: sha256Digest(body) }
  })
}

function denied(manifest, code) {
  assert.throws(() => projectCapabilityManifest(manifest), (error) => error.code === code)
}

function manifestBody(manifest) {
  return Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== 'attestation'))
}

function assertExactProjection(projection, source) {
  assert.equal(projection.schemaVersion, PROJECTION_SCHEMA)
  assert.equal(projection.source, source)
  assert.deepEqual(projection.product, { id: 'superset-bi-agent', version: PRODUCT_VERSION })
  assert.deepEqual(projection.contract, { id: 'superset-bi-agent.external', version: CONTRACT_VERSION })
  assert.equal(projection.digest, PINNED_EMBEDDED_DIGEST)
  assert.deepEqual(projection.freshness, {
    state: 'fresh',
    provenance: EMBEDDED_PROVENANCE,
    product: PRODUCT_VERSION,
    contract: CONTRACT_VERSION,
  })
  assert.equal(projection.actions.length, STABLE_ACTIONS.length)
  assert.deepEqual(projection.actions.map((action) => action.action), STABLE_ACTIONS)
  assert(projection.actions.every((action) => !TRUSTED_ACTIONS.includes(action.action)))
  for (const action of projection.actions) {
    const pinned = EXTERNAL_INTENT_CAPABILITY_MAP[action.action]
    assert.equal(action.capabilityId, pinned.capabilityId)
    assert.equal(action.authority, pinned.authority)
    assert.equal(action.nonMutating, true)
    assert.equal(action.digest, PINNED_EMBEDDED_DIGEST)
  }
  const body = Object.fromEntries(Object.entries(projection).filter(([key]) => key !== 'projectionDigest'))
  assert.equal(projection.projectionDigest, sha256Digest(body))
  assert(Object.isFrozen(projection))
  assert(Object.isFrozen(projection.actions))
  assert(projection.actions.every((action) => Object.isFrozen(action)))
}

test('pinned embedded fallback is explicit, self-consistent, and matches the vendored producer', () => {
  assert.match(PINNED_EMBEDDED_DIGEST, DIGEST_PATTERN)
  assert.equal(ATTESTATION_SCHEMA, 'superset-bi-agent.external/capability-attestation/v2')
  assert.equal(PINNED_EMBEDDED_MANIFEST.attestation.digest, PINNED_EMBEDDED_DIGEST)
  assert.equal(sha256Digest(manifestBody(PINNED_EMBEDDED_MANIFEST)), PINNED_EMBEDDED_DIGEST)
  assert(Object.isFrozen(PINNED_EMBEDDED_MANIFEST))
  assert(Object.isFrozen(PINNED_EMBEDDED_MANIFEST.capabilities))
  assert.equal(PINNED_CAPABILITIES.length, 9)
  assert.equal(canonicalJson(PINNED_EMBEDDED_MANIFEST), canonicalJson(capabilityAttestationV2()))
})

test('a valid supplied attestation projects exactly the six stable actions with full bindings', () => {
  assertExactProjection(projectCapabilityManifest(structuredClone(PINNED_EMBEDDED_MANIFEST)), 'supplied')
  // The frozen producer output must validate without being mutated.
  const attestation = capabilityAttestationV2()
  assertExactProjection(projectCapabilityManifest(attestation), 'supplied')
  assert.equal(canonicalJson(attestation), canonicalJson(capabilityAttestationV2()))
})

test('the embedded fallback projection and resolver default are the explicit pin', () => {
  assertExactProjection(embeddedCapabilityProjection(), 'embedded')
  assertExactProjection(resolveCapabilityManifest(), 'embedded')
  assertExactProjection(resolveCapabilityManifest({}), 'embedded')
  assertExactProjection(resolveCapabilityManifest({ supplied: null }), 'embedded')
  assert(canonicalJson(resolveCapabilityManifest()) === canonicalJson(embeddedCapabilityProjection()))
})

test('the resolver binds a supplied manifest and fails closed instead of falling back', () => {
  assertExactProjection(resolveCapabilityManifest({ supplied: capabilityAttestationV2() }), 'supplied')
  const stale = supplied((manifest) => { manifest.product.version = 'v0.15.9' })
  const body = manifestBody(stale)
  stale.attestation = { algorithm: 'sha256-canonical-json', digest: sha256Digest(body) }
  assert.throws(() => resolveCapabilityManifest({ supplied: stale }), (error) => error.code === 'KS_DSH_MANIFEST_PRODUCT_STALE')
})

test('stale product, contract, and schema versions are hidden', () => {
  denied(resealed((manifest) => { manifest.product.version = 'v0.15.9' }), 'KS_DSH_MANIFEST_PRODUCT_STALE')
  denied(resealed((manifest) => { manifest.product.id = 'superset-bi-agent-legacy' }), 'KS_DSH_MANIFEST_PRODUCT_STALE')
  denied(resealed((manifest) => { manifest.product.component = 'bi-agent-preview' }), 'KS_DSH_MANIFEST_PRODUCT_STALE')
  denied(resealed((manifest) => { manifest.contract.version = '1.0.0' }), 'KS_DSH_MANIFEST_CONTRACT_STALE')
  denied(resealed((manifest) => { manifest.contract.id = 'superset-bi-agent.external-legacy' }), 'KS_DSH_MANIFEST_CONTRACT_STALE')
  denied(resealed((manifest) => { manifest.schemaVersion = 'superset-bi-agent.external/capability-attestation/v1' }), 'KS_DSH_MANIFEST_SCHEMA_STALE')
})

test('tampered attestations are hidden', () => {
  const zeroDigest = supplied((manifest) => { manifest.attestation.digest = `sha256:${'0'.repeat(64)}` })
  denied(zeroDigest, 'KS_DSH_MANIFEST_TAMPERED')
  const foreignBodyDigest = supplied((manifest) => {
    const body = manifestBody(manifest)
    manifest.attestation.digest = sha256Digest({ ...body, contract: { ...body.contract, version: '9.9.9' } })
  })
  denied(foreignBodyDigest, 'KS_DSH_MANIFEST_TAMPERED')
  const unsealedGraph = supplied((manifest) => { manifest.graph.acceptedIncumbent = 'candidate-x' })
  denied(unsealedGraph, 'KS_DSH_MANIFEST_GRAPH_STALE')
  const unsealedRawRows = supplied((manifest) => { manifest.boundaries.rawSourceRowsReturned = true })
  denied(unsealedRawRows, 'KS_DSH_MANIFEST_BOUNDARIES_WIDENED')
})

test('unknown and missing capabilities are hidden', () => {
  const extra = resealed((manifest) => {
    manifest.capabilities.push({ id: 'bi.free-sql.run', action: 'free-sql', authority: 'full-mutation', externalIntent: true })
  })
  denied(extra, 'KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
  const duplicate = resealed((manifest) => {
    manifest.capabilities.push({ id: 'bi.status.read', action: 'status', authority: 'read-only' })
  })
  denied(duplicate, 'KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
  const renamed = resealed((manifest) => {
    manifest.capabilities.find((entry) => entry.id === 'bi.readback.read').action = 'readback-v2'
  })
  denied(renamed, 'KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
  const missing = resealed((manifest) => {
    manifest.capabilities = manifest.capabilities.filter((entry) => entry.id !== 'bi.readback.read')
  })
  denied(missing, 'KS_DSH_MANIFEST_CAPABILITY_MISSING')
  const keyless = resealed((manifest) => {
    manifest.capabilities.push({ action: 'status', authority: 'read-only' })
  })
  denied(keyless, 'KS_DSH_MANIFEST_SURFACE_INVALID')
})

test('widened capabilities and boundaries are hidden', () => {
  const widened = resealed((manifest) => {
    manifest.capabilities.find((entry) => entry.id === 'bi.status.read').authority = 'source-write'
  })
  denied(widened, 'KS_DSH_MANIFEST_CAPABILITY_WIDENED')
  const narrowed = resealed((manifest) => {
    manifest.capabilities.find((entry) => entry.id === 'bi.analysis.run').authority = 'read-only'
  })
  denied(narrowed, 'KS_DSH_MANIFEST_CAPABILITY_WIDENED')
  const externalized = resealed((manifest) => {
    manifest.capabilities.find((entry) => entry.id === 'superset.trusted-apply').externalIntent = true
  })
  denied(externalized, 'KS_DSH_MANIFEST_CAPABILITY_WIDENED')
  const freeSql = resealed((manifest) => {
    manifest.boundaries.freeSqlAccepted = true
  })
  denied(freeSql, 'KS_DSH_MANIFEST_BOUNDARIES_WIDENED')
  const mutation = resealed((manifest) => {
    manifest.boundaries.modelMutationAuthority = true
  })
  denied(mutation, 'KS_DSH_MANIFEST_BOUNDARIES_WIDENED')
  const graph = resealed((manifest) => {
    manifest.graph.candidatePromotion = 'candidate-v1'
  })
  denied(graph, 'KS_DSH_MANIFEST_GRAPH_STALE')
})

test('surface and digest-shape violations fail closed', () => {
  for (const value of [null, undefined, 42, 'attestation', ['schemaVersion']]) {
    assert.throws(() => projectCapabilityManifest(value), (error) => error.code === 'KS_DSH_MANIFEST_SURFACE_INVALID')
  }
  const extraKey = resealed((manifest) => { manifest.debug = true })
  denied(extraKey, 'KS_DSH_MANIFEST_SURFACE_INVALID')
  const noAttestation = supplied((manifest) => { delete manifest.attestation })
  denied(noAttestation, 'KS_DSH_MANIFEST_SURFACE_INVALID')
  const extraTopKey = resealed((manifest) => { manifest.boundaries.strict = false })
  denied(extraTopKey, 'KS_DSH_MANIFEST_SURFACE_INVALID')
  const wrongAlgorithm = supplied((manifest) => { manifest.attestation.algorithm = 'sha256' })
  denied(wrongAlgorithm, 'KS_DSH_MANIFEST_DIGEST_INVALID')
  const shortDigest = supplied((manifest) => { manifest.attestation.digest = 'sha256:abc' })
  denied(shortDigest, 'KS_DSH_MANIFEST_DIGEST_INVALID')
  const upperDigest = supplied((manifest) => {
    const body = manifestBody(manifest)
    manifest.attestation.digest = sha256Digest(body).toUpperCase()
  })
  denied(upperDigest, 'KS_DSH_MANIFEST_DIGEST_INVALID')
})

test('projections are deterministic and inputs are not mutated', () => {
  const before = structuredClone(PINNED_EMBEDDED_MANIFEST)
  const first = projectCapabilityManifest(structuredClone(before))
  const second = projectCapabilityManifest(structuredClone(before))
  assert.equal(canonicalJson(first), canonicalJson(second))
  assert.equal(canonicalJson(before), canonicalJson(PINNED_EMBEDDED_MANIFEST))
  const embeddedFirst = embeddedCapabilityProjection()
  const embeddedSecond = embeddedCapabilityProjection()
  assert.equal(canonicalJson(embeddedFirst), canonicalJson(embeddedSecond))
})

test('trusted capabilities stay known but hidden from the pin table and projection', () => {
  const trusted = PINNED_CAPABILITIES.filter((entry) => TRUSTED_ACTIONS.includes(entry.action))
  assert.equal(trusted.length, 3)
  assert(trusted.every((entry) => entry.externalIntent === false && entry.authority === 'trusted-approval-only'))
  const projected = new Set(embeddedCapabilityProjection().actions.map((action) => action.capabilityId))
  assert(trusted.every((entry) => !projected.has(entry.id)))
})