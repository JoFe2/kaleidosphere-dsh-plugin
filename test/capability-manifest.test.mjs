import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import {
  ATTESTATION_SCHEMA,
  CONTRACT_VERSION,
  embeddedCapabilityProjection,
  EMBEDDED_PROVENANCE,
  PINNED_CAPABILITIES,
  PINNED_EMBEDDED_DIGEST,
  PINNED_EMBEDDED_MANIFEST,
  PINNED_V0240_PINS,
  PROJECTION_SCHEMA,
  PRODUCT_VERSION,
  projectCapabilityManifest,
  resolveCapabilityManifest,
  STABLE_ACTIONS,
  V0240_AUTHORITY_SURFACE,
  V0240_SOURCE_COMMIT,
  verifyV0240PinTable,
} from '../lib/capability-manifest.mjs'
import {
  canonicalJson,
  capabilityAttestationV2,
  sha256Digest,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import {
  EXTERNAL_INTENT_CAPABILITY_MAP,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-intent-evidence-bridge.mjs'
import {
  buildObjectCapabilityContractV1,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-capability-contract-v1.mjs'

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
  assert(Object.isFrozen(projection.product))
  assert(Object.isFrozen(projection.contract))
  assert(Object.isFrozen(projection.freshness))
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

test('a resealed reordered manifest is denied: the self-consistent digest must equal the pin', () => {
  const reordered = resealed((manifest) => {
    manifest.capabilities = manifest.capabilities.reverse()
  })
  assert.notEqual(reordered.attestation.digest, PINNED_EMBEDDED_DIGEST)
  assert.equal(reordered.attestation.digest, sha256Digest(manifestBody(reordered)))
  denied(reordered, 'KS_DSH_MANIFEST_DIGEST_STALE')
  const swapped = resealed((manifest) => {
    const [first, last] = [manifest.capabilities[0], manifest.capabilities[manifest.capabilities.length - 1]]
    manifest.capabilities[0] = last
    manifest.capabilities[manifest.capabilities.length - 1] = first
  })
  denied(swapped, 'KS_DSH_MANIFEST_DIGEST_STALE')
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

// ---------------------------------------------------------------------------
// KS #65 M2-65-P2B1: closed additive v0.24.0 pin table.
//
// The pin table names exactly the three local v0.24.0 capabilities (Search,
// Details, Overview), binds each to its vendored v0.24.0 handler path with
// exact commit/path/digest provenance from the read-only VENDORED_MANIFEST.json
// v0240 section, and the canonical read-only-evidence-projection /
// PROJECTED_READ_ONLY / all-false (non-mutating) authority surface. Unknown or
// tampered pins fail closed, and the v0.16.0 pin entries stay unchanged.
// ---------------------------------------------------------------------------

const packageRoot = path.resolve(import.meta.dirname, '..')
const V0240_MANIFEST = JSON.parse(readFileSync(new URL('../VENDORED_MANIFEST.json', import.meta.url), 'utf8'))
const V0240_IDS = Object.freeze(['bi.object.search.read', 'bi.object.details.read', 'bi.database.overview.read'])
const V0240_HANDLER_PATHS = Object.freeze({
  'bi.object.search.read': 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-search-handler-v1.mjs',
  'bi.object.details.read': 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-details-handler-v1.mjs',
  'bi.database.overview.read': 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/database-overview-handler-v1.mjs',
})
const V0240_SOURCE_PATHS = Object.freeze({
  'bi.object.search.read': 'services/bi-agent/src/object-search-handler-v1.mjs',
  'bi.object.details.read': 'services/bi-agent/src/object-details-handler-v1.mjs',
  'bi.database.overview.read': 'services/bi-agent/src/database-overview-handler-v1.mjs',
})
const V0240_SHA256 = Object.freeze({
  'bi.object.search.read': '94e7ba13ca85cc10a407900e0049a9fa86e8dccfb6de8d26f90e50af5b492b37',
  'bi.object.details.read': 'abd5c5256737c8771c50ed7138be5fec4ed92b9fb791f46da6aaba2ec2fd8b79',
  'bi.database.overview.read': 'e015f9e408b676bdba7f55740b504bb364c66744c3f24e5a60aa938e4ca8f8a1',
})
// The seven authority flags the vendored object-capability contract requires
// to be false in every result (AUTHORITY_KEYS in object-capability-contract-v1.mjs).
const V0240_AUTHORITY_FLAG_KEYS = Object.freeze([
  'credentialsIncluded', 'dispatchAuthority', 'executionAuthority', 'mutationAuthority',
  'queryExecution', 'rawValuesIncluded', 'sqlAuthority',
])

function v0240Table(mutate) {
  const table = structuredClone(PINNED_V0240_PINS)
  mutate?.(table)
  return table
}

function v0240Denied(mutate, code) {
  assert.throws(() => verifyV0240PinTable(v0240Table(mutate)), (error) => error.code === code)
}

test('the v0.24.0 pin table is closed: exactly the three local capability ids', () => {
  assert.equal(PINNED_V0240_PINS.length, 3)
  assert.equal(new Set(PINNED_V0240_PINS.map((pin) => pin.id)).size, 3)
  assert.deepEqual(PINNED_V0240_PINS.map((pin) => pin.id).sort(), V0240_IDS.slice().sort())
  // No v0.16.0 capability id and no fourth entry may appear in the closed set.
  for (const v016 of PINNED_CAPABILITIES) {
    assert(!PINNED_V0240_PINS.some((pin) => pin.id === v016.id), v016.id)
  }
  assert(Object.isFrozen(PINNED_V0240_PINS))
  assert(PINNED_V0240_PINS.every((pin) => Object.isFrozen(pin)
    && Object.isFrozen(pin.provenance)
    && Object.isFrozen(pin.authoritySurface)))
})

test('each v0.24.0 pin binds the vendored v0.24.0 handler path and the read-only file exists', () => {
  for (const pin of PINNED_V0240_PINS) {
    assert.equal(pin.handlerPath, V0240_HANDLER_PATHS[pin.id])
    assert.equal(pin.provenance.vendorPath, pin.handlerPath)
    assert.ok(existsSync(path.resolve(packageRoot, pin.handlerPath)), `missing ${pin.handlerPath}`)
  }
})

test('each v0.24.0 pin provenance is byte-for-byte the VENDORED_MANIFEST.json v0240 entry', () => {
  assert.equal(V0240_MANIFEST.v0240.commit, V0240_SOURCE_COMMIT)
  assert.equal(V0240_SOURCE_COMMIT, 'e092bb0bce039936b88329793b24e9f987ae0ddb')
  for (const pin of PINNED_V0240_PINS) {
    // Independently pinned values (hermetic), matching the closure test pins.
    assert.equal(pin.provenance.sourceCommit, V0240_SOURCE_COMMIT)
    assert.equal(pin.provenance.sourcePath, V0240_SOURCE_PATHS[pin.id])
    assert.equal(pin.provenance.vendorPath, V0240_HANDLER_PATHS[pin.id])
    assert.equal(pin.provenance.sha256, V0240_SHA256[pin.id])
    // And byte-for-byte equal to the matching read-only manifest entry.
    const entry = V0240_MANIFEST.v0240.files.find((item) => item.vendorPath === pin.handlerPath)
    assert.ok(entry, `not listed in VENDORED_MANIFEST.json: ${pin.handlerPath}`)
    assert.deepEqual(pin.provenance, entry)
    assert.deepEqual(Object.keys(pin.provenance).sort(), ['sha256', 'sourceCommit', 'sourcePath', 'vendorPath'])
  }
})

test('every v0.24.0 pin declares the read-only, non-mutating authority surface', () => {
  const contract = buildObjectCapabilityContractV1()
  for (const pin of PINNED_V0240_PINS) {
    const profile = contract.capabilities.find((item) => item.id === pin.id)
    assert.ok(profile, `not a vendored v0.24.0 capability: ${pin.id}`)
    assert.equal(pin.authority, 'read-only-evidence-projection')
    assert.equal(pin.authority, profile.authority)
    assert.equal(pin.state, 'PROJECTED_READ_ONLY')
    assert.deepEqual(Object.keys(pin.authoritySurface).sort(), V0240_AUTHORITY_FLAG_KEYS.slice().sort())
    assert(V0240_AUTHORITY_FLAG_KEYS.every((key) => pin.authoritySurface[key] === false))
    assert.deepEqual(pin.authoritySurface, V0240_AUTHORITY_SURFACE)
  }
})

test('the v0.24.0 pin verifier accepts the closed pinned table', () => {
  assert.equal(verifyV0240PinTable(structuredClone(PINNED_V0240_PINS)), PINNED_V0240_PINS)
})

test('an unknown v0.24.0 capability id is denied', () => {
  v0240Denied((table) => { table[0].id = 'bi.free-sql.run' }, 'KS_DSH_V0240_PIN_UNKNOWN')
  // A v0.16.0 capability id is not a v0.24.0 pin id.
  v0240Denied((table) => { table[0].id = 'bi.status.read' }, 'KS_DSH_V0240_PIN_UNKNOWN')
  v0240Denied((table) => { delete table[0].id }, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
})

test('the closed v0.24.0 pin set cannot be widened or reduced', () => {
  v0240Denied((table) => { table.push(structuredClone(table[0])) }, 'KS_DSH_V0240_PIN_SET_INVALID')
  v0240Denied((table) => { table.push({ ...structuredClone(table[0]), id: 'bi.free-sql.run' }) }, 'KS_DSH_V0240_PIN_SET_INVALID')
  v0240Denied((table) => { table.length = 2 }, 'KS_DSH_V0240_PIN_SET_INVALID')
})

test('a v0.24.0 handler path not listed in the VENDORED_MANIFEST.json v0240 section is denied', () => {
  const unlisted = 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-search-handler-v2.mjs'
  v0240Denied((table) => {
    table[0].handlerPath = unlisted
    table[0].provenance.vendorPath = unlisted
    table[0].provenance.sourcePath = 'services/bi-agent/src/object-search-handler-v2.mjs'
  }, 'KS_DSH_V0240_PIN_PATH_UNLISTED')
})

test('a v0.24.0 pin whose commit, path, or digest does not match the manifest is denied', () => {
  v0240Denied((table) => { table[0].provenance.sha256 = `${'0'.repeat(64)}` }, 'KS_DSH_V0240_PIN_PROVENANCE_MISMATCH')
  // The v0.16.0 source commit is not the v0.24.0 source commit.
  v0240Denied((table) => { table[0].provenance.sourceCommit = '5a73ff8146afa0067d226cffa639efde959e8fde' }, 'KS_DSH_V0240_PIN_PROVENANCE_MISMATCH')
  v0240Denied((table) => { table[0].provenance.sourcePath = V0240_SOURCE_PATHS['bi.object.details.read'] }, 'KS_DSH_V0240_PIN_PROVENANCE_MISMATCH')
  // Cross-wired: the details handler provenance on the search id. Both halves
  // are listed and jointly self-consistent, so only the id/handler binding
  // check can deny it.
  v0240Denied((table) => {
    const search = structuredClone(table[0])
    const details = structuredClone(table[1])
    table[0] = { ...search, handlerPath: details.handlerPath, provenance: details.provenance }
  }, 'KS_DSH_V0240_PIN_PROVENANCE_MISMATCH')
})

test('a v0.24.0 pin with widened authority is denied', () => {
  v0240Denied((table) => { table[0].authority = 'full-execution' }, 'KS_DSH_V0240_PIN_AUTHORITY_WIDENED')
  v0240Denied((table) => { table[0].state = 'EXECUTING' }, 'KS_DSH_V0240_PIN_AUTHORITY_WIDENED')
  v0240Denied((table) => { table[0].authoritySurface.sqlAuthority = true }, 'KS_DSH_V0240_PIN_AUTHORITY_WIDENED')
  v0240Denied((table) => { table[0].authoritySurface.mutationAuthority = true }, 'KS_DSH_V0240_PIN_AUTHORITY_WIDENED')
  v0240Denied((table) => { table[0].authoritySurface.queryExecution = true }, 'KS_DSH_V0240_PIN_AUTHORITY_WIDENED')
  v0240Denied((table) => { delete table[0].authoritySurface.rawValuesIncluded }, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
  v0240Denied((table) => { table[0].authoritySurface.debug = true }, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
})

test('v0.24.0 pin-table surface violations fail closed', () => {
  for (const value of [null, undefined, 42, 'pins', {}]) {
    assert.throws(() => verifyV0240PinTable(value), (error) => error.code === 'KS_DSH_V0240_PIN_SURFACE_INVALID')
  }
  v0240Denied((table) => { table[0].debug = true }, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
  v0240Denied((table) => { table[0].handlerPath = 42 }, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
  // Internally inconsistent: handlerPath disagrees with provenance.vendorPath.
  v0240Denied((table) => { table[0].handlerPath = V0240_HANDLER_PATHS['bi.object.details.read'] }, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
})

test('the v0.16.0 pin entries remain byte-for-byte unchanged after the additive v0.24.0 pin table', () => {
  assert.equal(PINNED_CAPABILITIES.length, 9)
  assert.deepEqual(PINNED_CAPABILITIES, [
    { id: 'bi.status.read', action: 'status', authority: 'read-only' },
    { id: 'bi.discovery.run', action: 'discovery', authority: 'local-evidence-write' },
    { id: 'bi.analysis.run', action: 'analyze', authority: 'source-read-only' },
    { id: 'bi.graph.adaptive-v1.plan', action: 'plan', authority: 'proposal-only' },
    { id: 'bi.preview.create', action: 'preview', authority: 'proposal-only' },
    { id: 'bi.readback.read', action: 'readback', authority: 'read-only' },
    { id: 'superset.trusted-apply', action: 'trusted-apply', authority: 'trusted-approval-only', externalIntent: false },
    { id: 'superset.trusted-readback', action: 'trusted-readback', authority: 'trusted-approval-only', externalIntent: false },
    { id: 'superset.trusted-rollback', action: 'trusted-rollback', authority: 'trusted-approval-only', externalIntent: false },
  ])
  assert.equal(PINNED_EMBEDDED_DIGEST, 'sha256:eb8984c30875a911cb88b01d9a6098a9a4feb5d20db0d47ba708bdb04a158276')
  assert.equal(sha256Digest(manifestBody(PINNED_EMBEDDED_MANIFEST)), PINNED_EMBEDDED_DIGEST)
})