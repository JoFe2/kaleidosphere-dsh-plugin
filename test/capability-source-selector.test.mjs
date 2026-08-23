import assert from 'node:assert/strict'
import test from 'node:test'

import {
  embeddedCapabilityProjection,
  PINNED_EMBEDDED_DIGEST,
  PINNED_EMBEDDED_MANIFEST,
  PROJECTION_SCHEMA,
  projectCapabilityManifest,
  STABLE_ACTIONS,
} from '../lib/capability-manifest.mjs'
import {
  selectCapabilitySource,
  SOURCE_DECISION_SCHEMA,
  SOURCE_MODES,
} from '../lib/capability-source-selector.mjs'
import {
  canonicalJson,
  capabilityAttestationV2,
  sha256Digest,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/

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

function denied(fn, code) {
  assert.throws(fn, (error) => error.code === code)
}

function assertDecision(decision, mode, source) {
  assert.equal(decision.schemaVersion, SOURCE_DECISION_SCHEMA)
  assert.equal(decision.mode, mode)
  assert.equal(decision.source, source)
  assert.equal(decision.projectionDigest, decision.projection.projectionDigest)
  const projection = decision.projection
  assert.equal(projection.schemaVersion, PROJECTION_SCHEMA)
  assert.equal(projection.source, source === 'embedded' ? 'embedded' : 'supplied')
  assert.equal(projection.digest, PINNED_EMBEDDED_DIGEST)
  assert.equal(projection.actions.length, STABLE_ACTIONS.length)
  assert(Object.isFrozen(decision))
  assert(Object.isFrozen(decision.projection))
  assert(Object.isFrozen(decision.projection.actions))
}

test('EMBEDDED selects the exact pinned embedded projection without a supplied manifest', () => {
  const decision = selectCapabilitySource({ mode: 'EMBEDDED', supplied: null })
  assertDecision(decision, 'EMBEDDED', 'embedded')
  assert.equal(canonicalJson(decision.projection), canonicalJson(embeddedCapabilityProjection()))
  // Deterministic: identical inputs produce identical frozen decisions.
  assert.equal(canonicalJson(selectCapabilitySource({ mode: 'EMBEDDED', supplied: null })), canonicalJson(decision))
})

test('EXTERNAL with the exact pinned supplied manifest selects the supplied projection and binds its digest and source', () => {
  const decision = selectCapabilitySource({ mode: 'EXTERNAL', supplied: capabilityAttestationV2() })
  assertDecision(decision, 'EXTERNAL', 'external')
  assert.equal(decision.projection.digest, PINNED_EMBEDDED_DIGEST)
  assert.equal(decision.projection.source, 'supplied')
  assert.equal(canonicalJson(decision.projection), canonicalJson(projectCapabilityManifest(structuredClone(PINNED_EMBEDDED_MANIFEST))))
  // The frozen producer output must be accepted without being mutated.
  const attestation = capabilityAttestationV2()
  assert.equal(canonicalJson(selectCapabilitySource({ mode: 'EXTERNAL', supplied: attestation }).projection), canonicalJson(projectCapabilityManifest(attestation)))
  assert.equal(canonicalJson(attestation), canonicalJson(capabilityAttestationV2()))
})

test('missing external evidence denies and never falls back to the embedded pin', () => {
  denied(() => selectCapabilitySource({ mode: 'EXTERNAL', supplied: null }), 'KS_DSH_SOURCE_EXTERNAL_MANIFEST_MISSING')
  denied(() => selectCapabilitySource({ mode: 'EXTERNAL', supplied: undefined }), 'KS_DSH_SOURCE_EXTERNAL_MANIFEST_MISSING')
})

test('unknown modes and unknown or missing input fields deny', () => {
  // Missing required fields.
  denied(() => selectCapabilitySource({ supplied: null }), 'KS_DSH_SOURCE_SURFACE_INVALID')
  denied(() => selectCapabilitySource({ mode: 'EMBEDDED' }), 'KS_DSH_SOURCE_SURFACE_INVALID')
  for (const options of [null, undefined, 'EMBEDDED', ['EMBEDDED'], 42]) {
    denied(() => selectCapabilitySource(options), 'KS_DSH_SOURCE_SURFACE_INVALID')
  }
  // Unknown mode values (case, spacing, and non-strings included).
  for (const mode of ['', 'embedded', 'Embedded', 'embedded-only', 'EXTERNAL ', 42, null]) {
    denied(() => selectCapabilitySource({ mode, supplied: null }), 'KS_DSH_SOURCE_MODE_UNKNOWN')
  }
})

test('a supplied manifest in EMBEDDED mode denies: embedded needs no supplied evidence', () => {
  denied(() => selectCapabilitySource({ mode: 'EMBEDDED', supplied: capabilityAttestationV2() }), 'KS_DSH_SOURCE_EMBEDDED_MANIFEST_SUPPLIED')
  denied(() => selectCapabilitySource({ mode: 'EMBEDDED', supplied: {} }), 'KS_DSH_SOURCE_EMBEDDED_MANIFEST_SUPPLIED')
})

test('tampered, stale, and resealed external evidence denies with the manifest failure code and never falls back', () => {
  const tampered = supplied((manifest) => { manifest.attestation.digest = `sha256:${'0'.repeat(64)}` })
  denied(() => selectCapabilitySource({ mode: 'EXTERNAL', supplied: tampered }), 'KS_DSH_MANIFEST_TAMPERED')
  const staleProduct = resealed((manifest) => { manifest.product.version = 'v0.15.9' })
  denied(() => selectCapabilitySource({ mode: 'EXTERNAL', supplied: staleProduct }), 'KS_DSH_MANIFEST_PRODUCT_STALE')
  const widened = resealed((manifest) => { manifest.boundaries.freeSqlAccepted = true })
  denied(() => selectCapabilitySource({ mode: 'EXTERNAL', supplied: widened }), 'KS_DSH_MANIFEST_BOUNDARIES_WIDENED')
  // Digest substitution: a self-consistent digest that is not the pinned one.
  const reordered = resealed((manifest) => { manifest.capabilities = manifest.capabilities.reverse() })
  assert.equal(reordered.attestation.digest, sha256Digest(Object.fromEntries(Object.entries(reordered).filter(([key]) => key !== 'attestation'))))
  assert.notEqual(reordered.attestation.digest, PINNED_EMBEDDED_DIGEST)
  denied(() => selectCapabilitySource({ mode: 'EXTERNAL', supplied: reordered }), 'KS_DSH_MANIFEST_DIGEST_STALE')
})

test('no credential, path, free-text, service URL, or authority field is accepted or projected', () => {
  for (const extra of [
    { serviceUrl: 'https://superset.internal/v2' },
    { credential: 'password' },
    { path: '/var/lib/kaleidosphere' },
    { note: 'free text' },
    { authority: 'trusted-approval-only' },
  ]) {
    denied(() => selectCapabilitySource({ mode: 'EMBEDDED', supplied: null, ...extra }), 'KS_DSH_SOURCE_SURFACE_INVALID')
  }
  for (const [mode, suppliedValue] of [['EMBEDDED', null], ['EXTERNAL', structuredClone(PINNED_EMBEDDED_MANIFEST)]]) {
    const decision = selectCapabilitySource({ mode, supplied: suppliedValue })
    assert.deepEqual(Object.keys(decision).sort(), ['mode', 'projection', 'projectionDigest', 'schemaVersion', 'source'])
    const strings = Object.values(decision).filter((value) => typeof value === 'string')
    assert.ok(strings.every((value) =>
      value === SOURCE_DECISION_SCHEMA || value === mode || value === (mode === 'EMBEDDED' ? 'embedded' : 'external') || DIGEST_PATTERN.test(value)))
  }
})

test('source modes are a closed frozen surface and inputs are not mutated', () => {
  assert.deepEqual(SOURCE_MODES, ['EMBEDDED', 'EXTERNAL'])
  assert(Object.isFrozen(SOURCE_MODES))
  const manifest = structuredClone(PINNED_EMBEDDED_MANIFEST)
  const before = canonicalJson(manifest)
  selectCapabilitySource({ mode: 'EXTERNAL', supplied: manifest })
  assert.equal(canonicalJson(manifest), before)
})