/**
 * KS #64 M1b: closed capability-manifest consumer.
 *
 * Validates a closed supplied KaleidoSphere capability attestation (the
 * External API v2 `GET /v2/capabilities` body) against this consumer's
 * explicit pinned embedded fallback and deterministically projects the exact
 * six stable KS capability actions. A projection only exists for a fresh
 * manifest: stale product or contract versions, unknown capabilities,
 * widened authority or boundaries, and tampered attestation digests all fail
 * closed before any capability is projected. The three pinned non-external
 * `superset.trusted-*` capabilities are known but never projected.
 *
 * Each projected action binds product, contract version, action, the
 * attestation digest, freshness against the pinned provenance, and a
 * non-mutating authority. This module is read-only foundation; the runtime
 * keeps its current attestation source until M2 wiring.
 */
import { readFileSync } from 'node:fs'

import { sha256Digest } from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'

export const PROJECTION_SCHEMA = 'kaleidosphere.dsh/capability-projection/v1'

export const ATTESTATION_SCHEMA = 'superset-bi-agent.external/capability-attestation/v2'
export const PRODUCT_ID = 'superset-bi-agent'
export const PRODUCT_VERSION = 'v0.16.0'
export const PRODUCT_COMPONENT = 'bi-agent-runtime'
export const CONTRACT_ID = 'superset-bi-agent.external'
export const CONTRACT_VERSION = '2.0.0'

/** Pinned provenance of the embedded runtime subset this consumer accepts. */
export const EMBEDDED_PROVENANCE = 'kaleidosphere-v0.16.0@5a73ff8146afa0067d226cffa639efde959e8fde'

/** The six stable KS capability actions in closed canonical order. */
export const STABLE_ACTIONS = Object.freeze(['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'])

/**
 * Closed pin of every capability the embedded v0.16.0 attestation may
 * declare. The three `superset.trusted-*` entries carry `externalIntent:
 * false` and are hidden from every projection.
 */
export const PINNED_CAPABILITIES = Object.freeze([
  Object.freeze({ id: 'bi.status.read', action: 'status', authority: 'read-only' }),
  Object.freeze({ id: 'bi.discovery.run', action: 'discovery', authority: 'local-evidence-write' }),
  Object.freeze({ id: 'bi.analysis.run', action: 'analyze', authority: 'source-read-only' }),
  Object.freeze({ id: 'bi.graph.adaptive-v1.plan', action: 'plan', authority: 'proposal-only' }),
  Object.freeze({ id: 'bi.preview.create', action: 'preview', authority: 'proposal-only' }),
  Object.freeze({ id: 'bi.readback.read', action: 'readback', authority: 'read-only' }),
  Object.freeze({ id: 'superset.trusted-apply', action: 'trusted-apply', authority: 'trusted-approval-only', externalIntent: false }),
  Object.freeze({ id: 'superset.trusted-readback', action: 'trusted-readback', authority: 'trusted-approval-only', externalIntent: false }),
  Object.freeze({ id: 'superset.trusted-rollback', action: 'trusted-rollback', authority: 'trusted-approval-only', externalIntent: false }),
])

const PINNED_GRAPH = Object.freeze({ acceptedIncumbent: 'adaptive-v1', candidatePromotion: 'none' })
const PINNED_BOUNDARIES = Object.freeze({
  sourceDatabaseCredentialsAccepted: false,
  freeSqlAccepted: false,
  rawSourceRowsReturned: false,
  modelMutationAuthority: false,
  directSupersetMutationIntentAccepted: false,
  persistentSupersetWorkflow: 'trusted-preview-approval-apply-readback-rollback-only',
})

const PINNED_BODY = Object.freeze({
  schemaVersion: ATTESTATION_SCHEMA,
  product: Object.freeze({ id: PRODUCT_ID, version: PRODUCT_VERSION, component: PRODUCT_COMPONENT }),
  contract: Object.freeze({ id: CONTRACT_ID, version: CONTRACT_VERSION }),
  capabilities: PINNED_CAPABILITIES,
  graph: PINNED_GRAPH,
  boundaries: PINNED_BOUNDARIES,
})

/**
 * Explicit pin of the embedded fallback attestation digest. The module
 * refuses to load when the pinned body no longer recomputes this value.
 */
export const PINNED_EMBEDDED_DIGEST = 'sha256:eb8984c30875a911cb88b01d9a6098a9a4feb5d20db0d47ba708bdb04a158276'

if (sha256Digest(PINNED_BODY) !== PINNED_EMBEDDED_DIGEST) {
  const error = new Error('KS_DSH_MANIFEST_PIN_TAMPERED')
  error.code = 'KS_DSH_MANIFEST_PIN_TAMPERED'
  throw error
}

/** Explicit pinned embedded fallback manifest. */
export const PINNED_EMBEDDED_MANIFEST = Object.freeze({
  ...PINNED_BODY,
  attestation: Object.freeze({ algorithm: 'sha256-canonical-json', digest: PINNED_EMBEDDED_DIGEST }),
})

const STABLE_SET = new Set(STABLE_ACTIONS)
const PINNED_BY_ID = new Map(PINNED_CAPABILITIES.map((pinned) => [pinned.id, pinned]))
const PINNED_BY_ACTION = new Map(PINNED_CAPABILITIES.filter((pinned) => STABLE_SET.has(pinned.action)).map((pinned) => [pinned.action, pinned]))
const DIGEST = /^sha256:[a-f0-9]{64}$/

/**
 * Pinned non-mutation invariant per stable action. discovery's
 * `local-evidence-write` authority is confined to in-plugin evidence state;
 * no stable action mutates the source database or Superset.
 */
const NON_MUTATING = Object.freeze(Object.fromEntries(STABLE_ACTIONS.map((action) => [action, true])))

function fail(code) {
  const error = new Error(code)
  error.code = code
  throw error
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
}

function exactKeys(value, keys, code) {
  if (!plainObject(value)) fail(code)
  const actual = Object.keys(value)
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) fail(code)
}

function assertSection(value, pinned, code) {
  exactKeys(value, Object.keys(pinned), 'KS_DSH_MANIFEST_SURFACE_INVALID')
  for (const [key, expected] of Object.entries(pinned)) {
    if (value[key] !== expected) fail(code)
  }
}

function assertProduct(value) {
  exactKeys(value, ['id', 'version', 'component'], 'KS_DSH_MANIFEST_SURFACE_INVALID')
  if (value.id !== PRODUCT_ID || value.version !== PRODUCT_VERSION || value.component !== PRODUCT_COMPONENT) {
    fail('KS_DSH_MANIFEST_PRODUCT_STALE')
  }
}

function assertContract(value) {
  exactKeys(value, ['id', 'version'], 'KS_DSH_MANIFEST_SURFACE_INVALID')
  if (value.id !== CONTRACT_ID || value.version !== CONTRACT_VERSION) fail('KS_DSH_MANIFEST_CONTRACT_STALE')
}

function assertCapabilities(value) {
  if (!Array.isArray(value)) fail('KS_DSH_MANIFEST_SURFACE_INVALID')
  const seen = new Set()
  for (const entry of value) {
    if (!plainObject(entry) || typeof entry.id !== 'string') fail('KS_DSH_MANIFEST_SURFACE_INVALID')
    const pinned = PINNED_BY_ID.get(entry.id)
    if (pinned === undefined) fail('KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
    if (seen.has(pinned.id)) fail('KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
    seen.add(pinned.id)
    const stable = STABLE_SET.has(pinned.action)
    exactKeys(entry, stable ? ['id', 'action', 'authority'] : ['id', 'action', 'authority', 'externalIntent'], 'KS_DSH_MANIFEST_SURFACE_INVALID')
    if (entry.action !== pinned.action) fail('KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
    if (entry.authority !== pinned.authority) fail('KS_DSH_MANIFEST_CAPABILITY_WIDENED')
    if (!stable && entry.externalIntent !== false) fail('KS_DSH_MANIFEST_CAPABILITY_WIDENED')
  }
  for (const pinned of PINNED_CAPABILITIES) {
    if (!seen.has(pinned.id)) fail('KS_DSH_MANIFEST_CAPABILITY_MISSING')
  }
}

function assertAttestation(value) {
  exactKeys(value, ['algorithm', 'digest'], 'KS_DSH_MANIFEST_SURFACE_INVALID')
  if (value.algorithm !== 'sha256-canonical-json' || !DIGEST.test(value.digest ?? '')) {
    fail('KS_DSH_MANIFEST_DIGEST_INVALID')
  }
}

function assertManifest(supplied) {
  if (!plainObject(supplied)) fail('KS_DSH_MANIFEST_SURFACE_INVALID')
  exactKeys(supplied, ['schemaVersion', 'product', 'contract', 'capabilities', 'graph', 'boundaries', 'attestation'], 'KS_DSH_MANIFEST_SURFACE_INVALID')
  if (supplied.schemaVersion !== ATTESTATION_SCHEMA) fail('KS_DSH_MANIFEST_SCHEMA_STALE')
  assertProduct(supplied.product)
  assertContract(supplied.contract)
  assertCapabilities(supplied.capabilities)
  assertSection(supplied.graph, PINNED_GRAPH, 'KS_DSH_MANIFEST_GRAPH_STALE')
  assertSection(supplied.boundaries, PINNED_BOUNDARIES, 'KS_DSH_MANIFEST_BOUNDARIES_WIDENED')
  assertAttestation(supplied.attestation)
  const body = Object.fromEntries(Object.entries(supplied).filter(([key]) => key !== 'attestation'))
  if (sha256Digest(body) !== supplied.attestation.digest) fail('KS_DSH_MANIFEST_TAMPERED')
  // A self-consistent digest is not enough: it must equal the pinned embedded
  // digest. A resealed manifest that reorders the capabilities array
  // recomputes a different digest and is denied instead of projecting a
  // digest that misrepresents the pinned source.
  if (supplied.attestation.digest !== PINNED_EMBEDDED_DIGEST) fail('KS_DSH_MANIFEST_DIGEST_STALE')
  return supplied
}

function buildProjection(digest, source) {
  const body = {
    schemaVersion: PROJECTION_SCHEMA,
    source,
    product: Object.freeze({ id: PRODUCT_ID, version: PRODUCT_VERSION }),
    contract: Object.freeze({ id: CONTRACT_ID, version: CONTRACT_VERSION }),
    digest,
    freshness: Object.freeze({
      state: 'fresh',
      provenance: EMBEDDED_PROVENANCE,
      product: PRODUCT_VERSION,
      contract: CONTRACT_VERSION,
    }),
    actions: Object.freeze(STABLE_ACTIONS.map((action) => {
      const pinned = PINNED_BY_ACTION.get(action)
      return Object.freeze({
        action,
        capabilityId: pinned.id,
        authority: pinned.authority,
        nonMutating: NON_MUTATING[action],
        digest,
      })
    })),
  }
  return Object.freeze({ ...body, projectionDigest: sha256Digest(body) })
}

/**
 * Validate a closed supplied capability attestation and project the exact six
 * stable KS capability actions.
 * @param {object} supplied Closed attestation body in `GET /v2/capabilities` wire shape.
 * @returns {object} Frozen projection binding product, contract version, the six actions,
 * attestation digest, pinned freshness, and non-mutating authority.
 */
export function projectCapabilityManifest(supplied) {
  assertManifest(supplied)
  return buildProjection(PINNED_EMBEDDED_DIGEST, 'supplied')
}

/**
 * Project the explicit pinned embedded fallback manifest.
 * @returns {object} Frozen projection bound to the pinned embedded attestation digest.
 */
export function embeddedCapabilityProjection() {
  return buildProjection(PINNED_EMBEDDED_DIGEST, 'embedded')
}

/**
 * Resolve the capability projection for a runtime mode. A bound supplied
 * manifest must validate against the pin; its absence falls back to the
 * explicit pinned embedded fallback. An invalid supplied manifest never
 * falls back.
 * @param {{supplied?: (object|null)}} options Optional bound supplied attestation.
 * @returns {object} Frozen projection; `source` is `'supplied'` or `'embedded'`.
 */
export function resolveCapabilityManifest({ supplied = null } = {}) {
  if (supplied === null || supplied === undefined) return embeddedCapabilityProjection()
  return projectCapabilityManifest(supplied)
}

// ---------------------------------------------------------------------------
// KS #65 M2-65-P2B1: closed additive v0.24.0 handler pin table.
//
// Strictly additive beside the v0.16.0 runtime above. The three local v0.24.0
// object-capability handlers (Search, Details, Overview) are pinned to their
// vendored v0.24.0 handler paths with exact commit/path/digest provenance
// bound to the read-only VENDORED_MANIFEST.json v0240 section, and to the
// canonical read-only-evidence-projection / PROJECTED_READ_ONLY / all-false
// (non-mutating) authority surface declared by the vendored
// object-capability-contract-v1.mjs. Unknown, unlisted, or tampered pins fail
// closed; the pre-existing v0.16.0 pin table is untouched.
// ---------------------------------------------------------------------------

/** Pinned source commit of the v0.24.0 handler closure (VENDORED_MANIFEST.json v0240 section). */
export const V0240_SOURCE_COMMIT = 'e092bb0bce039936b88329793b24e9f987ae0ddb'

/** Canonical v0.24.0 object-capability authority kind (vendored object-capability-contract-v1.mjs). */
export const V0240_AUTHORITY_KIND = 'read-only-evidence-projection'

/** Canonical v0.24.0 object-capability result state (vendored object-capability-contract-v1.mjs). */
export const V0240_PROJECTION_STATE = 'PROJECTED_READ_ONLY'

/**
 * Closed v0.24.0 non-mutating authority surface: every flag the vendored
 * object-capability contract requires to be false in every result.
 */
export const V0240_AUTHORITY_SURFACE = Object.freeze({
  credentialsIncluded: false,
  dispatchAuthority: false,
  executionAuthority: false,
  mutationAuthority: false,
  queryExecution: false,
  rawValuesIncluded: false,
  sqlAuthority: false,
})

/**
 * Closed additive pin of the three local v0.24.0 object capabilities. Each
 * pin binds the vendored v0.24.0 handler path, the exact commit/path/digest
 * provenance of that handler in the read-only VENDORED_MANIFEST.json v0240
 * section, and the canonical read-only/non-mutating authority surface. The
 * set is exactly these three pins: no v0.16.0 capability id and no fourth
 * entry may appear.
 */
export const PINNED_V0240_PINS = Object.freeze([
  Object.freeze({
    id: 'bi.object.search.read',
    handlerPath: 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-search-handler-v1.mjs',
    provenance: Object.freeze({
      sourceCommit: V0240_SOURCE_COMMIT,
      sourcePath: 'services/bi-agent/src/object-search-handler-v1.mjs',
      vendorPath: 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-search-handler-v1.mjs',
      sha256: '94e7ba13ca85cc10a407900e0049a9fa86e8dccfb6de8d26f90e50af5b492b37',
    }),
    authority: V0240_AUTHORITY_KIND,
    state: V0240_PROJECTION_STATE,
    authoritySurface: V0240_AUTHORITY_SURFACE,
  }),
  Object.freeze({
    id: 'bi.object.details.read',
    handlerPath: 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-details-handler-v1.mjs',
    provenance: Object.freeze({
      sourceCommit: V0240_SOURCE_COMMIT,
      sourcePath: 'services/bi-agent/src/object-details-handler-v1.mjs',
      vendorPath: 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-details-handler-v1.mjs',
      sha256: 'abd5c5256737c8771c50ed7138be5fec4ed92b9fb791f46da6aaba2ec2fd8b79',
    }),
    authority: V0240_AUTHORITY_KIND,
    state: V0240_PROJECTION_STATE,
    authoritySurface: V0240_AUTHORITY_SURFACE,
  }),
  Object.freeze({
    id: 'bi.database.overview.read',
    handlerPath: 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/database-overview-handler-v1.mjs',
    provenance: Object.freeze({
      sourceCommit: V0240_SOURCE_COMMIT,
      sourcePath: 'services/bi-agent/src/database-overview-handler-v1.mjs',
      vendorPath: 'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/database-overview-handler-v1.mjs',
      sha256: 'e015f9e408b676bdba7f55740b504bb364c66744c3f24e5a60aa938e4ca8f8a1',
    }),
    authority: V0240_AUTHORITY_KIND,
    state: V0240_PROJECTION_STATE,
    authoritySurface: V0240_AUTHORITY_SURFACE,
  }),
])

const V0240_PIN_KEYS = ['id', 'handlerPath', 'provenance', 'authority', 'state', 'authoritySurface']
const V0240_PROVENANCE_KEYS = ['sourceCommit', 'sourcePath', 'vendorPath', 'sha256']
const V0240_PIN_BY_ID = new Map(PINNED_V0240_PINS.map((pin) => [pin.id, pin]))

/**
 * Read-only bound of the pin provenance: the v0240 section of the repo-root
 * VENDORED_MANIFEST.json. The module refuses to load when the section is
 * absent, carries a different source commit, or no longer lists a pinned
 * handler path with byte-identical provenance.
 */
const V0240_MANIFEST_SECTION = (() => {
  let manifest
  try {
    manifest = JSON.parse(readFileSync(new URL('../VENDORED_MANIFEST.json', import.meta.url), 'utf8'))
  } catch {
    fail('KS_DSH_V0240_MANIFEST_UNREADABLE')
  }
  const section = plainObject(manifest) ? manifest.v0240 : undefined
  if (!plainObject(section) || section.commit !== V0240_SOURCE_COMMIT || !Array.isArray(section.files)) {
    fail('KS_DSH_V0240_MANIFEST_INVALID')
  }
  return section
})()

const V0240_MANIFEST_FILES = new Map(
  V0240_MANIFEST_SECTION.files.filter((entry) => plainObject(entry) && typeof entry.vendorPath === 'string')
    .map((entry) => [entry.vendorPath, entry]),
)

/**
 * Validate a closed supplied v0.24.0 pin table against the pinned three-pin
 * set and the read-only VENDORED_MANIFEST.json v0240 section. Fails closed on
 * an unknown capability id, a handler path not listed in the manifest, a
 * commit/path/digest provenance mismatch, a widened set (duplicate, fourth,
 * or missing entry), and any widened authority.
 * @param {Array<object>} supplied Closed v0.24.0 pin table in the pinned wire shape.
 * @returns {object} The pinned v0.24.0 pin table.
 */
export function verifyV0240PinTable(supplied) {
  if (!Array.isArray(supplied)) fail('KS_DSH_V0240_PIN_SURFACE_INVALID')
  if (supplied.length !== PINNED_V0240_PINS.length) fail('KS_DSH_V0240_PIN_SET_INVALID')
  const seen = new Set()
  for (const entry of supplied) {
    if (!plainObject(entry) || typeof entry.id !== 'string' || typeof entry.handlerPath !== 'string') {
      fail('KS_DSH_V0240_PIN_SURFACE_INVALID')
    }
    exactKeys(entry, V0240_PIN_KEYS, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
    if (!plainObject(entry.provenance)) fail('KS_DSH_V0240_PIN_SURFACE_INVALID')
    exactKeys(entry.provenance, V0240_PROVENANCE_KEYS, 'KS_DSH_V0240_PIN_SURFACE_INVALID')
    if (!plainObject(entry.authoritySurface)) fail('KS_DSH_V0240_PIN_SURFACE_INVALID')
    exactKeys(entry.authoritySurface, Object.keys(V0240_AUTHORITY_SURFACE), 'KS_DSH_V0240_PIN_SURFACE_INVALID')
    if (entry.handlerPath !== entry.provenance.vendorPath) fail('KS_DSH_V0240_PIN_SURFACE_INVALID')
    const pinned = V0240_PIN_BY_ID.get(entry.id)
    if (pinned === undefined) fail('KS_DSH_V0240_PIN_UNKNOWN')
    if (seen.has(entry.id)) fail('KS_DSH_V0240_PIN_SET_INVALID')
    seen.add(entry.id)
    const manifestEntry = V0240_MANIFEST_FILES.get(entry.handlerPath)
    if (manifestEntry === undefined) fail('KS_DSH_V0240_PIN_PATH_UNLISTED')
    if (manifestEntry.sourceCommit !== entry.provenance.sourceCommit
      || manifestEntry.sourcePath !== entry.provenance.sourcePath
      || manifestEntry.sha256 !== entry.provenance.sha256) fail('KS_DSH_V0240_PIN_PROVENANCE_MISMATCH')
    if (pinned.handlerPath !== entry.handlerPath) fail('KS_DSH_V0240_PIN_PROVENANCE_MISMATCH')
    if (entry.authority !== V0240_AUTHORITY_KIND || entry.state !== V0240_PROJECTION_STATE) {
      fail('KS_DSH_V0240_PIN_AUTHORITY_WIDENED')
    }
    if (Object.values(entry.authoritySurface).some((value) => value !== false)) {
      fail('KS_DSH_V0240_PIN_AUTHORITY_WIDENED')
    }
  }
  return PINNED_V0240_PINS
}

// Load-time binding: the pinned table must pass its own closed validation and
// its provenance must be byte-identical to the read-only manifest. A vendored
// tree or manifest that drifts from the pin denies the module load.
for (const pin of PINNED_V0240_PINS) {
  const entry = V0240_MANIFEST_FILES.get(pin.provenance.vendorPath)
  if (entry === undefined
    || entry.sourceCommit !== pin.provenance.sourceCommit
    || entry.sourcePath !== pin.provenance.sourcePath
    || entry.sha256 !== pin.provenance.sha256) fail('KS_DSH_V0240_PIN_UNBOUND')
}
verifyV0240PinTable(structuredClone(PINNED_V0240_PINS))
