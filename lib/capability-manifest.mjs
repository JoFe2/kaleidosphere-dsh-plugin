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
