/**
 * KS #64 micro-slice 3: pure deterministic lifecycle readback receipt.
 *
 * Builds a closed, fail-closed readback receipt over a validated capability
 * projection. The input is exactly the closed surface `{runtimeMode,
 * projection, generation, observedAtMs}`: the mode binds to the projection
 * source (EMBEDDED -> 'embedded', EXTERNAL -> 'supplied'), the generation is
 * a safe integer >= 1, and the observed time is a bounded safe integer of
 * epoch milliseconds. The projection must recompute to the explicit pinned
 * binding: schema, source, product, contract, the pinned attestation digest,
 * pinned freshness, and the exact six stable action bindings in canonical
 * order, sealed by a self-consistent canonical digest.
 *
 * The receipt re-emits only the fixed source, product, contract, digest, the
 * six stable action bindings in canonical order, generation, observedAtMs,
 * status READY, and a canonical receiptDigest covering the entire closed
 * body. No arbitrary IDs, notes, paths, URLs, credentials, callbacks, or
 * authority changes ever enter or leave; any deviation denies the receipt.
 */
import { sha256Digest } from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import {
  CONTRACT_ID,
  CONTRACT_VERSION,
  EMBEDDED_PROVENANCE,
  PINNED_CAPABILITIES,
  PINNED_EMBEDDED_DIGEST,
  PRODUCT_ID,
  PRODUCT_VERSION,
  PROJECTION_SCHEMA,
  STABLE_ACTIONS,
} from './capability-manifest.mjs'

/** Closed mapping of runtime modes to the projection source each one binds. */
const MODE_SOURCE = Object.freeze({ EMBEDDED: 'embedded', EXTERNAL: 'supplied' })
const INPUT_KEYS = Object.freeze(['runtimeMode', 'projection', 'generation', 'observedAtMs'])
const PROJECTION_KEYS = Object.freeze(['schemaVersion', 'source', 'product', 'contract', 'digest', 'freshness', 'actions', 'projectionDigest'])
const FRESHNESS_KEYS = Object.freeze(['state', 'provenance', 'product', 'contract'])
const ACTION_KEYS = Object.freeze(['action', 'capabilityId', 'authority', 'nonMutating', 'digest'])
/** Upper bound of representable epoch milliseconds (year 275760). */
const MAX_OBSERVED_AT_MS = 8_640_000_000_000_000
const PINNED_BY_ACTION = new Map(PINNED_CAPABILITIES.filter((pinned) => STABLE_ACTIONS.includes(pinned.action)).map((pinned) => [pinned.action, pinned]))

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

function assertProduct(value) {
  exactKeys(value, ['id', 'version'], 'KS_DSH_RECEIPT_SURFACE_INVALID')
  if (value.id !== PRODUCT_ID || value.version !== PRODUCT_VERSION) fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
}

function assertContract(value) {
  exactKeys(value, ['id', 'version'], 'KS_DSH_RECEIPT_SURFACE_INVALID')
  if (value.id !== CONTRACT_ID || value.version !== CONTRACT_VERSION) fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
}

function assertFreshness(value) {
  exactKeys(value, FRESHNESS_KEYS, 'KS_DSH_RECEIPT_SURFACE_INVALID')
  if (value.state !== 'fresh' || value.provenance !== EMBEDDED_PROVENANCE
    || value.product !== PRODUCT_VERSION || value.contract !== CONTRACT_VERSION) {
    fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
  }
}

function assertActions(value) {
  if (!Array.isArray(value)) fail('KS_DSH_RECEIPT_SURFACE_INVALID')
  if (value.length !== STABLE_ACTIONS.length) fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
  for (const [index, entry] of value.entries()) {
    exactKeys(entry, ACTION_KEYS, 'KS_DSH_RECEIPT_SURFACE_INVALID')
    if (entry.action !== STABLE_ACTIONS[index]) fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
    const pinned = PINNED_BY_ACTION.get(entry.action)
    if (entry.capabilityId !== pinned.id || entry.authority !== pinned.authority
      || entry.nonMutating !== true || entry.digest !== PINNED_EMBEDDED_DIGEST) {
      fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
    }
  }
}

function assertProjection(projection, expectedSource) {
  if (!plainObject(projection)) fail('KS_DSH_RECEIPT_SURFACE_INVALID')
  exactKeys(projection, PROJECTION_KEYS, 'KS_DSH_RECEIPT_SURFACE_INVALID')
  if (projection.schemaVersion !== PROJECTION_SCHEMA) fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
  if (projection.source !== expectedSource) fail('KS_DSH_RECEIPT_MODE_SOURCE_MISMATCH')
  assertProduct(projection.product)
  assertContract(projection.contract)
  if (projection.digest !== PINNED_EMBEDDED_DIGEST) fail('KS_DSH_RECEIPT_PROJECTION_DRIFT')
  assertFreshness(projection.freshness)
  assertActions(projection.actions)
  const body = Object.fromEntries(Object.entries(projection).filter(([key]) => key !== 'projectionDigest'))
  if (sha256Digest(body) !== projection.projectionDigest) fail('KS_DSH_RECEIPT_PROJECTION_TAMPERED')
}

function buildReceipt({ source, generation, observedAtMs }) {
  const body = {
    source,
    product: Object.freeze({ id: PRODUCT_ID, version: PRODUCT_VERSION }),
    contract: Object.freeze({ id: CONTRACT_ID, version: CONTRACT_VERSION }),
    digest: PINNED_EMBEDDED_DIGEST,
    actions: Object.freeze(STABLE_ACTIONS.map((action) => {
      const pinned = PINNED_BY_ACTION.get(action)
      return Object.freeze({
        action,
        capabilityId: pinned.id,
        authority: pinned.authority,
        nonMutating: true,
        digest: PINNED_EMBEDDED_DIGEST,
      })
    })),
    generation,
    observedAtMs,
    status: 'READY',
  }
  return Object.freeze({ ...body, receiptDigest: sha256Digest(body) })
}

/**
 * Build the closed lifecycle readback receipt for a validated capability
 * projection. Pure and deterministic: identical inputs (regardless of object
 * key order) produce byte-identical canonical receipts.
 * @param {object} input Closed surface `{runtimeMode: 'EMBEDDED'|'EXTERNAL', projection, generation, observedAtMs}`.
 * @returns {object} Frozen receipt carrying only the fixed binding fields,
 * the six stable action bindings in canonical order, status READY, and the
 * canonical receiptDigest over the entire closed body.
 */
export function createReadbackReceipt(input) {
  if (!plainObject(input)) fail('KS_DSH_RECEIPT_SURFACE_INVALID')
  exactKeys(input, INPUT_KEYS, 'KS_DSH_RECEIPT_SURFACE_INVALID')
  const mode = input.runtimeMode
  if (mode !== 'EMBEDDED' && mode !== 'EXTERNAL') fail('KS_DSH_RECEIPT_MODE_INVALID')
  const generation = input.generation
  if (typeof generation !== 'number' || !Number.isSafeInteger(generation) || generation < 1) {
    fail('KS_DSH_RECEIPT_GENERATION_INVALID')
  }
  const observedAtMs = input.observedAtMs
  if (typeof observedAtMs !== 'number' || !Number.isSafeInteger(observedAtMs)
    || observedAtMs < 1 || observedAtMs >= MAX_OBSERVED_AT_MS) {
    fail('KS_DSH_RECEIPT_OBSERVED_AT_INVALID')
  }
  const source = MODE_SOURCE[mode]
  assertProjection(input.projection, source)
  return buildReceipt({ source, generation, observedAtMs })
}