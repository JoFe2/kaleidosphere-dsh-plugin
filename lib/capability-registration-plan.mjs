/**
 * KS #64 M2 micro-slice 2: closed registration-plan mapper.
 *
 * Maps a validated capability projection (the M1b
 * `projectCapabilityManifest` / `embeddedCapabilityProjection` output) to the
 * exact six stable DSH tool registrations. Before any tool is emitted, the
 * mapper re-verifies the closed projection envelope: exact key surface,
 * pinned projection schema, allowed source, pinned product/contract/
 * attestation digest/freshness, the recomputed projection digest, and the
 * exact stable action order, capability IDs, authorities, and non-mutating
 * flags against the pinned capability table. A reordered, resealed, or
 * otherwise tampered projection is denied fail-closed before the plan
 * exists.
 *
 * The plan is a frozen data-only structure: fixed toolName/action/
 * capabilityId/authority per stable action bound to the canonical projection
 * digest. It carries no caller-controlled identifiers, no executable
 * callbacks, and no arbitrary schema. This module is read-only foundation;
 * runtime defineTool wiring lands in a later slice.
 */
import { sha256Digest } from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import {
  CONTRACT_ID,
  CONTRACT_VERSION,
  EMBEDDED_PROVENANCE,
  PINNED_CAPABILITIES,
  PINNED_EMBEDDED_DIGEST,
  PROJECTION_SCHEMA,
  PRODUCT_ID,
  PRODUCT_VERSION,
  STABLE_ACTIONS,
} from './capability-manifest.mjs'

export const PLAN_SCHEMA = 'kaleidosphere.dsh/capability-registration-plan/v1'

/** The six stable DSH tool names in closed canonical order. */
export const STABLE_TOOL_NAMES = Object.freeze([
  'kaleidosphere_status',
  'kaleidosphere_discovery',
  'kaleidosphere_analyze',
  'kaleidosphere_plan',
  'kaleidosphere_preview',
  'kaleidosphere_readback',
])

/** Module-load pin: the tool-name table must track the stable action order. */
if (STABLE_TOOL_NAMES.length !== STABLE_ACTIONS.length
  || STABLE_TOOL_NAMES.some((name, index) => name !== `kaleidosphere_${STABLE_ACTIONS[index]}`)) {
  const error = new Error('KS_DSH_PLAN_TOOL_PIN_TAMPERED')
  error.code = 'KS_DSH_PLAN_TOOL_PIN_TAMPERED'
  throw error
}

const STABLE_SET = new Set(STABLE_ACTIONS)
const STABLE_PINNED_BY_ACTION = new Map(PINNED_CAPABILITIES.filter((pinned) => STABLE_SET.has(pinned.action)).map((pinned) => [pinned.action, pinned]))
const ENVELOPE_KEYS = ['schemaVersion', 'source', 'product', 'contract', 'digest', 'freshness', 'actions', 'projectionDigest']
const ACTION_KEYS = ['action', 'capabilityId', 'authority', 'nonMutating', 'digest']
const SOURCES = new Set(['supplied', 'embedded'])
const DIGEST = /^sha256:[a-f0-9]{64}$/
const PINNED_PRODUCT = Object.freeze({ id: PRODUCT_ID, version: PRODUCT_VERSION })
const PINNED_CONTRACT = Object.freeze({ id: CONTRACT_ID, version: CONTRACT_VERSION })
const PINNED_FRESHNESS = Object.freeze({
  state: 'fresh',
  provenance: EMBEDDED_PROVENANCE,
  product: PRODUCT_VERSION,
  contract: CONTRACT_VERSION,
})

function fail(code) {
  const error = new Error(code)
  error.code = code
  throw error
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
}

function assertExactKeys(value, keys, code) {
  if (!plainObject(value)) fail(code)
  const actual = Object.keys(value)
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) fail(code)
}

function assertPinnedSection(value, pinned, code) {
  assertExactKeys(value, Object.keys(pinned), 'KS_DSH_PLAN_SURFACE_INVALID')
  for (const [key, expected] of Object.entries(pinned)) {
    if (value[key] !== expected) fail(code)
  }
}

function assertEnvelope(projection) {
  assertExactKeys(projection, ENVELOPE_KEYS, 'KS_DSH_PLAN_SURFACE_INVALID')
  if (typeof projection.schemaVersion !== 'string' || projection.schemaVersion !== PROJECTION_SCHEMA) {
    fail('KS_DSH_PLAN_SCHEMA_STALE')
  }
  if (typeof projection.source !== 'string' || !SOURCES.has(projection.source)) fail('KS_DSH_PLAN_SOURCE_INVALID')
  assertPinnedSection(projection.product, PINNED_PRODUCT, 'KS_DSH_PLAN_PIN_STALE')
  assertPinnedSection(projection.contract, PINNED_CONTRACT, 'KS_DSH_PLAN_PIN_STALE')
  if (projection.digest !== PINNED_EMBEDDED_DIGEST) fail('KS_DSH_PLAN_PIN_STALE')
  assertPinnedSection(projection.freshness, PINNED_FRESHNESS, 'KS_DSH_PLAN_PIN_STALE')
  if (typeof projection.projectionDigest !== 'string' || !DIGEST.test(projection.projectionDigest)) {
    fail('KS_DSH_PLAN_DIGEST_INVALID')
  }
}

function assertActions(projection) {
  if (!Array.isArray(projection.actions)) fail('KS_DSH_PLAN_SURFACE_INVALID')
  // The exact stable order in the exact stable length: an unknown, missing,
  // duplicate, or reordered action breaks the positional match. A seventh
  // tool or a trusted apply/readback/rollback action can never enter.
  if (projection.actions.length !== STABLE_ACTIONS.length) fail('KS_DSH_PLAN_ACTION_INVALID')
  projection.actions.forEach((entry, index) => {
    const action = STABLE_ACTIONS[index]
    assertExactKeys(entry, ACTION_KEYS, 'KS_DSH_PLAN_SURFACE_INVALID')
    if (entry.action !== action) fail('KS_DSH_PLAN_ACTION_INVALID')
    const pinned = STABLE_PINNED_BY_ACTION.get(action)
    if (typeof entry.capabilityId !== 'string' || entry.capabilityId !== pinned.id) {
      fail('KS_DSH_PLAN_CAPABILITY_MISMATCH')
    }
    if (typeof entry.authority !== 'string' || entry.authority !== pinned.authority) {
      fail('KS_DSH_PLAN_AUTHORITY_WIDENED')
    }
    if (entry.nonMutating !== true) fail('KS_DSH_PLAN_MUTATING')
    if (typeof entry.digest !== 'string' || entry.digest !== PINNED_EMBEDDED_DIGEST) {
      fail('KS_DSH_PLAN_DIGEST_TAMPERED')
    }
  })
}

/**
 * Map a validated closed capability projection to the exact six stable DSH
 * tool registrations. Pure and deterministic: identical projection content
 * (in any key order) maps to byte-identical plan bytes and digest.
 * @param {object} projection Closed capability projection in the M1b
 * `kaleidosphere.dsh/capability-projection/v1` envelope.
 * @returns {object} Frozen plan binding the canonical projection digest and
 * fixed toolName/action/capabilityId/authority for the six stable tools.
 */
export function buildRegistrationPlan(projection) {
  assertEnvelope(projection)
  assertActions(projection)
  // Final sealed-body confirmation, run only after the structural checks have
  // proven every value JSON-safe: a substituted or resealed envelope that no
  // longer matches its sealed body is denied.
  const body = Object.fromEntries(Object.entries(projection).filter(([key]) => key !== 'projectionDigest'))
  if (sha256Digest(body) !== projection.projectionDigest) fail('KS_DSH_PLAN_DIGEST_TAMPERED')
  const planBody = {
    schemaVersion: PLAN_SCHEMA,
    projectionDigest: projection.projectionDigest,
    tools: Object.freeze(STABLE_ACTIONS.map((action, index) => {
      const pinned = STABLE_PINNED_BY_ACTION.get(action)
      return Object.freeze({
        toolName: STABLE_TOOL_NAMES[index],
        action,
        capabilityId: pinned.id,
        authority: pinned.authority,
      })
    })),
  }
  return Object.freeze({ ...planBody, planDigest: sha256Digest(planBody) })
}