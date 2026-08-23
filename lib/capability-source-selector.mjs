/**
 * KS #64 Micro-slice 1: pure capability source selector.
 *
 * Selects the closed capability projection source for an explicit runtime
 * mode over the existing capability-manifest consumer. EMBEDDED selects the
 * explicit pinned embedded projection and requires no supplied evidence; any
 * supplied manifest in embedded mode is invalid input and denies. EXTERNAL
 * requires a supplied pinned manifest and validates it through the
 * consumer: missing, tampered, stale, resealed, or digest-substituted
 * evidence denies with the consumer's failure code and never falls back to
 * the embedded pin. The decision is a frozen, deterministic, closed surface:
 * no credential, path, free-text, service URL, or authority field is
 * accepted or projected. This slice selects the source only; it performs no
 * runtime registration, network, or tool-schema work.
 */
import {
  embeddedCapabilityProjection,
  projectCapabilityManifest,
} from './capability-manifest.mjs'

export const SOURCE_DECISION_SCHEMA = 'kaleidosphere.dsh/capability-source-decision/v1'

/** Closed set of runtime source modes, in canonical order. */
export const SOURCE_MODES = Object.freeze(['EMBEDDED', 'EXTERNAL'])

const MODE_SET = new Set(SOURCE_MODES)

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

function buildDecision(mode, source, projection) {
  return Object.freeze({
    schemaVersion: SOURCE_DECISION_SCHEMA,
    mode,
    source,
    projection,
    projectionDigest: projection.projectionDigest,
  })
}

/**
 * Select the capability projection source for an explicit runtime mode.
 * @param {{mode: string, supplied: (object|null|undefined)}} options `mode` is
 * one of `SOURCE_MODES`; `supplied` is the bound supplied attestation for
 * EXTERNAL mode and must be absent evidence (`null`/`undefined`) for EMBEDDED.
 * @returns {object} Frozen decision binding `mode`, the selected `source`
 * (`'embedded'` or `'external'`), and the consumer's frozen projection.
 * @throws Errors with `code` `KS_DSH_SOURCE_SURFACE_INVALID`,
 * `KS_DSH_SOURCE_MODE_UNKNOWN`, `KS_DSH_SOURCE_EXTERNAL_MANIFEST_MISSING`,
 * `KS_DSH_SOURCE_EMBEDDED_MANIFEST_SUPPLIED`, or the consumer's manifest
 * failure code for invalid external evidence.
 */
export function selectCapabilitySource(options) {
  exactKeys(options, ['mode', 'supplied'], 'KS_DSH_SOURCE_SURFACE_INVALID')
  const { mode, supplied } = options
  if (typeof mode !== 'string' || !MODE_SET.has(mode)) fail('KS_DSH_SOURCE_MODE_UNKNOWN')
  if (mode === 'EMBEDDED') {
    if (supplied !== null && supplied !== undefined) fail('KS_DSH_SOURCE_EMBEDDED_MANIFEST_SUPPLIED')
    return buildDecision('EMBEDDED', 'embedded', embeddedCapabilityProjection())
  }
  if (supplied === null || supplied === undefined) fail('KS_DSH_SOURCE_EXTERNAL_MANIFEST_MISSING')
  return buildDecision('EXTERNAL', 'external', projectCapabilityManifest(supplied))
}