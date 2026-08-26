// P3A: direct executable oracle for the probe-bundle local-surface phase.
//
// Deterministic synthetic representative inputs drive runtime.execute for the
// three additive v0.24.0 local actions (search/details/overview) through the
// reusable local-surface phase exported by this bundle; the oracle asserts the
// four P3A proof contracts:
//   P3A-HAPPY        exactly three sealed read-only v2 result envelopes
//   P3A-AUTHORITY    no raw rows, secrets, SQL, execution or mutation authority
//   P3A-HOST-SURFACE the stub-host surface is exactly the six native tools and
//                    carries none of the three mapped capabilities
//   P3A-CLOSED-ACTIONS aliases and unknown actions deny with
//                    KS_DSH_ACTION_INVALID
//
// No live data, network, environment secrets, raw rows or SQL: every input is
// constructed inline from the verified synthetic fixture builders and the
// vendored handlers are the single authority. The seven-negative matrix (P3B)
// and the bundle lifecycle shell (P3C) are out of scope for this oracle.

import assert from 'node:assert/strict'
import test from 'node:test'

import { CLOSED_INTENTS } from '../../lib/runtime.mjs'
import {
  capabilityAttestationV2,
  sha256Digest,
} from '../../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import {
  P3A_ALIASES,
  P3A_AUTHORITY,
  P3A_CLAIMS,
  P3A_FORBIDDEN_KEYS,
  P3A_FORBIDDEN_VALUE_PATTERNS,
  P3A_HOST_TOOL_NAMES,
  P3A_MAPPED_CAPABILITIES,
  P3A_RESPONSE_KEYS,
  runLocalSurfaceProbe,
} from './local-surface.mjs'

// Contract literals, pinned independently of the module so the oracle catches
// any drift between the phase evidence boundary and the frozen work order.
const EXPECTED_ACTIONS = Object.freeze(['search', 'details', 'overview'])
const EXPECTED_RESPONSE_KEYS = Object.freeze([
  'schemaVersion', 'requestId', 'action', 'runtime', 'capabilityAttestationDigest', 'result', 'integrity',
])
const EXPECTED_RESULT_KEYS = Object.freeze([
  'authority', 'bindings', 'capabilityId', 'claims', 'projectionSha256', 'requestSha256', 'schemaVersion', 'state',
])
const EXPECTED_OVERVIEW_RESULT_KEYS = Object.freeze([
  'bytes', 'capabilityId', 'envelope', 'projectionSha256', 'requestSha256', 'resultSha256', 'schemaVersion', 'state',
])
const EXPECTED_HOST_TOOL_NAMES = Object.freeze([
  'kaleidosphere_analyze',
  'kaleidosphere_discovery',
  'kaleidosphere_plan',
  'kaleidosphere_preview',
  'kaleidosphere_readback',
  'kaleidosphere_status',
])
const EXPECTED_MAPPED_CAPABILITY_IDS = Object.freeze([
  'bi.object.search.read',
  'bi.object.details.read',
  'bi.database.overview.read',
])
const INTENT_RESULT_V2 = 'superset-bi-agent.external/intent-result/v2'
const PROJECTED_READ_ONLY = 'PROJECTED_READ_ONLY'
const SHA256_CANONICAL_JSON = 'sha256-canonical-json'
const KS_DSH_ACTION_INVALID = 'KS_DSH_ACTION_INVALID'

function assertFrozen(value) {
  if (!value || typeof value !== 'object') return
  assert(Object.isFrozen(value))
  Object.values(value).forEach(assertFrozen)
}

function scanForForbiddenContent(root, label) {
  const keys = new Set()
  const strings = []
  const walk = (value) => {
    if (Array.isArray(value)) { value.forEach(walk); return }
    if (value && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) { keys.add(key); walk(item) }
      return
    }
    if (typeof value === 'string') strings.push(value)
  }
  walk(root)
  for (const key of keys) {
    assert(!P3A_FORBIDDEN_KEYS.includes(key), `${label}: forbidden key "${key}"`)
  }
  for (const value of strings) {
    for (const { name, pattern } of P3A_FORBIDDEN_VALUE_PATTERNS) {
      assert(!pattern.test(value), `${label}: ${name} content in a string value`)
    }
  }
}

// The module's evidence-boundary pins must match the frozen contract.
function assertPins() {
  assert.deepEqual(P3A_RESPONSE_KEYS, EXPECTED_RESPONSE_KEYS)
  assert.deepEqual(P3A_HOST_TOOL_NAMES, EXPECTED_HOST_TOOL_NAMES)
  assert.deepEqual(P3A_MAPPED_CAPABILITIES.map(cap => cap.capabilityId).sort(),
    [...EXPECTED_MAPPED_CAPABILITY_IDS].sort())
  assert.deepEqual(P3A_MAPPED_CAPABILITIES.map(cap => cap.action).sort(),
    [...EXPECTED_ACTIONS].sort())
  // Sentinel entries keep the scan non-trivial if the pins drift.
  assert(P3A_FORBIDDEN_KEYS.includes('rows'))
  assert(P3A_FORBIDDEN_KEYS.includes('password'))
  assert(P3A_FORBIDDEN_VALUE_PATTERNS.some(item => item.name === 'url-scheme'))
  assert(P3A_FORBIDDEN_VALUE_PATTERNS.some(item => item.name === 'localhost'))
}

test('P3A-HAPPY: the local-surface phase dispatches exactly three representative local actions and seals exactly three read-only v2 result envelopes', async () => {
  assertPins()
  const evidence = await runLocalSurfaceProbe()
  assert.equal(evidence.engine, 'mssql')
  assert.deepEqual(evidence.actions.map(entry => entry.action), EXPECTED_ACTIONS)
  const attestation = capabilityAttestationV2()
  for (const { action, out } of evidence.actions) {
    // Exactly the sealed response: no v0.16 bridge evidence key.
    assert.deepEqual(Object.keys(out), ['response'])
    const response = out.response
    assertFrozen(response)
    assert.deepEqual(Object.keys(response), EXPECTED_RESPONSE_KEYS)
    assert.equal(response.schemaVersion, INTENT_RESULT_V2)
    assert.equal(response.action, action)
    assert.match(response.requestId, new RegExp(`^ks-${action}-[0-9a-f]{24}$`))
    assert.deepEqual(response.runtime, { product: attestation.product, contract: attestation.contract })
    assert.equal(response.capabilityAttestationDigest, attestation.attestation.digest)
    const { integrity, ...body } = response
    assert.equal(integrity.algorithm, SHA256_CANONICAL_JSON)
    assert.equal(integrity.digest, sha256Digest(body))
  }
})

test('P3A-AUTHORITY: the sealed local-surface evidence carries no raw rows, secrets, SQL, execution or mutation authority and every claim and authority flag is false', async () => {
  const evidence = await runLocalSurfaceProbe()
  for (const { action, out } of evidence.actions) {
    const envelope = action === 'overview' ? out.response.result.envelope : out.response.result
    assertFrozen(envelope)
    assert.equal(envelope.state, PROJECTED_READ_ONLY)
    assert.deepEqual(envelope.claims, P3A_CLAIMS)
    assert.deepEqual(envelope.authority, P3A_AUTHORITY)
    for (const flag of [...Object.values(envelope.claims), ...Object.values(envelope.authority)]) {
      assert.equal(flag, false)
    }
    // The sealed envelope surface is the common 8-key read-only surface for all
    // three actions (Overview's handler result wraps it as result.envelope).
    assert.deepEqual(Object.keys(envelope).sort(), [...EXPECTED_RESULT_KEYS])
    scanForForbiddenContent(out.response, action)
  }
  // The Overview handler result is the pinned 8-key read-only surface and its
  // bytes.* canonical-JSON payloads round-trip to the exact verified
  // structures (no hidden payload).
  const overview = evidence.actions.find(entry => entry.action === 'overview')
  const result = overview.out.response.result
  assertFrozen(result)
  assert.equal(result.state, PROJECTED_READ_ONLY)
  assert.deepEqual(Object.keys(result).sort(), [...EXPECTED_OVERVIEW_RESULT_KEYS])
  assert.deepEqual(JSON.parse(result.bytes.result), result.envelope)
  // The exposed attestation metadata carries only false authority flags and
  // no forbidden content.
  scanForForbiddenContent(evidence.attestation, 'attestation')
  for (const flag of Object.values(evidence.attestation.boundaries).filter(value => typeof value === 'boolean')) {
    assert.equal(flag, false)
  }
})

test('P3A-HOST-SURFACE: the stub-host surface is exactly the six closed-intent native tools and carries none of the three mapped capabilities', async () => {
  const evidence = await runLocalSurfaceProbe()
  assert.deepEqual(evidence.hostSurface.toolNames, [...EXPECTED_HOST_TOOL_NAMES])
  assert.equal(evidence.hostSurface.capabilities.length, EXPECTED_HOST_TOOL_NAMES.length)
  for (const tool of evidence.hostSurface.capabilities) {
    assert(EXPECTED_HOST_TOOL_NAMES.includes(tool.name), `unexpected host tool: ${tool.name}`)
    assert(CLOSED_INTENTS.includes(tool.action), `host tool action is not a closed intent: ${tool.action}`)
    for (const cap of P3A_MAPPED_CAPABILITIES) {
      assert.notEqual(tool.action, cap.action, `host tool exposes mapped action: ${cap.action}`)
      assert.notEqual(tool.capabilityId, cap.capabilityId, `host tool exposes mapped capability: ${cap.capabilityId}`)
    }
  }
})

test('P3A-CLOSED-ACTIONS: every representative alias and unknown action denies with KS_DSH_ACTION_INVALID', async () => {
  const evidence = await runLocalSurfaceProbe()
  const { denied } = evidence.closedActions
  assert.equal(denied.length, P3A_ALIASES.length)
  assert.deepEqual(denied.map(entry => entry.alias), [...P3A_ALIASES])
  for (const entry of denied) {
    assert.equal(entry.code, KS_DSH_ACTION_INVALID)
    assert.equal(entry.message, KS_DSH_ACTION_INVALID)
  }
  for (const alias of P3A_ALIASES) {
    assert(!CLOSED_INTENTS.includes(alias), `alias must not be a closed intent: ${alias}`)
  }
})