import assert from 'node:assert/strict'
import test from 'node:test'

import {
  embeddedCapabilityProjection,
  PINNED_EMBEDDED_MANIFEST,
  projectCapabilityManifest,
  STABLE_ACTIONS,
} from '../lib/capability-manifest.mjs'
import {
  buildRegistrationPlan,
  PLAN_SCHEMA,
  STABLE_TOOL_NAMES,
} from '../lib/capability-registration-plan.mjs'
import {
  canonicalJson,
  sha256Digest,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'

const EXPECTED_TOOLS = Object.freeze([
  Object.freeze({ toolName: 'kaleidosphere_status', action: 'status', capabilityId: 'bi.status.read', authority: 'read-only' }),
  Object.freeze({ toolName: 'kaleidosphere_discovery', action: 'discovery', capabilityId: 'bi.discovery.run', authority: 'local-evidence-write' }),
  Object.freeze({ toolName: 'kaleidosphere_analyze', action: 'analyze', capabilityId: 'bi.analysis.run', authority: 'source-read-only' }),
  Object.freeze({ toolName: 'kaleidosphere_plan', action: 'plan', capabilityId: 'bi.graph.adaptive-v1.plan', authority: 'proposal-only' }),
  Object.freeze({ toolName: 'kaleidosphere_preview', action: 'preview', capabilityId: 'bi.preview.create', authority: 'proposal-only' }),
  Object.freeze({ toolName: 'kaleidosphere_readback', action: 'readback', capabilityId: 'bi.readback.read', authority: 'read-only' }),
])
const TRUSTED_ACTIONS = ['trusted-apply', 'trusted-readback', 'trusted-rollback']

const SUPPLIED = projectCapabilityManifest(structuredClone(PINNED_EMBEDDED_MANIFEST))
const EMBEDDED = embeddedCapabilityProjection()

function projection(mutate) {
  const value = structuredClone(EMBEDDED)
  mutate?.(value)
  return value
}

function sealedWith(mutate) {
  return projection((value) => {
    mutate(value)
    const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'projectionDigest'))
    value.projectionDigest = sha256Digest(body)
  })
}

function denied(projection, code) {
  assert.throws(() => buildRegistrationPlan(projection), (error) => error.code === code)
}

function assertNoExecutableValues(value) {
  if (Array.isArray(value)) {
    value.forEach(assertNoExecutableValues)
    return
  }
  if (value !== null && typeof value === 'object') {
    assert(Object.getPrototypeOf(value) === Object.prototype, 'plan contains an exotic object')
    for (const entry of Object.values(value)) assertNoExecutableValues(entry)
    return
  }
  assert(value === null || typeof value === 'string' || typeof value === 'boolean', `plan contains an executable or arbitrary value: ${typeof value}`)
}

function assertExactPlan(plan, projection) {
  assert.equal(PLAN_SCHEMA, 'kaleidosphere.dsh/capability-registration-plan/v1')
  assert.equal(plan.schemaVersion, PLAN_SCHEMA)
  assert.equal(plan.projectionDigest, projection.projectionDigest)
  assert.equal(plan.tools.length, 6)
  assert.deepEqual(plan.tools, EXPECTED_TOOLS)
  assert.deepEqual(plan.tools.map((tool) => tool.toolName), STABLE_TOOL_NAMES)
  assert(plan.tools.every((tool) => !TRUSTED_ACTIONS.includes(tool.action)))
  const body = Object.fromEntries(Object.entries(plan).filter(([key]) => key !== 'planDigest'))
  assert.equal(plan.planDigest, sha256Digest(body))
  assert(Object.isFrozen(plan))
  assert(Object.isFrozen(plan.tools))
  assert(plan.tools.every((tool) => Object.isFrozen(tool)))
  assertNoExecutableValues(plan)
}

test('the six stable DSH tool names are a pinned closed set in stable action order', () => {
  assert.deepEqual(STABLE_TOOL_NAMES, [
    'kaleidosphere_status',
    'kaleidosphere_discovery',
    'kaleidosphere_analyze',
    'kaleidosphere_plan',
    'kaleidosphere_preview',
    'kaleidosphere_readback',
  ])
  assert.equal(STABLE_TOOL_NAMES.length, STABLE_ACTIONS.length)
  assert(STABLE_TOOL_NAMES.every((name, index) => name === `kaleidosphere_${STABLE_ACTIONS[index]}`))
  assert(new Set(STABLE_TOOL_NAMES).size === STABLE_TOOL_NAMES.length)
  assert(STABLE_TOOL_NAMES.every((name) => !TRUSTED_ACTIONS.some((action) => name === `kaleidosphere_${action}`)))
})

test('valid supplied and embedded projections map to the same six stable tools except their fixed source metadata', () => {
  const suppliedPlan = buildRegistrationPlan(SUPPLIED)
  const embeddedPlan = buildRegistrationPlan(EMBEDDED)
  assertExactPlan(suppliedPlan, SUPPLIED)
  assertExactPlan(embeddedPlan, EMBEDDED)
  assert.deepEqual(suppliedPlan.tools, embeddedPlan.tools)
  assert.equal(suppliedPlan.projectionDigest, SUPPLIED.projectionDigest)
  assert.equal(embeddedPlan.projectionDigest, EMBEDDED.projectionDigest)
  // Only the source-bound digests differ: the six tool registrations are identical.
  assert.notEqual(suppliedPlan.projectionDigest, embeddedPlan.projectionDigest)
  assert.notEqual(suppliedPlan.planDigest, embeddedPlan.planDigest)
})

test('repeated and key-reordered equivalent projection input yields identical plan bytes and digest', () => {
  const first = buildRegistrationPlan(structuredClone(EMBEDDED))
  const second = buildRegistrationPlan(structuredClone(EMBEDDED))
  assert.equal(canonicalJson(first), canonicalJson(second))
  assert.equal(first.planDigest, second.planDigest)
  // Reordered top-level envelope keys and reversed action-entry keys are the
  // same closed projection and must produce byte-identical plan bytes.
  const reordered = projection((value) => {
    const entries = Object.entries(value)
    for (const [key] of entries) delete value[key]
    for (const [key, entry] of entries.sort(([a], [b]) => (a < b ? -1 : 1))) value[key] = entry
    value.actions = value.actions.map((action) => Object.fromEntries(Object.entries(action).reverse()))
  })
  const reorderedPlan = buildRegistrationPlan(reordered)
  assert.equal(canonicalJson(reorderedPlan), canonicalJson(first))
  assert.equal(reorderedPlan.planDigest, first.planDigest)
})

test('unknown, missing, duplicate, and reordered actions deny', () => {
  denied(sealedWith((value) => { value.actions[0].action = 'free-sql' }), 'KS_DSH_PLAN_ACTION_INVALID')
  denied(sealedWith((value) => { value.actions.pop() }), 'KS_DSH_PLAN_ACTION_INVALID')
  denied(sealedWith((value) => { value.actions[5].action = value.actions[4].action }), 'KS_DSH_PLAN_ACTION_INVALID')
  denied(sealedWith((value) => { value.actions.reverse() }), 'KS_DSH_PLAN_ACTION_INVALID')
})

test('widened authority and false nonMutating deny', () => {
  denied(sealedWith((value) => { value.actions[0].authority = 'source-write' }), 'KS_DSH_PLAN_AUTHORITY_WIDENED')
  denied(sealedWith((value) => { value.actions[2].authority = 'read-only' }), 'KS_DSH_PLAN_AUTHORITY_WIDENED')
  denied(sealedWith((value) => { value.actions[4].nonMutating = false }), 'KS_DSH_PLAN_MUTATING')
  denied(sealedWith((value) => { value.actions[1].nonMutating = 'no' }), 'KS_DSH_PLAN_MUTATING')
})

test('altered capability IDs and digest substitution deny', () => {
  denied(sealedWith((value) => { value.actions[5].capabilityId = 'bi.readback.read-v2' }), 'KS_DSH_PLAN_CAPABILITY_MISMATCH')
  denied(sealedWith((value) => { value.actions[0].capabilityId = 'bi.readback.read' }), 'KS_DSH_PLAN_CAPABILITY_MISMATCH')
  denied(projection((value) => { value.projectionDigest = `sha256:${'0'.repeat(64)}` }), 'KS_DSH_PLAN_DIGEST_TAMPERED')
  denied(projection((value) => { value.actions[1].digest = `sha256:${'a'.repeat(64)}` }), 'KS_DSH_PLAN_DIGEST_TAMPERED')
})

test('a seventh tool or a trusted apply/readback/rollback action cannot enter the plan', () => {
  denied(sealedWith((value) => {
    value.actions.push({ action: 'trusted-apply', capabilityId: 'superset.trusted-apply', authority: 'trusted-approval-only', nonMutating: true, digest: value.actions[0].digest })
  }), 'KS_DSH_PLAN_ACTION_INVALID')
  denied(sealedWith((value) => { value.actions[0].action = 'trusted-apply' }), 'KS_DSH_PLAN_ACTION_INVALID')
  const plan = buildRegistrationPlan(EMBEDDED)
  assert.equal(plan.tools.length, 6)
  assert(plan.tools.every((tool) => !TRUSTED_ACTIONS.includes(tool.action)))
})

test('claim-bearing extra identifiers and wrong envelopes deny', () => {
  denied(sealedWith((value) => { value.claims = ['full-control'] }), 'KS_DSH_PLAN_SURFACE_INVALID')
  denied(sealedWith((value) => { value.actions[0].claims = { scope: 'write' } }), 'KS_DSH_PLAN_SURFACE_INVALID')
  denied(sealedWith((value) => { value.schemaVersion = 'kaleidosphere.dsh/capability-projection/v0' }), 'KS_DSH_PLAN_SCHEMA_STALE')
  denied(sealedWith((value) => { value.source = 'supplied-override' }), 'KS_DSH_PLAN_SOURCE_INVALID')
  denied(sealedWith((value) => { value.product.version = 'v0.17.0' }), 'KS_DSH_PLAN_PIN_STALE')
  denied(sealedWith((value) => { value.freshness.provenance = 'attacker@0000000000000000000000000000000000000000' }), 'KS_DSH_PLAN_PIN_STALE')
})

test('arbitrary executable values cannot enter the plan', () => {
  denied(projection((value) => { value.actions[0].authority = () => 'full-mutation' }), 'KS_DSH_PLAN_AUTHORITY_WIDENED')
  denied(projection((value) => { value.actions[3].nonMutating = () => true }), 'KS_DSH_PLAN_MUTATING')
  denied(projection((value) => { value.tools = () => ['evil-tool'] }), 'KS_DSH_PLAN_SURFACE_INVALID')
  const plan = buildRegistrationPlan(SUPPLIED)
  assertNoExecutableValues(plan)
})

test('plans are deterministic and inputs are not mutated', () => {
  const before = structuredClone(EMBEDDED)
  const first = buildRegistrationPlan(structuredClone(before))
  const second = buildRegistrationPlan(structuredClone(before))
  assert.equal(canonicalJson(first), canonicalJson(second))
  assert.equal(first.planDigest, second.planDigest)
  assert.equal(canonicalJson(before), canonicalJson(EMBEDDED))
})