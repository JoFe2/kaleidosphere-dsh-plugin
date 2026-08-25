import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { createServer } from 'node:http'
import os from 'node:os'
import test from 'node:test'

import { CLOSED_INTENTS, createToolDefinitions, KaleidoSphereRuntime, TOOL_NAMES } from '../lib/runtime.mjs'
import {
  capabilityAttestationV2,
  executeExternalIntentV2,
  sha256Digest,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import {
  embeddedCapabilityProjection,
  PINNED_EMBEDDED_MANIFEST,
  projectCapabilityManifest,
} from '../lib/capability-manifest.mjs'
import {
  buildRegistrationPlan,
  STABLE_TOOL_NAMES,
} from '../lib/capability-registration-plan.mjs'
import {
  buildObjectSearchAuthorityBoundResult,
  continueObjectSearchAuthorityBoundResult,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-search-authority-bound-result-v1.mjs'
import {
  createObjectInventorySnapshot,
  createObjectSearchCoverageBinding,
  createObjectSearchEnvelope,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-search-envelope-v1.mjs'
import {
  canonicalJson,
  identitySha256,
  normalizeJsonValue,
  buildPreflightEvidence,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/core.mjs'
import {
  buildObjectNameAuthority,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-name-authority-v1.mjs'
import {
  buildObjectRelationKindAuthority,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-relation-kind-authority-v1.mjs'
import {
  buildObjectInventoryAuthorityDigest,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-inventory-authority-digest-v1.mjs'
import {
  buildProgressiveCoverage,
  buildProgressiveMethodRegistry,
  createProgressiveCoverage,
  createProgressiveRun,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/progressive-controller.mjs'
import {
  KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
  KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
  buildObjectCapabilityContractV1,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-capability-contract-v1.mjs'
import {
  KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID,
  handleObjectSearchV1,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-search-handler-v1.mjs'
import {
  KS_OBJECT_DETAILS_HANDLER_CAPABILITY,
  KS_OBJECT_DETAILS_HANDLER_FAIL_CLOSED_CODES,
  handleObjectDetailsV1,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-details-handler-v1.mjs'
import {
  OBJECT_DETAILS_PROJECTION_SCHEMA,
  projectObjectDetails,
  verifyObjectDetailsProjection,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-details-projection-v1.mjs'

const expectedDigests = JSON.parse(await readFile(new URL('./expected-fixture-digests.json', import.meta.url), 'utf8'))

test('fixture executes all six released intents through External API v2 and K1', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const status = await runtime.execute('status')
    assert.equal(status.response.action, 'status')
    assert.equal(status.response.result.status, 'READY')
    assert.equal(status.response.result.pluginVersion, '0.1.0-preview.4')

    const analyze = await runtime.execute('analyze')
    assert.equal(analyze.response.action, 'analyze')
    assert.equal(analyze.response.result.evidence.snapshotSha256,
      '293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a')
    assert.equal(analyze.response.result.evidence.runtimeValidation, 'SYNTHETIC_UNVALIDATED')

    const discovery = await runtime.execute('discovery', { command: 'start', sessionId: 'demo-1' })
    assert.equal(discovery.response.result.status, 'IN_PROGRESS')
    const plan = await runtime.execute('plan', { objective: 'Review weekly order value' })
    assert.equal(plan.response.result.authority.proposalOnly, true)
    const preview = await runtime.execute('preview', { objective: 'Preview weekly order value' })
    assert.deepEqual(preview.response.result.relations, ['dbo.customers', 'dbo.orders'])
    const readback = await runtime.execute('readback')
    assert.equal(readback.response.result.catalog.coverageComplete, true)
    assert.equal(readback.response.result.technicalOverview.relationRows, 2)

    for (const [action, output] of Object.entries({ status, analyze, discovery, plan, preview, readback })) {
      assert.match(output.response.integrity.digest, /^sha256:[a-f0-9]{64}$/)
      assert.match(output.evidence.evidenceDigest, /^sha256:[a-f0-9]{64}$/)
      assert.equal(output.evidence.status, 'succeeded')
      assert.equal(output.evidence.resultIntegrityDigest, output.response.integrity.digest)
      assert.deepEqual({ response: output.response.integrity.digest, evidence: output.evidence.evidenceDigest }, expectedDigests[action])
    }
  } finally {
    await runtime.dispose()
  }
})

test('tool surface is six separate discoverable native names', async () => {
  const runtime = await KaleidoSphereRuntime.create()
  try {
    const tools = createToolDefinitions(runtime)
    assert.deepEqual(CLOSED_INTENTS, ['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'])
    assert.deepEqual(tools.map(tool => tool.name), CLOSED_INTENTS.map(action => TOOL_NAMES[action]))
    assert.equal(new Set(tools.map(tool => tool.name)).size, 6)
    assert(tools.every(tool => tool.output && typeof tool.execute === 'function'))
  } finally {
    await runtime.dispose()
  }
})

test('intent exposure defaults on and accepts six fail-closed boolean toggles', async () => {
  const runtime = await KaleidoSphereRuntime.create({
    expose: { discovery: false, plan: false, preview: false },
  })
  try {
    assert.deepEqual(createToolDefinitions(runtime).map(tool => tool.name), [
      'kaleidosphere_status',
      'kaleidosphere_analyze',
      'kaleidosphere_readback',
    ])
  } finally {
    await runtime.dispose()
  }

  await assert.rejects(KaleidoSphereRuntime.create({ expose: { unknown: false } }),
    /KS_DSH_EXPOSURE_CONFIG_INVALID/)
  await assert.rejects(KaleidoSphereRuntime.create({ expose: { analyze: 'yes' } }),
    /KS_DSH_EXPOSURE_BOOLEAN_REQUIRED_ANALYZE/)
  await assert.rejects(KaleidoSphereRuntime.create({
    expose: Object.fromEntries(CLOSED_INTENTS.map(action => [action, false])),
  }), /KS_DSH_EXPOSURE_EMPTY/)
})

test('external runtime mode binds the attested loopback v2 API without an embedded runtime', async () => {
  const requests = []
  const server = createServer((request, response) => {
    const chunks = []
    request.on('data', chunk => chunks.push(chunk))
    request.on('end', async () => {
      try {
        requests.push({ method: request.method, url: request.url })
        let value
        if (request.method === 'GET' && request.url === '/v2/capabilities') {
          value = capabilityAttestationV2()
        } else if (request.method === 'POST' && request.url === '/v2/intents') {
          value = await executeExternalIntentV2(JSON.parse(Buffer.concat(chunks).toString('utf8')), {
            status: () => ({ status: 'EXTERNAL_READY', sourceMode: 'fixture', engine: 'mssql' }),
          })
        } else {
          response.writeHead(404).end()
          return
        }
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(JSON.stringify(value))
      } catch (error) {
        response.writeHead(500, { 'content-type': 'application/json' })
        response.end(JSON.stringify({ error: error.message }))
      }
    })
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert(address && typeof address !== 'string')
  const before = new Set((await readdir(os.tmpdir())).filter(name => name.startsWith('kaleidosphere-dsh-')))
  const expose = Object.fromEntries(CLOSED_INTENTS.map(action => [action, action === 'status']))
  const runtime = await KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    external: { baseUrl: `http://127.0.0.1:${address.port}` },
    expose,
  })
  try {
    assert.deepEqual(createToolDefinitions(runtime).map(tool => tool.name), ['kaleidosphere_status'])
    const status = await runtime.execute('status')
    assert.equal(status.response.result.status, 'EXTERNAL_READY')
    assert.equal(status.evidence.status, 'succeeded')
    const after = (await readdir(os.tmpdir())).filter(name =>
      name.startsWith('kaleidosphere-dsh-') && !before.has(name))
    assert.deepEqual(after, [])
    assert.deepEqual(requests, [
      { method: 'GET', url: '/v2/capabilities' },
      { method: 'POST', url: '/v2/intents' },
    ])
  } finally {
    await runtime.dispose()
    await new Promise(resolve => server.close(resolve))
  }

  await assert.rejects(KaleidoSphereRuntime.create({ runtimeMode: 'external' }),
    /KS_DSH_EXTERNAL_CONFIG_REQUIRED/)
  await assert.rejects(KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    source: { mode: 'fixture' },
    external: { baseUrl: 'http://127.0.0.1:18790' },
  }), /KS_DSH_EXTERNAL_SOURCE_DENIED/)
  await assert.rejects(KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    external: { baseUrl: 'https://ks.example.com' },
  }), /KS_DSH_EXTERNAL_BASE_URL_DENIED/)
})

test('external runtime preserves caller cancellation and distinguishes transport timeout', async () => {
  const server = createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/v2/capabilities') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(capabilityAttestationV2()))
      return
    }
    if (request.method === 'POST' && request.url === '/v2/intents') {
      request.resume()
      setTimeout(() => {
        if (response.destroyed) return
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end('{}')
      }, 250)
      return
    }
    response.writeHead(404).end()
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert(address && typeof address !== 'string')
  const baseUrl = `http://127.0.0.1:${address.port}`
  try {
    const cancellable = await KaleidoSphereRuntime.create({
      runtimeMode: 'external', external: { baseUrl, timeoutMs: 1_000 },
    })
    try {
      const controller = new AbortController()
      const execution = cancellable.execute('status', {}, controller.signal)
      controller.abort()
      await assert.rejects(execution, error => error?.name === 'AbortError')
    } finally {
      await cancellable.dispose()
    }

    const bounded = await KaleidoSphereRuntime.create({
      runtimeMode: 'external', external: { baseUrl, timeoutMs: 100 },
    })
    try {
      await assert.rejects(bounded.execute('status'), /KS_DSH_EXTERNAL_TIMEOUT/)
    } finally {
      await bounded.dispose()
    }
  } finally {
    await new Promise(resolve => server.close(resolve))
  }
})

test('configuration fails loud and analysis-dependent tools explain missing state', async () => {
  await assert.rejects(KaleidoSphereRuntime.create({ unknown: true }), /KS_DSH_CONFIG_INVALID/)
  await assert.rejects(KaleidoSphereRuntime.create({ source: { mode: 'remote' } }), /KS_DSH_SOURCE_MODE_INVALID/)
  await assert.rejects(KaleidoSphereRuntime.create({ source: { mode: 'live' } }), /KS_DSH_LIVE_PROFILE_REQUIRED/)

  const runtime = await KaleidoSphereRuntime.create()
  try {
    await assert.rejects(runtime.execute('readback'), /KS_DSH_ANALYSIS_REQUIRED/)
    await assert.rejects(runtime.execute('plan', { objective: 'Review weekly order value' }), /KS_DSH_ANALYSIS_REQUIRED/)
  } finally {
    await runtime.dispose()
  }
})

test('released MSSQL and Oracle live profile contracts load without contacting a database', async () => {
  const common = {
    schemaVersion: 'chimpmaera.db/analyze-profile/v1',
    mode: 'RUNTIME',
    queryPack: { version: 'v1' },
    policy: { access: 'READ_ONLY', allowRowSamples: false, maxQueryTimeoutMs: 10000 },
  }
  const cases = [
    {
      env: 'KS_TEST_MSSQL_PASSWORD',
      profile: {
        ...common,
        profileId: 'test-readonly-mssql',
        engine: 'mssql',
        scope: { database: 'Analytics', container: null, schemas: ['dbo'] },
        adapter: { kind: 'mssql', host: 'sql.example.internal', port: 1433, user: 'reader', passwordEnv: 'KS_TEST_MSSQL_PASSWORD', encrypt: true, trustServerCertificate: false },
      },
    },
    {
      env: 'KS_TEST_ORACLE_PASSWORD',
      profile: {
        ...common,
        profileId: 'test-readonly-oracle',
        engine: 'oracle',
        scope: { database: 'FREE', container: 'FREEPDB1', schemas: ['BI_DEMO'] },
        adapter: { kind: 'oracle', host: 'oracle.example.internal', port: 1521, user: 'BI_ANALYZE', passwordEnv: 'KS_TEST_ORACLE_PASSWORD', protocol: 'tcp', serviceName: 'FREEPDB1', serverDn: null, connectTimeoutMs: 10000 },
      },
    },
  ]
  for (const item of cases) {
    process.env[item.env] = 'test-only-not-a-real-secret'
    const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'live', profile: item.profile } })
    try {
      const status = await runtime.execute('status')
      assert.equal(status.response.result.engine, item.profile.engine)
      assert.equal(status.response.result.sourceMode, 'live')
    } finally {
      await runtime.dispose()
      delete process.env[item.env]
    }
  }
  const oracle = (await import('../third_party/oracledb-7.0.1/index.js')).default
  assert.equal(oracle.versionString, '7.0.1')
  assert.equal(oracle.thin, true)
})

test('dispose removes the runtime temp resource and rejects later work', async () => {
  const before = new Set((await readdir(os.tmpdir())).filter(name => name.startsWith('kaleidosphere-dsh-')))
  const runtime = await KaleidoSphereRuntime.create()
  const active = (await readdir(os.tmpdir())).filter(name => name.startsWith('kaleidosphere-dsh-') && !before.has(name))
  assert.equal(active.length, 1)
  await runtime.dispose()
  const after = (await readdir(os.tmpdir())).filter(name => name.startsWith('kaleidosphere-dsh-') && !before.has(name))
  assert.deepEqual(after, [])
  await assert.rejects(runtime.execute('status'), /KS_DSH_RUNTIME_DISPOSED/)
})

test('default EMBEDDED runtime creation binds the six stable tools to the pinned registration plan', async () => {
  const runtime = await KaleidoSphereRuntime.create()
  try {
    const plan = buildRegistrationPlan(embeddedCapabilityProjection())
    assert.equal(runtime.capabilityDecision.mode, 'EMBEDDED')
    assert.equal(runtime.capabilityDecision.source, 'embedded')
    assert.deepEqual(runtime.registrationPlan, plan)
    const tools = createToolDefinitions(runtime)
    assert.deepEqual(tools.map(tool => tool.name), STABLE_TOOL_NAMES)
    assert.deepEqual(tools.map(tool => tool.name), CLOSED_INTENTS.map(action => TOOL_NAMES[action]))
    tools.forEach((tool, index) => {
      assert.equal(tool.name, plan.tools[index].toolName)
      assert.deepEqual(tool.capability, {
        action: plan.tools[index].action,
        capabilityId: plan.tools[index].capabilityId,
        authority: plan.tools[index].authority,
      })
    })
    const status = await tools[0].execute({}, { signal: new AbortController().signal })
    assert.equal(status.response.result.status, 'READY')
  } finally {
    await runtime.dispose()
  }
})

const canonicalManifest = (mutate) => {
  const manifest = structuredClone(PINNED_EMBEDDED_MANIFEST)
  mutate?.(manifest)
  return manifest
}

const resealedManifest = (mutate) => canonicalManifest((manifest) => {
  mutate(manifest)
  const body = Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== 'attestation'))
  manifest.attestation = { algorithm: 'sha256-canonical-json', digest: sha256Digest(body) }
})

test('canonical supplied EXTERNAL manifest yields the same closed registration surface', async () => {
  const runtime = await KaleidoSphereRuntime.create({
    capability: { mode: 'EXTERNAL', supplied: canonicalManifest() },
  })
  try {
    const embeddedPlan = buildRegistrationPlan(embeddedCapabilityProjection())
    const suppliedPlan = buildRegistrationPlan(projectCapabilityManifest(canonicalManifest()))
    assert.equal(runtime.capabilityDecision.mode, 'EXTERNAL')
    assert.equal(runtime.capabilityDecision.source, 'external')
    assert.deepEqual(runtime.registrationPlan, suppliedPlan)
    assert.notEqual(runtime.registrationPlan.projectionDigest, embeddedPlan.projectionDigest)
    assert.deepEqual(runtime.registrationPlan.tools, embeddedPlan.tools)
    const tools = createToolDefinitions(runtime)
    assert.deepEqual(tools.map(tool => tool.name), STABLE_TOOL_NAMES)
    tools.forEach((tool, index) => assert.equal(tool.name, embeddedPlan.tools[index].toolName))
    const status = await runtime.execute('status')
    assert.equal(status.response.result.status, 'READY')
    const analyze = await runtime.execute('analyze')
    assert.equal(analyze.response.result.evidence.snapshotSha256,
      '293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a')
    const readback = await runtime.execute('readback')
    assert.equal(readback.response.result.catalog.coverageComplete, true)
  } finally {
    await runtime.dispose()
  }
})

test('capability source admission denies unknown modes, fields, and missing evidence', async () => {
  const createWith = (capability) => KaleidoSphereRuntime.create({ capability })
  await assert.rejects(createWith({ mode: 'EXTERNAL' }),
    (error) => error.code === 'KS_DSH_SOURCE_EXTERNAL_MANIFEST_MISSING')
  await assert.rejects(createWith({ mode: 'EXTERNAL', supplied: null }),
    (error) => error.code === 'KS_DSH_SOURCE_EXTERNAL_MANIFEST_MISSING')
  await assert.rejects(createWith({ mode: 'EMBEDDED', supplied: canonicalManifest() }),
    (error) => error.code === 'KS_DSH_SOURCE_EMBEDDED_MANIFEST_SUPPLIED')
  await assert.rejects(createWith({ supplied: canonicalManifest() }),
    (error) => error.code === 'KS_DSH_SOURCE_EMBEDDED_MANIFEST_SUPPLIED')
  await assert.rejects(createWith({ mode: 'HYBRID' }), (error) => error.code === 'KS_DSH_SOURCE_MODE_UNKNOWN')
  await assert.rejects(createWith({ mode: 'embedded' }), (error) => error.code === 'KS_DSH_SOURCE_MODE_UNKNOWN')
  await assert.rejects(createWith({ mode: 42 }), (error) => error.code === 'KS_DSH_SOURCE_MODE_UNKNOWN')
  await assert.rejects(createWith({ mode: 'EMBEDDED', supplied: null, extra: true }),
    (error) => error.code === 'KS_DSH_SOURCE_SURFACE_INVALID')
  await assert.rejects(createWith({ credential: 'x' }), (error) => error.code === 'KS_DSH_SOURCE_SURFACE_INVALID')
  await assert.rejects(createWith({ mode: 'EXTERNAL', baseUrl: 'http://127.0.0.1:8790' }),
    (error) => error.code === 'KS_DSH_SOURCE_SURFACE_INVALID')
  await assert.rejects(createWith({ mode: 'EXTERNAL', note: 'free text' }),
    (error) => error.code === 'KS_DSH_SOURCE_SURFACE_INVALID')
  await assert.rejects(createWith({ mode: 'EXTERNAL', supplied: canonicalManifest(), callback: () => {} }),
    (error) => error.code === 'KS_DSH_SOURCE_SURFACE_INVALID')
  await assert.rejects(createWith('http://ks.example.com'), (error) => error.code === 'KS_DSH_SOURCE_SURFACE_INVALID')
  await assert.rejects(createWith([canonicalManifest()]), (error) => error.code === 'KS_DSH_SOURCE_SURFACE_INVALID')
  await assert.rejects(createWith({ mode: 'EXTERNAL', supplied: Object.create(PINNED_EMBEDDED_MANIFEST) }),
    (error) => error.code === 'KS_DSH_MANIFEST_SURFACE_INVALID')
})

test('stale, tampered, substituted, or re-digested external evidence denies without fallback', async () => {
  const createWith = (mutate) => KaleidoSphereRuntime.create({
    capability: { mode: 'EXTERNAL', supplied: canonicalManifest(mutate) },
  })
  await assert.rejects(createWith((m) => { m.schemaVersion = 'superset-bi-agent.external/capability-attestation/v1' }),
    (error) => error.code === 'KS_DSH_MANIFEST_SCHEMA_STALE')
  await assert.rejects(createWith((m) => { m.product.version = 'v0.15.0' }),
    (error) => error.code === 'KS_DSH_MANIFEST_PRODUCT_STALE')
  await assert.rejects(createWith((m) => { m.contract.version = '1.9.9' }),
    (error) => error.code === 'KS_DSH_MANIFEST_CONTRACT_STALE')
  await assert.rejects(createWith((m) => { m.capabilities[0].authority = 'source-read-only' }),
    (error) => error.code === 'KS_DSH_MANIFEST_CAPABILITY_WIDENED')
  await assert.rejects(createWith((m) => { m.capabilities[0].id = 'bi.status.write' }),
    (error) => error.code === 'KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
  // identifier substitution with unchanged digest: a stable entry claiming another pinned id
  await assert.rejects(createWith((m) => { m.capabilities[0].id = m.capabilities[5].id }),
    (error) => error.code === 'KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
  // a seventh capability or a trusted action cannot enter the closed set
  await assert.rejects(createWith((m) => { m.capabilities.push({ ...m.capabilities[0] }) }),
    (error) => error.code === 'KS_DSH_MANIFEST_CAPABILITY_UNKNOWN')
  await assert.rejects(createWith((m) => { m.boundaries.freeSqlAccepted = true }),
    (error) => error.code === 'KS_DSH_MANIFEST_BOUNDARIES_WIDENED')
  await assert.rejects(createWith((m) => { m.graph.acceptedIncumbent = 'candidate-v2' }),
    (error) => error.code === 'KS_DSH_MANIFEST_GRAPH_STALE')
  // claim-bearing fields on valid identifiers are outside the closed surface
  await assert.rejects(createWith((m) => { m.capabilities[0].claim = 'audited' }),
    (error) => error.code === 'KS_DSH_MANIFEST_SURFACE_INVALID')
  await assert.rejects(createWith((m) => { m.claim = { audited: true } }),
    (error) => error.code === 'KS_DSH_MANIFEST_SURFACE_INVALID')
  // reordered capability array: structurally valid, attestation digest no longer matches
  await assert.rejects(createWith((m) => { const [first] = m.capabilities.splice(0, 1); m.capabilities.push(first) }),
    (error) => error.code === 'KS_DSH_MANIFEST_TAMPERED')
  // fully re-digested forged envelope: self-consistent but no longer the pinned digest
  await assert.rejects(KaleidoSphereRuntime.create({
    capability: { mode: 'EXTERNAL', supplied: resealedManifest((m) => { const [first] = m.capabilities.splice(0, 1); m.capabilities.push(first) }) },
  }), (error) => error.code === 'KS_DSH_MANIFEST_DIGEST_STALE')
  // denial is fail closed: no runtime is produced and the default EMBEDDED pin is untouched
  const embedded = await KaleidoSphereRuntime.create()
  try {
    assert.deepEqual(embedded.registrationPlan, buildRegistrationPlan(embeddedCapabilityProjection()))
  } finally {
    await embedded.dispose()
  }
})

test('tampered, reordered, widened, or re-digested projections deny the plan before exposure', () => {
  const base = embeddedCapabilityProjection()
  const deny = (mutate, code) => {
    const value = structuredClone(base)
    mutate(value)
    assert.throws(() => buildRegistrationPlan(value), (error) => error.code === code)
  }
  deny((value) => { const [first] = value.actions.splice(0, 1); value.actions.push(first) }, 'KS_DSH_PLAN_ACTION_INVALID')
  deny((value) => { value.actions.push(structuredClone(value.actions[0])) }, 'KS_DSH_PLAN_ACTION_INVALID')
  deny((value) => { value.actions.splice(2, 1) }, 'KS_DSH_PLAN_ACTION_INVALID')
  deny((value) => { value.actions[0].action = 'analyze' }, 'KS_DSH_PLAN_ACTION_INVALID')
  deny((value) => { value.actions[0].capabilityId = 'bi.discovery.run' }, 'KS_DSH_PLAN_CAPABILITY_MISMATCH')
  deny((value) => { value.actions[0].authority = 'source-read-only' }, 'KS_DSH_PLAN_AUTHORITY_WIDENED')
  deny((value) => { value.actions[0].nonMutating = false }, 'KS_DSH_PLAN_MUTATING')
  deny((value) => { value.digest = `sha256:${'0'.repeat(64)}` }, 'KS_DSH_PLAN_PIN_STALE')
  deny((value) => { value.schemaVersion = 'kaleidosphere.dsh/capability-projection/v0' }, 'KS_DSH_PLAN_SCHEMA_STALE')
  deny((value) => { value.actions[0].digest = `sha256:${'0'.repeat(64)}` }, 'KS_DSH_PLAN_DIGEST_TAMPERED')
  deny((value) => { value.projectionDigest = `sha256:${'1'.repeat(64)}` }, 'KS_DSH_PLAN_DIGEST_TAMPERED')
  // fully re-digested forged projection envelope: sealed body matches, pinned capability does not
  const forged = structuredClone(base)
  forged.actions[0].capabilityId = 'bi.readback.read'
  const body = Object.fromEntries(Object.entries(forged).filter(([key]) => key !== 'projectionDigest'))
  forged.projectionDigest = sha256Digest(body)
  assert.throws(() => buildRegistrationPlan(forged), (error) => error.code === 'KS_DSH_PLAN_CAPABILITY_MISMATCH')
})

test('exposed tools carry only the six plan-bound non-mutating registrations', async () => {
  const runtime = await KaleidoSphereRuntime.create()
  try {
    const tools = createToolDefinitions(runtime)
    assert.equal(tools.length, 6)
    assert.equal(new Set(tools.map(tool => tool.name)).size, 6)
    assert.deepEqual(tools.map(tool => tool.name), STABLE_TOOL_NAMES)
    const forbiddenActions = ['trusted-apply', 'trusted-readback', 'trusted-rollback', 'apply', 'rollback']
    assert(tools.every(tool => !forbiddenActions.includes(tool.capability.action)))
    const mutatingAuthorities = ['source-write', 'model-mutation', 'trusted-approval-only', 'apply']
    assert(tools.every(tool => !mutatingAuthorities.includes(tool.capability.authority)))
    assert(tools.every(tool => Object.isFrozen(tool.capability)))
    await assert.rejects(KaleidoSphereRuntime.create({ credential: 'x' }),
      (error) => error.code === 'KS_DSH_CONFIG_INVALID')
    await assert.rejects(KaleidoSphereRuntime.create({ path: '/etc/passwd' }),
      (error) => error.code === 'KS_DSH_CONFIG_INVALID')
    await assert.rejects(KaleidoSphereRuntime.create({ callback: () => {} }),
      (error) => error.code === 'KS_DSH_CONFIG_INVALID')
  } finally {
    await runtime.dispose()
  }
})

test('external runtime mode keeps the attested v2 fetch and binds the plan by capability source', async () => {
  const requests = []
  const server = createServer((request, response) => {
    const chunks = []
    request.on('data', chunk => chunks.push(chunk))
    request.on('end', async () => {
      requests.push({ method: request.method, url: request.url })
      let value
      if (request.method === 'GET' && request.url === '/v2/capabilities') {
        value = capabilityAttestationV2()
      } else if (request.method === 'POST' && request.url === '/v2/intents') {
        value = await executeExternalIntentV2(JSON.parse(Buffer.concat(chunks).toString('utf8')), {
          status: () => ({ status: 'EXTERNAL_READY', sourceMode: 'fixture', engine: 'mssql' }),
        })
      } else {
        response.writeHead(404).end()
        return
      }
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(value))
    })
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert(address && typeof address !== 'string')
  const embeddedPlan = buildRegistrationPlan(embeddedCapabilityProjection())
  const baseUrl = `http://127.0.0.1:${address.port}`
  try {
    const embeddedSource = await KaleidoSphereRuntime.create({ runtimeMode: 'external', external: { baseUrl } })
    try {
      assert.deepEqual(embeddedSource.registrationPlan.tools, embeddedPlan.tools)
      const status = await embeddedSource.execute('status')
      assert.equal(status.response.result.status, 'EXTERNAL_READY')
    } finally {
      await embeddedSource.dispose()
    }

    const suppliedSource = await KaleidoSphereRuntime.create({
      runtimeMode: 'external',
      external: { baseUrl },
      capability: { mode: 'EXTERNAL', supplied: canonicalManifest() },
    })
    try {
      assert.deepEqual(suppliedSource.registrationPlan.tools, embeddedPlan.tools)
      assert.notEqual(suppliedSource.registrationPlan.projectionDigest, embeddedPlan.projectionDigest)
      assert.deepEqual(createToolDefinitions(suppliedSource).map(tool => tool.name), STABLE_TOOL_NAMES)
      const status = await suppliedSource.execute('status')
      assert.equal(status.response.result.status, 'EXTERNAL_READY')
    } finally {
      await suppliedSource.dispose()
    }
    assert.deepEqual(requests, [
      { method: 'GET', url: '/v2/capabilities' },
      { method: 'POST', url: '/v2/intents' },
      { method: 'GET', url: '/v2/capabilities' },
      { method: 'POST', url: '/v2/intents' },
    ])
  } finally {
    await new Promise(resolve => server.close(resolve))
  }
})

// P2B2A: reusable fully synthetic direct Search-handler fixture and focused
// happy/negative oracle against the pinned vendored handleObjectSearchV1
// (v0.24.0 closure, source commit e092bb0), derived from the upstream reference
// test object-search-handler-v1.test.mjs. The fixture is self-contained: the
// structure manifest, SQL templates, result sets and profile context are built
// inline, so there are no query-pack/profile data-file reads, environment
// credentials, network access, or production edits. The only filesystem access
// in the handler import chain is the vendored external-api-v2.mjs reading its
// own co-located services/bi-agent/package.json (one of the 16 pinned closure
// files).
const SEARCH_CAPABILITY_ID = KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID
const SEARCH_OTHER_CAPABILITY_ID = 'bi.object.details.read'
const FORGED_PROJECTION = 'KS_OBJECT_SEARCH_HANDLER_PROJECTION_FORGED'
const HANDLER_INPUT_INVALID = 'KS_OBJECT_SEARCH_HANDLER_INPUT_INVALID'
const CAPABILITY_MISMATCH = 'KS_OBJECT_SEARCH_HANDLER_CAPABILITY_MISMATCH'
const PINNED_SEARCH_CLAIMS = Object.freeze({
  absenceClaimed: false, completenessClaimed: false, replayPreventionClaimed: false, sourceRowsIncluded: false,
})
const PINNED_SEARCH_AUTHORITY = Object.freeze({
  credentialsIncluded: false, dispatchAuthority: false, executionAuthority: false,
  mutationAuthority: false, queryExecution: false, rawValuesIncluded: false, sqlAuthority: false,
})
const hash64 = (character) => character.repeat(64)
const assertFrozen = (value) => {
  if (!value || typeof value !== 'object') return
  assert(Object.isFrozen(value))
  Object.values(value).forEach(assertFrozen)
}

test('P2B2A: vendored handleObjectSearchV1 returns a deterministic deeply frozen read-only envelope bound to the canonical request and projection digests (mssql and oracle first page)', () => {
  for (const engine of ['mssql', 'oracle']) {
    const { sources, envelope } = syntheticSearchFixture(engine)
    const value = validSearchHandlerInput({ engine, sources, envelope })
    const first = handleObjectSearchV1(value)
    const repeated = handleObjectSearchV1({
      request: { ...value.request, bindings: { ...value.request.bindings }, scope: { ...value.request.scope, schemas: [...value.request.scope.schemas] } },
      projection: value.projection,
      projectionInput: value.projectionInput,
    })
    assert.equal(first.schemaVersion, KS_OBJECT_CAPABILITY_RESULT_SCHEMA)
    assert.equal(first.capabilityId, SEARCH_CAPABILITY_ID)
    assert.equal(first.state, 'PROJECTED_READ_ONLY')
    assert.equal(first.requestSha256, identitySha256(value.request))
    assert.equal(first.projectionSha256, value.projection.projectionSha256)
    assert.deepEqual(first.bindings, value.request.bindings)
    assert.notEqual(first.bindings, value.request.bindings)
    assert.deepEqual(first.claims, PINNED_SEARCH_CLAIMS)
    assert.deepEqual(first.authority, PINNED_SEARCH_AUTHORITY)
    assertFrozen(first)
    assert.throws(() => { first.state = 'MUTATED' }, TypeError)
    assert.equal(canonicalJson(first), canonicalJson(repeated))
    const validated = buildObjectCapabilityContractV1().validateResult(first, {
      capabilityId: SEARCH_CAPABILITY_ID,
      requestSha256: first.requestSha256,
      projectionSha256: first.projectionSha256,
      bindings: value.request.bindings,
    })
    assert.deepEqual(validated, first)
    assert.notEqual(validated, first)
    assertFrozen(validated)
  }
})

test('P2B2A: vendored handleObjectSearchV1 continuation inputs are deterministic and bound to the first-page cursor (mssql and oracle)', () => {
  for (const engine of ['mssql', 'oracle']) {
    const { sources, envelope } = syntheticSearchFixture(engine)
    const firstPage = buildObjectSearchAuthorityBoundResult({ ...sources, request: envelope })
    assert(firstPage.nextCursor)
    const value = validSearchHandlerInput({ engine, sources, envelope, cursor: firstPage.nextCursor })
    assert.equal(value.projection.page.pageIndex, 1)
    assert.equal(value.projection.nextCursor, null)
    const first = handleObjectSearchV1(value)
    const repeated = handleObjectSearchV1(value)
    assert.equal(first.schemaVersion, KS_OBJECT_CAPABILITY_RESULT_SCHEMA)
    assert.equal(first.state, 'PROJECTED_READ_ONLY')
    assert.equal(first.requestSha256, identitySha256(value.request))
    assert.equal(first.projectionSha256, value.projection.projectionSha256)
    assertFrozen(first)
    assert.equal(canonicalJson(first), canonicalJson(repeated))
  }
})

test('P2B2A: capability mismatch, request surface, binding drift and scope denials carry pinned codes', () => {
  const { sources, envelope } = syntheticSearchFixture('mssql')
  const value = validSearchHandlerInput({ engine: 'mssql', sources, envelope })
  const bindings = value.request.bindings
  const closed = (capabilityId, requestBindings, schemas) => ({
    schemaVersion: KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
    requestId: `handler-${capabilityId.split('.').pop()}`,
    capabilityId,
    bindings: requestBindings,
    scope: { schemas },
  })
  const cases = [
    [{ ...value, request: closed(SEARCH_OTHER_CAPABILITY_ID, bindings, value.request.scope.schemas) }, CAPABILITY_MISMATCH],
    [{ ...value, request: { ...closed(SEARCH_CAPABILITY_ID, bindings, value.request.scope.schemas), sql: 'SELECT 1' } }, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED'],
    [{ ...value, request: { ...closed(SEARCH_CAPABILITY_ID, bindings, value.request.scope.schemas), credentials: 'secret' } }, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED'],
    [{ ...value, request: { ...closed(SEARCH_CAPABILITY_ID, bindings, value.request.scope.schemas), callback: 'https://evil.invalid' } }, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED'],
    [{ ...value, request: { ...closed(SEARCH_CAPABILITY_ID, bindings, value.request.scope.schemas), rawRows: [] } }, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED'],
    [{ ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, claims: { completenessClaimed: true } }, value.request.scope.schemas) }, 'KS_OBJECT_CAPABILITY_BINDING_DENIED'],
    [{ ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, dispatchAuthority: true }, value.request.scope.schemas) }, 'KS_OBJECT_CAPABILITY_BINDING_DENIED'],
    ...Object.keys(bindings).filter((key) => key !== 'engine').map((key) => [
      { ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, [key]: hash64('0') }, value.request.scope.schemas) },
      'KS_OBJECT_CAPABILITY_BINDING_DENIED',
    ]),
    [{ ...value, request: closed(SEARCH_CAPABILITY_ID, bindings, ['../escape']) }, 'KS_OBJECT_CAPABILITY_SCOPE_DENIED'],
    [{ ...value, request: closed(SEARCH_CAPABILITY_ID, bindings, ['other']) }, 'KS_OBJECT_CAPABILITY_SCOPE_DENIED'],
    [{ ...value, request: closed(SEARCH_CAPABILITY_ID, bindings, Array.from({ length: 257 }, (_, index) => `s${index}`)) }, 'KS_OBJECT_CAPABILITY_SCOPE_DENIED'],
    [{ ...value, request: null }, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED'],
  ]
  for (const [input, code] of cases) assert.throws(() => handleObjectSearchV1(input), { code, message: code })
})

test('P2B2A: handler-surface injection and projectionInput forgery deny with pinned codes', () => {
  const { sources, envelope } = syntheticSearchFixture('mssql')
  const value = validSearchHandlerInput({ engine: 'mssql', sources, envelope })
  for (const extra of [{ sql: 'SELECT 1' }, { credentials: 'secret' }, { callback: 'https://evil.invalid' }, { result: {} }, { query: 'SELECT 1' }]) {
    assert.throws(() => handleObjectSearchV1({ ...value, ...extra }), { code: HANDLER_INPUT_INVALID, message: HANDLER_INPUT_INVALID })
  }
  for (const projectionInput of [
    { ...value.projectionInput, sql: 'SELECT 1' },
    { ...value.projectionInput, credentials: 'secret' },
    { ...value.projectionInput, callback: 'https://evil.invalid' },
  ]) {
    assert.throws(() => handleObjectSearchV1({ ...value, projectionInput }), { code: FORGED_PROJECTION, message: FORGED_PROJECTION })
  }
})

test('P2B2A: substituted, re-digested, stale and page-mismatched projections deny with one fixed code', () => {
  const { sources, envelope } = syntheticSearchFixture('mssql')
  const value = validSearchHandlerInput({ engine: 'mssql', sources, envelope })
  const forged = (mutate) => {
    const projection = structuredClone(value.projection)
    mutate(projection)
    return { ...value, projection }
  }
  const tampered = [
    (projection) => { projection.items[0].objectName = 'ForgedTable' },
    (projection) => { projection.page.matchCount += 1 },
    (projection) => { projection.bindings.objectNameAuthoritySha256 = hash64('0') },
    (projection) => { projection.claims.absenceClaimed = true },
    (projection) => { projection.authority.sqlAuthority = true },
    (projection) => { projection.authority.dispatchAuthority = true },
    (projection) => { projection.authority.executionAuthority = true },
    (projection) => { projection.authority.mutationAuthority = true },
    (projection) => { projection.authority.replayPreventionClaimed = true },
    (projection) => { projection.rawRows = [] },
  ]
  for (const mutate of tampered) {
    assert.throws(() => handleObjectSearchV1(forged(mutate)), { code: FORGED_PROJECTION, message: FORGED_PROJECTION })
  }
  const redigested = forged((projection) => { projection.items[0].objectName = 'ForgedTable' })
  const { projectionSha256: observedSha256, ...redigestedBody } = normalizeJsonValue(redigested.projection)
  assert.throws(() => handleObjectSearchV1({
    ...redigested,
    projection: { ...redigestedBody, projectionSha256: identitySha256(redigestedBody) },
  }), { code: FORGED_PROJECTION, message: FORGED_PROJECTION })
  const firstInput = { ...sources, request: envelope }
  const first = buildObjectSearchAuthorityBoundResult(firstInput)
  assert(first.nextCursor)
  const secondInput = { ...sources, request: envelope, cursor: first.nextCursor }
  const second = continueObjectSearchAuthorityBoundResult(secondInput)
  assert.throws(() => handleObjectSearchV1({ ...value, projection: second }), { code: FORGED_PROJECTION, message: FORGED_PROJECTION })
  assert.throws(() => handleObjectSearchV1({ ...value, projection: first, projectionInput: secondInput }), { code: FORGED_PROJECTION, message: FORGED_PROJECTION })
  const exhaustedEnvelope = searchEnvelopeFor('mssql', { pageSize: 10 })
  const exhaustedInput = { ...sources, request: exhaustedEnvelope, cursor: first.nextCursor }
  assert.throws(() => handleObjectSearchV1({
    ...validSearchHandlerInput({ engine: 'mssql', sources, envelope: exhaustedEnvelope }),
    projectionInput: exhaustedInput,
  }), { code: FORGED_PROJECTION, message: FORGED_PROJECTION })
})

test('P2B2A: resealed unsafe search envelopes and request scope substitution deny', () => {
  const { sources, envelope } = syntheticSearchFixture('mssql')
  const value = validSearchHandlerInput({ engine: 'mssql', sources, envelope })
  const resealedEnvelope = (mutate) => {
    const copy = structuredClone(envelope)
    delete copy.envelopeSha256
    mutate(copy)
    return { ...normalizeJsonValue(copy), envelopeSha256: identitySha256(normalizeJsonValue(copy)) }
  }
  const withEnvelope = (mutate) => ({
    ...value,
    projection: buildObjectSearchAuthorityBoundResult({ ...sources, request: envelope }),
    projectionInput: { ...sources, request: resealedEnvelope(mutate) },
  })
  const cases = [
    (body) => { body.prefix = 'Inventory; DROP TABLE Students;--' },
    (body) => { body.prefix = 'password123' },
    (body) => { body.pageSize = 501 },
    (body) => { delete body.coverage.stateCounts.DENIED },
    (body) => { body.receiptSha256 = hash64('0') },
    (body) => { body.scope.schemas = ['../escape'] },
  ]
  for (const mutate of cases) {
    assert.throws(() => handleObjectSearchV1(withEnvelope(mutate)), { code: FORGED_PROJECTION, message: FORGED_PROJECTION })
  }
  const SCOPE_DENIED = 'KS_OBJECT_CAPABILITY_SCOPE_DENIED'
  for (const engine of ['mssql', 'oracle']) {
    const fixture = syntheticSearchFixture(engine)
    const scoped = validSearchHandlerInput({ engine, sources: fixture.sources, envelope: fixture.envelope })
    assert.throws(() => handleObjectSearchV1({
      ...scoped,
      request: { ...scoped.request, scope: { schemas: ['other'] } },
    }), { code: SCOPE_DENIED, message: SCOPE_DENIED })
  }
})

// Fully synthetic fixture builders for the direct Search handler oracle above.
// Every input is constructed inline: a minimal structure manifest, template SQL,
// runtime result sets and a profile context, sealed through the vendored
// buildPreflightEvidence and progressive-controller authority chain. No
// query-pack/profile files are read and no environment is consulted.
const SYNTHETIC_SCHEMA = { mssql: 'dbo', oracle: 'BI_DEMO' }
const SYNTHETIC_DATABASE = { mssql: 'Analytics', oracle: 'FREE' }
const SYNTHETIC_CONTAINER = { mssql: null, oracle: 'FREEPDB1' }
const SYNTHETIC_PREFIX = { mssql: 'Inventory', oracle: 'Order' }
const SYNTHETIC_RELATIONS = {
  mssql: [
    { schema_name: 'dbo', relation_name: 'InventoryTable', relation_kind: 'TABLE' },
    { schema_name: 'dbo', relation_name: 'InventoryView', relation_kind: 'VIEW' },
  ],
  oracle: [
    { schema_name: 'BI_DEMO', relation_name: 'Order Detail$Table', relation_kind: 'TABLE' },
    { schema_name: 'BI_DEMO', relation_name: 'Order Detail$View', relation_kind: 'VIEW' },
  ],
}
const SYNTHETIC_COVERAGE_STATES = ['COMPLETE', 'PARTIAL', 'DENIED', 'UNKNOWN']

function syntheticStructureManifest(engine) {
  const provenance = { url: 'https://github.com/JoFe2/KaleidoSphere', copiedCode: false }
  const query = (id, category, file, outputColumns) => ({
    id,
    category,
    file,
    outputColumns,
    sortKeys: [],
    scopeColumn: 'schema_name',
    timeoutMs: 1000,
    cost: 'BOUNDED',
    readOnly: true,
    privilege: { minimum: 'CONNECT' },
    fallback: { onDenied: 'DENIED_IS_NOT_ABSENT' },
    provenance,
  })
  return {
    schemaVersion: 'chimpmaera.db/query-manifest/v1',
    packId: `synthetic-${engine}-search-pack`,
    packVersion: '1.0.0',
    engine,
    queries: [
      query(`${engine}.structure.schemas`, 'schemas', `synthetic-${engine}-structure-schemas.sql`, ['schema_name']),
      query(`${engine}.structure.relations`, 'relations', `synthetic-${engine}-structure-relations.sql`, ['schema_name', 'relation_name', 'relation_kind']),
    ],
  }
}

function syntheticStructureEvidence(engine) {
  const manifest = syntheticStructureManifest(engine)
  const sqlByQueryId = Object.fromEntries(manifest.queries.map((item) => [item.id, `SELECT synthetic ${item.category} rows for ${item.id};`]))
  const resultSets = {
    schemaVersion: 'chimpmaera.db/runtime-query-results/v1',
    engine,
    runtimeValidated: true,
    results: {
      [`${engine}.structure.schemas`]: { state: 'SUCCEEDED', reasonCode: null, rows: [{ schema_name: SYNTHETIC_SCHEMA[engine] }] },
      [`${engine}.structure.relations`]: { state: 'SUCCEEDED', reasonCode: null, rows: SYNTHETIC_RELATIONS[engine] },
    },
  }
  const profileContext = {
    profileId: `synthetic-${engine}-search-profile`,
    mode: 'RUNTIME',
    scope: { database: SYNTHETIC_DATABASE[engine], container: SYNTHETIC_CONTAINER[engine], schemas: [SYNTHETIC_SCHEMA[engine]] },
    policy: { access: 'READ_ONLY', allowRowSamples: false, maxQueryTimeoutMs: 10000 },
    adapter: { kind: engine },
  }
  return buildPreflightEvidence({ manifest, sqlByQueryId, resultSets, profileContext })
}

function syntheticSearchSources(engine) {
  const evidence = syntheticStructureEvidence(engine)
  const base = buildProgressiveCoverage(evidence)
  const coverage = createProgressiveCoverage({
    engine,
    structureSnapshotSha256: base.structureSnapshotSha256,
    structureCoverageLedgerSha256: base.structureCoverageLedgerSha256,
    entries: base.entries.map((entry, index) => ({
      objectRef: entry.objectRef,
      state: SYNTHETIC_COVERAGE_STATES[index % 4],
      reasonCode: index % 4 === 0 ? null : `FIXTURE_${SYNTHETIC_COVERAGE_STATES[index % 4]}`,
      sourceQueryId: entry.sourceQueryId,
      evidenceRefs: entry.evidenceRefs,
    })),
    queryCoverage: base.queryCoverage,
  })
  const controllerRun = createProgressiveRun({
    runId: `${engine}-search-handler-v1-secret`,
    engine,
    scope: evidence.profile.scope,
    methodRegistry: buildProgressiveMethodRegistry({ structureManifest: syntheticStructureManifest(engine) }),
    coverage,
    budgets: { maxRunProbes: 4, maxObjectProbes: 2 },
  })
  const inventoryAuthorityProjection = buildObjectInventoryAuthorityDigest(controllerRun)
  const relationKindAuthorityProjection = buildObjectRelationKindAuthority({
    controllerRun, inventoryAuthorityProjection, structureEvidence: evidence,
  })
  const objectNameAuthorityProjection = buildObjectNameAuthority({
    controllerRun, inventoryAuthorityProjection, relationKindAuthorityProjection, structureEvidence: evidence,
  })
  return {
    controllerRun,
    inventoryAuthorityProjection,
    relationKindAuthorityProjection,
    objectNameAuthorityProjection,
    structureEvidence: evidence,
  }
}

function searchEnvelopeFor(engine, { pageSize = 1 } = {}) {
  return createObjectSearchEnvelope({
    engine,
    scope: { schemas: [SYNTHETIC_SCHEMA[engine]] },
    prefix: SYNTHETIC_PREFIX[engine],
    kindFilters: ['TABLE', 'VIEW'],
    pageSize,
    inventory: createObjectInventorySnapshot({
      engine,
      kindCounts: { TABLE: 2, VIEW: 1, COLUMN: 0, INDEX: 0, SEQUENCE: 0, SYNONYM: 0 },
    }),
    coverage: createObjectSearchCoverageBinding({
      stateCounts: { SUCCEEDED: 5, PARTIAL: 1, DENIED: 1, UNSUPPORTED: 0, TIMEOUT: 0, ERROR: 0 },
    }),
  })
}

function syntheticSearchFixture(engine) {
  return { sources: syntheticSearchSources(engine), envelope: searchEnvelopeFor(engine) }
}

function validSearchHandlerInput({ engine, sources, envelope, cursor }) {
  const bindings = {
    engine,
    snapshotSha256: sources.objectNameAuthorityProjection.structureSnapshotSha256,
    receiptSha256: envelope.envelopeSha256,
    coverageSha256: sources.controllerRun.coverage.coverageSha256,
    inventoryAuthoritySha256: sources.objectNameAuthorityProjection.inventoryAuthorityDigestSha256,
    relationKindAuthoritySha256: sources.objectNameAuthorityProjection.relationKindAuthoritySha256,
    objectNameAuthoritySha256: sources.objectNameAuthorityProjection.objectNameAuthoritySha256,
    cancellationSha256: identitySha256({ cancellation: 'NONE', engine }),
  }
  const projectionInput = cursor
    ? { ...sources, request: envelope, cursor }
    : { ...sources, request: envelope }
  const projection = cursor
    ? continueObjectSearchAuthorityBoundResult(projectionInput)
    : buildObjectSearchAuthorityBoundResult(projectionInput)
  return {
    request: {
      schemaVersion: KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
      requestId: `handler-${SEARCH_CAPABILITY_ID.split('.').pop()}`,
      capabilityId: SEARCH_CAPABILITY_ID,
      bindings,
      scope: { schemas: envelope.scope.schemas },
    },
    projection,
    projectionInput,
  }
}

// P2B2B: focused oracle for runtime Search dispatch. Reuses the verified P2B2A
// synthetic Search fixture/oracle: the runtime dispatches Search locally to the
// pinned vendored handleObjectSearchV1 (v0.24.0 closure, source commit e092bb0),
// passes the sealed handler input through untouched (the pinned handler is the
// single authority for malformed or authority-bearing input and re-derives every
// binding from its recomputed projection), and seals the frozen PROJECTED_READ_ONLY
// result in a v2 result envelope. Search is additive and local only: the six v0.16
// paths and the six-tool surface are untouched, Search is never sent to the shared
// external API, and no Details/Overview/credential/SQL/network/mutation surface is
// added. The sealed handler result (all claims and authority false) is the evidence;
// the v0.16 evidence bridge is fail closed to actions outside the six closed intents
// by design (the v0.24 contract marks object capabilities a separate-versioned
// extension with externalApiV2Changed false).
const SEARCH_RESULT_SCHEMA = 'superset-bi-agent.external/intent-result/v2'
const SEARCH_EXTERNAL_DENIED = 'KS_DSH_SEARCH_EXTERNAL_DENIED'
const SEARCH_RESPONSE_KEYS = Object.freeze([
  'schemaVersion', 'requestId', 'action', 'runtime', 'capabilityAttestationDigest', 'result', 'integrity',
])
const REQUEST_SURFACE_DENIED = 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED'
const BINDING_DENIED = 'KS_OBJECT_CAPABILITY_BINDING_DENIED'
const SCOPE_DENIED = 'KS_OBJECT_CAPABILITY_SCOPE_DENIED'

test('P2B2B: runtime Search dispatches locally to the pinned handler, preserving bindings and the sealed result (mssql and oracle first page and continuation)', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    for (const engine of ['mssql', 'oracle']) {
      const { sources, envelope } = syntheticSearchFixture(engine)
      const cursors = [undefined, buildObjectSearchAuthorityBoundResult({ ...sources, request: envelope }).nextCursor]
      for (const cursor of cursors) {
        const value = validSearchHandlerInput({ engine, sources, envelope, cursor })
        const direct = handleObjectSearchV1(value)
        const out = await runtime.execute('search', value)
        // Pass-through to the pinned handler: the sealed result is returned
        // unaltered (byte-identical to a direct dispatch) and re-validated
        // through the vendored capability contract.
        assert.deepEqual(out.response.result, direct)
        assert.equal(canonicalJson(out.response.result), canonicalJson(handleObjectSearchV1(value)))
        const validated = buildObjectCapabilityContractV1().validateResult(out.response.result, {
          capabilityId: SEARCH_CAPABILITY_ID,
          requestSha256: out.response.result.requestSha256,
          projectionSha256: out.response.result.projectionSha256,
          bindings: value.request.bindings,
        })
        assert.deepEqual(validated, out.response.result)
        // Preserves the canonical request bindings of the verified fixture.
        assert.deepEqual(out.response.result.bindings, value.request.bindings)
        // Sealed, deeply frozen v2 result envelope around the pinned result.
        assertFrozen(out.response)
        assert.deepEqual(Object.keys(out.response), SEARCH_RESPONSE_KEYS)
        assert.equal(out.response.schemaVersion, SEARCH_RESULT_SCHEMA)
        assert.equal(out.response.action, 'search')
        assert.equal(out.response.requestId, `ks-search-${sha256Digest({ action: 'search', input: value }).slice(7, 31)}`)
        const attestation = capabilityAttestationV2()
        assert.deepEqual(out.response.runtime, { product: attestation.product, contract: attestation.contract })
        assert.equal(out.response.capabilityAttestationDigest, attestation.attestation.digest)
        assert.equal(out.response.integrity.algorithm, 'sha256-canonical-json')
        assert.match(out.response.integrity.digest, /^sha256:[a-f0-9]{64}$/)
        const { integrity, ...body } = out.response
        assert.equal(sha256Digest(body), out.response.integrity.digest)
        // No authority: the pinned claims and authority surface stays all false.
        assert.deepEqual(out.response.result.claims, PINNED_SEARCH_CLAIMS)
        assert.deepEqual(out.response.result.authority, PINNED_SEARCH_AUTHORITY)
        // Dispatch is deterministic: a repeated dispatch seals an identical envelope.
        const repeated = await runtime.execute('search', value)
        assert.equal(canonicalJson(repeated.response), canonicalJson(out.response))
      }
    }
    // Additive: the six closed v0.16 paths and the six-tool surface are untouched.
    const status = await runtime.execute('status')
    assert.equal(status.response.result.status, 'READY')
    assert.equal(status.evidence.status, 'succeeded')
    const tools = createToolDefinitions(runtime)
    assert.equal(tools.length, 6)
    assert(tools.every(tool => tool.capability.action !== 'search'))
    await assert.rejects(runtime.execute('details'), /KS_DSH_ACTION_INVALID/)
    await assert.rejects(runtime.execute('overview'), /KS_DSH_ACTION_INVALID/)
  } finally {
    await runtime.dispose()
  }
})

test('P2B2B: malformed and authority-bearing Search input denies with the pinned handler codes through the runtime', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const { sources, envelope } = syntheticSearchFixture('mssql')
    const value = validSearchHandlerInput({ engine: 'mssql', sources, envelope })
    const bindings = value.request.bindings
    const closed = (capabilityId, requestBindings, schemas) => ({
      schemaVersion: KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
      requestId: `handler-${capabilityId.split('.').pop()}`,
      capabilityId,
      bindings: requestBindings,
      scope: { schemas },
    })
    const first = buildObjectSearchAuthorityBoundResult({ ...sources, request: envelope })
    const second = continueObjectSearchAuthorityBoundResult({ ...sources, request: envelope, cursor: first.nextCursor })
    const cases = [
      // Absent or wrong-surface handler input never reaches a result.
      [{}, HANDLER_INPUT_INVALID],
      [null, HANDLER_INPUT_INVALID],
      [{ ...value, sql: 'SELECT 1' }, HANDLER_INPUT_INVALID],
      [{ ...value, credentials: 'secret' }, HANDLER_INPUT_INVALID],
      [{ ...value, callback: 'https://evil.invalid' }, HANDLER_INPUT_INVALID],
      [{ ...value, request: null }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...closed(SEARCH_CAPABILITY_ID, bindings, value.request.scope.schemas), sql: 'SELECT 1' } }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...closed(SEARCH_CAPABILITY_ID, bindings, value.request.scope.schemas), rawRows: [] } }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: closed(SEARCH_OTHER_CAPABILITY_ID, bindings, value.request.scope.schemas) }, CAPABILITY_MISMATCH],
      // Authority-bearing or drifted request bindings deny.
      [{ ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, dispatchAuthority: true }, value.request.scope.schemas) }, BINDING_DENIED],
      [{ ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, executionAuthority: true }, value.request.scope.schemas) }, BINDING_DENIED],
      [{ ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, sqlAuthority: true }, value.request.scope.schemas) }, BINDING_DENIED],
      [{ ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, claims: { completenessClaimed: true } }, value.request.scope.schemas) }, BINDING_DENIED],
      [{ ...value, request: closed(SEARCH_CAPABILITY_ID, { ...bindings, objectNameAuthoritySha256: hash64('0') }, value.request.scope.schemas) }, BINDING_DENIED],
      // Out-of-scope or escaped request scope denies.
      [{ ...value, request: closed(SEARCH_CAPABILITY_ID, bindings, ['other']) }, SCOPE_DENIED],
      [{ ...value, request: closed(SEARCH_CAPABILITY_ID, bindings, ['../escape']) }, SCOPE_DENIED],
      // Substituted or page-mismatched projections and forged projectionInput deny.
      [{ ...value, projection: second }, FORGED_PROJECTION],
      [{ ...value, projectionInput: { ...sources, request: envelope, cursor: first.nextCursor } }, FORGED_PROJECTION],
      [{ ...value, projectionInput: { ...value.projectionInput, sql: 'SELECT 1' } }, FORGED_PROJECTION],
      [{ ...value, projectionInput: { ...value.projectionInput, credentials: 'secret' } }, FORGED_PROJECTION],
    ]
    for (const [input, code] of cases) {
      await assert.rejects(runtime.execute('search', input), { code, message: code })
    }
    // Denial is fail closed: a denied Search leaves no result and the runtime stays usable.
    const after = await runtime.execute('search', value)
    assert.equal(canonicalJson(after.response.result), canonicalJson(handleObjectSearchV1(value)))
  } finally {
    await runtime.dispose()
  }
})

test('P2B2B: external runtime mode denies Search locally and never sends it to the shared external API', async () => {
  const requests = []
  const server = createServer((request, response) => {
    requests.push({ method: request.method, url: request.url })
    if (request.method === 'GET' && request.url === '/v2/capabilities') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end(JSON.stringify(capabilityAttestationV2()))
      return
    }
    response.writeHead(404).end()
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  assert(address && typeof address !== 'string')
  const { sources, envelope } = syntheticSearchFixture('mssql')
  const value = validSearchHandlerInput({ engine: 'mssql', sources, envelope })
  const runtime = await KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    external: { baseUrl: `http://127.0.0.1:${address.port}` },
  })
  try {
    // Search is local only: it is outside the v0.16 closed intent set and must
    // deny before any request leaves the process.
    await assert.rejects(runtime.execute('search', value),
      { code: SEARCH_EXTERNAL_DENIED, message: SEARCH_EXTERNAL_DENIED })
    // Only the create-time attestation fetch touched the network; Search never did.
    assert.deepEqual(requests, [{ method: 'GET', url: '/v2/capabilities' }])
  } finally {
    await runtime.dispose()
    await new Promise(resolve => server.close(resolve))
  }
})

// P2B3A: reusable fully synthetic direct Details-handler fixture and focused
// happy/negative oracle against the pinned vendored handleObjectDetailsV1
// (v0.24.0 closure, source commit e092bb0), derived from the upstream reference
// test object-details-handler-v1.test.mjs (SHA-256
// aa340155e06a1f97092b8f7a3759d248aa45e283ede1cd2562153f22bf9fc4c5). The oracle
// follows the pinned post-merge two-argument
// handleObjectDetailsV1(request, projectionInput) signature and is
// self-contained: the progressive coverage ledger, sealed evidence receipt,
// projection input and capability request are built inline from synthetic
// literals, so there are no query-pack/profile data-file reads, environment
// credentials, network access, production runtime edits, or Search fixture
// rewrites. The reference adversarial-matrix helper is not part of the pinned
// closure; its negative cases are therefore enumerated inline with exact
// pinned codes, matching the P2B2A oracle precedent.
const DETAILS_ENGINES = ['mssql', 'oracle']
const DETAILS_REQUEST_IDENTITY_DENIED = 'KS_OBJECT_CAPABILITY_REQUEST_IDENTITY_DENIED'
const DETAILS_CLAIM_DENIED = 'KS_OBJECT_CAPABILITY_CLAIM_DENIED'
const DETAILS_AUTHORITY_DENIED = 'KS_OBJECT_CAPABILITY_AUTHORITY_DENIED'
const DETAILS_HANDLER_FAIL_CLOSED_CODES = Object.freeze([
  'KS_OBJECT_DETAILS_HANDLER_CAPABILITY_DENIED',
  'KS_OBJECT_DETAILS_HANDLER_REQUEST_DIGEST_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_PROJECTION_INPUT_INVALID',
  'KS_OBJECT_DETAILS_HANDLER_ENGINE_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_SCOPE_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_BINDING_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_PROJECTION_DIGEST_DRIFT',
])
const DETAILS_RESULT_KEYS = Object.freeze([
  'authority', 'bindings', 'capabilityId', 'claims', 'projectionSha256', 'requestSha256', 'schemaVersion', 'state',
])
const DETAILS_CLAIMS = Object.freeze({
  absenceClaimed: false, completenessClaimed: false, replayPreventionClaimed: false, sourceRowsIncluded: false,
})
const DETAILS_AUTHORITY = Object.freeze({
  credentialsIncluded: false, dispatchAuthority: false, executionAuthority: false,
  mutationAuthority: false, queryExecution: false, rawValuesIncluded: false, sqlAuthority: false,
})

test('P2B3A: vendored handleObjectDetailsV1 derives exact MSSQL/Oracle coverage states and returns deterministic isolated read-only projections', () => {
  for (const engine of DETAILS_ENGINES) {
    for (const [name, spec] of Object.entries(DETAILS_STATES)) {
      const {projectionInput, request, projection} = syntheticDetailsScenario(engine, spec)
      const result = handleObjectDetailsV1(request, projectionInput)
      assert.equal(result.schemaVersion, KS_OBJECT_CAPABILITY_RESULT_SCHEMA)
      assert.equal(result.state, 'PROJECTED_READ_ONLY')
      assert.equal(result.capabilityId, KS_OBJECT_DETAILS_HANDLER_CAPABILITY)
      assert.equal(result.requestSha256, identitySha256(normalizeJsonValue(request)))
      assert.equal(result.projectionSha256, projection.projectionSha256)
      assert.deepEqual(result.bindings, detailsBindingsOf(projection))
      assert.notEqual(result.bindings, request.bindings)
      assert.deepEqual(Object.keys(result).sort(), [...DETAILS_RESULT_KEYS])
      assert.deepEqual(result.claims, DETAILS_CLAIMS)
      assert.deepEqual(result.authority, DETAILS_AUTHORITY)
      verifyObjectDetailsProjection(projection, projectionInput)
      assert.equal(projection.schemaVersion, OBJECT_DETAILS_PROJECTION_SCHEMA)
      assert.equal(projection.coverage.state, spec.state, `${engine} ${name}`)
      assertFrozen(result)
      assert.equal(canonicalJson(handleObjectDetailsV1(request, projectionInput)), canonicalJson(result))
    }
  }
})

test('P2B3A: handler exports the closed read-only details capability and the pinned fail-closed code set without dispatch', () => {
  assert.equal(KS_OBJECT_DETAILS_HANDLER_CAPABILITY, 'bi.object.details.read')
  assert.ok(Object.isFrozen(KS_OBJECT_DETAILS_HANDLER_FAIL_CLOSED_CODES))
  assert.deepEqual(KS_OBJECT_DETAILS_HANDLER_FAIL_CLOSED_CODES, [...DETAILS_HANDLER_FAIL_CLOSED_CODES])
  assert.ok(!KS_OBJECT_DETAILS_HANDLER_FAIL_CLOSED_CODES.includes('KS_OBJECT_DETAILS_HANDLER_DISPATCH_INCLUDED'))
})

test('P2B3A: capability, scope and every capability-profile binding substitution deny with pinned codes against unchanged authority', () => {
  const {projectionInput, request} = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
  assert.throws(() => handleObjectDetailsV1({...request, capabilityId: 'bi.object.search.read'}, projectionInput),
    {code: DETAILS_REQUEST_IDENTITY_DENIED, message: DETAILS_REQUEST_IDENTITY_DENIED})
  const substitutions = [
    ['scope', {schemas: ['other']}],
    ...Object.keys(request.bindings).filter((key) => key !== 'engine').map((key) => [key, hash64('0')]),
  ]
  for (const [key, value] of substitutions) {
    const substituted = key === 'scope'
      ? {...request, scope: value}
      : {...request, bindings: {...request.bindings, [key]: value}}
    const code = key === 'scope' ? SCOPE_DENIED : BINDING_DENIED
    assert.throws(() => handleObjectDetailsV1(substituted, projectionInput), {code, message: code})
  }
  assert.throws(() => handleObjectDetailsV1(
    {...request, bindings: {...request.bindings, cancellationSha256: hash64('7')}}, projectionInput),
    {code: BINDING_DENIED, message: BINDING_DENIED})
})

test('P2B3A: unsafe request fields, identifiers, oversized evidence, stale receipt and projection-input substitutions deny with pinned codes', () => {
  const {ledger, entry, request, projectionInput} = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
  for (const [field, value] of [['sql', 'SELECT 1'], ['credentials', 'secret'], ['rawRows', []], ['callback', 'https://evil.invalid']]) {
    assert.throws(() => handleObjectDetailsV1({...request, [field]: value}, projectionInput),
      {code: REQUEST_SURFACE_DENIED, message: REQUEST_SURFACE_DENIED})
  }
  const withEntry = (next) => detailsProjectionInputFor('mssql', {entry: next, ledger: detailsLedgerWithEntry(ledger, next)})
  assert.throws(() => handleObjectDetailsV1(request, withEntry(detailsRawEntry({relationName: 'sales--orders'}))),
    {code: 'DB_OBJECT_DETAILS_IDENTIFIER_INVALID', message: 'DB_OBJECT_DETAILS_IDENTIFIER_INVALID'})
  assert.throws(() => handleObjectDetailsV1(request, withEntry(detailsRawEntry({relationName: 'sales_orders_verified'}))),
    {code: 'DB_OBJECT_DETAILS_IDENTIFIER_CLAIM', message: 'DB_OBJECT_DETAILS_IDENTIFIER_CLAIM'})
  const oversized = detailsRawEntry({})
  oversized.evidenceRefs = Array.from({length: 17}, (_, index) => identitySha256({evidence: index}))
  assert.throws(() => handleObjectDetailsV1(request, withEntry(oversized)),
    {code: 'DB_OBJECT_DETAILS_EVIDENCE_INVALID', message: 'DB_OBJECT_DETAILS_EVIDENCE_INVALID'})
  assert.throws(() => handleObjectDetailsV1(request, {...projectionInput, objectKey: identitySha256({missing: true})}),
    {code: 'DB_OBJECT_DETAILS_COVERAGE_MISSING', message: 'DB_OBJECT_DETAILS_COVERAGE_MISSING'})
  const unrelated = detailsLedgerFor('mssql', DETAILS_STATES.COMPLETE, {relationName: 'other_orders'})
  assert.throws(() => handleObjectDetailsV1(request, detailsProjectionInputFor('mssql', {
    entry, ledger, receipt: detailsReceiptFor('mssql', {entry: unrelated.entry, ledger: unrelated.ledger}),
  })), {code: 'DB_OBJECT_DETAILS_RECEIPT_BINDING_INVALID', message: 'DB_OBJECT_DETAILS_RECEIPT_BINDING_INVALID'})
  assert.throws(() => handleObjectDetailsV1(request, {...projectionInput, hint: 'select 1'}),
    {code: 'DB_OBJECT_DETAILS_INPUT_INVALID', message: 'DB_OBJECT_DETAILS_INPUT_INVALID'})
})

test('P2B3A: re-digested forged details evidence and every result authority widening deny with pinned codes', () => {
  const {projectionInput, request, projection} = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
  const {projectionSha256: _old, ...body} = {...projection, coverage: {...projection.coverage, visibility: 'EXHAUSTIVE'}}
  const forged = {...body, projectionSha256: identitySha256(body)}
  assert.throws(() => verifyObjectDetailsProjection(forged, projectionInput),
    {code: 'DB_OBJECT_DETAILS_FORGED', message: 'DB_OBJECT_DETAILS_FORGED'})

  const result = handleObjectDetailsV1(request, projectionInput)
  const expected = {
    capabilityId: result.capabilityId,
    requestSha256: result.requestSha256,
    projectionSha256: result.projectionSha256,
    bindings: detailsBindingsOf(projection),
  }
  const {validateResult} = buildObjectCapabilityContractV1()
  assert.deepEqual(validateResult(result, expected), result)
  const widenings = [
    [{...result, claims: {...result.claims, completenessClaimed: true}}, DETAILS_CLAIM_DENIED],
    [{...result, claims: {...result.claims, sourceRowsIncluded: true}}, DETAILS_CLAIM_DENIED],
    [{...result, authority: {...result.authority, dispatchAuthority: true}}, DETAILS_AUTHORITY_DENIED],
    [{...result, authority: {...result.authority, executionAuthority: true}}, DETAILS_AUTHORITY_DENIED],
    [{...result, authority: {...result.authority, mutationAuthority: true}}, DETAILS_AUTHORITY_DENIED],
    [{...result, authority: {...result.authority, sqlAuthority: true}}, DETAILS_AUTHORITY_DENIED],
    [{...result, authority: {...result.authority, rawValuesIncluded: true}}, DETAILS_AUTHORITY_DENIED],
  ]
  for (const [changed, code] of widenings) assert.throws(() => validateResult(changed, expected), {code, message: code})
})

test('P2B3A: Proxy, accessor, hidden and symbol request surfaces deny before traps execute', () => {
  const {projectionInput, request} = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
  let traps = 0
  const proxy = new Proxy(request, {getPrototypeOf() { traps += 1; return Object.prototype; }})
  assert.throws(() => handleObjectDetailsV1(proxy, projectionInput),
    {code: REQUEST_SURFACE_DENIED, message: REQUEST_SURFACE_DENIED})
  assert.equal(traps, 0)

  const hidden = structuredClone(request)
  Object.defineProperty(hidden, 'credentials', {value: 'secret', enumerable: false})
  assert.throws(() => handleObjectDetailsV1(hidden, projectionInput),
    {code: REQUEST_SURFACE_DENIED, message: REQUEST_SURFACE_DENIED})
  const symbol = structuredClone(request)
  symbol[Symbol('secret')] = 'hidden'
  assert.throws(() => handleObjectDetailsV1(symbol, projectionInput),
    {code: REQUEST_SURFACE_DENIED, message: REQUEST_SURFACE_DENIED})

  let getterCalls = 0
  const accessor = structuredClone(request)
  Object.defineProperty(accessor.bindings, 'coverageSha256', {
    enumerable: true, get() { getterCalls += 1; return request.bindings.coverageSha256; },
  })
  assert.throws(() => handleObjectDetailsV1(accessor, projectionInput),
    {code: REQUEST_SURFACE_DENIED, message: REQUEST_SURFACE_DENIED})
  assert.equal(getterCalls, 0)
})

// Fully synthetic fixture builders for the direct Details handler oracle
// above. Every input is constructed inline from synthetic literals: a coverage
// ledger sealed through the vendored createProgressiveCoverage, a sealed
// evidence receipt, the projection input and the capability request bound to
// the recomputed projection. No query-pack/profile files are read and no
// environment is consulted.
const DETAILS_SCOPES = {
  mssql: {database: 'salesdb', container: null, schemas: ['dbo', 'finance']},
  oracle: {database: 'orcl_sales', container: null, schemas: ['DBO', 'FIN']},
}
const DETAILS_STATES = {
  COMPLETE: {state: 'COMPLETE', reasonCode: null},
  DENIED: {state: 'DENIED', reasonCode: 'PRIVILEGE_DENIED'},
  PARTIAL: {state: 'PARTIAL', reasonCode: 'PARTIAL_ROW_LIMIT'},
  UNKNOWN: {state: 'UNKNOWN', reasonCode: 'OBJECT_NOT_FOUND'},
}
const DETAILS_VISIBILITY = {COMPLETE: 'VISIBLE', DENIED: 'INVISIBLE', PARTIAL: 'VISIBLE_PARTIAL', UNKNOWN: 'UNKNOWN'}

const detailsScopeSha256 = (engine) => identitySha256(normalizeJsonValue(DETAILS_SCOPES[engine]))
const detailsSnapshotSha256 = (engine) => identitySha256({kind: 'structure-snapshot', engine})
const detailsPreflightLedgerSha256 = (engine) => identitySha256({kind: 'preflight-coverage-ledger', engine})
const detailsSourceObjectSha256 = (engine, relationName) => identitySha256({kind: 'inventory-object', engine, relationName})
const detailsSeal = (body, key) => ({...normalizeJsonValue(body), [key]: identitySha256(normalizeJsonValue(body))})

function detailsLedgerFor(engine, spec, {relationName = 'sales_orders'} = {}) {
  const sourceObjectSha256 = detailsSourceObjectSha256(engine, relationName)
  const refs = [...new Set([detailsSnapshotSha256(engine), detailsPreflightLedgerSha256(engine), sourceObjectSha256])].sort()
  const objectRef = {
    kind: 'RELATION', schemaName: DETAILS_SCOPES[engine].schemas[0], relationName,
    columnName: null, objectName: null, sourceObjectSha256,
  }
  const queryState = spec.state === 'COMPLETE' ? 'SUCCEEDED' : spec.state === 'DENIED' ? 'DENIED' : 'PARTIAL'
  const ledger = createProgressiveCoverage({
    engine,
    structureSnapshotSha256: detailsSnapshotSha256(engine),
    structureCoverageLedgerSha256: detailsPreflightLedgerSha256(engine),
    entries: [{objectRef, state: spec.state, reasonCode: spec.reasonCode, sourceQueryId: `${engine}.structure-relations`, evidenceRefs: refs}],
    queryCoverage: [{
      queryId: `${engine}.structure-relations`, category: 'relations', state: queryState,
      reasonCode: spec.state === 'COMPLETE' ? null : spec.reasonCode,
      visibility: spec.state === 'COMPLETE' ? 'VISIBLE_COMPLETE' : DETAILS_VISIBILITY[spec.state], absenceClaim: 'NOT_CLAIMED',
    }],
  })
  return {ledger, entry: ledger.entries[0]}
}

function detailsReceiptFor(engine, {entry, ledger}) {
  return detailsSeal({
    schemaVersion: 'kaleidosphere.analysis/object-details-evidence-receipt/v1', engine,
    scopeSha256: detailsScopeSha256(engine), inventorySnapshotSha256: detailsSnapshotSha256(engine),
    coverageLedgerSha256: ledger.coverageSha256,
    objectKey: entry.objectKey, coverageEntrySha256: identitySha256(entry), evidenceRefs: [...entry.evidenceRefs].sort(),
  }, 'receiptSha256')
}

function detailsProjectionInputFor(engine, {
  entry,
  ledger,
  receipt = detailsReceiptFor(engine, {entry, ledger}),
  objectKey = entry.objectKey,
  scope = DETAILS_SCOPES[engine],
  scopeSha256 = detailsScopeSha256(engine),
  inventorySnapshotSha256 = detailsSnapshotSha256(engine),
  ...extra
} = {}) {
  return {engine, scope, scopeSha256, inventorySnapshotSha256, coverageLedger: ledger, receipt, objectKey, ...extra}
}

function detailsBindingsOf(projection) {
  return {
    engine: projection.engine,
    snapshotSha256: projection.bindings.inventorySnapshotSha256,
    receiptSha256: projection.bindings.receiptSha256,
    coverageSha256: projection.bindings.coverageLedgerSha256,
  }
}

function syntheticDetailsScenario(engine, spec) {
  const {ledger, entry} = detailsLedgerFor(engine, spec)
  const receipt = detailsReceiptFor(engine, {entry, ledger})
  const projectionInput = detailsProjectionInputFor(engine, {entry, ledger, receipt})
  const projection = projectObjectDetails(projectionInput)
  const request = {
    schemaVersion: KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
    requestId: `details-${engine}-${spec.state.toLowerCase()}`,
    capabilityId: KS_OBJECT_DETAILS_HANDLER_CAPABILITY,
    bindings: detailsBindingsOf(projection),
    scope: {schemas: [...DETAILS_SCOPES[engine].schemas]},
  }
  return {ledger, entry, receipt, projectionInput, request, projection}
}

function detailsRawEntry({engine = 'mssql', relationName = 'sales_orders', schemaName = DETAILS_SCOPES.mssql.schemas[0], evidenceRefs} = {}) {
  const objectRef = {
    kind: 'RELATION', schemaName, relationName, columnName: null, objectName: null,
    sourceObjectSha256: detailsSourceObjectSha256(engine, relationName),
  }
  return {
    objectKey: identitySha256(objectRef), objectRef, state: 'COMPLETE', reasonCode: null,
    sourceQueryId: `${engine}.structure-relations`,
    evidenceRefs: evidenceRefs ?? [...new Set([detailsSnapshotSha256(engine), detailsPreflightLedgerSha256(engine), detailsSourceObjectSha256(engine, relationName)])].sort(),
    absenceClaim: 'NOT_CLAIMED',
  }
}

function detailsLedgerWithEntry(ledger, entry) {
  const {coverageSha256: _old, ...body} = structuredClone(ledger)
  body.entries = [entry]
  return detailsSeal(body, 'coverageSha256')
}
