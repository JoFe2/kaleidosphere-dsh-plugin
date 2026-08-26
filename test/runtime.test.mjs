import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import os from 'node:os'
import path from 'node:path'
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
  PROGRESSIVE_RECEIPT_SCHEMA,
  PROGRESSIVE_RUN_SCHEMA,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/progressive-controller.mjs'
import {
  KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
  KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
  buildObjectCapabilityContractV1,
  getObjectCapabilityBindingProfileV1,
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
import {
  DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID,
  DATABASE_OVERVIEW_HANDLER_SCHEMA,
  handleDatabaseOverviewRequestV1,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/database-overview-handler-v1.mjs'
import {
  DATABASE_OVERVIEW_PROJECTION_SCHEMA,
  buildDatabaseOverviewProjection,
  verifyDatabaseOverviewProjection,
} from '../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/database-overview-projection-v1.mjs'

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
    // P2B3B supersedes the Details half and P2B4B the Overview half of this
    // check: both are now known local actions and deny an empty dispatch
    // envelope with their own input codes.
    await assert.rejects(runtime.execute('details'), /KS_DSH_DETAILS_INPUT_INVALID/)
    await assert.rejects(runtime.execute('overview'), /KS_DSH_OVERVIEW_INPUT_INVALID/)
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

// P2B3B: focused oracle for runtime Details dispatch. Reuses the verified
// P2B3A synthetic Details fixture/oracle: the runtime dispatches Details
// locally to the pinned vendored two-argument handleObjectDetailsV1(request,
// projectionInput) (v0.24.0 closure, source commit e092bb0), passes the sealed
// {request, projectionInput} envelope through untouched (the pinned handler is
// the single authority for malformed or authority-bearing request or
// projection-input content and re-derives every authoritative binding from its
// recomputed projection), and seals the frozen PROJECTED_READ_ONLY result in a
// v2 result envelope. Details is additive and local only: the six v0.16 paths
// and the six-tool surface are untouched, Details is never sent to the shared
// external API, and no Search/Overview/credential/raw-row/SQL/network/mutation
// surface is added. The sealed handler result (all claims and authority false)
// is the evidence.
const DETAILS_EXTERNAL_DENIED = 'KS_DSH_DETAILS_EXTERNAL_DENIED'
const DETAILS_INPUT_INVALID = 'KS_DSH_DETAILS_INPUT_INVALID'
const DETAILS_RESPONSE_KEYS = Object.freeze([
  'schemaVersion', 'requestId', 'action', 'runtime', 'capabilityAttestationDigest', 'result', 'integrity',
])

test('P2B3B: runtime Details dispatches locally to the pinned two-argument handler, preserving authoritative bindings and the sealed result (every coverage state, mssql and oracle)', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    for (const engine of DETAILS_ENGINES) {
      for (const spec of Object.values(DETAILS_STATES)) {
        const scenario = syntheticDetailsScenario(engine, spec)
        const value = { request: scenario.request, projectionInput: scenario.projectionInput }
        const direct = handleObjectDetailsV1(scenario.request, scenario.projectionInput)
        const out = await runtime.execute('details', value)
        // Pass-through to the pinned handler: the sealed result is returned
        // unaltered (byte-identical to a direct dispatch) and re-validated
        // through the vendored capability contract.
        assert.deepEqual(out.response.result, direct)
        assert.equal(canonicalJson(out.response.result), canonicalJson(handleObjectDetailsV1(scenario.request, scenario.projectionInput)))
        const validated = buildObjectCapabilityContractV1().validateResult(out.response.result, {
          capabilityId: KS_OBJECT_DETAILS_HANDLER_CAPABILITY,
          requestSha256: out.response.result.requestSha256,
          projectionSha256: out.response.result.projectionSha256,
          bindings: detailsBindingsOf(scenario.projection),
        })
        assert.deepEqual(validated, out.response.result)
        // Preserves the authoritative Details bindings re-derived by the pinned handler.
        assert.deepEqual(out.response.result.bindings, detailsBindingsOf(scenario.projection))
        assert.notEqual(out.response.result.bindings, value.request.bindings)
        assert.equal(out.response.result.projectionSha256, scenario.projection.projectionSha256)
        // Sealed, deeply frozen v2 result envelope around the pinned result.
        assertFrozen(out.response)
        assert.deepEqual(Object.keys(out.response), DETAILS_RESPONSE_KEYS)
        assert.equal(out.response.schemaVersion, SEARCH_RESULT_SCHEMA)
        assert.equal(out.response.action, 'details')
        assert.equal(out.response.requestId, `ks-details-${sha256Digest({ action: 'details', input: value }).slice(7, 31)}`)
        const attestation = capabilityAttestationV2()
        assert.deepEqual(out.response.runtime, { product: attestation.product, contract: attestation.contract })
        assert.equal(out.response.capabilityAttestationDigest, attestation.attestation.digest)
        assert.equal(out.response.integrity.algorithm, 'sha256-canonical-json')
        assert.match(out.response.integrity.digest, /^sha256:[a-f0-9]{64}$/)
        const { integrity, ...body } = out.response
        assert.equal(sha256Digest(body), out.response.integrity.digest)
        // No authority: the pinned claims and authority surface stays all false.
        assert.deepEqual(out.response.result.claims, DETAILS_CLAIMS)
        assert.deepEqual(out.response.result.authority, DETAILS_AUTHORITY)
        // Dispatch is deterministic: a repeated dispatch seals an identical envelope.
        const repeated = await runtime.execute('details', value)
        assert.equal(canonicalJson(repeated.response), canonicalJson(out.response))
      }
    }
    // Additive: the six closed v0.16 paths, the six-tool surface and the P2B2B
    // Search dispatch are untouched on the same runtime.
    const status = await runtime.execute('status')
    assert.equal(status.response.result.status, 'READY')
    assert.equal(status.evidence.status, 'succeeded')
    const analyze = await runtime.execute('analyze')
    assert.equal(analyze.response.result.evidence.snapshotSha256,
      '293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a')
    const readback = await runtime.execute('readback')
    assert.equal(readback.response.result.catalog.coverageComplete, true)
    const { sources: searchSources, envelope: searchEnvelope } = syntheticSearchFixture('mssql')
    const searchValue = validSearchHandlerInput({ engine: 'mssql', sources: searchSources, envelope: searchEnvelope })
    const searchOut = await runtime.execute('search', searchValue)
    assert.equal(canonicalJson(searchOut.response.result), canonicalJson(handleObjectSearchV1(searchValue)))
    const tools = createToolDefinitions(runtime)
    assert.equal(tools.length, 6)
    assert(tools.every(tool => tool.capability.action !== 'details'))
    // P2B4B supersedes the Overview half of this check: Overview is now a
    // known local action and denies an empty dispatch envelope with its own
    // input code.
    await assert.rejects(runtime.execute('overview'), /KS_DSH_OVERVIEW_INPUT_INVALID/)
  } finally {
    await runtime.dispose()
  }
})

test('P2B3B: malformed envelope and authority-bearing Details input deny through the runtime with pinned codes', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const { request, projectionInput, ledger, entry } = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
    const value = { request, projectionInput }
    const bindings = request.bindings
    const withEntry = (next) => detailsProjectionInputFor('mssql', { entry: next, ledger: detailsLedgerWithEntry(ledger, next) })
    const oversized = detailsRawEntry({})
    oversized.evidenceRefs = Array.from({ length: 17 }, (_, index) => identitySha256({ evidence: index }))
    const unrelated = detailsLedgerFor('mssql', DETAILS_STATES.COMPLETE, { relationName: 'other_orders' })
    const cases = [
      // Envelope-level malformation never reaches the pinned handler.
      [{}, DETAILS_INPUT_INVALID],
      [null, DETAILS_INPUT_INVALID],
      [[request, projectionInput], DETAILS_INPUT_INVALID],
      [{ request }, DETAILS_INPUT_INVALID],
      [{ projectionInput }, DETAILS_INPUT_INVALID],
      [{ ...value, sql: 'SELECT 1' }, DETAILS_INPUT_INVALID],
      [{ ...value, credentials: 'secret' }, DETAILS_INPUT_INVALID],
      [{ ...value, callback: 'https://evil.invalid' }, DETAILS_INPUT_INVALID],
      // Request-level content denies with the pinned handler codes.
      [{ ...value, request: null }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, sql: 'SELECT 1' } }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, credentials: 'secret' } }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, rawRows: [] } }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, callback: 'https://evil.invalid' } }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, capabilityId: 'bi.object.search.read' } }, DETAILS_REQUEST_IDENTITY_DENIED],
      [{ ...value, request: { ...request, scope: { schemas: ['other'] } } }, SCOPE_DENIED],
      [{ ...value, request: { ...request, scope: { schemas: ['../escape'] } } }, SCOPE_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, dispatchAuthority: true } } }, BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, executionAuthority: true } } }, BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, mutationAuthority: true } } }, BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, sqlAuthority: true } } }, BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, claims: { completenessClaimed: true } } } }, BINDING_DENIED],
      ...Object.keys(bindings).filter((key) => key !== 'engine').map((key) => [
        { ...value, request: { ...request, bindings: { ...bindings, [key]: hash64('0') } } },
        BINDING_DENIED,
      ]),
      // Hidden and symbol request surfaces deny before any trap executes.
      [{ ...value, request: (hidden => { const copy = structuredClone(request); Object.defineProperty(copy, 'credentials', { value: 'secret', enumerable: false }); return copy })() }, REQUEST_SURFACE_DENIED],
      [{ ...value, request: (symbol => { const copy = structuredClone(request); copy[Symbol('secret')] = 'hidden'; return copy })() }, REQUEST_SURFACE_DENIED],
      // Projection-input-level content denies with the pinned handler codes.
      [{ ...value, projectionInput: { ...projectionInput, hint: 'select 1' } }, 'DB_OBJECT_DETAILS_INPUT_INVALID'],
      [{ ...value, projectionInput: { ...projectionInput, objectKey: identitySha256({ missing: true }) } }, 'DB_OBJECT_DETAILS_COVERAGE_MISSING'],
      [{ ...value, projectionInput: withEntry(detailsRawEntry({ relationName: 'sales--orders' })) }, 'DB_OBJECT_DETAILS_IDENTIFIER_INVALID'],
      [{ ...value, projectionInput: withEntry(detailsRawEntry({ relationName: 'sales_orders_verified' })) }, 'DB_OBJECT_DETAILS_IDENTIFIER_CLAIM'],
      [{ ...value, projectionInput: withEntry(oversized) }, 'DB_OBJECT_DETAILS_EVIDENCE_INVALID'],
      [{ ...value, projectionInput: detailsProjectionInputFor('mssql', {
        entry, ledger, receipt: detailsReceiptFor('mssql', { entry: unrelated.entry, ledger: unrelated.ledger }),
      }) }, 'DB_OBJECT_DETAILS_RECEIPT_BINDING_INVALID'],
    ]
    for (const [input, code] of cases) {
      await assert.rejects(runtime.execute('details', input), { code, message: code })
    }
    // A Proxy request surface denies before any trap executes.
    let traps = 0
    const proxyRequest = new Proxy(request, { getPrototypeOf() { traps += 1; return Object.prototype; } })
    await assert.rejects(runtime.execute('details', { ...value, request: proxyRequest }),
      { code: REQUEST_SURFACE_DENIED, message: REQUEST_SURFACE_DENIED })
    assert.equal(traps, 0)
    // Denial is fail closed: a denied Details leaves no result and the runtime stays usable.
    const after = await runtime.execute('details', value)
    assert.equal(canonicalJson(after.response.result), canonicalJson(handleObjectDetailsV1(request, projectionInput)))
  } finally {
    await runtime.dispose()
  }
})

test('P2B3B: external runtime mode denies Details locally and never sends it to the shared external API', async () => {
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
  const scenario = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
  const value = { request: scenario.request, projectionInput: scenario.projectionInput }
  const runtime = await KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    external: { baseUrl: `http://127.0.0.1:${address.port}` },
  })
  try {
    // Details is local only: it is outside the v0.16 closed intent set and must
    // deny before any request leaves the process.
    await assert.rejects(runtime.execute('details', value),
      { code: DETAILS_EXTERNAL_DENIED, message: DETAILS_EXTERNAL_DENIED })
    // Only the create-time attestation fetch touched the network; Details never did.
    assert.deepEqual(requests, [{ method: 'GET', url: '/v2/capabilities' }])
  } finally {
    await runtime.dispose()
    await new Promise(resolve => server.close(resolve))
  }
})

// P2B4A: reusable fully synthetic direct Overview-handler fixture and focused
// happy/negative oracle against the pinned vendored
// handleDatabaseOverviewRequestV1 (v0.24.0 closure, source commit e092bb0).
// The oracle is self-contained: the sealed progressive coverage (built
// through the vendored createProgressiveCoverage), the probe/receipt records
// in the pinned progressive shape, the run seal (stateSha256) and the
// capability request are built inline from synthetic literals, so there are
// no query-pack/profile data-file reads, environment credentials, network
// access, production runtime edits, or Search/Details fixture reuse. The
// authoritative bindings are derived independently of the handler: the
// snapshot and coverage digests come from the vendored
// buildDatabaseOverviewProjection, the receipt chain is recomputed from the
// sealed receipts following the pinned chain rule, and the cancellation
// digest is the pinned identity hash over the receipt chain and the
// projection's cancellation state. The P2B4A leaf itself adds no runtime
// dispatch (the additive local dispatch is added by P2B4B below), and the
// pinned contract marks object capabilities a separate-versioned extension
// with handlerDispatchIncluded false.
const OVERVIEW_ENGINES = ['mssql', 'oracle']
const OVERVIEW_INPUT_INVALID = 'DB_OVERVIEW_HANDLER_INPUT_INVALID'
const OVERVIEW_AUTHORITY_CLAIM_DENIED = 'DB_OVERVIEW_HANDLER_AUTHORITY_CLAIM_DENIED'
const OVERVIEW_REQUEST_SURFACE_DENIED = 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED'
const OVERVIEW_REQUEST_IDENTITY_DENIED = 'KS_OBJECT_CAPABILITY_REQUEST_IDENTITY_DENIED'
const OVERVIEW_BINDING_DENIED = 'KS_OBJECT_CAPABILITY_BINDING_DENIED'
const OVERVIEW_SCOPE_DENIED = 'KS_OBJECT_CAPABILITY_SCOPE_DENIED'
const OVERVIEW_CLAIM_DENIED = 'KS_OBJECT_CAPABILITY_CLAIM_DENIED'
const OVERVIEW_AUTHORITY_DENIED = 'KS_OBJECT_CAPABILITY_AUTHORITY_DENIED'
const OVERVIEW_BINDING_PROFILE_SCHEMA = 'kaleidosphere.object-capabilities/binding-profile/database-overview/v1'
const OVERVIEW_BINDING_KEYS = Object.freeze(['engine', 'runStateSha256', 'snapshotSha256', 'coverageSha256', 'receiptChainSha256', 'cancellationSha256'])
const OVERVIEW_RESULT_KEYS = Object.freeze(['bytes', 'capabilityId', 'envelope', 'projectionSha256', 'requestSha256', 'resultSha256', 'schemaVersion', 'state'])
const OVERVIEW_CONTRACT_FAIL_CLOSED_CODES = Object.freeze([
  'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED', 'KS_OBJECT_CAPABILITY_REQUEST_IDENTITY_DENIED',
  'KS_OBJECT_CAPABILITY_BINDING_DENIED', 'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
  'KS_OBJECT_CAPABILITY_RESULT_SURFACE_DENIED', 'KS_OBJECT_CAPABILITY_RESULT_IDENTITY_DENIED',
  'KS_OBJECT_CAPABILITY_RESULT_BINDING_DENIED', 'KS_OBJECT_CAPABILITY_CLAIM_DENIED',
  'KS_OBJECT_CAPABILITY_AUTHORITY_DENIED',
])
const OVERVIEW_CLAIMS = Object.freeze({
  absenceClaimed: false, completenessClaimed: false, replayPreventionClaimed: false, sourceRowsIncluded: false,
})
const OVERVIEW_AUTHORITY = Object.freeze({
  credentialsIncluded: false, dispatchAuthority: false, executionAuthority: false,
  mutationAuthority: false, queryExecution: false, rawValuesIncluded: false, sqlAuthority: false,
})
const deepFreezeValue = (value) => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreezeValue)
    Object.freeze(value)
  }
  return value
}

test('P2B4A: pinned handleDatabaseOverviewRequestV1 returns a deterministic deeply frozen read-only envelope bound to the independently derived Overview bindings (mssql and oracle, with and without a cancelled receipt)', () => {
  for (const engine of OVERVIEW_ENGINES) {
    for (const withCancelledReceipt of [true, false]) {
      const {run, projection, bindings, request} = syntheticOverviewScenario(engine, {withCancelledReceipt})
      const result = handleDatabaseOverviewRequestV1(request, deepFreezeValue(run))
      assert.equal(result.schemaVersion, DATABASE_OVERVIEW_HANDLER_SCHEMA)
      assert.equal(result.capabilityId, DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID)
      assert.equal(result.state, 'PROJECTED_READ_ONLY')
      assert.deepEqual(Object.keys(result).sort(), [...OVERVIEW_RESULT_KEYS])
      assert.equal(result.requestSha256, identitySha256(request))
      assert.equal(result.projectionSha256, projection.projectionSha256)
      assert.equal(result.resultSha256, identitySha256(result.envelope))
      assert.equal(result.envelope.schemaVersion, KS_OBJECT_CAPABILITY_RESULT_SCHEMA)
      assert.equal(result.envelope.state, 'PROJECTED_READ_ONLY')
      assert.equal(result.envelope.capabilityId, DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID)
      assert.equal(result.envelope.requestSha256, result.requestSha256)
      assert.equal(result.envelope.projectionSha256, projection.projectionSha256)
      assert.deepEqual(result.envelope.bindings, bindings)
      // The authoritative bindings equal the independently derived
      // vendored projection and pinned identities.
      assert.equal(result.envelope.bindings.engine, run.engine)
      assert.equal(result.envelope.bindings.runStateSha256, run.stateSha256)
      assert.equal(result.envelope.bindings.snapshotSha256, projection.bindings.inventorySnapshotSha256)
      assert.equal(result.envelope.bindings.coverageSha256, projection.bindings.coverageSha256)
      assert.equal(result.envelope.bindings.receiptChainSha256, projection.bindings.receiptChainSha256)
      assert.equal(result.envelope.bindings.cancellationSha256, identitySha256({
        schemaVersion: 'kaleidosphere.object-capabilities/cancellation-binding/v1',
        receiptChainSha256: projection.bindings.receiptChainSha256,
        cancellation: projection.cancellation,
      }))
      assert.deepEqual(result.envelope.claims, OVERVIEW_CLAIMS)
      assert.deepEqual(result.envelope.authority, OVERVIEW_AUTHORITY)
      assert.equal(result.bytes.request, canonicalJson(request))
      assert.equal(result.bytes.projection, canonicalJson(projection))
      assert.equal(result.bytes.result, canonicalJson(result.envelope))
      // The projection is the vendored sealed read-only analysis projection.
      verifyDatabaseOverviewProjection(projection, run)
      assert.equal(projection.schemaVersion, DATABASE_OVERVIEW_PROJECTION_SCHEMA)
      assert.equal(projection.projectionKind, 'DATABASE_OVERVIEW')
      const byKind = Object.fromEntries(projection.countsByKind.map((item) => [item.kind, item]))
      assert.equal(byKind.SCHEMA.visibleCount, 1)
      assert.equal(byKind.RELATION.visibleCount, 1)
      assert.equal(byKind.COLUMN.partialCount, 1)
      assert.equal(byKind.INDEX.deniedCount, 1)
      assert.equal(byKind.SEQUENCE.unknownCount, 1)
      assert.deepEqual(projection.totals, {visibleCount: 2, partialCount: 1, deniedCount: 1, unsupportedCount: 0, unknownCount: 1, totalCount: 5})
      assert.equal(projection.coverageBasisPoints, 8000)
      assert.deepEqual(projection.blindSpotCodes, ['OBJECT_NOT_FOUND', 'PARTIAL_ROW_LIMIT', 'PRIVILEGE_DENIED'])
      assert.deepEqual(projection.cancellation, withCancelledReceipt
        ? {state: 'CANCELLED', cancelledReceiptCount: 1, receiptCount: 2}
        : {state: 'NOT_CANCELLED', cancelledReceiptCount: 0, receiptCount: 1})
      assert.deepEqual(projection.claims, {absence: false, businessTruth: false, completeness: false})
      assert.deepEqual(projection.authority, {dispatchAuthority: 'NONE', mutationAuthority: 'NONE', sqlAuthority: 'NONE'})
      assertFrozen(result)
      assertFrozen(run)
      // The sealed result re-verifies against the pinned contract.
      const {validateResult} = buildObjectCapabilityContractV1()
      assert.deepEqual(validateResult(result.envelope, {
        capabilityId: result.capabilityId,
        requestSha256: result.requestSha256,
        projectionSha256: result.projectionSha256,
        bindings,
      }), result.envelope)
      // Deterministic across a fresh independent run instance.
      const repeated = syntheticOverviewScenario(engine, {withCancelledReceipt})
      assert.equal(canonicalJson(handleDatabaseOverviewRequestV1(repeated.request, deepFreezeValue(repeated.run))), canonicalJson(result))
    }
  }
})

test('P2B4A: the pinned handler and contract expose the closed read-only Overview capability surface without runtime dispatch', async () => {
  assert.equal(DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID, 'bi.database.overview.read')
  assert.equal(DATABASE_OVERVIEW_HANDLER_SCHEMA, 'kaleidosphere.object-capabilities/database-overview-handler/v1')
  assert.equal(DATABASE_OVERVIEW_PROJECTION_SCHEMA, 'kaleidosphere.analysis/database-overview-projection/v1')
  const profile = getObjectCapabilityBindingProfileV1(DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID)
  assert.equal(profile.schemaVersion, OVERVIEW_BINDING_PROFILE_SCHEMA)
  assert.deepEqual([...profile.requiredBindings], [...OVERVIEW_BINDING_KEYS])
  assert.ok(Object.isFrozen(profile))
  const contract = buildObjectCapabilityContractV1()
  assert.deepEqual(contract.failClosedCodes, [...OVERVIEW_CONTRACT_FAIL_CLOSED_CODES])
  assert.deepEqual(contract.integration, {
    mode: 'separate-versioned-extension',
    externalApiV2Changed: false,
    externalApiV2Actions: ['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'],
  })
  assert.equal(contract.boundaries.handlerDispatchIncluded, false)
  assert.equal(contract.boundaries.freeSqlAccepted, false)
  assert.equal(contract.boundaries.rawRowsAccepted, false)
  assert.equal(contract.boundaries.mutationAuthority, false)
  // P2B4B supersedes the no-dispatch half of this check: Overview is now a
  // known local action and denies an empty dispatch envelope with its own
  // input code; the six-intent closed surface and the six-tool surface
  // remain unchanged (no Overview tool name).
  const runtime = await KaleidoSphereRuntime.create()
  try {
    await assert.rejects(runtime.execute('overview', {}),
      { code: 'KS_DSH_OVERVIEW_INPUT_INVALID', message: 'KS_DSH_OVERVIEW_INPUT_INVALID' })
    const toolNames = createToolDefinitions(runtime).map((tool) => tool.name)
    assert.ok(toolNames.every((name) => !name.includes('overview')), 'no Overview tool surface')
    assert.deepEqual([...toolNames].sort(), [...CLOSED_INTENTS.map((action) => TOOL_NAMES[action])].sort())
  } finally {
    await runtime.dispose()
  }
})

test('P2B4A: capability, schema, request id, scope, stale and unknown-binding requests deny with the pinned codes against an unchanged run', () => {
  const {run, request} = syntheticOverviewScenario('mssql', {withCancelledReceipt: true})
  const frozen = deepFreezeValue(run)
  for (const [field, value] of [['sql', 'SELECT 1'], ['credentials', 'secret'], ['rawRows', []], ['callback', 'https://evil.invalid']]) {
    assert.throws(() => handleDatabaseOverviewRequestV1({...request, [field]: value}, frozen),
      {code: OVERVIEW_REQUEST_SURFACE_DENIED, message: OVERVIEW_REQUEST_SURFACE_DENIED})
  }
  const substitutions = [
    [(next) => ({...next, capabilityId: 'bi.object.details.read'}), OVERVIEW_REQUEST_IDENTITY_DENIED],
    [(next) => ({...next, schemaVersion: 'kaleidosphere.object-capabilities/request/v2'}), OVERVIEW_REQUEST_IDENTITY_DENIED],
    [(next) => ({...next, requestId: '!invalid'}), OVERVIEW_REQUEST_IDENTITY_DENIED],
    [(next) => ({...next, scope: {schemas: ['other']}}), OVERVIEW_SCOPE_DENIED],
    ...Object.keys(request.bindings).filter((key) => key !== 'engine').map((key) => [
      (next) => ({...next, bindings: {...next.bindings, [key]: hash64('0')}}), OVERVIEW_BINDING_DENIED,
    ]),
    [(next) => ({...next, bindings: {...next.bindings, engine: 'postgres'}}), OVERVIEW_BINDING_DENIED],
    [(next) => ({...next, bindings: {...next.bindings, extraBinding: hash64('1')}}), OVERVIEW_BINDING_DENIED],
  ]
  for (const [mutate, code] of substitutions) {
    assert.throws(() => handleDatabaseOverviewRequestV1(mutate(request), frozen), {code, message: code})
  }
  // Stale request: same capability and scope but bindings derived from a
  // different run (no cancelled receipt), i.e. no binding in the request
  // matches the authoritative projection of the frozen run.
  const stale = syntheticOverviewScenario('mssql', {withCancelledReceipt: false})
  assert.throws(() => handleDatabaseOverviewRequestV1(stale.request, frozen),
    {code: OVERVIEW_BINDING_DENIED, message: OVERVIEW_BINDING_DENIED})
})

test('P2B4A: non-frozen, Proxy, accessor, hidden, symbol and authority-bearing runs deny with the pinned handler codes before any effect', () => {
  const {run, request} = syntheticOverviewScenario('mssql', {withCancelledReceipt: true})
  // The handler requires the run itself to be deeply frozen.
  assert.throws(() => handleDatabaseOverviewRequestV1(request, run),
    {code: OVERVIEW_INPUT_INVALID, message: OVERVIEW_INPUT_INVALID})
  const topOnlyFrozen = structuredClone(run)
  Object.freeze(topOnlyFrozen)
  assert.throws(() => handleDatabaseOverviewRequestV1(request, topOnlyFrozen),
    {code: OVERVIEW_INPUT_INVALID, message: OVERVIEW_INPUT_INVALID})
  // Proxy: denied before any trap executes.
  let traps = 0
  const proxy = new Proxy(structuredClone(run), {getPrototypeOf() { traps += 1; return Object.prototype; }})
  assert.throws(() => handleDatabaseOverviewRequestV1(request, proxy),
    {code: OVERVIEW_INPUT_INVALID, message: OVERVIEW_INPUT_INVALID})
  assert.equal(traps, 0)
  // Hidden (non-enumerable) run field.
  const hidden = structuredClone(run)
  Object.defineProperty(hidden, 'sqlAuthority', {value: 'ALL', enumerable: false})
  assert.throws(() => handleDatabaseOverviewRequestV1(request, hidden),
    {code: OVERVIEW_INPUT_INVALID, message: OVERVIEW_INPUT_INVALID})
  // Symbol-keyed run field.
  const symbol = structuredClone(run)
  symbol[Symbol('probe')] = 'hidden'
  assert.throws(() => handleDatabaseOverviewRequestV1(request, symbol),
    {code: OVERVIEW_INPUT_INVALID, message: OVERVIEW_INPUT_INVALID})
  // Accessor (getter) run field: denied before the getter executes.
  let getterCalls = 0
  const accessor = structuredClone(run)
  Object.defineProperty(accessor.coverage, 'entries', {
    enumerable: true,
    get() { getterCalls += 1; return run.coverage.entries; },
  })
  assert.throws(() => handleDatabaseOverviewRequestV1(request, accessor),
    {code: OVERVIEW_INPUT_INVALID, message: OVERVIEW_INPUT_INVALID})
  assert.equal(getterCalls, 0)
  // Authority/claim-bearing run fields deny even on a frozen run.
  for (const field of ['authority', 'claims']) {
    const bearing = deepFreezeValue({...structuredClone(run), [field]: {sqlAuthority: 'ALL'}})
    assert.throws(() => handleDatabaseOverviewRequestV1(request, bearing),
      {code: OVERVIEW_AUTHORITY_CLAIM_DENIED, message: OVERVIEW_AUTHORITY_CLAIM_DENIED})
  }
})

test('P2B4A: tampered, drifted, unsafe and internally inconsistent synthetic runs deny with the exact pinned projection codes', () => {
  const {run, request} = syntheticOverviewScenario('mssql', {withCancelledReceipt: true})
  const mutatedRun = (mutate) => {
    const value = structuredClone(run)
    mutate(value)
    return deepFreezeValue(value)
  }
  const resealedRun = (mutate) => {
    const value = structuredClone(run)
    mutate(value)
    const {stateSha256: _old, ...body} = value
    return deepFreezeValue({...body, stateSha256: identitySha256(body)})
  }
  const expectRunDenial = (code, frozenRun) => {
    assert.throws(() => handleDatabaseOverviewRequestV1(request, frozenRun), {code, message: code})
  }
  const resealCoverage = (coverage, mutate) => {
    const {coverageSha256: _old, ...rest} = coverage
    mutate(rest)
    return overviewSeal(rest, 'coverageSha256')
  }
  // A re-sealed coverage has a new digest: keep the probe and receipt
  // coverage binding consistent so the mutation is tested exactly where it
  // is meant to deny (totals and blind-spot checks, not probe validation).
  const rebindCoverageDigest = (value, coverage) => {
    for (const probe of value.probes) probe.coverageSha256 = coverage.coverageSha256
    for (const receipt of value.receipts) {
      const {receiptSha256: _old, ...rest} = receipt
      rest.coverageSha256 = coverage.coverageSha256
      Object.assign(receipt, overviewSeal(rest, 'receiptSha256'))
    }
  }

  // Broken run seal: the body changed but the pinned stateSha256 did not.
  expectRunDenial('DB_OVERVIEW_RUN_TAMPERED', mutatedRun((value) => { value.scope.schemas.push('other') }))
  // Unsafe JSON surface: a denied key and a denied string value.
  expectRunDenial('DB_OVERVIEW_UNSAFE_JSON', mutatedRun((value) => { value.sql = 'SELECT 1' }))
  expectRunDenial('DB_OVERVIEW_UNSAFE_JSON', mutatedRun((value) => { value.runId = 'https://evil.invalid' }))
  // Claim-bearing identifier (re-sealed so the run seal passes first).
  expectRunDenial('DB_OVERVIEW_CLAIM_BEARING_IDENTIFIER', resealedRun((value) => {
    value.scope.database = 'trusted_sales'
    value.scopeSha256 = identitySha256(value.scope)
  }))
  // Malformed run: a sealed required array is missing.
  expectRunDenial('DB_OVERVIEW_SOURCE_INVALID', resealedRun((value) => { delete value.probes }))
  // Broken coverage seal: the entry state changed but coverageSha256 did not.
  expectRunDenial('DB_OVERVIEW_COVERAGE_TAMPERED', resealedRun((value) => { value.coverage.entries[0].state = 'DENIED' }))
  // Evidence binding and engine drift.
  expectRunDenial('DB_OVERVIEW_BINDING_DRIFT', resealedRun((value) => {
    value.evidenceBinding.structureSnapshotSha256 = hash64('f')
  }))
  expectRunDenial('DB_OVERVIEW_BINDING_DRIFT', resealedRun((value) => { value.engine = 'oracle' }))
  // Coverage entry and query tampering (coverage re-sealed).
  expectRunDenial('DB_OVERVIEW_COVERAGE_INVALID', resealedRun((value) => {
    value.coverage = resealCoverage(value.coverage, (cov) => { cov.entries[0].objectKey = hash64('0') })
  }))
  expectRunDenial('DB_OVERVIEW_COVERAGE_INVALID', resealedRun((value) => {
    value.coverage = resealCoverage(value.coverage, (cov) => { cov.entries[0].hint = 1 })
  }))
  expectRunDenial('DB_OVERVIEW_COVERAGE_INVALID', resealedRun((value) => {
    value.coverage = resealCoverage(value.coverage, (cov) => { cov.queryCoverage.push({...cov.queryCoverage[0]}) })
  }))
  // Summary tampering passes the source checks but not the totals check.
  expectRunDenial('DB_OVERVIEW_TOTALS_INCONSISTENT', resealedRun((value) => {
    value.coverage = resealCoverage(value.coverage, (cov) => { cov.summary.coverageBps = 9999 })
    rebindCoverageDigest(value, value.coverage)
  }))
  // A query state outside the pinned states yields an invalid blind-spot code.
  expectRunDenial('DB_OVERVIEW_BLIND_SPOT_CODE_INVALID', resealedRun((value) => {
    value.coverage = resealCoverage(value.coverage, (cov) => {
      const query = cov.queryCoverage.find((entry) => entry.queryId.endsWith('structure-columns'))
      query.state = 'weird state'
      query.reasonCode = null
    })
    rebindCoverageDigest(value, value.coverage)
  }))
  // Probe tampering: duplicate probe key and drifted coverage digest.
  expectRunDenial('DB_OVERVIEW_PROBE_INVALID', resealedRun((value) => {
    value.probes.push(structuredClone(value.probes[0]))
  }))
  expectRunDenial('DB_OVERVIEW_PROBE_INVALID', resealedRun((value) => {
    value.probes[0].coverageSha256 = hash64('9')
  }))
  // Broken receipt seal: the result state changed but receiptSha256 did not.
  expectRunDenial('DB_OVERVIEW_RECEIPT_TAMPERED', resealedRun((value) => {
    value.receipts[0].resultState = 'DENIED'
  }))
  // Receipt drift against its probe (receipt re-sealed).
  const resealReceipt = (index, mutate) => resealedRun((value) => {
    const {receiptSha256: _old, ...rest} = value.receipts[index]
    mutate(rest)
    value.receipts = value.receipts.map((entry, i) => (i === index ? overviewSeal(rest, 'receiptSha256') : entry))
  })
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealReceipt(0, (receipt) => { receipt.runId = 'other-run' }))
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealReceipt(0, (receipt) => { receipt.methodRef = 'oracle.other@overview-v1' }))
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealReceipt(0, (receipt) => { receipt.phase = 'PRIORITIZATION' }))
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealReceipt(0, (receipt) => { receipt.target = {kind: 'SCOPE', extra: true} }))
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealReceipt(0, (receipt) => { receipt.argumentsSha256 = hash64('b') }))
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealReceipt(0, (receipt) => { receipt.blindRetryAllowed = true }))
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealReceipt(0, (receipt) => { receipt.probeKey = hash64('c') }))
  expectRunDenial('DB_OVERVIEW_RECEIPT_INVALID', resealedRun((value) => {
    value.receipts.push(structuredClone(value.receipts[0]))
  }))
})

test('P2B4A: re-digested and broken overview projections and every result authority widening deny with the pinned codes', () => {
  const {run, projection, request} = syntheticOverviewScenario('mssql', {withCancelledReceipt: true})
  const frozen = deepFreezeValue(run)
  const broken = structuredClone(projection)
  broken.totals.totalCount = 6
  assert.throws(() => verifyDatabaseOverviewProjection(broken, frozen),
    {code: 'DB_OVERVIEW_PROJECTION_TAMPERED', message: 'DB_OVERVIEW_PROJECTION_TAMPERED'})
  const {projectionSha256: _old, ...projectionBody} = structuredClone(projection)
  projectionBody.totals.totalCount = 6
  const forged = {...projectionBody, projectionSha256: identitySha256(projectionBody)}
  assert.throws(() => verifyDatabaseOverviewProjection(forged, frozen),
    {code: 'DB_OVERVIEW_PROJECTION_MISMATCH', message: 'DB_OVERVIEW_PROJECTION_MISMATCH'})

  const result = handleDatabaseOverviewRequestV1(request, frozen)
  const expected = {
    capabilityId: result.capabilityId,
    requestSha256: result.requestSha256,
    projectionSha256: result.projectionSha256,
    bindings: result.envelope.bindings,
  }
  const {validateResult} = buildObjectCapabilityContractV1()
  assert.deepEqual(validateResult(result.envelope, expected), result.envelope)
  const widenings = [
    [{...result.envelope, claims: {...result.envelope.claims, completenessClaimed: true}}, OVERVIEW_CLAIM_DENIED],
    [{...result.envelope, claims: {...result.envelope.claims, sourceRowsIncluded: true}}, OVERVIEW_CLAIM_DENIED],
    [{...result.envelope, authority: {...result.envelope.authority, dispatchAuthority: true}}, OVERVIEW_AUTHORITY_DENIED],
    [{...result.envelope, authority: {...result.envelope.authority, executionAuthority: true}}, OVERVIEW_AUTHORITY_DENIED],
    [{...result.envelope, authority: {...result.envelope.authority, mutationAuthority: true}}, OVERVIEW_AUTHORITY_DENIED],
    [{...result.envelope, authority: {...result.envelope.authority, sqlAuthority: true}}, OVERVIEW_AUTHORITY_DENIED],
    [{...result.envelope, authority: {...result.envelope.authority, rawValuesIncluded: true}}, OVERVIEW_AUTHORITY_DENIED],
  ]
  for (const [changed, code] of widenings) assert.throws(() => validateResult(changed, expected), {code, message: code})
})

// Fully synthetic fixture builders for the direct Overview handler oracle
// above. Every input is constructed inline from synthetic literals: a sealed
// progressive coverage built through the vendored createProgressiveCoverage,
// probe/receipt records in the pinned progressive shape, a run sealed with
// stateSha256, and the capability request bound to the independently derived
// authoritative bindings. No query-pack/profile files are read and no
// environment is consulted.
const OVERVIEW_SCOPES = {
  mssql: {database: 'Analytics', container: null, schemas: ['dbo']},
  oracle: {database: 'FREE', container: 'FREEPDB1', schemas: ['BI_DEMO']},
}
const OVERVIEW_PROBE_PHASE = 'BREADTH_INVENTORY'

const overviewSeal = (body, key) => {
  const normalized = normalizeJsonValue(body)
  return {...normalized, [key]: identitySha256(normalized)}
}

function syntheticOverviewScenario(engine, {withCancelledReceipt = true} = {}) {
  const scope = structuredClone(OVERVIEW_SCOPES[engine])
  const scopeSha256 = identitySha256(scope)
  const structureSnapshotSha256 = identitySha256({kind: 'overview-structure-snapshot', engine})
  const structureCoverageLedgerSha256 = identitySha256({kind: 'overview-structure-coverage-ledger', engine})
  const objectId = (name) => identitySha256({kind: 'overview-inventory-object', engine, name})
  const objectRef = (kind, {schemaName = null, relationName = null, columnName = null, objectName = null, id}) => ({
    kind, schemaName, relationName, columnName, objectName, sourceObjectSha256: objectId(id),
  })
  const schemaName = scope.schemas[0]
  const entryRefs = (id) => [...new Set([structureSnapshotSha256, structureCoverageLedgerSha256, objectId(id)])].sort()
  const entries = [
    {
      objectRef: objectRef('SCHEMA', {objectName: schemaName, id: `schema-${schemaName}`}),
      state: 'COMPLETE', reasonCode: null, sourceQueryId: `${engine}.structure-schemas`, evidenceRefs: entryRefs(`schema-${schemaName}`),
    },
    {
      objectRef: objectRef('RELATION', {schemaName, relationName: 'sales_orders', id: `relation-sales_orders`}),
      state: 'COMPLETE', reasonCode: null, sourceQueryId: `${engine}.structure-relations`, evidenceRefs: entryRefs('relation-sales_orders'),
    },
    {
      objectRef: objectRef('COLUMN', {schemaName, relationName: 'sales_orders', columnName: 'order_id', id: 'column-order_id'}),
      state: 'PARTIAL', reasonCode: 'PARTIAL_ROW_LIMIT', sourceQueryId: `${engine}.structure-columns`, evidenceRefs: entryRefs('column-order_id'),
    },
    {
      objectRef: objectRef('INDEX', {schemaName, relationName: 'sales_orders', objectName: 'ix_sales_orders', id: 'index-ix_sales_orders'}),
      state: 'DENIED', reasonCode: 'PRIVILEGE_DENIED', sourceQueryId: `${engine}.structure-indexes`, evidenceRefs: entryRefs('index-ix_sales_orders'),
    },
    {
      objectRef: objectRef('SEQUENCE', {schemaName, objectName: 'seq_sales_orders', id: 'sequence-seq_sales_orders'}),
      state: 'UNKNOWN', reasonCode: 'OBJECT_NOT_FOUND', sourceQueryId: `${engine}.structure-sequences`, evidenceRefs: entryRefs('sequence-seq_sales_orders'),
    },
  ]
  const queryCoverage = [
    {queryId: `${engine}.structure-schemas`, category: 'schemas', state: 'SUCCEEDED', reasonCode: null, visibility: 'VISIBLE_COMPLETE', absenceClaim: 'NOT_CLAIMED'},
    {queryId: `${engine}.structure-columns`, category: 'columns', state: 'SUCCEEDED', reasonCode: null, visibility: 'VISIBLE_COMPLETE', absenceClaim: 'NOT_CLAIMED'},
  ]
  const coverage = createProgressiveCoverage({
    engine,
    structureSnapshotSha256,
    structureCoverageLedgerSha256,
    entries,
    queryCoverage,
  })
  const runId = `overview-${engine}-run`
  const probeCount = withCancelledReceipt ? 2 : 1
  const probes = Array.from({length: probeCount}, (_, index) => ({
    probeKey: identitySha256({kind: 'overview-probe', engine, index}),
    methodRef: `${engine}.structure-schemas@overview-v1`,
    phase: OVERVIEW_PROBE_PHASE,
    target: {kind: 'SCOPE'},
    arguments: {},
    coverageSha256: coverage.coverageSha256,
  }))
  const receipts = probes.map((probe, index) => overviewSeal({
    schemaVersion: PROGRESSIVE_RECEIPT_SCHEMA,
    runId,
    scopeSha256,
    probeKey: probe.probeKey,
    methodRef: probe.methodRef,
    phase: probe.phase,
    target: probe.target,
    argumentsSha256: identitySha256(probe.arguments),
    coverageSha256: probe.coverageSha256,
    resultState: withCancelledReceipt && index === 1 ? 'CANCELLED' : 'SUCCEEDED',
    evidenceRefs: [structureSnapshotSha256, identitySha256({kind: 'overview-receipt-evidence', engine, index})].sort(),
    blindRetryAllowed: false,
  }, 'receiptSha256'))
  const runBody = {
    schemaVersion: PROGRESSIVE_RUN_SCHEMA,
    runId,
    engine,
    scope,
    scopeSha256,
    coverage,
    evidenceBinding: {
      structureSnapshotSha256: coverage.structureSnapshotSha256,
      structureCoverageSha256: coverage.structureCoverageLedgerSha256,
    },
    probes,
    receipts,
  }
  const run = {...runBody, stateSha256: identitySha256(runBody)}
  const projection = buildDatabaseOverviewProjection(run)
  // Independent derivation of the authoritative Overview bindings: snapshot
  // and coverage digests from the vendored projection, receipt chain from the
  // vendored chain rule, cancellation from the pinned identity hash over the
  // receipt chain and the projection's cancellation state.
  const bindings = {
    engine: run.engine,
    runStateSha256: run.stateSha256,
    snapshotSha256: projection.bindings.inventorySnapshotSha256,
    coverageSha256: projection.bindings.coverageSha256,
    receiptChainSha256: projection.bindings.receiptChainSha256,
    cancellationSha256: identitySha256({
      schemaVersion: 'kaleidosphere.object-capabilities/cancellation-binding/v1',
      receiptChainSha256: projection.bindings.receiptChainSha256,
      cancellation: projection.cancellation,
    }),
  }
  const request = {
    schemaVersion: KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
    requestId: `overview-${engine}-${withCancelledReceipt ? 'cancelled' : 'complete'}`,
    capabilityId: DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID,
    bindings,
    scope: {schemas: [...scope.schemas]},
  }
  return {run, projection, bindings, request}
}

// P2B4B: focused oracle for runtime Overview dispatch. Reuses the verified
// P2B4A synthetic Overview fixture/oracle: the runtime dispatches Overview
// locally to the pinned vendored handleDatabaseOverviewRequestV1 (v0.24.0
// closure, source commit e092bb0), passes the sealed {request, run} envelope
// through untouched (the pinned handler is the single authority for
// malformed or authority-bearing input — including the requirement that the
// run be deeply frozen — and re-derives every binding from its recomputed
// projection), and seals the frozen PROJECTED_READ_ONLY result in a v2
// result envelope. Overview is additive and local only: the six v0.16 paths
// and the six-tool surface are untouched, Overview is never sent to the
// shared external API, is never exposed as a native tool, and no
// credential/raw-row/SQL/network/mutation surface is added. The sealed
// handler result (all claims and authority false) is the evidence.
const OVERVIEW_EXTERNAL_DENIED = 'KS_DSH_OVERVIEW_EXTERNAL_DENIED'
const OVERVIEW_DISPATCH_INPUT_INVALID = 'KS_DSH_OVERVIEW_INPUT_INVALID'
const OVERVIEW_RESPONSE_KEYS = Object.freeze([
  'schemaVersion', 'requestId', 'action', 'runtime', 'capabilityAttestationDigest', 'result', 'integrity',
])

test('P2B4B: runtime Overview dispatches locally to the pinned handler, preserving exact Overview bindings and the sealed result (mssql and oracle, with and without a cancelled receipt)', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    for (const engine of OVERVIEW_ENGINES) {
      for (const withCancelledReceipt of [true, false]) {
        const scenario = syntheticOverviewScenario(engine, {withCancelledReceipt})
        const value = { request: scenario.request, run: deepFreezeValue(scenario.run) }
        const direct = handleDatabaseOverviewRequestV1(scenario.request, value.run)
        const out = await runtime.execute('overview', value)
        // Pass-through to the pinned handler: the sealed result is returned
        // unaltered (byte-identical to a direct dispatch) and re-validated
        // through the vendored capability contract.
        assert.deepEqual(out.response.result, direct)
        assert.equal(canonicalJson(out.response.result), canonicalJson(handleDatabaseOverviewRequestV1(scenario.request, value.run)))
        const validated = buildObjectCapabilityContractV1().validateResult(out.response.result.envelope, {
          capabilityId: out.response.result.capabilityId,
          requestSha256: out.response.result.requestSha256,
          projectionSha256: out.response.result.projectionSha256,
          bindings: scenario.bindings,
        })
        assert.deepEqual(validated, out.response.result.envelope)
        // Preserves the exact Overview bindings: the snapshot, coverage,
        // receipt-chain and cancellation digests pass through unchanged from
        // the independently derived fixture bindings.
        assert.deepEqual(out.response.result.envelope.bindings, scenario.bindings)
        assert.equal(out.response.result.envelope.bindings.snapshotSha256, scenario.projection.bindings.inventorySnapshotSha256)
        assert.equal(out.response.result.envelope.bindings.coverageSha256, scenario.projection.bindings.coverageSha256)
        assert.equal(out.response.result.envelope.bindings.receiptChainSha256, scenario.projection.bindings.receiptChainSha256)
        assert.equal(out.response.result.projectionSha256, scenario.projection.projectionSha256)
        // Sealed, deeply frozen v2 result envelope around the pinned result.
        assertFrozen(out.response)
        assert.deepEqual(Object.keys(out.response), OVERVIEW_RESPONSE_KEYS)
        assert.equal(out.response.schemaVersion, SEARCH_RESULT_SCHEMA)
        assert.equal(out.response.action, 'overview')
        assert.equal(out.response.requestId, `ks-overview-${sha256Digest({ action: 'overview', input: value }).slice(7, 31)}`)
        const attestation = capabilityAttestationV2()
        assert.deepEqual(out.response.runtime, { product: attestation.product, contract: attestation.contract })
        assert.equal(out.response.capabilityAttestationDigest, attestation.attestation.digest)
        assert.equal(out.response.integrity.algorithm, 'sha256-canonical-json')
        assert.match(out.response.integrity.digest, /^sha256:[a-f0-9]{64}$/)
        const { integrity, ...body } = out.response
        assert.equal(sha256Digest(body), out.response.integrity.digest)
        // No authority: the pinned claims and authority surface stays all false.
        assert.deepEqual(out.response.result.envelope.claims, OVERVIEW_CLAIMS)
        assert.deepEqual(out.response.result.envelope.authority, OVERVIEW_AUTHORITY)
        // Dispatch is deterministic: a repeated dispatch seals an identical envelope.
        const repeated = await runtime.execute('overview', value)
        assert.equal(canonicalJson(repeated.response), canonicalJson(out.response))
      }
    }
    // Additive: the six closed v0.16 paths, the six-tool surface and the
    // P2B2B Search / P2B3B Details dispatches are untouched on the same
    // runtime.
    const status = await runtime.execute('status')
    assert.equal(status.response.result.status, 'READY')
    assert.equal(status.evidence.status, 'succeeded')
    const analyze = await runtime.execute('analyze')
    assert.equal(analyze.response.result.evidence.snapshotSha256,
      '293a896156d8f6269c4ad33e8d632da653ea180d35a4ea5f390b0be52ce3e44a')
    const discovery = await runtime.execute('discovery', { command: 'start', sessionId: 'p2b4b-1' })
    assert.equal(discovery.response.result.status, 'IN_PROGRESS')
    const plan = await runtime.execute('plan', { objective: 'Review weekly order value' })
    assert.equal(plan.response.result.authority.proposalOnly, true)
    const preview = await runtime.execute('preview', { objective: 'Preview weekly order value' })
    assert.deepEqual(preview.response.result.relations, ['dbo.customers', 'dbo.orders'])
    const readback = await runtime.execute('readback')
    assert.equal(readback.response.result.catalog.coverageComplete, true)
    const { sources: searchSources, envelope: searchEnvelope } = syntheticSearchFixture('mssql')
    const searchValue = validSearchHandlerInput({ engine: 'mssql', sources: searchSources, envelope: searchEnvelope })
    const searchOut = await runtime.execute('search', searchValue)
    assert.equal(canonicalJson(searchOut.response.result), canonicalJson(handleObjectSearchV1(searchValue)))
    const detailsScenario = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
    const detailsValue = { request: detailsScenario.request, projectionInput: detailsScenario.projectionInput }
    const detailsOut = await runtime.execute('details', detailsValue)
    assert.equal(canonicalJson(detailsOut.response.result), canonicalJson(handleObjectDetailsV1(detailsScenario.request, detailsScenario.projectionInput)))
    const tools = createToolDefinitions(runtime)
    assert.equal(tools.length, 6)
    assert(tools.every(tool => tool.capability.action !== 'overview'))
    // P2B4B supersedes the previous no-dispatch checks: Overview is now a
    // known local action and denies an empty dispatch envelope with its own
    // input code (the six-intent closed surface itself is unchanged).
    await assert.rejects(runtime.execute('overview'), /KS_DSH_OVERVIEW_INPUT_INVALID/)
  } finally {
    await runtime.dispose()
  }
})

test('P2B4B: malformed envelope and authority-bearing Overview input deny through the runtime with pinned codes', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const { request, run, bindings } = syntheticOverviewScenario('mssql', {withCancelledReceipt: true})
    const frozenRun = deepFreezeValue(structuredClone(run))
    const value = { request, run: frozenRun }
    const stale = syntheticOverviewScenario('mssql', {withCancelledReceipt: false})
    const cases = [
      // Envelope-level malformation never reaches the pinned handler.
      [{}, OVERVIEW_DISPATCH_INPUT_INVALID],
      [null, OVERVIEW_DISPATCH_INPUT_INVALID],
      [[request, run], OVERVIEW_DISPATCH_INPUT_INVALID],
      [{ request }, OVERVIEW_DISPATCH_INPUT_INVALID],
      [{ run: frozenRun }, OVERVIEW_DISPATCH_INPUT_INVALID],
      [{ ...value, sql: 'SELECT 1' }, OVERVIEW_DISPATCH_INPUT_INVALID],
      [{ ...value, credentials: 'secret' }, OVERVIEW_DISPATCH_INPUT_INVALID],
      [{ ...value, callback: 'https://evil.invalid' }, OVERVIEW_DISPATCH_INPUT_INVALID],
      // Request-level content denies with the pinned handler codes.
      [{ ...value, request: null }, OVERVIEW_REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, sql: 'SELECT 1' } }, OVERVIEW_REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, credentials: 'secret' } }, OVERVIEW_REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, rawRows: [] } }, OVERVIEW_REQUEST_SURFACE_DENIED],
      [{ ...value, request: { ...request, capabilityId: 'bi.object.details.read' } }, OVERVIEW_REQUEST_IDENTITY_DENIED],
      [{ ...value, request: { ...request, scope: { schemas: ['other'] } } }, OVERVIEW_SCOPE_DENIED],
      [{ ...value, request: { ...request, scope: { schemas: ['../escape'] } } }, OVERVIEW_SCOPE_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, engine: 'postgres' } } }, OVERVIEW_BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, dispatchAuthority: true } } }, OVERVIEW_BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, executionAuthority: true } } }, OVERVIEW_BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, sqlAuthority: true } } }, OVERVIEW_BINDING_DENIED],
      [{ ...value, request: { ...request, bindings: { ...bindings, claims: { completenessClaimed: true } } } }, OVERVIEW_BINDING_DENIED],
      ...Object.keys(bindings).filter((key) => key !== 'engine').map((key) => [
        { ...value, request: { ...request, bindings: { ...bindings, [key]: hash64('0') } } },
        OVERVIEW_BINDING_DENIED,
      ]),
      // Stale request: same capability and scope but bindings derived from a
      // different run.
      [{ ...value, request: stale.request }, OVERVIEW_BINDING_DENIED],
      // Hidden and symbol request surfaces deny before any trap executes.
      [{ ...value, request: (hidden => { const copy = structuredClone(request); Object.defineProperty(copy, 'credentials', { value: 'secret', enumerable: false }); return copy })() }, OVERVIEW_REQUEST_SURFACE_DENIED],
      [{ ...value, request: (symbol => { const copy = structuredClone(request); copy[Symbol('secret')] = 'hidden'; return copy })() }, OVERVIEW_REQUEST_SURFACE_DENIED],
      // Run-level content denies with the pinned handler codes: the pinned
      // handler is the single authority and requires a deeply frozen run.
      // (A null run is not pinned: the pinned closure's data-tree and
      // deep-freeze checks both pass null through, so the handler denies it
      // with a raw TypeError at Object.hasOwn before any pinned code —
      // still fail-closed: no projection, no result, no dispatch.)
      [{ ...value, run: structuredClone(run) }, 'DB_OVERVIEW_HANDLER_INPUT_INVALID'],
      [{ ...value, run: deepFreezeValue({ ...structuredClone(run), authority: { sqlAuthority: 'ALL' } }) }, 'DB_OVERVIEW_HANDLER_AUTHORITY_CLAIM_DENIED'],
      [{ ...value, run: deepFreezeValue({ ...structuredClone(run), claims: { completenessClaimed: true } }) }, 'DB_OVERVIEW_HANDLER_AUTHORITY_CLAIM_DENIED'],
      // Broken run seal: the body changed but the pinned stateSha256 did not.
      [{ ...value, run: deepFreezeValue({ ...structuredClone(run), scope: { ...run.scope, schemas: ['other'] } }) }, 'DB_OVERVIEW_RUN_TAMPERED'],
    ]
    for (const [input, code] of cases) {
      await assert.rejects(runtime.execute('overview', input), { code, message: code })
    }
    // A Proxy run denies before any trap executes.
    let traps = 0
    const proxyRun = new Proxy(structuredClone(run), { getPrototypeOf() { traps += 1; return Object.prototype; } })
    await assert.rejects(runtime.execute('overview', { ...value, run: proxyRun }),
      { code: 'DB_OVERVIEW_HANDLER_INPUT_INVALID', message: 'DB_OVERVIEW_HANDLER_INPUT_INVALID' })
    assert.equal(traps, 0)
    // Denial is fail closed: a denied Overview leaves no result and the runtime stays usable.
    const after = await runtime.execute('overview', value)
    assert.equal(canonicalJson(after.response.result), canonicalJson(handleDatabaseOverviewRequestV1(request, frozenRun)))
  } finally {
    await runtime.dispose()
  }
})

test('P2B4B: external runtime mode denies Overview locally and never sends it to the shared external API', async () => {
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
  const scenario = syntheticOverviewScenario('mssql', {withCancelledReceipt: true})
  const value = { request: scenario.request, run: deepFreezeValue(scenario.run) }
  const runtime = await KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    external: { baseUrl: `http://127.0.0.1:${address.port}` },
  })
  try {
    // Overview is local only: it is outside the v0.16 closed intent set and
    // must deny before any request leaves the process.
    await assert.rejects(runtime.execute('overview', value),
      { code: OVERVIEW_EXTERNAL_DENIED, message: OVERVIEW_EXTERNAL_DENIED })
    // Only the create-time attestation fetch touched the network; Overview never did.
    assert.deepEqual(requests, [{ method: 'GET', url: '/v2/capabilities' }])
  } finally {
    await runtime.dispose()
    await new Promise(resolve => server.close(resolve))
  }
})

// P2B5A: compact integrated authority guard over the combined pinned v0.24.0
// Search/Details/Overview local surface (v0.24.0 closure, source commit
// e092bb0). It reuses the verified P2B2B/P2B3B/P2B4B synthetic fixtures and
// runtime dispatch without reconstructing fixtures or duplicating the
// exhaustive per-leaf negative matrices, and proves the combined surface is
// closed (exactly the three pinned v0.24 capabilities are locally
// dispatchable, absent from the six native tools and the EXTERNAL transport)
// and carries no authority (the representative sealed outputs and the exposed
// attestation metadata keep every claim and authority flag false and contain
// no raw-row, credential, SQL, network, executable or mutation fields). Test
// only: no production or vendor file is added or modified.
const P2B5A_LOCAL_CAPABILITIES = Object.freeze([
  { action: 'search', capabilityId: SEARCH_CAPABILITY_ID, externalDenied: SEARCH_EXTERNAL_DENIED },
  { action: 'details', capabilityId: KS_OBJECT_DETAILS_HANDLER_CAPABILITY, externalDenied: DETAILS_EXTERNAL_DENIED },
  { action: 'overview', capabilityId: DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID, externalDenied: OVERVIEW_EXTERNAL_DENIED },
])
// Representative alias/authority names for the three capabilities plus generic
// mutation/execution words: none is a closed intent, and none may be a locally
// dispatchable action (a compact sweep, not the exhaustive per-leaf matrices).
const P2B5A_ALIASES = Object.freeze([
  'Search', 'search-v1', 'object-search', 'objectSearch', 'searchObjects', 'db-search',
  'Details', 'details-v1', 'object-details', 'objectDetails', 'db-details',
  'Overview', 'overview-v1', 'database-overview', 'databaseOverview', 'db-overview',
  'sql', 'query', 'execute', 'run', 'raw', 'rows', 'mutation', 'write',
])
// Forbidden field names (exact key match): the raw-row, credential/secret,
// SQL, network and executable/callback classes. The pinned authority/claim
// flag names (sqlAuthority, credentialsIncluded, rawValuesIncluded,
// queryExecution) are deliberately not in this set: they are the pinned
// all-false flags asserted below, not forbidden surfaces.
const P2B5A_FORBIDDEN_KEYS = Object.freeze([
  'raw', 'rawRows', 'raw_rows', 'rows', 'rawData', 'raw_data', 'cells',
  'credential', 'credentials', 'password', 'passwords', 'passwd', 'secret', 'secrets',
  'token', 'tokens', 'apiKey', 'api_key', 'accessToken', 'authToken', 'dsn',
  'connectionString', 'connection_string', 'connection',
  'sql', 'sqlText', 'statement', 'statements', 'query', 'queries', 'commandText',
  'url', 'urls', 'uri', 'uris', 'endpoint', 'endpoints', 'baseUrl', 'base_url',
  'host', 'hostname', 'port', 'protocol', 'ip', 'ips', 'webhook', 'webhooks',
  'callback', 'callbacks', 'executable', 'executables', 'script', 'scripts',
  'command', 'commands', 'shell', 'binary',
])
// Forbidden content classes for string values (including the Overview bytes.*
// canonical-JSON payloads, which are scanned as text): URL schemes, IPv4
// endpoints, localhost, statement-shaped SQL, leading SQL statements,
// credential/secret words, and exact forbidden JSON key names embedded in a
// JSON string.
const P2B5A_FORBIDDEN_VALUE_PATTERNS = Object.freeze([
  { name: 'url-scheme', pattern: /\b(?:https?|ftp|wss?):\/\//i },
  { name: 'ipv4-endpoint', pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/ },
  { name: 'localhost', pattern: /\blocalhost\b/i },
  { name: 'sql-statement', pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|MERGE|EXECUTE|EXEC|GRANT|REVOKE|CREATE)\b[^a-z0-9]*(?:FROM|INTO|TABLE|SET|WHERE|GRANT|TO)\b/i },
  { name: 'leading-sql-statement', pattern: /^\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|EXEC)\b/i },
  { name: 'credential-word', pattern: /\b(?:passw(?:or)?d|secret|token|bearer|credential|api[-_ ]?key)\b/i },
  { name: 'embedded-forbidden-key', pattern: /"(?:rawRows|raw_rows|rows|rawData|raw_data|password|passwd|secret|token|apiKey|api_key|accessToken|authToken|credential|credentials|dsn|connectionString|sql|statement|query|url|uri|endpoint|baseUrl|host|hostname|port|protocol|callback|webhook|executable|script|command|function)"\s*:/i },
])
// The exposed capability attestation metadata: every boundary is a false
// authority flag except the named readback-only persistent workflow.
const P2B5A_ATTESTATION_BOUNDARIES = Object.freeze({
  sourceDatabaseCredentialsAccepted: false,
  freeSqlAccepted: false,
  rawSourceRowsReturned: false,
  modelMutationAuthority: false,
  directSupersetMutationIntentAccepted: false,
  persistentSupersetWorkflow: 'trusted-preview-approval-apply-readback-rollback-only',
})

function p2b5aRepresentativeValues() {
  const { sources, envelope } = syntheticSearchFixture('mssql')
  const search = validSearchHandlerInput({ engine: 'mssql', sources, envelope })
  const detailsScenario = syntheticDetailsScenario('mssql', DETAILS_STATES.COMPLETE)
  const details = { request: detailsScenario.request, projectionInput: detailsScenario.projectionInput }
  const overviewScenario = syntheticOverviewScenario('mssql', { withCancelledReceipt: true })
  const overview = { request: overviewScenario.request, run: deepFreezeValue(overviewScenario.run) }
  return { search, details, overview, overviewScenario }
}

test('P2B5A: the combined pinned v0.24 Search/Details/Overview local surface is closed: exactly three local actions, absent from the six native tools and the EXTERNAL transport', async () => {
  const values = p2b5aRepresentativeValues()
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    // Exactly the three pinned v0.24 capabilities are locally dispatchable,
    // each sealing its own representative v2 result locally.
    for (const { action } of P2B5A_LOCAL_CAPABILITIES) {
      const out = await runtime.execute(action, values[action])
      assertFrozen(out.response)
      assert.equal(out.response.schemaVersion, SEARCH_RESULT_SCHEMA)
      assert.equal(out.response.action, action)
    }
    // No other non-intent action is locally dispatchable: a compact
    // alias/authority sweep denies with the pinned unknown-action code.
    for (const alias of P2B5A_ALIASES) {
      assert(!CLOSED_INTENTS.includes(alias), `alias must not be a closed intent: ${alias}`)
      await assert.rejects(runtime.execute(alias, values.search),
        { code: 'KS_DSH_ACTION_INVALID', message: 'KS_DSH_ACTION_INVALID' })
    }
    // Absent from the six native tools: the tool surface is exactly the six
    // closed-intent names and carries none of the three v0.24 capabilities.
    const tools = createToolDefinitions(runtime)
    assert.deepEqual(tools.map(tool => tool.name), CLOSED_INTENTS.map(action => TOOL_NAMES[action]))
    assert(tools.every(tool => P2B5A_LOCAL_CAPABILITIES.every(cap =>
      tool.capability.action !== cap.action && tool.capability.capabilityId !== cap.capabilityId)))
    // Additive: the six closed intents remain dispatchable on the same runtime.
    const status = await runtime.execute('status')
    assert.equal(status.response.result.status, 'READY')
  } finally {
    await runtime.dispose()
  }
  // Absent from the EXTERNAL transport: one shared loopback server proves all
  // three deny locally and only the create-time attestation fetch occurred.
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
  const external = await KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    external: { baseUrl: `http://127.0.0.1:${address.port}` },
  })
  try {
    for (const { action, externalDenied } of P2B5A_LOCAL_CAPABILITIES) {
      await assert.rejects(external.execute(action, values[action]),
        { code: externalDenied, message: externalDenied })
    }
    // Only the create-time attestation fetch touched the network; none of the
    // three capabilities ever reached the shared external API.
    assert.deepEqual(requests, [{ method: 'GET', url: '/v2/capabilities' }])
  } finally {
    await external.dispose()
    await new Promise(resolve => server.close(resolve))
  }
})

test('P2B5A: the integrated sealed outputs and exposed metadata carry no authority: all claims and authority flags false and no raw-row, credential, SQL, network, executable or mutation fields', async () => {
  const values = p2b5aRepresentativeValues()
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const searchOut = await runtime.execute('search', values.search)
    const detailsOut = await runtime.execute('details', values.details)
    const overviewOut = await runtime.execute('overview', values.overview)
    const attestation = capabilityAttestationV2()
    // Representative sealed results: the Search/Details results and the
    // Overview envelope share the pinned 8-key PROJECTED_READ_ONLY surface
    // with every claim and authority flag false.
    for (const result of [searchOut.response.result, detailsOut.response.result, overviewOut.response.result.envelope]) {
      assertFrozen(result)
      assert.equal(result.state, 'PROJECTED_READ_ONLY')
      assert.deepEqual(Object.keys(result).sort(), DETAILS_RESULT_KEYS)
      assert.deepEqual(result.claims, PINNED_SEARCH_CLAIMS)
      assert.deepEqual(result.authority, PINNED_SEARCH_AUTHORITY)
      for (const flag of [...Object.values(result.claims), ...Object.values(result.authority)]) {
        assert.equal(flag, false)
      }
    }
    // The Overview handler result surface is pinned and its bytes.* payloads
    // round-trip to the exact verified structures (no hidden payload).
    const overviewResult = overviewOut.response.result
    assertFrozen(overviewResult)
    assert.equal(overviewResult.state, 'PROJECTED_READ_ONLY')
    assert.deepEqual(Object.keys(overviewResult).sort(), OVERVIEW_RESULT_KEYS)
    assert.deepEqual(JSON.parse(overviewResult.bytes.result), overviewResult.envelope)
    assert.deepEqual(JSON.parse(overviewResult.bytes.request), values.overview.request)
    assert.deepEqual(JSON.parse(overviewResult.bytes.projection), values.overviewScenario.projection)
    // Exposed metadata: the sealed response metadata is pinned and the
    // attestation the runtime exposes carries only false authority flags.
    for (const out of [searchOut, detailsOut, overviewOut]) {
      assertFrozen(out.response)
      assert.deepEqual(Object.keys(out.response), SEARCH_RESPONSE_KEYS)
      assert.equal(out.response.schemaVersion, SEARCH_RESULT_SCHEMA)
      const { integrity, ...body } = out.response
      assert.equal(sha256Digest(body), out.response.integrity.digest)
      assert.deepEqual(out.response.runtime, { product: attestation.product, contract: attestation.contract })
      assert.equal(out.response.capabilityAttestationDigest, attestation.attestation.digest)
    }
    // The vendored attestation is shallow-frozen (the v0.16.0 closure
    // freezes the top-level body only); assert the depth it actually pins.
    assert(Object.isFrozen(attestation))
    assert.deepEqual(attestation.boundaries, P2B5A_ATTESTATION_BOUNDARIES)
    assert.deepEqual(attestation.graph, { acceptedIncumbent: 'adaptive-v1', candidatePromotion: 'none' })
    // No raw-row, credential, SQL, network, executable or mutation fields:
    // no forbidden key name at any depth and no forbidden content class in any
    // string value (including the Overview bytes.* canonical-JSON payloads and
    // the exposed attestation metadata).
    const scan = (root, label) => {
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
        assert(!P2B5A_FORBIDDEN_KEYS.includes(key), `${label}: forbidden key "${key}"`)
      }
      for (const value of strings) {
        for (const { name, pattern } of P2B5A_FORBIDDEN_VALUE_PATTERNS) {
          assert(!pattern.test(value), `${label}: ${name} content in a string value`)
        }
      }
    }
    for (const [label, out] of [['search', searchOut], ['details', detailsOut], ['overview', overviewOut]]) {
      scan(out.response, label)
    }
    scan(attestation, 'attestation')
  } finally {
    await runtime.dispose()
  }
})

// P2B5B: compact v0.16 regression oracle. With all three additive local
// v0.24.0 mappings (Search/Details/Overview, source commit e092bb0) present
// and locally dispatchable, it proves exactly the six pinned v0.16 intents
// and six native tools remain byte-for-byte/pin-for-pin represented and
// executable, and the representative v0.16 runtime success/denial behavior
// and provenance remain unchanged. The pins are literals independent of the
// tables under test (the v0.16-era response/evidence digest table is the
// committed expected-fixture-digests.json); the three v0.24 mappings are
// proven present through the P2B5A-verified fixtures and absent from the
// native tool surface and the EXTERNAL transport. This oracle does not
// duplicate the P2B5A authority proof or absorb P2B5C rollback
// responsibility. Test only: no production or vendor file is added or
// modified.
const P2B5B_INTENTS = Object.freeze(['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'])
const P2B5B_TOOL_NAMES = Object.freeze([
  'kaleidosphere_status',
  'kaleidosphere_discovery',
  'kaleidosphere_analyze',
  'kaleidosphere_plan',
  'kaleidosphere_preview',
  'kaleidosphere_readback',
])
const P2B5B_CAPABILITIES = Object.freeze([
  { action: 'status', capabilityId: 'bi.status.read', authority: 'read-only' },
  { action: 'discovery', capabilityId: 'bi.discovery.run', authority: 'local-evidence-write' },
  { action: 'analyze', capabilityId: 'bi.analysis.run', authority: 'source-read-only' },
  { action: 'plan', capabilityId: 'bi.graph.adaptive-v1.plan', authority: 'proposal-only' },
  { action: 'preview', capabilityId: 'bi.preview.create', authority: 'proposal-only' },
  { action: 'readback', capabilityId: 'bi.readback.read', authority: 'read-only' },
])
const P2B5B_DESCRIPTIONS = Object.freeze({
  status: 'Read KaleidoSphere plugin readiness, configured source mode, engine, and latest receipt identity.',
  discovery: 'Run or continue a guided, receipt-bound KaleidoSphere database discovery session.',
  analyze: 'Analyze the configured database metadata through the configured KaleidoSphere read-only runtime.',
  plan: 'Create an evidence-bound KaleidoSphere analysis plan without persistent mutation authority.',
  preview: 'Create an evidence-bound proposal preview from the latest KaleidoSphere analysis receipt.',
  readback: 'Read back the latest KaleidoSphere receipt, catalog summary, and technical coverage counts.',
})
const P2B5B_PARAMETERS = Object.freeze({
  status: {},
  analyze: {},
  readback: {},
  discovery: {
    command: { type: 'string', required: true, enum: ['start', 'resume', 'status', 'answer', 'revise', 'confirm', 'export'] },
    sessionId: { type: 'string', required: true, description: 'Stable lowercase discovery session id.' },
    field: { type: 'string', description: 'Field name for answer or revise.' },
    value: { type: 'json', description: 'JSON value for answer or revise.' },
  },
  plan: {
    objective: { type: 'string', required: true, description: 'Business analysis objective.' },
    receiptId: { type: 'string', description: 'Optional exact latest receipt id.' },
  },
  preview: {
    objective: { type: 'string', required: true, description: 'Business analysis objective.' },
    receiptId: { type: 'string', description: 'Optional exact latest receipt id.' },
  },
})
const P2B5B_TIMEOUTS = Object.freeze({ status: 30_000, discovery: 30_000, analyze: 180_000, plan: 30_000, preview: 30_000, readback: 30_000 })
const P2B5B_OUTPUT_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  properties: {
    response: { type: 'object', additionalProperties: true, required: true },
    evidence: { type: 'object', additionalProperties: true, required: true },
  },
})
// v0.16-era provenance pin: the exact event and receipt identities for the
// six representative intent executions (deterministic in fixture mode).
const P2B5B_PROVENANCE = Object.freeze({
  status: { eventId: 'ks-event-status-cfd38e0dc01a', receiptId: 'ks-status-4749a27fa59ecfd38e0dc01a' },
  analyze: { eventId: 'ks-event-analyze-5997a2bd2c96', receiptId: 'ks-analyze-5536317306925997a2bd2c96' },
  discovery: { eventId: 'ks-event-discovery-100a9fb6ce64', receiptId: 'ks-discovery-56f65c082345100a9fb6ce64' },
  plan: { eventId: 'ks-event-plan-2dc63bb0fc1f', receiptId: 'ks-plan-efe8e523f1712dc63bb0fc1f' },
  preview: { eventId: 'ks-event-preview-b3a44e23c77c', receiptId: 'ks-preview-27228dff832bb3a44e23c77c' },
  readback: { eventId: 'ks-event-readback-79b590696831', receiptId: 'ks-readback-de6cac970d7579b590696831' },
})

test('P2B5B: with the three additive v0.24 local mappings present, the six pinned v0.16 intents and native tools remain byte-for-byte/pin-for-pin represented, executable and green with unchanged runtime behavior and provenance', async () => {
  const values = p2b5aRepresentativeValues()
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    // Presence precondition: all three additive local v0.24 mappings
    // dispatch locally on this same runtime (P2B5A-verified fixtures).
    for (const { action } of P2B5A_LOCAL_CAPABILITIES) {
      const out = await runtime.execute(action, values[action])
      assert.equal(out.response.schemaVersion, SEARCH_RESULT_SCHEMA)
      assert.equal(out.response.action, action)
    }
    // P2B5B-SIX: exactly the six pinned v0.16 intents and native tool names,
    // pinned against literals independent of the tables under test.
    assert.deepEqual(CLOSED_INTENTS, P2B5B_INTENTS)
    assert.deepEqual(TOOL_NAMES, Object.fromEntries(P2B5B_INTENTS.map((action, index) => [action, P2B5B_TOOL_NAMES[index]])))
    const tools = createToolDefinitions(runtime)
    assert.equal(tools.length, 6)
    assert.deepEqual(tools.map(tool => tool.name), P2B5B_TOOL_NAMES)
    // Byte-for-byte representation: the full per-tool data surface is the
    // pinned v0.16 surface, and no v0.24 capability is exposed natively.
    tools.forEach((tool, index) => {
      const { action, capabilityId, authority } = P2B5B_CAPABILITIES[index]
      assert.deepEqual(
        {
          name: tool.name,
          description: tool.description,
          parameters: tool.parameters,
          timeoutMs: tool.timeoutMs,
          capability: tool.capability,
          output: tool.output.schema,
        },
        {
          name: P2B5B_TOOL_NAMES[index],
          description: P2B5B_DESCRIPTIONS[action],
          parameters: P2B5B_PARAMETERS[action],
          timeoutMs: P2B5B_TIMEOUTS[action],
          capability: { action, capabilityId, authority },
          output: P2B5B_OUTPUT_SCHEMA,
        },
      )
      assert(!P2B5A_LOCAL_CAPABILITIES.some(cap =>
        tool.capability.action === cap.action || tool.capability.capabilityId === cap.capabilityId))
    })
    // P2B5B-RUNTIME: all six remain executable with the v0.16-era
    // representative inputs; the exact response/evidence digests remain the
    // v0.16-era pins and the provenance fields are unchanged.
    const outputs = {
      status: await runtime.execute('status'),
      analyze: await runtime.execute('analyze'),
      discovery: await runtime.execute('discovery', { command: 'start', sessionId: 'demo-1' }),
      plan: await runtime.execute('plan', { objective: 'Review weekly order value' }),
      preview: await runtime.execute('preview', { objective: 'Preview weekly order value' }),
      readback: await runtime.execute('readback'),
    }
    for (const [action, out] of Object.entries(outputs)) {
      assert.equal(out.response.action, action)
      assert.equal(out.response.integrity.digest, expectedDigests[action].response)
      assert.equal(out.evidence.evidenceDigest, expectedDigests[action].evidence)
      assert.equal(out.evidence.status, 'succeeded')
      assert.equal(out.evidence.resultIntegrityDigest, out.response.integrity.digest)
      assert.equal(out.evidence.bridgeSchemaVersion, 'kaleidosphere/external-intent-evidence-bridge/v1')
      assert.equal(out.evidence.eventId, P2B5B_PROVENANCE[action].eventId)
      assert.equal(out.evidence.receiptId, P2B5B_PROVENANCE[action].receiptId)
      assert.equal(out.evidence.capabilityId, P2B5B_CAPABILITIES[P2B5B_INTENTS.indexOf(action)].capabilityId)
    }
    // Representative v0.16 denial behavior remains unchanged.
    const denied = await KaleidoSphereRuntime.create()
    try {
      await assert.rejects(denied.execute('readback'), { code: 'KS_DSH_ANALYSIS_REQUIRED' })
      await assert.rejects(denied.execute('plan', { objective: 'Review weekly order value' }), { code: 'KS_DSH_ANALYSIS_REQUIRED' })
      await assert.rejects(denied.execute('query'), { code: 'KS_DSH_ACTION_INVALID' })
    } finally {
      await denied.dispose()
    }
  } finally {
    await runtime.dispose()
  }
  // Absent from the EXTERNAL transport while the v0.16 intents still ride the
  // shared /v2/intents API: one loopback server proves the three v0.24
  // mappings deny locally before the wire and the representative v0.16
  // external success keeps its pinned attested flow.
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
  const external = await KaleidoSphereRuntime.create({
    runtimeMode: 'external',
    external: { baseUrl: `http://127.0.0.1:${address.port}` },
  })
  try {
    for (const { action, externalDenied } of P2B5A_LOCAL_CAPABILITIES) {
      await assert.rejects(external.execute(action, values[action]),
        { code: externalDenied, message: externalDenied })
    }
    const externalStatus = await external.execute('status')
    assert.equal(externalStatus.response.result.status, 'EXTERNAL_READY')
    assert.equal(externalStatus.evidence.status, 'succeeded')
    // Only the create-time attestation fetch and the one v0.16 intent POST
    // touched the wire; none of the three v0.24 mappings ever reached it.
    assert.deepEqual(requests, [
      { method: 'GET', url: '/v2/capabilities' },
      { method: 'POST', url: '/v2/intents' },
    ])
  } finally {
    await external.dispose()
    await new Promise(resolve => server.close(resolve))
  }
})

// P2B5C1: compact vendor-pin oracle. The real fail-closed verifier
// (scripts/verify-vendor.mjs) must prove the exact provenance of the 73-file
// v0.16.0 and 16-file v0.24.0 vendor trees against VENDORED_MANIFEST.json, and
// read-only git plumbing over the reachable baseline 414b40b..HEAD must prove
// that the net vendor change is exactly the 16-file v0.24 closure (pure
// additions under the v0.24 root, no v0.16 path) and that vendor-touching
// commits are disjoint from lib mapping commits. Test-only: no lib or vendor
// file is written; the scratch archive is created under os.tmpdir and removed.
test('P2B5C1: vendor trees retain exact pinned provenance and stay outside the additive mapping commits', async () => {
  const packageRoot = path.resolve(import.meta.dirname, '..')
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))

  // Exact pins re-derived at implementation time from VENDORED_MANIFEST.json and
  // the on-disk source (the discarded partial draft's 15-file literal is not
  // evidence). The baseline is the reachable origin/main commit the P2A/P2B
  // range starts from.
  const BASELINE_COMMIT = '414b40b4c63a880ddd80c2a8c872ba3bd8002eaa'
  const V016_TAG = 'v0.16.0'
  const V016_COMMIT = '5a73ff8146afa0067d226cffa639efde959e8fde'
  const V016_FILE_COUNT = 73
  const V016_DIGEST = 'f62109b120c0bc677d47ce4ce8e23278a30bacd7bc3555c1f4877d09cefd58a2'
  const V0240_TAG = 'v0.24.0'
  const V0240_COMMIT = 'e092bb0bce039936b88329793b24e9f987ae0ddb'
  const V0240_FILE_COUNT = 16
  const V0240_DIGEST = '2eb277886ab2abcb5cd0513da16bd72fa88f4d85a220e83d6665785830da0444'

  const sha256Hex = (buffer) => createHash('sha256').update(buffer).digest('hex')

  async function walk(directory) {
    const result = []
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const item = path.join(directory, entry.name)
      if (entry.isDirectory()) result.push(...await walk(item))
      else if (entry.isFile()) result.push(item)
    }
    return result
  }

  // Same aggregate algorithm as scripts/verify-vendor.mjs:
  // sha256(relative-path NUL content NUL, lexicographic relative paths).
  async function aggregateTree(rootDir) {
    const digest = createHash('sha256')
    const paths = (await walk(rootDir)).sort()
    for (const item of paths) {
      digest.update(`${path.relative(rootDir, item)}\0`)
      digest.update(await readFile(item))
      digest.update('\0')
    }
    return { count: paths.length, digest: digest.digest('hex') }
  }

  // Read-only git plumbing only (rev-parse / log / diff): fail closed (status
  // nonzero) if the git binary is unavailable, so the test never skips.
  function git(...args) {
    try {
      return { status: 0, output: execFileSync('git', args, { encoding: 'utf8', cwd: packageRoot }) }
    } catch (error) {
      return { status: typeof error.status === 'number' ? error.status : 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}${error.code ?? ''}` }
    }
  }

  // Run the real fail-closed verifier against a package root (the script
  // resolves its root from its own location) and report { status, output }.
  function runRealVerifier(root) {
    try {
      return { status: 0, output: execFileSync(process.execPath, [path.join(root, 'scripts', 'verify-vendor.mjs')], { encoding: 'utf8' }) }
    } catch (error) {
      return { status: typeof error.status === 'number' ? error.status : 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
    }
  }

  // -- PINS: the manifest records the exact provenance and the on-disk trees
  // -- match it byte-for-byte (independent recomputation, both roots).
  assert.equal(manifest.tag, V016_TAG, 'v0.16.0 section must pin the exact tag')
  assert.equal(manifest.commit, V016_COMMIT, 'v0.16.0 section must pin the exact source commit')
  assert.equal(manifest.fileCount, V016_FILE_COUNT, 'v0.16.0 section must record exactly 73 files')
  assert.equal(manifest.digest, V016_DIGEST, 'v0.16.0 section must pin the exact aggregate digest')
  const v016Tree = await aggregateTree(path.join(packageRoot, manifest.root))
  assert.equal(v016Tree.count, V016_FILE_COUNT, 'v0.16.0 tree must contain exactly the 73 pinned files')
  assert.equal(v016Tree.digest, V016_DIGEST, 'v0.16.0 tree must be byte-identical to the pinned digest')

  const closure = manifest.v0240
  assert.ok(closure, 'VENDORED_MANIFEST.json must carry a v0240 handler-closure section')
  assert.equal(closure.tag, V0240_TAG, 'v0240 section must pin the exact tag')
  assert.equal(closure.commit, V0240_COMMIT, 'v0240 section must pin the exact source commit')
  assert.equal(closure.fileCount, V0240_FILE_COUNT, 'v0240 section must record exactly 16 files')
  assert.equal(closure.digest, V0240_DIGEST, 'v0240 section must pin the exact aggregate digest')
  assert.ok(Array.isArray(closure.files) && closure.files.length === V0240_FILE_COUNT,
    'v0240 section must carry exactly 16 per-file entries')
  const seenVendorPaths = new Set()
  for (const entry of closure.files) {
    assert.equal(entry.sourceCommit, V0240_COMMIT, `source commit must be e092bb0 for ${entry.sourcePath}`)
    assert.equal(entry.vendorPath, `${closure.root}/${entry.sourcePath}`,
      `vendor path must mirror the source path under ${closure.root}`)
    assert.equal(seenVendorPaths.has(entry.vendorPath), false, `duplicate vendor path ${entry.vendorPath}`)
    seenVendorPaths.add(entry.vendorPath)
    const buffer = await readFile(path.join(packageRoot, entry.vendorPath))
    assert.equal(sha256Hex(buffer), entry.sha256, `vendor file ${entry.vendorPath} must match its pinned digest`)
  }
  const v0240OnDisk = new Set((await walk(path.join(packageRoot, closure.root))).map((item) => path.relative(packageRoot, item)))
  assert.equal(v0240OnDisk.size, V0240_FILE_COUNT, 'v0.24.0 tree must contain exactly the 16 pinned files')
  for (const item of v0240OnDisk) {
    assert.ok(seenVendorPaths.has(item), `unmanifested vendor file ${item} in the v0.24.0 tree`)
  }
  const v0240Tree = await aggregateTree(path.join(packageRoot, closure.root))
  assert.equal(v0240Tree.count, V0240_FILE_COUNT, 'v0.24.0 tree count must equal the pinned 16')
  assert.equal(v0240Tree.digest, V0240_DIGEST, 'v0.24.0 tree must be byte-identical to the pinned digest')

  // -- PINS: the real fail-closed verifier agrees: exit 0, and its two JSON
  // -- lines equal the exact manifest provenance for both roots (73/16).
  const clean = runRealVerifier(packageRoot)
  assert.equal(clean.status, 0, `real tree must pass the real verifier (got exit ${clean.status}: ${clean.output})`)
  const verifierLines = clean.output.trim().split('\n').map((line) => JSON.parse(line))
  assert.equal(verifierLines.length, 2, 'the real verifier must emit exactly two provenance lines')
  assert.deepEqual(verifierLines[0],
    { tag: manifest.tag, commit: manifest.commit, fileCount: manifest.fileCount, digest: manifest.digest },
    'verifier v0.16.0 output must equal the exact manifest provenance')
  assert.deepEqual(verifierLines[1],
    { tag: closure.tag, commit: closure.commit, fileCount: closure.fileCount, digest: closure.digest },
    'verifier v0.24.0 output must equal the exact manifest provenance')
  assert.deepEqual(verifierLines[0],
    { tag: V016_TAG, commit: V016_COMMIT, fileCount: V016_FILE_COUNT, digest: V016_DIGEST },
    'verifier v0.16.0 output must equal the exact 73-file pin')
  assert.deepEqual(verifierLines[1],
    { tag: V0240_TAG, commit: V0240_COMMIT, fileCount: V0240_FILE_COUNT, digest: V0240_DIGEST },
    'verifier v0.24.0 output must equal the exact 16-file pin')

  // -- ABSENT-CLOSURE RED CONTROL: with the v0.24 closure absent from a scratch
  // -- archive (v0.16 tree, manifest and the real verifier intact), the real
  // -- verifier must fail closed: nonzero exit, the v0.16 line emitted and the
  // -- v0.24 line not.
  const scratch = await mkdtemp(path.join(os.tmpdir(), 'ks-p2b5c1-'))
  try {
    for (const item of (await walk(path.join(packageRoot, manifest.root))).map((p) => path.relative(packageRoot, p))) {
      const target = path.join(scratch, item)
      await mkdir(path.dirname(target), { recursive: true })
      await writeFile(target, await readFile(path.join(packageRoot, item)))
    }
    await mkdir(path.join(scratch, 'scripts'), { recursive: true })
    await writeFile(path.join(scratch, 'scripts', 'verify-vendor.mjs'),
      await readFile(path.join(packageRoot, 'scripts', 'verify-vendor.mjs')))
    await writeFile(path.join(scratch, 'VENDORED_MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n')
    // Deliberately no vendor/kaleidosphere-v0.24.0 file: the v0.24 closure is absent.
    const absent = runRealVerifier(scratch)
    assert.notEqual(absent.status, 0, 'an absent v0.24 closure must make the real verifier exit nonzero')
    assert.ok(absent.output.includes(JSON.stringify({ tag: V016_TAG, commit: V016_COMMIT, fileCount: V016_FILE_COUNT, digest: V016_DIGEST })),
      'the v0.16.0 section must have passed and emitted its exact provenance line')
    assert.ok(!absent.output.includes(JSON.stringify({ tag: V0240_TAG, commit: V0240_COMMIT, fileCount: V0240_FILE_COUNT, digest: V0240_DIGEST })),
      'the v0.24.0 section must have failed and not emitted its provenance line')
  } finally {
    await rm(scratch, { recursive: true, force: true })
  }

  // -- DISJOINT + RANGE: read-only git range over the reachable baseline; fail
  // -- closed (never skip) if the baseline ref or the git binary is unavailable.
  const rev = git('rev-parse', '--verify', `${BASELINE_COMMIT}^{commit}`)
  assert.equal(rev.status, 0,
    `baseline ${BASELINE_COMMIT} must be a reachable commit (git unavailable or ref missing — failing closed)`)
  assert.equal(rev.output.trim(), BASELINE_COMMIT)
  const head = git('rev-parse', 'HEAD')
  assert.equal(head.status, 0, 'HEAD must resolve to a commit (not a git checkout — failing closed)')

  const vendorLog = git('log', '--format=%H', `${BASELINE_COMMIT}..HEAD`, '--', 'vendor/')
  assert.equal(vendorLog.status, 0, 'vendor commit range must resolve')
  const libLog = git('log', '--format=%H', `${BASELINE_COMMIT}..HEAD`, '--', 'lib/')
  assert.equal(libLog.status, 0, 'lib commit range must resolve')
  const vendorCommits = new Set(vendorLog.output.trim().split('\n').filter(Boolean))
  const libCommits = new Set(libLog.output.trim().split('\n').filter(Boolean))
  assert.ok(vendorCommits.size > 0, 'the range must contain vendor commits (non-vacuous proof)')
  assert.ok(libCommits.size > 0, 'the range must contain lib mapping commits (non-vacuous proof)')
  for (const commit of vendorCommits) {
    assert.ok(!libCommits.has(commit),
      `vendor-touching commit ${commit} must be disjoint from the lib mapping commits`)
  }

  const vendorRange = git('diff', '--name-status', `${BASELINE_COMMIT}..HEAD`, '--', 'vendor/')
  assert.equal(vendorRange.status, 0, 'vendor range diff must resolve')
  const rangeEntries = vendorRange.output.trim().split('\n').filter(Boolean).map((line) => line.split('\t'))
  assert.equal(rangeEntries.length, V0240_FILE_COUNT,
    'the net vendor range must touch exactly the 16 closure files')
  const manifestClosure = new Set(closure.files.map((entry) => entry.vendorPath))
  const rangePaths = new Set()
  for (const [status, vendorPath] of rangeEntries) {
    assert.equal(status, 'A', `vendor range entry ${vendorPath} must be a pure addition, not ${status}`)
    assert.ok(vendorPath.startsWith(`${closure.root}/`),
      `vendor range entry ${vendorPath} must live under the v0.24 root ${closure.root}`)
    assert.ok(!vendorPath.startsWith(`${manifest.root}/`), 'no v0.16 vendor path may change in the range')
    rangePaths.add(vendorPath)
  }
  assert.deepEqual([...rangePaths].sort(), [...manifestClosure].sort(),
    'the net vendor range must equal the manifest v0.24 closure exactly')
})

// P2B5C2: compact footprint-confinement oracle. Read-only git plumbing
// (diff / rev-parse / log / show / status) over the reachable baseline
// 414b40b..HEAD must prove that the net additive production footprint is
// confined to the two approved lib mapping files (purely additive: 172/0 and
// 129/0), plus exactly the 3 test support paths, the 5 pin support paths and
// the manifest-derived 16 v0.24 vendor additions — nothing else, no renames,
// no duplicates, no out-of-set paths — and that the same predicate fails
// closed when the v0.24 vendor closure is absent from the range (the baseline
// state). Anchors (baseline commit, manifest closure file list, fail-closed
// git helper shape) are reused from P2B5C1; C1's vendor-pin semantics (digest
// verification, real verifier) are not re-proven here, and no rollback
// simulation is performed. Test-only: no lib, vendor or production file is
// written.
test('P2B5C2: the additive production footprint is confined to the two approved lib mapping files plus test/pin support and the pinned v0.24 vendor additions', async () => {
  const packageRoot = path.resolve(import.meta.dirname, '..')
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
  const closure = manifest.v0240
  assert.ok(closure && Array.isArray(closure.files),
    'VENDORED_MANIFEST.json must carry the v0240 closure section with per-file entries (anchor reused from P2B5C1)')
  assert.equal(closure.fileCount, 16, 'the v0240 section must record exactly 16 files')
  assert.equal(closure.files.length, 16, 'the v0240 section must carry exactly 16 per-file entries')

  // Reachable baseline anchor (same as P2B5C1) and the source-derived allowed
  // footprint: 2 lib mapping files, 3 test support paths, 5 pin support paths
  // and the manifest-derived 16 v0.24 vendor additions. P2B5C1's test lives in
  // the same existing test/runtime.test.mjs path, so it adds no extra path.
  const BASELINE_COMMIT = '414b40b4c63a880ddd80c2a8c872ba3bd8002eaa'
  const LIB_FOOTPRINT = new Map([
    ['lib/capability-manifest.mjs', { added: 172, deleted: 0 }],
    ['lib/runtime.mjs', { added: 129, deleted: 0 }],
  ])
  const TEST_SUPPORT = [
    'test/capability-manifest.test.mjs',
    'test/runtime.test.mjs',
    'test/vendor-v0240-closure.test.mjs',
  ]
  const PIN_SUPPORT = [
    'THIRD_PARTY_MANIFEST.json',
    'VENDORED_MANIFEST.json',
    'package.json',
    'scripts/verify-package.mjs',
    'scripts/verify-vendor.mjs',
  ]
  const VENDOR_ADDITIONS = closure.files.map((entry) => entry.vendorPath)
  const ADDITIONS = new Set([...VENDOR_ADDITIONS, 'test/vendor-v0240-closure.test.mjs'])
  const ALLOWED = new Set([...LIB_FOOTPRINT.keys(), ...TEST_SUPPORT, ...PIN_SUPPORT, ...VENDOR_ADDITIONS])

  // Read-only git plumbing only; fail closed (never skip) if the git binary
  // or a ref is unavailable.
  function git(...args) {
    try {
      return { status: 0, output: execFileSync('git', args, { encoding: 'utf8', cwd: packageRoot }) }
    } catch (error) {
      return { status: typeof error.status === 'number' ? error.status : 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}${error.code ?? ''}` }
    }
  }

  // Whole-tree range facts: canonical name-status (no renames, no duplicates)
  // plus the lib numstat.
  function rangeFootprint(base, head) {
    const nameStatus = git('diff', '--name-status', '--no-renames', `${base}..${head}`)
    assert.equal(nameStatus.status, 0, `range ${base}..${head} name-status must resolve`)
    const lines = nameStatus.output.trim() ? nameStatus.output.trim().split('\n') : []
    const statuses = new Map()
    for (const line of lines) {
      const fields = line.split('\t')
      assert.equal(fields.length, 2, `range name-status line must be STATUS<TAB>PATH, got: ${line}`)
      const [status, target] = fields
      assert.ok(!status.startsWith('R'), `range entry ${target} must not be a rename, got ${status}`)
      assert.ok(!statuses.has(target), `range entry ${target} must not be duplicated`)
      statuses.set(target, status)
    }
    const numstat = git('diff', '--numstat', '--no-renames', `${base}..${head}`, '--', 'lib/')
    assert.equal(numstat.status, 0, `range ${base}..${head} lib numstat must resolve`)
    const libNumstat = new Map()
    for (const line of (numstat.output.trim() ? numstat.output.trim().split('\n') : [])) {
      const [added, deleted, target] = line.split('\t')
      assert.ok(!Number.isNaN(Number(added)) && !Number.isNaN(Number(deleted)),
        `lib numstat line must be numeric (not binary), got: ${line}`)
      assert.ok(!libNumstat.has(target), `lib numstat path ${target} must not be duplicated`)
      libNumstat.set(target, { added: Number(added), deleted: Number(deleted) })
    }
    return { statuses, libNumstat }
  }

  // The confinement predicate: exact whole-tree path set, exact per-path
  // status (pure addition vs modification) and exact purely additive lib
  // numstat. Returns the violation list (empty = confined).
  function confinementViolations(footprint) {
    const violations = []
    for (const [target, status] of footprint.statuses) {
      if (!ALLOWED.has(target)) violations.push(`out-of-set path ${target}`)
      else if (status !== (ADDITIONS.has(target) ? 'A' : 'M')) violations.push(`path ${target} must be a pure ${ADDITIONS.has(target) ? 'addition' : 'modification'}, got ${status}`)
    }
    for (const target of ALLOWED) {
      if (!footprint.statuses.has(target)) violations.push(`missing path ${target}`)
    }
    for (const [target, expected] of LIB_FOOTPRINT) {
      const actual = footprint.libNumstat.get(target)
      if (!actual) violations.push(`missing lib numstat for ${target}`)
      else if (actual.added !== expected.added || actual.deleted !== 0) violations.push(`lib ${target} numstat ${actual.added}/${actual.deleted} is not the exact purely additive ${expected.added}/0`)
    }
    for (const target of footprint.libNumstat.keys()) {
      if (!LIB_FOOTPRINT.has(target)) violations.push(`unexpected lib path ${target} in the range`)
    }
    return violations
  }

  // -- ANCHORS: the baseline is reachable and HEAD resolves (fail closed).
  const rev = git('rev-parse', '--verify', `${BASELINE_COMMIT}^{commit}`)
  assert.equal(rev.status, 0,
    `baseline ${BASELINE_COMMIT} must be a reachable commit (git unavailable or ref missing — failing closed)`)
  assert.equal(rev.output.trim(), BASELINE_COMMIT)
  const head = git('rev-parse', 'HEAD')
  assert.equal(head.status, 0, 'HEAD must resolve to a commit (not a git checkout — failing closed)')

  // -- P2B5C2-SET + LIB + SUPPORT: the whole additive range is exactly the
  // -- allowed footprint (26 paths), and the lib change is exactly the two
  // -- purely additive numstat entries.
  const footprint = rangeFootprint(BASELINE_COMMIT, 'HEAD')
  assert.deepEqual([...footprint.statuses.keys()].sort(), [...ALLOWED].sort(),
    'the whole-range path set must equal exactly the 26 allowed paths (2 lib + 3 test support + 5 pin support + 16 vendor additions)')
  assert.deepEqual(confinementViolations(footprint), [],
    'the additive range must be confined to the allowed footprint with exact statuses and purely additive lib numstat')
  assert.deepEqual([...footprint.statuses.keys()].filter((t) => t.startsWith('test/')).sort(), [...TEST_SUPPORT].sort(),
    'the test support paths must be exactly the 3 allowed paths')
  assert.deepEqual([...footprint.statuses.keys()].filter((t) => !t.startsWith('test/') && !t.startsWith('lib/') && !t.startsWith('vendor/')).sort(), [...PIN_SUPPORT].sort(),
    'the pin support paths must be exactly the 5 allowed paths')
  assert.deepEqual([...footprint.statuses.keys()].filter((t) => t.startsWith(`${closure.root}/`)).sort(), [...VENDOR_ADDITIONS].sort(),
    'the vendor range paths must equal exactly the manifest-derived 16 v0.24 additions')
  assert.deepEqual([...footprint.libNumstat].sort((a, b) => a[0].localeCompare(b[0])),
    [...LIB_FOOTPRINT].sort((a, b) => a[0].localeCompare(b[0])),
    'the lib numstat must be exactly the two purely additive 172/0 and 129/0 entries')

  // -- P2B5C2-RED CONTROL: with the v0.24 vendor closure absent from the range
  // -- (the baseline state, BASELINE..BASELINE), the same predicate must fail
  // -- closed with the closure-absent signature: no path touched at all, no lib
  // -- numstat, and all 16 vendor additions plus both lib files reported missing.
  const absent = rangeFootprint(BASELINE_COMMIT, BASELINE_COMMIT)
  assert.equal(absent.statuses.size, 0, 'the closure-absent range must touch no path')
  assert.equal(absent.libNumstat.size, 0, 'the closure-absent range must carry no lib numstat')
  const absentViolations = confinementViolations(absent)
  assert.ok(absentViolations.length > 0, 'the footprint proof must fail when the v0.24 vendor closure is absent from the range')
  assert.equal(absentViolations.filter((v) => v.startsWith('missing path vendor/')).length, 16,
    'the closure-absent signature must report all 16 v0.24 vendor additions missing')
  assert.equal(absentViolations.filter((v) => v.startsWith('missing lib numstat')).length, 2,
    'the closure-absent signature must report both lib mapping files missing from the numstat')

  // -- P2B5C2-NO-PRODUCTION: this leaf's own change is confined to
  // -- test/runtime.test.mjs. Post-commit runs: the leaf commit, located by its
  // -- subject marker, touches exactly that one path. Pre-commit (this leaf's
  // -- own gate): the uncommitted delta is exactly that one modified path
  // -- carrying the P2B5C2 marker. The committed range facts above are the
  // -- primary proof; uncommitted status is never the sole proof.
  const leafLog = git('log', '--fixed-strings', '--format=%H', '--grep=#65 P2B5C2')
  assert.equal(leafLog.status, 0, 'the leaf commit lookup must resolve')
  const leafCommits = leafLog.output.trim() ? leafLog.output.trim().split('\n') : []
  if (leafCommits.length > 0) {
    const leafShow = git('show', '--name-status', '--format=', leafCommits[0])
    assert.equal(leafShow.status, 0, 'the leaf commit must resolve')
    const leafEntries = leafShow.output.trim().split('\n').filter(Boolean).map((line) => line.split('\t'))
    assert.deepEqual(leafEntries, [['M', 'test/runtime.test.mjs']],
      'the committed leaf change must touch exactly test/runtime.test.mjs and nothing else')
  } else {
    const status = git('status', '--porcelain')
    assert.equal(status.status, 0, 'the working tree status must resolve')
    const trimmedTrailing = status.output.replace(/\n+$/, '')
    const lines = trimmedTrailing === '' ? [] : trimmedTrailing.split('\n')
    assert.equal(lines.length, 1, 'pre-commit the uncommitted delta must be a single path')
    const [xy, pendingPath] = [lines[0].slice(0, 2), lines[0].slice(3)]
    assert.ok(xy.includes('M') && !xy.includes('?') && !xy.includes('D'),
      `pre-commit the delta must be a modification (got "${lines[0]}")`)
    assert.equal(pendingPath, 'test/runtime.test.mjs', 'pre-commit the delta must be exactly test/runtime.test.mjs')
    const pendingDiff = git('diff', 'HEAD', '--', 'test/runtime.test.mjs')
    assert.equal(pendingDiff.status, 0, 'the pending test diff must resolve')
    assert.ok(pendingDiff.output.includes('P2B5C2'), 'the pending change must carry the P2B5C2 marker (this leaf\'s change)')
  }
})

// P2B5C3: compact in-memory git-object rollback-simulation oracle. Read-only
// git plumbing (rev-parse / show / diff / log / status) over the reachable
// baseline 414b40b..HEAD must prove that restoring the exact baseline bytes
// of the two lib mapping files — recovered as git objects and hash-verified
// against their exact baseline blob ids — removes exactly the 301-line purely
// additive delta (172/0 + 129/0, zero removals), that the removed mapping
// references only the three manifest-pinned v0.24 handlers and no v0.16
// vendor path, that the simulated post-revert lib contents are a v0.16-only
// runtime with no v0.24 tree or handler identifier, and that both vendor
// pins remain green at the P2B5C1 anchors. The revert set is exactly the two
// approved lib mapping files and stays disjoint from vendor. The same
// predicate must fail closed with the exact 8-violation closure-absent
// signature when the v0.24 vendor closure is absent from the range (the
// baseline state). The C1/C2 proofs (real verifier, commit disjointness,
// footprint confinement) are not re-proven; their anchors (baseline commit,
// manifest closure file list, pinned vendor digests, fail-closed git helper
// shape) are reused. No actual rollback is performed: no reset, revert,
// checkout, write, push or network access — the simulation is pure in-memory
// state over read-only git objects, the worktree production files stay
// anchored to HEAD, and the pre/post-simulation working tree status is
// byte-identical. Test-only: the only leaf change is this test in
// test/runtime.test.mjs.
test('P2B5C3: the simulated baseline rollback of the two lib mapping files removes exactly the additive v0.24 mapping and leaves both vendor trees and the v0.16 runtime untouched', async () => {
  const packageRoot = path.resolve(import.meta.dirname, '..')
  const manifest = JSON.parse(await readFile(path.join(packageRoot, 'VENDORED_MANIFEST.json'), 'utf8'))
  const closure = manifest.v0240
  assert.ok(closure && Array.isArray(closure.files),
    'VENDORED_MANIFEST.json must carry the v0240 closure section with per-file entries (anchor reused from P2B5C1)')
  assert.equal(closure.fileCount, 16, 'the v0240 section must record exactly 16 files')

  // Reachable baseline anchor (same as P2B5C1/P2B5C2) and the P2B5C1 vendor-pin
  // anchors (reused, not re-proven): the exact pinned provenance of both
  // trees.
  const BASELINE_COMMIT = '414b40b4c63a880ddd80c2a8c872ba3bd8002eaa'
  const V016_FILE_COUNT = 73
  const V016_DIGEST = 'f62109b120c0bc677d47ce4ce8e23278a30bacd7bc3555c1f4877d09cefd58a2'
  const V0240_FILE_COUNT = 16
  const V0240_DIGEST = '2eb277886ab2abcb5cd0513da16bd72fa88f4d85a220e83d6665785830da0444'

  // Exact blob-object anchors of the two mapping paths at the baseline and at
  // HEAD (git object ids recovered from the reachable history at
  // implementation time).
  const BASE_BLOB = new Map([
    ['lib/capability-manifest.mjs', 'f673e98acc9f64a37139f9bc1ecaa9da1ff48d68'],
    ['lib/runtime.mjs', 'f4b44082c391aad87405a67c6d00bfa105fefaa5'],
  ])
  const HEAD_BLOB = new Map([
    ['lib/capability-manifest.mjs', '3826e360893d2d938999a85555bf573a2b007254'],
    ['lib/runtime.mjs', '0fdce702fc70ffb70cde9aaed3c83ad96e8ae473'],
  ])

  // The exact revert set and the exact purely additive per-file delta.
  const REVERT_SET = ['lib/capability-manifest.mjs', 'lib/runtime.mjs']
  const LIB_DELTA = new Map([
    ['lib/capability-manifest.mjs', { added: 172, deleted: 0 }],
    ['lib/runtime.mjs', { added: 129, deleted: 0 }],
  ])
  const TOTAL_ADDED = 301

  // The three manifest-pinned v0.24 handlers (source-derived from the v0240
  // section, cross-checked against the exact pinned paths).
  const PINNED_HANDLERS = closure.files
    .filter((entry) => entry.vendorPath.includes('/services/bi-agent/src/') && entry.vendorPath.endsWith('-handler-v1.mjs'))
    .map((entry) => entry.vendorPath)
  assert.equal(PINNED_HANDLERS.length, 3, 'the manifest v0240 section must pin exactly three bi-agent handlers')
  const PINNED_HANDLER_SET = new Set(PINNED_HANDLERS)
  assert.deepEqual([...PINNED_HANDLERS].sort(), [
    'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/database-overview-handler-v1.mjs',
    'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-details-handler-v1.mjs',
    'vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-search-handler-v1.mjs',
  ], 'the three pinned v0.24 handlers must be exactly the Search, Details and Overview handler paths')

  // The v0.24 tree and handler identifiers that a v0.16-only post-revert
  // runtime must not carry.
  const V024_IDENTIFIERS = [
    'kaleidosphere-v0.24.0',
    'handleObjectSearchV1',
    'handleObjectDetailsV1',
    'handleDatabaseOverviewRequestV1',
    'e092bb0bce039936b88329793b24e9f987ae0ddb',
    'V0240',
    'PROJECTED_READ_ONLY',
    'read-only-evidence-projection',
  ]

  // Read-only git plumbing only; fail closed (never skip) if the git binary
  // or a ref is unavailable, and structurally deny any non-read-only
  // subcommand so the simulation can never issue a git write.
  const READ_ONLY_GIT_SUBCOMMANDS = new Set(['rev-parse', 'show', 'diff', 'log', 'status'])
  function git(...args) {
    if (!READ_ONLY_GIT_SUBCOMMANDS.has(args[0])) throw new Error(`P2B5C3 git helper is read-only; subcommand ${args[0]} is not allowed`)
    try {
      return { status: 0, output: execFileSync('git', args, { encoding: 'utf8', cwd: packageRoot }) }
    } catch (error) {
      return { status: typeof error.status === 'number' ? error.status : 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}${error.code ?? ''}` }
    }
  }

  // Raw read-only `git show` for byte-exact git-object recovery.
  function gitShowBuffer(objectish) {
    return execFileSync('git', ['show', objectish], { cwd: packageRoot })
  }

  // Git blob-object id of a content buffer (sha1 of "blob <len>\0" + bytes).
  function blobId(content) {
    return createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${content.length}\0`), content])).digest('hex')
  }

  // Same aggregate algorithm as P2B5C1 (sha256 over lexicographic relative
  // paths, path NUL content NUL).
  async function walk(directory) {
    const result = []
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const item = path.join(directory, entry.name)
      if (entry.isDirectory()) result.push(...await walk(item))
      else if (entry.isFile()) result.push(item)
    }
    return result
  }

  async function aggregateTree(rootDir) {
    const digest = createHash('sha256')
    const paths = (await walk(rootDir)).sort()
    for (const item of paths) {
      digest.update(`${path.relative(rootDir, item)}\0`)
      digest.update(await readFile(item))
      digest.update('\0')
    }
    return { count: paths.length, digest: digest.digest('hex') }
  }

  // In-memory git-object revert simulation over the range base..head: recover
  // the exact baseline bytes of the two approved lib paths as git objects
  // (hash-verified against their exact blob ids), anchor the head bytes, and
  // compute the additive delta the simulated rollback would remove. Pure
  // in-memory state; no git, worktree or external write is performed.
  function simulateRollbackRange(base, head) {
    const wholeNameStatus = git('diff', '--name-status', '--no-renames', `${base}..${head}`)
    assert.equal(wholeNameStatus.status, 0, `range ${base}..${head} whole-tree name-status must resolve`)
    const vendorRangePaths = new Set()
    for (const line of (wholeNameStatus.output.trim() ? wholeNameStatus.output.trim().split('\n') : [])) {
      const fields = line.split('\t')
      assert.equal(fields.length, 2, `whole-tree name-status line must be STATUS<TAB>PATH, got: ${line}`)
      if (fields[1].startsWith('vendor/')) vendorRangePaths.add(fields[1])
    }

    const libNameStatus = git('diff', '--name-status', '--no-renames', `${base}..${head}`, '--', 'lib/')
    assert.equal(libNameStatus.status, 0, `range ${base}..${head} lib name-status must resolve`)
    const statuses = new Map()
    for (const line of (libNameStatus.output.trim() ? libNameStatus.output.trim().split('\n') : [])) {
      const fields = line.split('\t')
      assert.equal(fields.length, 2, `lib name-status line must be STATUS<TAB>PATH, got: ${line}`)
      assert.ok(!statuses.has(fields[1]), `lib name-status path ${fields[1]} must not be duplicated`)
      statuses.set(fields[1], fields[0])
    }

    const numstat = git('diff', '--numstat', '--no-renames', `${base}..${head}`, '--', 'lib/')
    assert.equal(numstat.status, 0, `range ${base}..${head} lib numstat must resolve`)
    const libNumstat = new Map()
    for (const line of (numstat.output.trim() ? numstat.output.trim().split('\n') : [])) {
      const [added, deleted, target] = line.split('\t')
      assert.ok(!Number.isNaN(Number(added)) && !Number.isNaN(Number(deleted)), `lib numstat line must be numeric (not binary), got: ${line}`)
      libNumstat.set(target, { added: Number(added), deleted: Number(deleted) })
    }

    const unified = git('diff', `${base}..${head}`, '--', 'lib/')
    assert.equal(unified.status, 0, `range ${base}..${head} lib unified diff must resolve`)
    let addedLines = 0
    let removedLines = 0
    const addedLineTexts = []
    for (const line of unified.output.split('\n')) {
      if (line.startsWith('+++') || line.startsWith('---')) continue
      if (line.startsWith('+')) { addedLines += 1; addedLineTexts.push(line.slice(1)) }
      else if (line.startsWith('-')) removedLines += 1
    }

    const blobs = new Map()
    for (const target of REVERT_SET) {
      const baseBlob = git('rev-parse', `${base}:${target}`)
      assert.equal(baseBlob.status, 0, `baseline blob ${base}:${target} must resolve`)
      const headBlob = git('rev-parse', `${head}:${target}`)
      assert.equal(headBlob.status, 0, `head blob ${head}:${target} must resolve`)
      const baseBytes = gitShowBuffer(`${base}:${target}`)
      const headBytes = gitShowBuffer(`${head}:${target}`)
      blobs.set(target, {
        baseBlobId: baseBlob.output.trim(),
        headBlobId: headBlob.output.trim(),
        baseOk: blobId(baseBytes) === baseBlob.output.trim(),
        headOk: blobId(headBytes) === headBlob.output.trim(),
        baseBytes,
        headBytes,
      })
    }

    return { vendorRangePaths, statuses, libNumstat, addedLines, removedLines, addedLineTexts, blobs }
  }

  // The rollback-simulation predicate: exact two-path revert set disjoint from
  // vendor, byte-exact restoration with the exact purely additive 301/0
  // delta, removed mapping confined to the three pinned v0.24 handlers, and a
  // v0.16-only post-revert runtime. Returns the violation list (empty =
  // proven).
  function rollbackViolations(sim) {
    const violations = []
    // P2B5C3-SET: exact two-path revert set, disjoint from vendor.
    for (const [target, status] of sim.statuses) {
      if (target.startsWith('vendor/')) violations.push(`revert path ${target} must not be a vendor path`)
      else if (!REVERT_SET.includes(target)) violations.push(`out-of-set revert path ${target}`)
      else if (status !== 'M') violations.push(`revert path ${target} must be a modification, got ${status}`)
    }
    for (const target of REVERT_SET) {
      if (!sim.statuses.has(target)) violations.push(`missing revert path ${target}`)
    }
    for (const target of sim.vendorRangePaths) {
      if (REVERT_SET.includes(target)) violations.push(`vendor path ${target} must stay out of the revert set`)
    }
    // P2B5C3-BYTES: byte-exact restoration, exact 172/0 + 129/0 = 301/0 delta.
    for (const [target, expected] of LIB_DELTA) {
      const actual = sim.libNumstat.get(target)
      if (!actual) violations.push(`missing lib numstat for ${target}`)
      else if (actual.added !== expected.added || actual.deleted !== 0) violations.push(`lib ${target} delta ${actual.added}/${actual.deleted} is not the exact purely additive ${expected.added}/0`)
    }
    for (const target of sim.libNumstat.keys()) {
      if (!LIB_DELTA.has(target)) violations.push(`unexpected lib path ${target} in the delta`)
    }
    if (sim.addedLines !== TOTAL_ADDED || sim.removedLines !== 0) violations.push(`whole-lib delta ${sim.addedLines}/${sim.removedLines} is not the exact 301/0 additive delta`)
    for (const target of REVERT_SET) {
      const blob = sim.blobs.get(target)
      if (!blob) violations.push(`missing baseline bytes for ${target}`)
      else if (!blob.baseOk) violations.push(`restored baseline bytes for ${target} do not hash to the exact baseline blob`)
      else if (!blob.headOk) violations.push(`head bytes for ${target} do not hash to the exact head blob`)
    }
    // P2B5C3-V016: the removed mapping references exactly the three pinned
    // v0.24 handlers and no v0.16 vendor path.
    const removedRefs = new Set()
    for (const line of sim.addedLineTexts) {
      for (const match of line.matchAll(/vendor\/[A-Za-z0-9._/-]+\.mjs/g)) removedRefs.add(match[0])
    }
    for (const handler of PINNED_HANDLERS) {
      if (!removedRefs.has(handler)) violations.push(`missing removed v0.24 handler reference ${handler}`)
    }
    for (const ref of removedRefs) {
      if (!PINNED_HANDLER_SET.has(ref)) violations.push(`removed mapping references a vendor path outside the three pinned v0.24 handlers: ${ref}`)
      if (ref.startsWith(`${manifest.root}/`)) violations.push(`removed mapping references a v0.16 vendor path: ${ref}`)
    }
    // P2B5C3-V016: the simulated post-revert lib contents are a v0.16-only
    // runtime with no v0.24 tree or handler identifier.
    for (const target of REVERT_SET) {
      const blob = sim.blobs.get(target)
      if (!blob) continue
      const text = blob.baseBytes.toString('utf8')
      for (const identifier of V024_IDENTIFIERS) {
        if (text.includes(identifier)) violations.push(`post-revert ${target} still carries the v0.24 identifier ${identifier}`)
      }
    }
    return violations
  }

  // -- NO-MUTATION (before): the working tree state at the start of the
  // -- simulation; the simulation must leave it byte-identical.
  const statusBefore = git('status', '--porcelain')
  assert.equal(statusBefore.status, 0, 'the pre-simulation working tree status must resolve')

  // -- ANCHORS: the baseline is reachable and HEAD resolves (fail closed).
  const rev = git('rev-parse', '--verify', `${BASELINE_COMMIT}^{commit}`)
  assert.equal(rev.status, 0,
    `baseline ${BASELINE_COMMIT} must be a reachable commit (git unavailable or ref missing — failing closed)`)
  assert.equal(rev.output.trim(), BASELINE_COMMIT)
  const head = git('rev-parse', 'HEAD')
  assert.equal(head.status, 0, 'HEAD must resolve to a commit (not a git checkout — failing closed)')

  // -- P2B5C3-SET + BYTES + V016: the rollback simulation over the real
  // -- BASELINE..HEAD range proves every contract clause with no violations,
  // -- every recovered git object hashes to the exact pinned blob id, and the
  // -- worktree production files are anchored to HEAD.
  const sim = simulateRollbackRange(BASELINE_COMMIT, 'HEAD')
  assert.deepEqual(rollbackViolations(sim), [],
    'the rollback simulation must prove the exact two-path revert set, the byte-exact 301/0 additive delta, the three-handler-only removed mapping and the v0.16-only post-revert contents with no violations')
  assert.deepEqual([...sim.statuses.entries()].sort(),
    [['lib/capability-manifest.mjs', 'M'], ['lib/runtime.mjs', 'M']],
    'the revert set must be exactly the two approved lib mapping files')
  assert.equal(REVERT_SET.filter((target) => target.startsWith('vendor/')).length, 0,
    'the revert set must be disjoint from vendor')
  assert.equal(sim.vendorRangePaths.size, V0240_FILE_COUNT,
    'the range vendor paths must be exactly the 16 pinned additions, all outside the revert set')
  assert.equal(sim.addedLines, TOTAL_ADDED, 'restoring the baseline must remove exactly the 301-line additive delta')
  assert.equal(sim.removedLines, 0, 'the additive delta must carry zero removals')
  for (const [target, expected] of LIB_DELTA) {
    assert.deepEqual(sim.libNumstat.get(target), expected,
      `the lib delta for ${target} must be exactly the purely additive ${expected.added}/0`)
  }
  for (const target of REVERT_SET) {
    const blob = sim.blobs.get(target)
    assert.ok(blob, `the simulation must recover the baseline and head git objects for ${target}`)
    assert.equal(blob.baseBlobId, BASE_BLOB.get(target), `the baseline blob for ${target} must be the exact pinned baseline git object`)
    assert.equal(blob.headBlobId, HEAD_BLOB.get(target), `the head blob for ${target} must be the exact pinned head git object`)
    assert.ok(blob.baseOk, `the recovered baseline bytes for ${target} must hash to the exact baseline blob (byte-exact restoration)`)
    assert.ok(blob.headOk, `the recovered head bytes for ${target} must hash to the exact head blob (byte-exact current state)`)
    const worktree = await readFile(path.join(packageRoot, target))
    assert.equal(Buffer.compare(worktree, blob.headBytes), 0,
      `the worktree production file ${target} must be anchored to HEAD (byte-identical to the head git object)`)
  }

  // -- P2B5C3-V016: both vendor pins remain green at the P2B5C1 anchors — the
  // -- simulation touches only in-memory lib bytes, so the on-disk
  // -- (HEAD-anchored) trees are the post-revert truth.
  const v016Tree = await aggregateTree(path.join(packageRoot, manifest.root))
  assert.equal(v016Tree.count, V016_FILE_COUNT, 'the v0.16.0 tree must remain exactly the 73 pinned files after the simulated rollback')
  assert.equal(v016Tree.digest, V016_DIGEST, 'the v0.16.0 tree must remain byte-identical to the pinned digest after the simulated rollback')
  const v024Tree = await aggregateTree(path.join(packageRoot, closure.root))
  assert.equal(v024Tree.count, V0240_FILE_COUNT, 'the v0.24.0 tree must remain exactly the 16 pinned files after the simulated rollback')
  assert.equal(v024Tree.digest, V0240_DIGEST, 'the v0.24.0 tree must remain byte-identical to the pinned digest after the simulated rollback')

  // -- P2B5C3-RED CONTROL: with the v0.24 vendor closure absent from the
  // -- range (the baseline state, BASELINE..BASELINE), the same predicate
  // -- must fail closed with the exact closure-absent signature: both lib
  // -- mapping files missing from the revert set and the delta, no 301/0
  // -- delta to remove, and all three pinned v0.24 handler references absent
  // -- from the removed mapping (8 violations).
  const absent = simulateRollbackRange(BASELINE_COMMIT, BASELINE_COMMIT)
  const absentViolations = rollbackViolations(absent)
  assert.ok(absentViolations.length > 0, 'the rollback simulation must fail closed when the v0.24 vendor closure is absent from the range')
  assert.equal(absentViolations.length, 8, 'the closure-absent signature must carry exactly 8 violations')
  assert.equal(absentViolations.filter((v) => v.startsWith('missing revert path ')).length, 2,
    'the closure-absent signature must report both lib mapping files missing from the revert set')
  assert.equal(absentViolations.filter((v) => v.startsWith('missing lib numstat ')).length, 2,
    'the closure-absent signature must report both lib mapping files missing from the delta')
  assert.equal(absentViolations.filter((v) => v.startsWith('missing removed v0.24 handler reference ')).length, 3,
    'the closure-absent signature must report all three pinned v0.24 handler references missing from the removed mapping')
  assert.ok(absentViolations.includes(`whole-lib delta ${absent.addedLines}/${absent.removedLines} is not the exact 301/0 additive delta`),
    'the closure-absent signature must report the empty delta as not the exact 301/0 additive delta')

  // -- P2B5C3-NO-MUTATION (after): the simulation (every git call above plus
  // -- the read-only tree walks) must leave the worktree and index
  // -- byte-identical; no git, worktree or external write was performed.
  const statusAfter = git('status', '--porcelain')
  assert.equal(statusAfter.status, 0, 'the post-simulation working tree status must resolve')
  assert.equal(statusAfter.output, statusBefore.output,
    'the simulated rollback must leave the worktree and index byte-identical (no git or worktree write)')

  // -- P2B5C3-NO-PRODUCTION: this leaf's own change is confined to
  // -- test/runtime.test.mjs. Post-commit runs: the leaf commit, located by
  // -- its subject marker, touches exactly that one path. Pre-commit (this
  // -- leaf's own gate): the uncommitted delta is exactly that one modified
  // -- path carrying the P2B5C3 marker. The committed range facts above are
  // -- the primary proof; uncommitted status is never the sole proof.
  const leafLog = git('log', '--fixed-strings', '--format=%H', '--grep=#65 P2B5C3')
  assert.equal(leafLog.status, 0, 'the leaf commit lookup must resolve')
  const leafCommits = leafLog.output.trim() ? leafLog.output.trim().split('\n') : []
  if (leafCommits.length > 0) {
    const leafShow = git('show', '--name-status', '--format=', leafCommits[0])
    assert.equal(leafShow.status, 0, 'the leaf commit must resolve')
    const leafEntries = leafShow.output.trim().split('\n').filter(Boolean).map((line) => line.split('\t'))
    assert.deepEqual(leafEntries, [['M', 'test/runtime.test.mjs']],
      'the committed leaf change must touch exactly test/runtime.test.mjs and nothing else')
  } else {
    const status = git('status', '--porcelain')
    assert.equal(status.status, 0, 'the working tree status must resolve')
    const trimmedTrailing = status.output.replace(/\n+$/, '')
    const lines = trimmedTrailing === '' ? [] : trimmedTrailing.split('\n')
    assert.equal(lines.length, 1, 'pre-commit the uncommitted delta must be a single path')
    const [xy, pendingPath] = [lines[0].slice(0, 2), lines[0].slice(3)]
    assert.ok(xy.includes('M') && !xy.includes('?') && !xy.includes('D'),
      `pre-commit the delta must be a modification (got "${lines[0]}")`)
    assert.equal(pendingPath, 'test/runtime.test.mjs', 'pre-commit the delta must be exactly test/runtime.test.mjs')
    const pendingDiff = git('diff', 'HEAD', '--', 'test/runtime.test.mjs')
    assert.equal(pendingDiff.status, 0, 'the pending test diff must resolve')
    assert.ok(pendingDiff.output.includes('P2B5C3'), 'the pending change must carry the P2B5C3 marker (this leaf\'s change)')
  }
})
