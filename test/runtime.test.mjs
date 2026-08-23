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

const expectedDigests = JSON.parse(await readFile(new URL('./expected-fixture-digests.json', import.meta.url), 'utf8'))

test('fixture executes all six released intents through External API v2 and K1', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const status = await runtime.execute('status')
    assert.equal(status.response.action, 'status')
    assert.equal(status.response.result.status, 'READY')
    assert.equal(status.response.result.pluginVersion, '0.1.0-preview.2')

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
