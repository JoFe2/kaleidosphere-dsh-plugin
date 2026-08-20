import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { createServer } from 'node:http'
import os from 'node:os'
import test from 'node:test'

import { CLOSED_INTENTS, createToolDefinitions, KaleidoSphereRuntime, TOOL_NAMES } from '../lib/runtime.mjs'
import {
  capabilityAttestationV2,
  executeExternalIntentV2,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'

const expectedDigests = JSON.parse(await readFile(new URL('./expected-fixture-digests.json', import.meta.url), 'utf8'))

test('fixture executes all six released intents through External API v2 and K1', async () => {
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const status = await runtime.execute('status')
    assert.equal(status.response.action, 'status')
    assert.equal(status.response.result.status, 'READY')

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
