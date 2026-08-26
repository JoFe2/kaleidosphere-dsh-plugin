import { existsSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { runLocalSurfaceProbe } from './local-surface.mjs'
import { runNegativeMatrix } from './negative-matrix.mjs'

const names = ['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'].map(action => `kaleidosphere_${action}`)
const expectedNames = process.env.KS_PROBE_EXPECTED_TOOL_NAMES?.split(',').filter(Boolean) ?? names
const signal = new AbortController().signal

function writeJson(filename, value) {
  const runId = process.env.KS_PROBE_RUN_ID
  if (typeof runId !== 'string' || runId.length === 0) throw new Error('missing fresh probe run id')
  writeFileSync(filename, `${JSON.stringify({ ...value, runId }, null, 2)}\n`)
}

const FORBIDDEN_MAPPED_EXPOSURE = new Set([
  'search', 'details', 'overview',
  'kaleidosphere_search', 'kaleidosphere_details', 'kaleidosphere_overview',
  'bi.object.search.read', 'bi.object.details.read', 'bi.database.overview.read',
])

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])]))
  }
  return value
}

function schemaCatalog(ctx) {
  const records = ctx.tools.schemas().map(canonicalize)
  const sortedRecords = records.sort((left, right) => {
    const leftKey = `${left.name ?? ''}\u0000${JSON.stringify(left)}`
    const rightKey = `${right.name ?? ''}\u0000${JSON.stringify(right)}`
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0
  })
  const completeHostSchemaNames = sortedRecords.map(item => item.name).sort()
  const completeHostSchemaDigest = `sha256:${createHash('sha256').update(JSON.stringify(sortedRecords)).digest('hex')}`
  for (const record of sortedRecords) {
    assertNoForbiddenExposure(record)
  }
  return { records: sortedRecords, completeHostSchemaNames, completeHostSchemaDigest }
}

export function assertNoForbiddenExposure(value) {
  if (typeof value === 'string') {
    if (FORBIDDEN_MAPPED_EXPOSURE.has(value)) throw new Error(`forbidden mapped exposure: ${value}`)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) assertNoForbiddenExposure(item)
  } else if (value && typeof value === 'object') {
    for (const childValue of Object.values(value)) assertNoForbiddenExposure(childValue)
  }
}

function available(catalog, { allowEmpty = false } = {}) {
  const allSchemaNames = catalog.completeHostSchemaNames
  const schemaNames = allSchemaNames.filter(name => name.startsWith('kaleidosphere_'))
  const expected = [...expectedNames].sort()
  if (!(allowEmpty && schemaNames.length === 0) && (schemaNames.length !== expected.length || schemaNames.some((name, index) => name !== expected[index]))) {
    throw new Error(`host tool surface mismatch: expected ${expected.join(',')} got ${schemaNames.join(',')}`)
  }
  return schemaNames
}

function expectedSurfaceReady(catalog) {
  const observed = catalog.completeHostSchemaNames.filter(name => name.startsWith('kaleidosphere_'))
  const expected = new Set(expectedNames)
  // DSH may apply sibling bundles in either order on slower fresh CI hosts.
  // Retry only while the observed surface is an incomplete subset of the
  // closed expected surface. Unexpected/extra names flow immediately into
  // available() below and fail closed; the outer run-bound file timeout keeps
  // an incomplete surface bounded.
  return observed.length >= expected.size || observed.some(name => !expected.has(name))
}

function parameterizedSchemas(catalog) {
  return catalog.records.filter(item => [
    'kaleidosphere_discovery',
    'kaleidosphere_plan',
    'kaleidosphere_preview',
  ].includes(item.name))
}

async function executeInvalid(ctx) {
  const results = []
  for (const [index, name] of ['kaleidosphere_discovery', 'kaleidosphere_plan', 'kaleidosphere_preview'].entries()) {
    const result = await ctx.tools.execute({ signal, callId: `ks-invalid-${index + 1}`, name, arguments: {} })
    results.push({ name, isError: result.isError, error: result.error ?? null, content: result.content })
  }
  return results
}

async function executeAll(ctx) {
  const calls = [
    ['kaleidosphere_status', {}],
    ['kaleidosphere_analyze', {}],
    ['kaleidosphere_discovery', { command: 'start', sessionId: 'demo-1' }],
    ['kaleidosphere_plan', { objective: 'Review weekly order value' }],
    ['kaleidosphere_preview', { objective: 'Preview weekly order value' }],
    ['kaleidosphere_readback', {}],
  ]
  const results = []
  for (let index = 0; index < calls.length; index += 1) {
    const [name, args] = calls[index]
    const result = await ctx.tools.execute({ signal, callId: `ks-probe-${index + 1}`, name, arguments: args })
    if (result.isError) throw new Error(`${name}: ${result.content.map(block => block.text ?? '').join(' ')}`)
    results.push({ name, value: result.value, content: result.content })
  }
  return results
}

async function executeStatus(ctx) {
  const result = await ctx.tools.execute({ signal, callId: 'ks-probe-status', name: 'kaleidosphere_status', arguments: {} })
  if (result.isError) throw new Error(`kaleidosphere_status: ${result.content.map(block => block.text ?? '').join(' ')}`)
  return [{ name: 'kaleidosphere_status', value: result.value, content: result.content }]
}

export const name = 'kaleidosphere-dsh-probe'
export const inject = ['tools']

// P3C bridges the verified P3A/P3B evidence into the real rc.8 host
// lifecycle. exactly six native host tools are exposed; mapped capabilities
// remain below this host surface and are never exposed as host tool names.

export function apply(ctx) {
  let stopped = false
  let phase = 'boot'
  const generation = (globalThis.__kaleidosphereProbeGeneration ?? 0) + 1
  globalThis.__kaleidosphereProbeGeneration = generation
  const executionBinding = {
    boundary: 'IN_PLUGIN_PROCESS_LOCAL_RUNTIME_NOT_HOST_TOOL',
    processId: process.pid,
    generation,
  }
  const interval = setInterval(async () => {
    if (stopped) return
    stopped = true
    try {
      if (phase === 'boot') {
        const catalog = schemaCatalog(ctx)
        if (!expectedSurfaceReady(catalog)) return
        const tools = available(catalog)
        const hostSchemaNames = [...tools]
        const { completeHostSchemaNames, completeHostSchemaDigest, records: completeHostSchemaRecords } = catalog
        const results = process.env.KS_PROBE_MODE === 'inventory'
          ? []
          : process.env.KS_PROBE_MODE === 'status'
            ? await executeStatus(ctx)
            : await executeAll(ctx)
        if (process.env.KS_PROBE_MODE !== 'inventory' && process.env.KS_PROBE_MODE !== 'status') {
          const localSurface = await runLocalSurfaceProbe({ hostSchemaNames, executionBinding })
          const negativeMatrix = await runNegativeMatrix({ hostSchemaNames, executionBinding })
          writeJson(process.env.KS_PROBE_LOCAL_SURFACE, { ...localSurface, executionBinding, hostSchemaNames, completeHostSchemaNames, completeHostSchemaDigest })
          writeJson(process.env.KS_PROBE_NEGATIVE_MATRIX, { ...negativeMatrix, executionBinding, hostSchemaNames, completeHostSchemaNames, completeHostSchemaDigest })
        }
        writeJson(process.env.KS_PROBE_ACTIVE, {
          state: 'ACTIVE',
          tools,
          hostSchemaNames,
          completeHostSchemaNames,
          completeHostSchemaRecords,
          completeHostSchemaDigest,
          executionBinding,
          schemas: parameterizedSchemas(catalog),
          results,
          invalid: await executeInvalid(ctx),
        })
        if (process.env.KS_PROBE_MODE === 'inventory' || process.env.KS_PROBE_MODE === 'status') {
          process.emit('SIGTERM')
          return
        }
        if (process.env.KS_PROBE_MODE === 'oneshot') {
          process.emit('SIGTERM')
          return
        }
        phase = 'await-unload'
      } else if (phase === 'await-unload') {
        if (!existsSync(process.env.KS_PROBE_UNLOAD_REQUEST)) return
        const catalog = schemaCatalog(ctx)
        const unloadedTools = available(catalog, { allowEmpty: true })
        if (unloadedTools.length !== 0) return
        writeJson(process.env.KS_PROBE_UNLOADED, { state: 'UNLOADED', tools: unloadedTools, hostSchemaNames: unloadedTools, executionBinding })
        phase = 'await-reload'
      } else if (phase === 'await-reload') {
        if (!existsSync(process.env.KS_PROBE_RELOAD_REQUEST)) return
        const catalog = schemaCatalog(ctx)
        if (!expectedSurfaceReady(catalog)) return
        const hostSchemaNames = available(catalog)
        if (hostSchemaNames.length !== names.length) return
        const status = await ctx.tools.execute({ signal, callId: 'ks-probe-reloaded', name: 'kaleidosphere_status', arguments: {} })
        if (status.isError) throw new Error('reloaded status failed')
        writeJson(process.env.KS_PROBE_RELOADED, { state: 'RELOADED', tools: hostSchemaNames, hostSchemaNames, completeHostSchemaNames: catalog.completeHostSchemaNames, completeHostSchemaRecords: catalog.records, completeHostSchemaDigest: catalog.completeHostSchemaDigest, status: status.value, executionBinding })
        process.emit('SIGTERM')
      }
    } catch (error) {
      writeJson(process.env.KS_PROBE_FAILURE, { message: error.message, stack: error.stack })
      process.emit('SIGTERM')
    } finally {
      stopped = false
    }
  }, 25)
  ctx.effect(() => () => {
    clearInterval(interval)
    writeFileSync(process.env.KS_PROBE_DISPOSED, 'disposed\n')
  }, 'kaleidosphere-dsh-probe: lifecycle')
}
