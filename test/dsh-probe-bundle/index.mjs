import { existsSync, writeFileSync } from 'node:fs'
import { runLocalSurfaceProbe } from './local-surface.mjs'
import { runNegativeMatrix } from './negative-matrix.mjs'

const names = ['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'].map(action => `kaleidosphere_${action}`)
const expectedNames = process.env.KS_PROBE_EXPECTED_TOOL_NAMES?.split(',').filter(Boolean) ?? names
const signal = new AbortController().signal

function writeJson(filename, value) {
  writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`)
}

function available(ctx, { allowEmpty = false } = {}) {
  const allSchemaNames = ctx.tools.schemas().map(item => item.name).sort()
  const schemaNames = allSchemaNames.filter(name => name.startsWith('kaleidosphere_'))
  const expected = [...expectedNames].sort()
  if (!(allowEmpty && schemaNames.length === 0) && (schemaNames.length !== expected.length || schemaNames.some((name, index) => name !== expected[index]))) {
    throw new Error(`host tool surface mismatch: expected ${expected.join(',')} got ${schemaNames.join(',')}`)
  }
  return schemaNames
}

function allSchemaNames(ctx) {
  return ctx.tools.schemas().map(item => item.name).sort()
}

function parameterizedSchemas(ctx) {
  return ctx.tools.schemas().filter(item => [
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
        const tools = available(ctx)
        const hostSchemaNames = [...tools]
        const completeHostSchemaNames = allSchemaNames(ctx)
        const results = process.env.KS_PROBE_MODE === 'inventory'
          ? []
          : process.env.KS_PROBE_MODE === 'status'
            ? await executeStatus(ctx)
            : await executeAll(ctx)
        if (process.env.KS_PROBE_MODE !== 'inventory' && process.env.KS_PROBE_MODE !== 'status') {
          const localSurface = await runLocalSurfaceProbe({ hostSchemaNames, executionBinding })
          const negativeMatrix = await runNegativeMatrix({ hostSchemaNames, executionBinding })
          writeJson(process.env.KS_PROBE_LOCAL_SURFACE, { ...localSurface, executionBinding, hostSchemaNames, completeHostSchemaNames })
          writeJson(process.env.KS_PROBE_NEGATIVE_MATRIX, { ...negativeMatrix, executionBinding, hostSchemaNames, completeHostSchemaNames })
        }
        writeJson(process.env.KS_PROBE_ACTIVE, {
          state: 'ACTIVE',
          tools,
          hostSchemaNames,
          completeHostSchemaNames,
          executionBinding,
          schemas: parameterizedSchemas(ctx),
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
        const unloadedTools = available(ctx, { allowEmpty: true })
        if (unloadedTools.length !== 0) return
        writeJson(process.env.KS_PROBE_UNLOADED, { state: 'UNLOADED', tools: unloadedTools, hostSchemaNames: unloadedTools, executionBinding })
        phase = 'await-reload'
      } else if (phase === 'await-reload') {
        if (!existsSync(process.env.KS_PROBE_RELOAD_REQUEST)) return
        const hostSchemaNames = available(ctx)
        if (hostSchemaNames.length !== names.length) return
        const status = await ctx.tools.execute({ signal, callId: 'ks-probe-reloaded', name: 'kaleidosphere_status', arguments: {} })
        if (status.isError) throw new Error('reloaded status failed')
        writeJson(process.env.KS_PROBE_RELOADED, { state: 'RELOADED', tools: hostSchemaNames, hostSchemaNames, status: status.value, executionBinding })
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
