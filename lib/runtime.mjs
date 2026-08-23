import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  capabilityAttestationV2,
  executeExternalIntentV2,
  sha256Digest,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import {
  assertCapabilityAttestationForEvidence,
  buildExternalIntentEvidence,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-intent-evidence-bridge.mjs'
import {
  CLOSED_INTENTS,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/closed-intent-conformance-pack.mjs'
import {
  validateAnalyzeProfile,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-control/src/db-analyzer/core.mjs'
import {
  runAnalyzeProfile,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-control/src/db-analyzer/workflow.mjs'
import {
  selectPlanningPolicy,
} from '../vendor/kaleidosphere-v0.16.0/services/bi-control/src/bi-specialist/planning-policy.mjs'
import {
  buildRegistrationPlan,
  PLAN_SCHEMA,
} from './capability-registration-plan.mjs'
import {
  selectCapabilitySource,
} from './capability-source-selector.mjs'

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const KS_ROOT = path.join(PACKAGE_ROOT, 'vendor', 'kaleidosphere-v0.16.0', 'services', 'bi-control')
const FIXTURE_PROFILE = path.join(KS_ROOT, 'fixtures', 'mssql-profile-v1.json')
const PLUGIN_VERSION = '0.1.0-preview.2'
const PRODUCER_DIGEST = sha256Digest(`kaleidosphere-dsh-plugin@${PLUGIN_VERSION}`)
const EXTERNAL_RESPONSE_LIMIT_BYTES = 2 * 1024 * 1024
const ACTION_INDEX = new Map(CLOSED_INTENTS.map((action, index) => [action, index]))
const TOOL_NAMES = Object.freeze(Object.fromEntries(CLOSED_INTENTS.map((action) => [action, `kaleidosphere_${action}`])))

function fail(code) {
  const error = new Error(code)
  error.code = code
  throw error
}

function exact(value, allowed, required = allowed, code = 'KS_DSH_CONFIG_SURFACE_DENIED') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(code)
  const keys = Object.keys(value)
  if (keys.some(key => !allowed.includes(key)) || required.some(key => !keys.includes(key))) fail(code)
  return value
}

function externalConfig(value) {
  exact(value, ['baseUrl', 'timeoutMs'], ['baseUrl'], 'KS_DSH_EXTERNAL_CONFIG_INVALID')
  if (typeof value.baseUrl !== 'string') fail('KS_DSH_EXTERNAL_BASE_URL_INVALID')
  let url
  try {
    url = new URL(value.baseUrl)
  } catch {
    fail('KS_DSH_EXTERNAL_BASE_URL_INVALID')
  }
  if (url.protocol !== 'http:'
    || !['127.0.0.1', '[::1]'].includes(url.hostname)
    || url.port.length === 0
    || url.username.length > 0
    || url.password.length > 0
    || url.pathname !== '/'
    || url.search.length > 0
    || url.hash.length > 0) {
    fail('KS_DSH_EXTERNAL_BASE_URL_DENIED')
  }
  const timeoutMs = value.timeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300_000) {
    fail('KS_DSH_EXTERNAL_TIMEOUT_INVALID')
  }
  return Object.freeze({ baseUrl: url.origin, timeoutMs })
}

async function externalJson(config, pathname, init = {}, callerSignal) {
  const timeoutSignal = AbortSignal.timeout(config.timeoutMs)
  let response
  let buffer
  try {
    response = await fetch(`${config.baseUrl}${pathname}`, {
      ...init,
      headers: { accept: 'application/json', ...init.headers },
      signal: callerSignal === undefined
        ? timeoutSignal
        : AbortSignal.any([callerSignal, timeoutSignal]),
    })
    const declaredLength = Number(response.headers.get('content-length'))
    if (Number.isFinite(declaredLength) && declaredLength > EXTERNAL_RESPONSE_LIMIT_BYTES) {
      fail('KS_DSH_EXTERNAL_RESPONSE_TOO_LARGE')
    }
    const chunks = []
    let length = 0
    if (response.body !== null) {
      const reader = response.body.getReader()
      while (true) {
        const item = await reader.read()
        if (item.done) break
        length += item.value.byteLength
        if (length > EXTERNAL_RESPONSE_LIMIT_BYTES) {
          await reader.cancel()
          fail('KS_DSH_EXTERNAL_RESPONSE_TOO_LARGE')
        }
        chunks.push(Buffer.from(item.value))
      }
    }
    buffer = Buffer.concat(chunks, length)
  } catch (cause) {
    if (cause?.code?.startsWith?.('KS_DSH_')) throw cause
    if (callerSignal?.aborted) callerSignal.throwIfAborted()
    const code = timeoutSignal.aborted ? 'KS_DSH_EXTERNAL_TIMEOUT' : 'KS_DSH_EXTERNAL_UNAVAILABLE'
    const error = new Error(code, { cause })
    error.code = code
    throw error
  }
  if (!response.ok) fail(`KS_DSH_EXTERNAL_HTTP_${response.status}`)
  if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')) {
    fail('KS_DSH_EXTERNAL_CONTENT_TYPE_INVALID')
  }
  try {
    const value = JSON.parse(buffer.toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('KS_DSH_EXTERNAL_RESPONSE_INVALID')
    return value
  } catch (error) {
    if (error?.code === 'KS_DSH_EXTERNAL_RESPONSE_INVALID') throw error
    fail('KS_DSH_EXTERNAL_RESPONSE_INVALID')
  }
}

function resolveConfig(value) {
  exact(value, ['source', 'expose', 'runtimeMode', 'external', 'capability'], [], 'KS_DSH_CONFIG_INVALID')
  const expose = value.expose ?? {}
  exact(expose, CLOSED_INTENTS, [], 'KS_DSH_EXPOSURE_CONFIG_INVALID')
  for (const [action, enabled] of Object.entries(expose)) {
    if (typeof enabled !== 'boolean') fail(`KS_DSH_EXPOSURE_BOOLEAN_REQUIRED_${action.toUpperCase()}`)
  }
  const exposedIntents = Object.freeze(CLOSED_INTENTS.filter(action => expose[action] !== false))
  if (exposedIntents.length === 0) fail('KS_DSH_EXPOSURE_EMPTY')
  const capability = value.capability ?? undefined
  if (capability !== undefined) exact(capability, ['mode', 'supplied'], [], 'KS_DSH_SOURCE_SURFACE_INVALID')
  const capabilityDecision = selectCapabilitySource({
    mode: capability?.mode ?? 'EMBEDDED',
    supplied: capability?.supplied ?? null,
  })
  const registrationPlan = buildRegistrationPlan(capabilityDecision.projection)
  const runtimeMode = value.runtimeMode ?? 'embedded'
  if (!['embedded', 'external'].includes(runtimeMode)) fail('KS_DSH_RUNTIME_MODE_INVALID')
  if (runtimeMode === 'external') {
    if (value.source !== undefined) fail('KS_DSH_EXTERNAL_SOURCE_DENIED')
    if (value.external === undefined) fail('KS_DSH_EXTERNAL_CONFIG_REQUIRED')
    return Object.freeze({ runtimeMode, external: externalConfig(value.external), exposedIntents, capabilityDecision, registrationPlan })
  }
  if (value.external !== undefined) fail('KS_DSH_EMBEDDED_EXTERNAL_CONFIG_DENIED')
  const source = value.source ?? { mode: 'fixture' }
  exact(source, ['mode', 'profile'], ['mode'], 'KS_DSH_SOURCE_CONFIG_INVALID')
  if (source.mode === 'fixture') {
    if (source.profile !== undefined) fail('KS_DSH_FIXTURE_PROFILE_DENIED')
    return Object.freeze({ runtimeMode, mode: 'fixture', engine: 'mssql', profile: null, exposedIntents, capabilityDecision, registrationPlan })
  }
  if (source.mode !== 'live') fail('KS_DSH_SOURCE_MODE_INVALID')
  if (source.profile === undefined) fail('KS_DSH_LIVE_PROFILE_REQUIRED')
  const profile = validateAnalyzeProfile(structuredClone(source.profile))
  if (profile.mode !== 'RUNTIME' || !['mssql', 'oracle'].includes(profile.engine)) fail('KS_DSH_LIVE_ENGINE_UNSUPPORTED')
  if (profile.adapter.kind !== profile.engine) fail('KS_DSH_LIVE_ADAPTER_MISMATCH')
  const passwordEnv = profile.adapter.passwordEnv
  if (typeof passwordEnv !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(passwordEnv)) fail('KS_DSH_PASSWORD_ENV_INVALID')
  if (!process.env[passwordEnv]) fail(`KS_DSH_PASSWORD_ENV_MISSING_${passwordEnv}`)
  return Object.freeze({ runtimeMode, mode: 'live', engine: profile.engine, profile, exposedIntents, capabilityDecision, registrationPlan })
}

function requestId(action, input) {
  return `ks-${action}-${sha256Digest({ action, input: input ?? null }).slice(7, 31)}`
}

function fixtureTimes(action) {
  const index = ACTION_INDEX.get(action)
  if (index === undefined) fail('KS_DSH_ACTION_INVALID')
  const second = index * 3
  const iso = offset => `2026-08-20T00:00:${String(second + offset).padStart(2, '0')}.000Z`
  return { startedAt: iso(0), finishedAt: iso(1), occurredAt: iso(2) }
}

function liveTimes() {
  const occurred = Date.now()
  return {
    startedAt: new Date(occurred - 2).toISOString(),
    finishedAt: new Date(occurred - 1).toISOString(),
    occurredAt: new Date(occurred).toISOString(),
  }
}

function countRows(analysis, category) {
  return analysis.extracts.filter(item => item.category === category).reduce((sum, item) => sum + item.rows.length, 0)
}

function relationNames(analysis) {
  return analysis.extracts
    .filter(item => item.category === 'relations')
    .flatMap(item => item.rows)
    .map(row => `${row.schema_name}.${row.relation_name}`)
    .sort()
    .slice(0, 12)
}

function publicEvidence(evidence) {
  return {
    bridgeSchemaVersion: evidence.event.payload.bridgeSchemaVersion,
    evidenceDigest: evidence.evidenceDigest,
    eventId: evidence.event.eventId,
    receiptId: evidence.receipt.executionId,
    capabilityId: evidence.receipt.capabilityId,
    status: evidence.receipt.status,
    resultIntegrityDigest: evidence.event.payload.resultIntegrityDigest,
  }
}

/**
 * In-process KaleidoSphere runtime owned by one DSH Loader fiber.
 *
 * Runtime creation selects the closed capability evidence source (the
 * explicit pinned embedded projection by default, or a supplied and
 * validated external capability manifest) and builds the closed six-tool
 * registration plan before any tool definition is exposed. Invalid or
 * missing external evidence denies fail closed; there is no embedded
 * fallback for a selected EXTERNAL source.
 */
export class KaleidoSphereRuntime {
  #config
  #tempDirectory
  #profileFile
  #latest = null
  #discovery = new Map()
  #disposed = false
  #analysisRunning = false
  #externalAttestation = null

  static async create(config = {}) {
    const resolved = resolveConfig(config)
    if (resolved.runtimeMode === 'external') {
      const attestation = assertCapabilityAttestationForEvidence(
        await externalJson(resolved.external, '/v2/capabilities'),
      )
      return new KaleidoSphereRuntime(resolved, null, null, attestation)
    }
    const directory = await mkdtemp(path.join(tmpdir(), 'kaleidosphere-dsh-'))
    let profileFile = FIXTURE_PROFILE
    if (resolved.mode === 'live') {
      profileFile = path.join(directory, 'live-profile.json')
      await writeFile(profileFile, `${JSON.stringify(resolved.profile, null, 2)}\n`, { mode: 0o600 })
    }
    return new KaleidoSphereRuntime(resolved, directory, profileFile, null)
  }

  constructor(config, tempDirectory, profileFile, externalAttestation) {
    this.#config = config
    this.#tempDirectory = tempDirectory
    this.#profileFile = profileFile
    this.#externalAttestation = externalAttestation
  }

  get exposedIntents() {
    return this.#config.exposedIntents
  }

  get capabilityDecision() {
    return this.#config.capabilityDecision
  }

  get registrationPlan() {
    return this.#config.registrationPlan
  }

  async dispose() {
    if (this.#disposed) return
    this.#disposed = true
    this.#latest = null
    this.#discovery.clear()
    if (this.#tempDirectory !== null) await rm(this.#tempDirectory, { recursive: true, force: true })
  }

  async execute(action, input = {}, signal) {
    if (this.#disposed) fail('KS_DSH_RUNTIME_DISPOSED')
    signal?.throwIfAborted()
    if (!CLOSED_INTENTS.includes(action)) fail('KS_DSH_ACTION_INVALID')
    const id = requestId(action, input)
    const request = {
      schemaVersion: 'superset-bi-agent.external/intent-request/v2',
      requestId: id,
      action,
      ...Object.keys(input).length === 0 ? {} : { input },
    }
    const response = this.#config.runtimeMode === 'external'
      ? await externalJson(this.#config.external, '/v2/intents', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(request),
        }, signal)
      : await executeExternalIntentV2(request, this.#handlers())
    signal?.throwIfAborted()
    const times = this.#config.runtimeMode === 'embedded' && this.#config.mode === 'fixture'
      ? fixtureTimes(action)
      : liveTimes()
    const evidence = buildExternalIntentEvidence({
      request,
      response,
      attestation: this.#externalAttestation ?? capabilityAttestationV2(),
      terminal: { status: 'succeeded', code: 'RESULT_VERIFIED' },
      context: {
        eventId: `ks-event-${action}-${id.slice(-12)}`,
        streamId: 'kaleidosphere-dsh-plugin',
        correlationId: id,
        seq: (ACTION_INDEX.get(action) ?? 0) + 1,
        occurredAt: times.occurredAt,
        producerArtifactDigest: PRODUCER_DIGEST,
        startedAt: times.startedAt,
        finishedAt: times.finishedAt,
        idempotencyKey: id,
      },
    })
    return Object.freeze({ response, evidence: publicEvidence(evidence) })
  }

  #handlers() {
    return {
      status: () => this.#status(),
      discovery: input => this.#discover(input),
      analyze: () => this.#analyze(),
      plan: input => this.#plan(input),
      preview: input => this.#preview(input),
      readback: () => this.#readback(),
    }
  }

  #status() {
    return {
      status: 'READY',
      engine: this.#config.engine,
      sourceMode: this.#config.mode,
      catalogReady: this.#latest !== null,
      latestReceiptId: this.#latest?.receiptId ?? null,
      pluginVersion: PLUGIN_VERSION,
      compatibility: 'deepseek-harness/dsh-v0.1.0-rc.8',
    }
  }

  async #analyze() {
    if (this.#analysisRunning) fail('KS_DSH_ANALYSIS_IN_PROGRESS')
    this.#analysisRunning = true
    try {
      const options = { repositoryRoot: KS_ROOT }
      if (this.#config.mode === 'live' && this.#config.engine === 'oracle') {
        options.oracleDriver = (await import('../third_party/oracledb-7.0.1/index.js')).default
      }
      const analysis = await runAnalyzeProfile(this.#profileFile, options)
      const receiptId = `${analysis.engine}-${analysis.snapshotSha256.slice(0, 24)}`
      const projectionDigest = sha256Digest({
        engine: analysis.engine,
        snapshotSha256: analysis.snapshotSha256,
        coverageLedger: analysis.coverageLedger,
      })
      this.#latest = Object.freeze({
        receiptId,
        status: 'ANALYZED_READ_ONLY',
        sourceMode: this.#config.mode,
        engine: analysis.engine,
        scope: analysis.profile.scope,
        safety: {
          sourceReadOnly: true,
          queryPackSelectOnly: true,
          rawRowsReturned: false,
        },
        analysis,
        projection: { sha256: projectionDigest },
      })
      return this.#latest
    } finally {
      this.#analysisRunning = false
    }
  }

  #requireLatest() {
    if (this.#latest === null) fail('KS_DSH_ANALYSIS_REQUIRED')
    return this.#latest
  }

  #discover(input) {
    const latest = this.#requireLatest()
    const current = this.#discovery.get(input.sessionId)
    if (input.command === 'start') {
      if (current !== undefined) fail('KS_DSH_DISCOVERY_SESSION_EXISTS')
      const state = {
        schemaVersion: 'kaleidosphere.dsh/discovery-session/v1',
        sessionId: input.sessionId,
        revision: 1,
        status: 'IN_PROGRESS',
        receiptId: latest.receiptId,
        scope: latest.scope,
        suggestedRelations: relationNames(latest.analysis),
        answers: {},
      }
      this.#discovery.set(input.sessionId, state)
      return structuredClone(state)
    }
    if (current === undefined) fail('KS_DSH_DISCOVERY_SESSION_NOT_FOUND')
    if (input.command === 'answer' || input.command === 'revise') {
      current.answers[input.field] = structuredClone(input.value)
      current.revision += 1
      current.status = 'IN_PROGRESS'
    } else if (input.command === 'confirm') {
      current.revision += 1
      current.status = 'CONFIRMED'
    }
    if (input.command === 'export') {
      return {
        schemaVersion: 'kaleidosphere.dsh/discovery-brief/v1',
        sessionId: current.sessionId,
        receiptId: current.receiptId,
        status: current.status,
        scope: current.scope,
        suggestedRelations: current.suggestedRelations,
        answers: structuredClone(current.answers),
      }
    }
    return structuredClone(current)
  }

  #plan(input) {
    const latest = this.#requireLatest()
    if (input.receiptId !== undefined && input.receiptId !== latest.receiptId) fail('KS_DSH_PLAN_RECEIPT_MISMATCH')
    const selected = selectPlanningPolicy(input.objective)
    // K1 deliberately rejects token-bearing/internal runtime knobs from public
    // evidence. Keep the released policy decision while projecting only its
    // public, evidence-safe contract.
    const planning = {
      schemaVersion: selected.schemaVersion,
      taskClass: selected.taskClass,
      sampling: selected.sampling,
      validationDepth: selected.validationDepth,
      toolBudget: selected.toolBudget,
      stepBudget: selected.stepBudget,
      clarification: selected.clarification,
      escalation: selected.escalation,
      fallback: selected.fallback,
      reconciliation: selected.reconciliation,
      persistentActionAllowed: selected.persistentActionAllowed,
    }
    return {
      schemaVersion: 'superset-bi-agent.external/plan/v2',
      planId: `plan-${sha256Digest({ receiptId: latest.receiptId, objective: input.objective }).slice(7, 31)}`,
      objective: input.objective,
      evidenceBinding: { receiptId: latest.receiptId, snapshotSha256: latest.analysis.snapshotSha256 },
      graph: { acceptedIncumbent: 'adaptive-v1', candidatePromotion: 'none' },
      planning,
      authority: { proposalOnly: true, persistentActionAllowed: false, modelMutationAuthority: false },
    }
  }

  #preview(input) {
    const plan = this.#plan(input)
    const latest = this.#requireLatest()
    return {
      schemaVersion: 'superset-bi-agent.external/preview/v2',
      previewId: `preview-${plan.planId.slice(5)}`,
      planId: plan.planId,
      evidenceBinding: plan.evidenceBinding,
      graph: plan.graph,
      objective: input.objective,
      relations: relationNames(latest.analysis),
      visualizationProposal: {
        kind: 'evidence-table',
        title: input.objective,
        scope: latest.scope.schemas,
      },
      confidence: latest.analysis.coverageLedger.allComplete ? 'FIXTURE_COMPLETE' : 'PARTIAL',
      authority: {
        proposalOnly: true,
        applyPerformed: false,
        rawSourceRowsReturned: false,
        modelMutationAuthority: false,
      },
    }
  }

  #readback() {
    const latest = this.#requireLatest()
    const analysis = latest.analysis
    return {
      receiptId: latest.receiptId,
      summary: {
        source_engine: latest.engine,
        source_mode: latest.sourceMode,
        status: latest.status,
        snapshot_sha256: analysis.snapshotSha256,
        source_read_only: 1,
      },
      catalogSnapshot: {
        receiptId: latest.receiptId,
        snapshotSha256: analysis.snapshotSha256,
        schemas: analysis.profile.scope.schemas,
        collectorCount: analysis.coverageLedger.totalQueries,
        coverageComplete: analysis.coverageLedger.allComplete,
      },
      technicalOverview: {
        schemaRows: countRows(analysis, 'schemas'),
        relationRows: countRows(analysis, 'relations'),
        columnRows: countRows(analysis, 'columns'),
        incompleteCollectors: analysis.coverageLedger.invisibleOrUnknownQueries + analysis.coverageLedger.partialQueries,
      },
      publication: null,
    }
  }
}

const descriptions = Object.freeze({
  status: 'Read KaleidoSphere plugin readiness, configured source mode, engine, and latest receipt identity.',
  discovery: 'Run or continue a guided, receipt-bound KaleidoSphere database discovery session.',
  analyze: 'Analyze the configured database metadata through the configured KaleidoSphere read-only runtime.',
  plan: 'Create an evidence-bound KaleidoSphere analysis plan without persistent mutation authority.',
  preview: 'Create an evidence-bound proposal preview from the latest KaleidoSphere analysis receipt.',
  readback: 'Read back the latest KaleidoSphere receipt, catalog summary, and technical coverage counts.',
})

const parameters = Object.freeze({
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

/**
 * Build the six K2-closed native DSH tool definitions bound to the
 * runtime's closed registration plan. Each exposed tool name, action,
 * capability, and authority is taken from the sealed plan entry; a runtime
 * without a valid closed plan exposes no tools.
 * @param {KaleidoSphereRuntime} runtime Fiber-owned runtime.
 * @returns {object[]} DSH ToolRuntime definitions.
 */
export function createToolDefinitions(runtime) {
  const plan = runtime.registrationPlan
  if (!plan || plan.schemaVersion !== PLAN_SCHEMA || !Array.isArray(plan.tools)
    || plan.tools.length !== CLOSED_INTENTS.length) fail('KS_DSH_REGISTRATION_PLAN_REQUIRED')
  const planned = new Map(plan.tools.map(tool => [tool?.action, tool]))
  return runtime.exposedIntents.map(action => {
    const entry = planned.get(action)
    if (entry === undefined || entry.toolName !== TOOL_NAMES[action]) fail('KS_DSH_REGISTRATION_PLAN_MISMATCH')
    return {
      name: entry.toolName,
      description: descriptions[action],
      parameters: parameters[action],
      timeoutMs: action === 'analyze' ? 180_000 : 30_000,
      capability: Object.freeze({ action, capabilityId: entry.capabilityId, authority: entry.authority }),
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            response: { type: 'object', additionalProperties: true, required: true },
            evidence: { type: 'object', additionalProperties: true, required: true },
          },
        },
        render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
      },
      execute: (args, exec) => runtime.execute(action, args, exec.signal),
      presentCall: args => ({ card: 'generic', title: `KaleidoSphere ${action}`, kind: 'other', rawInput: args }),
    }
  })
}

export { CLOSED_INTENTS, TOOL_NAMES }
