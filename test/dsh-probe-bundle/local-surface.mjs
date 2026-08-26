// P3A: the probe-bundle local-surface phase.
//
// Deterministic synthetic representative inputs drive the fixture (mssql)
// runtime through the three additive v0.24.0 local actions (search, details,
// overview) and capture sealed, read-only, evidence-bound output for the P3A
// oracle (local-surface.test.mjs):
//   P3A-HAPPY         exactly three sealed read-only v2 result envelopes,
//   P3A-AUTHORITY     no raw rows, secrets, SQL, execution or mutation
//                     authority and every claim/authority flag false,
//   P3A-HOST-SURFACE  the stub-host surface is exactly the six closed-intent
//                     native tools and carries none of the three mapped
//                     capabilities,
//   P3A-CLOSED-ACTIONS representative aliases and unknown actions deny with
//                     KS_DSH_ACTION_INVALID.
//
// Everything is synthetic: the fixture builders below are the verified
// synthetic inputs shared with the root runtime oracle, the vendored handlers
// are the single authority, and no live data, network, environment secrets,
// raw rows or SQL is touched. The fixture builders are exported so the
// seven-negative matrix phase (P3B) can reuse them without duplication; the
// bundle lifecycle shell (P3C) is a separate phase and out of scope here.

import { createToolDefinitions, KaleidoSphereRuntime } from '../../lib/runtime.mjs'
import { capabilityAttestationV2 } from '../../vendor/kaleidosphere-v0.16.0/services/bi-agent/src/external-api-v2.mjs'
import { buildObjectSearchAuthorityBoundResult } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-search-authority-bound-result-v1.mjs'
import { createObjectInventorySnapshot, createObjectSearchCoverageBinding, createObjectSearchEnvelope } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-search-envelope-v1.mjs'
import { buildPreflightEvidence, identitySha256, normalizeJsonValue } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/core.mjs'
import { buildObjectNameAuthority } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-name-authority-v1.mjs'
import { buildObjectRelationKindAuthority } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-relation-kind-authority-v1.mjs'
import { buildObjectInventoryAuthorityDigest } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-inventory-authority-digest-v1.mjs'
import { buildProgressiveCoverage, buildProgressiveMethodRegistry, createProgressiveCoverage, createProgressiveRun, PROGRESSIVE_RECEIPT_SCHEMA, PROGRESSIVE_RUN_SCHEMA } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/progressive-controller.mjs'
import { KS_OBJECT_CAPABILITY_REQUEST_SCHEMA } from '../../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-capability-contract-v1.mjs'
import { KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID } from '../../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-search-handler-v1.mjs'
import { KS_OBJECT_DETAILS_HANDLER_CAPABILITY } from '../../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/object-details-handler-v1.mjs'
import { projectObjectDetails } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/object-details-projection-v1.mjs'
import { DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID } from '../../vendor/kaleidosphere-v0.24.0/services/bi-agent/src/database-overview-handler-v1.mjs'
import { buildDatabaseOverviewProjection } from '../../vendor/kaleidosphere-v0.24.0/services/bi-control/src/db-analyzer/database-overview-projection-v1.mjs'

// The fixture source mode resolves to the mssql engine; the probe phase pins
// that single engine so every claim about the local surface is reproducible.
const ENGINE = 'mssql'

// P3A evidence-boundary pins: frozen work-order contract literals, exported so
// the oracle pins them independently of the phase implementation.
const P3A_LOCAL_ACTIONS = Object.freeze(['search', 'details', 'overview'])
const P3A_INVALID_ACTION = 'KS_DSH_ACTION_INVALID'
const P3A_RESPONSE_KEYS = Object.freeze(['schemaVersion', 'requestId', 'action', 'runtime', 'capabilityAttestationDigest', 'result', 'integrity'])
const P3A_RESULT_KEYS = Object.freeze(['authority', 'bindings', 'capabilityId', 'claims', 'projectionSha256', 'requestSha256', 'schemaVersion', 'state'])
const P3A_OVERVIEW_RESULT_KEYS = Object.freeze(['bytes', 'capabilityId', 'envelope', 'projectionSha256', 'requestSha256', 'resultSha256', 'schemaVersion', 'state'])
const P3A_CLAIMS = Object.freeze({ absenceClaimed: false, completenessClaimed: false, replayPreventionClaimed: false, sourceRowsIncluded: false })
const P3A_AUTHORITY = Object.freeze({ credentialsIncluded: false, dispatchAuthority: false, executionAuthority: false, mutationAuthority: false, queryExecution: false, rawValuesIncluded: false, sqlAuthority: false })
const SEARCH_CAPABILITY_ID = KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID
const P3A_MAPPED_CAPABILITIES = Object.freeze([
  { action: 'search', capabilityId: SEARCH_CAPABILITY_ID },
  { action: 'details', capabilityId: KS_OBJECT_DETAILS_HANDLER_CAPABILITY },
  { action: 'overview', capabilityId: DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID },
])
const P3A_HOST_TOOL_NAMES = Object.freeze([
  'kaleidosphere_analyze',
  'kaleidosphere_discovery',
  'kaleidosphere_plan',
  'kaleidosphere_preview',
  'kaleidosphere_readback',
  'kaleidosphere_status',
])
const P3A_ALIASES = Object.freeze([
  'Search', 'search-v1', 'object-search', 'objectSearch', 'searchObjects', 'db-search',
  'Details', 'details-v1', 'object-details', 'objectDetails', 'db-details',
  'Overview', 'overview-v1', 'database-overview', 'databaseOverview', 'db-overview',
  'sql', 'query', 'execute', 'run', 'raw', 'rows', 'mutation', 'write',
])
const P3A_FORBIDDEN_KEYS = Object.freeze([
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
const P3A_FORBIDDEN_VALUE_PATTERNS = Object.freeze([
  { name: 'url-scheme', pattern: /\b(?:https?|ftp|wss?):\/\//i },
  { name: 'ipv4-endpoint', pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/ },
  { name: 'localhost', pattern: /\blocalhost\b/i },
  { name: 'sql-statement', pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|MERGE|EXECUTE|EXEC|GRANT|REVOKE|CREATE)\b[^a-z0-9]*(?:FROM|INTO|TABLE|SET|WHERE|GRANT|TO)\b/i },
  { name: 'leading-sql-statement', pattern: /^\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|EXEC)\b/i },
  { name: 'credential-word', pattern: /\b(?:passw(?:or)?d|secret|token|bearer|credential|api[-_ ]?key)\b/i },
  { name: 'embedded-forbidden-key', pattern: /"(?:rawRows|raw_rows|rows|rawData|raw_data|password|passwd|secret|token|apiKey|api_key|accessToken|authToken|credential|credentials|dsn|connectionString|sql|statement|query|url|uri|endpoint|baseUrl|host|hostname|port|protocol|callback|webhook|executable|script|command|function)"\s*:/i },
])

// Synthetic representative inputs: the verified fixture builders shared with
// the root runtime oracle, re-issued here so the probe phase is self-contained
// inside test/dsh-probe-bundle/**.

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
    id, category, file, outputColumns, sortKeys: [], scopeColumn: 'schema_name',
    timeoutMs: 1000, cost: 'BOUNDED', readOnly: true,
    privilege: { minimum: 'CONNECT' }, fallback: { onDenied: 'DENIED_IS_NOT_ABSENT' }, provenance,
  })
  return {
    schemaVersion: 'chimpmaera.db/query-manifest/v1',
    packId: `synthetic-${engine}-search-pack`, packVersion: '1.0.0', engine,
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
    schemaVersion: 'chimpmaera.db/runtime-query-results/v1', engine, runtimeValidated: true,
    results: {
      [`${engine}.structure.schemas`]: { state: 'SUCCEEDED', reasonCode: null, rows: [{ schema_name: SYNTHETIC_SCHEMA[engine] }] },
      [`${engine}.structure.relations`]: { state: 'SUCCEEDED', reasonCode: null, rows: SYNTHETIC_RELATIONS[engine] },
    },
  }
  const profileContext = {
    profileId: `synthetic-${engine}-search-profile`, mode: 'RUNTIME',
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
    controllerRun, inventoryAuthorityProjection, relationKindAuthorityProjection,
    objectNameAuthorityProjection, structureEvidence: evidence,
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
      engine, kindCounts: { TABLE: 2, VIEW: 1, COLUMN: 0, INDEX: 0, SEQUENCE: 0, SYNONYM: 0 },
    }),
    coverage: createObjectSearchCoverageBinding({
      stateCounts: { SUCCEEDED: 5, PARTIAL: 1, DENIED: 1, UNSUPPORTED: 0, TIMEOUT: 0, ERROR: 0 },
    }),
  })
}

function syntheticSearchFixture(engine) {
  return { sources: syntheticSearchSources(engine), envelope: searchEnvelopeFor(engine) }
}

// First-page representative search input only: the P3A happy path dispatches a
// single initial search, so the continuation branch is not exercised here.
function validSearchHandlerInput({ engine, sources, envelope }) {
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
  const projectionInput = { ...sources, request: envelope }
  const projection = buildObjectSearchAuthorityBoundResult(projectionInput)
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

const DETAILS_SCOPES = {
  mssql: { database: 'salesdb', container: null, schemas: ['dbo', 'finance'] },
  oracle: { database: 'orcl_sales', container: null, schemas: ['DBO', 'FIN'] },
}
const DETAILS_STATES = {
  COMPLETE: { state: 'COMPLETE', reasonCode: null },
  DENIED: { state: 'DENIED', reasonCode: 'PRIVILEGE_DENIED' },
  PARTIAL: { state: 'PARTIAL', reasonCode: 'PARTIAL_ROW_LIMIT' },
  UNKNOWN: { state: 'UNKNOWN', reasonCode: 'OBJECT_NOT_FOUND' },
}
const DETAILS_VISIBILITY = { COMPLETE: 'VISIBLE', DENIED: 'INVISIBLE', PARTIAL: 'VISIBLE_PARTIAL', UNKNOWN: 'UNKNOWN' }

const detailsScopeSha256 = (engine) => identitySha256(normalizeJsonValue(DETAILS_SCOPES[engine]))
const detailsSnapshotSha256 = (engine) => identitySha256({ kind: 'structure-snapshot', engine })
const detailsPreflightLedgerSha256 = (engine) => identitySha256({ kind: 'preflight-coverage-ledger', engine })
const detailsSourceObjectSha256 = (engine, relationName) => identitySha256({ kind: 'inventory-object', engine, relationName })
const detailsSeal = (body, key) => ({ ...normalizeJsonValue(body), [key]: identitySha256(normalizeJsonValue(body)) })

function detailsLedgerFor(engine, spec, { relationName = 'sales_orders' } = {}) {
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
    entries: [{ objectRef, state: spec.state, reasonCode: spec.reasonCode, sourceQueryId: `${engine}.structure-relations`, evidenceRefs: refs }],
    queryCoverage: [{
      queryId: `${engine}.structure-relations`, category: 'relations', state: queryState,
      reasonCode: spec.state === 'COMPLETE' ? null : spec.reasonCode,
      visibility: spec.state === 'COMPLETE' ? 'VISIBLE_COMPLETE' : DETAILS_VISIBILITY[spec.state], absenceClaim: 'NOT_CLAIMED',
    }],
  })
  return { ledger, entry: ledger.entries[0] }
}

function detailsReceiptFor(engine, { entry, ledger }) {
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
  receipt = detailsReceiptFor(engine, { entry, ledger }),
  objectKey = entry.objectKey,
  scope = DETAILS_SCOPES[engine],
  scopeSha256 = detailsScopeSha256(engine),
  inventorySnapshotSha256 = detailsSnapshotSha256(engine),
  ...extra
} = {}) {
  return { engine, scope, scopeSha256, inventorySnapshotSha256, coverageLedger: ledger, receipt, objectKey, ...extra }
}

// Oversized-evidence and resealed-ledger helpers shared with the root runtime
// oracle's P2B3B negative cases: a raw coverage entry with caller-supplied
// evidence refs and a resealed ledger carrying exactly that entry.
function detailsRawEntry({ engine = ENGINE, relationName = 'sales_orders', schemaName = DETAILS_SCOPES[engine].schemas[0], evidenceRefs } = {}) {
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
  const { coverageSha256: _old, ...body } = structuredClone(ledger)
  body.entries = [entry]
  return detailsSeal(body, 'coverageSha256')
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
  const { ledger, entry } = detailsLedgerFor(engine, spec)
  const receipt = detailsReceiptFor(engine, { entry, ledger })
  const projectionInput = detailsProjectionInputFor(engine, { entry, ledger, receipt })
  const projection = projectObjectDetails(projectionInput)
  const request = {
    schemaVersion: KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
    requestId: `details-${engine}-${spec.state.toLowerCase()}`,
    capabilityId: KS_OBJECT_DETAILS_HANDLER_CAPABILITY,
    bindings: detailsBindingsOf(projection),
    scope: { schemas: [...DETAILS_SCOPES[engine].schemas] },
  }
  return { ledger, entry, receipt, projectionInput, request, projection }
}

const OVERVIEW_SCOPES = {
  mssql: { database: 'Analytics', container: null, schemas: ['dbo'] },
  oracle: { database: 'FREE', container: 'FREEPDB1', schemas: ['BI_DEMO'] },
}
const OVERVIEW_PROBE_PHASE = 'BREADTH_INVENTORY'

const overviewSeal = (body, key) => {
  const normalized = normalizeJsonValue(body)
  return { ...normalized, [key]: identitySha256(normalized) }
}

function syntheticOverviewScenario(engine, { withCancelledReceipt = true } = {}) {
  const scope = structuredClone(OVERVIEW_SCOPES[engine])
  const scopeSha256 = identitySha256(scope)
  const structureSnapshotSha256 = identitySha256({ kind: 'overview-structure-snapshot', engine })
  const structureCoverageLedgerSha256 = identitySha256({ kind: 'overview-structure-coverage-ledger', engine })
  const objectId = (name) => identitySha256({ kind: 'overview-inventory-object', engine, name })
  const objectRef = (kind, { schemaName = null, relationName = null, columnName = null, objectName = null, id }) => ({
    kind, schemaName, relationName, columnName, objectName, sourceObjectSha256: objectId(id),
  })
  const schemaName = scope.schemas[0]
  const entryRefs = (id) => [...new Set([structureSnapshotSha256, structureCoverageLedgerSha256, objectId(id)])].sort()
  const entries = [
    {
      objectRef: objectRef('SCHEMA', { objectName: schemaName, id: `schema-${schemaName}` }),
      state: 'COMPLETE', reasonCode: null, sourceQueryId: `${engine}.structure-schemas`, evidenceRefs: entryRefs(`schema-${schemaName}`),
    },
    {
      objectRef: objectRef('RELATION', { schemaName, relationName: 'sales_orders', id: 'relation-sales_orders' }),
      state: 'COMPLETE', reasonCode: null, sourceQueryId: `${engine}.structure-relations`, evidenceRefs: entryRefs('relation-sales_orders'),
    },
    {
      objectRef: objectRef('COLUMN', { schemaName, relationName: 'sales_orders', columnName: 'order_id', id: 'column-order_id' }),
      state: 'PARTIAL', reasonCode: 'PARTIAL_ROW_LIMIT', sourceQueryId: `${engine}.structure-columns`, evidenceRefs: entryRefs('column-order_id'),
    },
    {
      objectRef: objectRef('INDEX', { schemaName, relationName: 'sales_orders', objectName: 'ix_sales_orders', id: 'index-ix_sales_orders' }),
      state: 'DENIED', reasonCode: 'PRIVILEGE_DENIED', sourceQueryId: `${engine}.structure-indexes`, evidenceRefs: entryRefs('index-ix_sales_orders'),
    },
    {
      objectRef: objectRef('SEQUENCE', { schemaName, objectName: 'seq_sales_orders', id: 'sequence-seq_sales_orders' }),
      state: 'UNKNOWN', reasonCode: 'OBJECT_NOT_FOUND', sourceQueryId: `${engine}.structure-sequences`, evidenceRefs: entryRefs('sequence-seq_sales_orders'),
    },
  ]
  const queryCoverage = [
    { queryId: `${engine}.structure-schemas`, category: 'schemas', state: 'SUCCEEDED', reasonCode: null, visibility: 'VISIBLE_COMPLETE', absenceClaim: 'NOT_CLAIMED' },
    { queryId: `${engine}.structure-columns`, category: 'columns', state: 'SUCCEEDED', reasonCode: null, visibility: 'VISIBLE_COMPLETE', absenceClaim: 'NOT_CLAIMED' },
  ]
  const coverage = createProgressiveCoverage({
    engine, structureSnapshotSha256, structureCoverageLedgerSha256, entries, queryCoverage,
  })
  const runId = `overview-${engine}-run`
  const probeCount = withCancelledReceipt ? 2 : 1
  const probes = Array.from({ length: probeCount }, (_, index) => ({
    probeKey: identitySha256({ kind: 'overview-probe', engine, index }),
    methodRef: `${engine}.structure-schemas@overview-v1`,
    phase: OVERVIEW_PROBE_PHASE,
    target: { kind: 'SCOPE' },
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
    evidenceRefs: [structureSnapshotSha256, identitySha256({ kind: 'overview-receipt-evidence', engine, index })].sort(),
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
  const run = { ...runBody, stateSha256: identitySha256(runBody) }
  const projection = buildDatabaseOverviewProjection(run)
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
    scope: { schemas: [...scope.schemas] },
  }
  return { run, projection, bindings, request }
}

const deepFreezeValue = (value) => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreezeValue)
    Object.freeze(value)
  }
  return value
}

// The three representative local-action inputs: a first-page search, a
// COMPLETE details projection and an overview run carrying a cancelled
// receipt, exactly as the root runtime oracle exercises them.
function representativeValues() {
  const { sources, envelope } = syntheticSearchFixture(ENGINE)
  const search = validSearchHandlerInput({ engine: ENGINE, sources, envelope })
  const detailsScenario = syntheticDetailsScenario(ENGINE, DETAILS_STATES.COMPLETE)
  const details = { request: detailsScenario.request, projectionInput: detailsScenario.projectionInput }
  const overviewScenario = syntheticOverviewScenario(ENGINE, { withCancelledReceipt: true })
  const overview = { request: overviewScenario.request, run: deepFreezeValue(overviewScenario.run) }
  return { search, details, overview }
}

/**
 * Run the P3A local-surface probe: dispatch the three representative local
 * actions through the fixture runtime, capture the stub-host tool surface and
 * the alias/unknown-action denials, and return one sealed, JSON-safe,
 * read-only evidence bundle. The runtime is always disposed.
 * @returns {Promise<object>} The frozen P3A evidence bundle:
 *   `{ engine, actions, hostSurface, closedActions, attestation }`.
 */
export async function runLocalSurfaceProbe() {
  const values = representativeValues()
  const runtime = await KaleidoSphereRuntime.create({ source: { mode: 'fixture' } })
  try {
    const actions = []
    for (const action of P3A_LOCAL_ACTIONS) {
      const out = await runtime.execute(action, values[action])
      actions.push({ action, out })
    }
    // Stub-host surface: flatten the tool definitions' nested capability
    // metadata into plain evidence entries, ordered by tool name.
    const capabilities = createToolDefinitions(runtime)
      .map((tool) => ({
        name: tool.name,
        action: tool.capability.action,
        capabilityId: tool.capability.capabilityId,
        authority: tool.capability.authority,
      }))
      .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
    const toolNames = capabilities.map((tool) => tool.name)
    const denied = []
    for (const alias of P3A_ALIASES) {
      try {
        await runtime.execute(alias, values.search)
        throw new Error(`expected denial for action: ${alias}`)
      } catch (error) {
        if (error.code !== P3A_INVALID_ACTION) throw error
        denied.push({ alias, code: error.code, message: error.message })
      }
    }
    return Object.freeze({
      engine: ENGINE,
      actions: Object.freeze(actions.map((entry) => Object.freeze(entry))),
      hostSurface: Object.freeze({
        toolNames: Object.freeze(toolNames),
        capabilities: Object.freeze(capabilities.map((tool) => Object.freeze(tool))),
      }),
      closedActions: Object.freeze({
        denied: Object.freeze(denied.map((entry) => Object.freeze(entry))),
      }),
      attestation: capabilityAttestationV2(),
    })
  } finally {
    await runtime.dispose()
  }
}

export {
  DETAILS_STATES,
  P3A_ALIASES,
  P3A_AUTHORITY,
  P3A_CLAIMS,
  P3A_FORBIDDEN_KEYS,
  P3A_FORBIDDEN_VALUE_PATTERNS,
  P3A_HOST_TOOL_NAMES,
  P3A_INVALID_ACTION,
  P3A_LOCAL_ACTIONS,
  P3A_MAPPED_CAPABILITIES,
  P3A_OVERVIEW_RESULT_KEYS,
  P3A_RESPONSE_KEYS,
  P3A_RESULT_KEYS,
  deepFreezeValue,
  detailsLedgerFor,
  detailsLedgerWithEntry,
  detailsProjectionInputFor,
  detailsRawEntry,
  detailsReceiptFor,
  syntheticDetailsScenario,
  syntheticOverviewScenario,
  syntheticSearchFixture,
  validSearchHandlerInput,
}