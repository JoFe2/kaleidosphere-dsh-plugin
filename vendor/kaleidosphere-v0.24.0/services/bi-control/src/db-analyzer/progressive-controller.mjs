import {
  canonicalJson,
  identitySha256,
  normalizeJsonValue,
  validateProfilingQueryManifest,
  validateQueryManifest,
} from './core.mjs';
import {validateSafeAnalysisMethodManifest} from './safe-analysis-methods.mjs';

export const PROGRESSIVE_RUN_SCHEMA = 'kaleidosphere.analysis/progressive-run/v1';
export const PROGRESSIVE_METHOD_REGISTRY_SCHEMA = 'kaleidosphere.analysis/progressive-method-registry/v1';
export const PROGRESSIVE_COVERAGE_SCHEMA = 'kaleidosphere.analysis/progressive-object-coverage/v1';
export const PROGRESSIVE_OVERRIDE_SCHEMA = 'kaleidosphere.analysis/progressive-breadth-override/v1';
export const PROGRESSIVE_RECEIPT_SCHEMA = 'kaleidosphere.analysis/progressive-probe-receipt/v1';
export const PROGRESSIVE_REPORT_SCHEMA = 'kaleidosphere.analysis/progressive-controller-report/v1';
export const EXISTING_EVIDENCE_STORE_SCHEMA = 'kaleidosphere.analysis/evidence-store/v1';

export const PROGRESSIVE_PHASES = Object.freeze([
  'PREFLIGHT',
  'BREADTH_INVENTORY',
  'PRIORITIZATION',
  'SAFE_AGGREGATES',
  'RELATIONSHIP_GRAPH',
  'HYPOTHESIS_VALIDATION',
  'REPORT',
]);

export const PROGRESSIVE_COVERAGE_STATES = Object.freeze([
  'COMPLETE',
  'PARTIAL',
  'DENIED',
  'UNSUPPORTED',
  'UNKNOWN',
]);

const DEPTH_PHASES = new Set(['SAFE_AGGREGATES', 'RELATIONSHIP_GRAPH', 'HYPOTHESIS_VALIDATION']);
const RECEIPT_STATES = new Set(['SUCCEEDED', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'TIMEOUT', 'CANCELLED', 'UNKNOWN']);
const SHA256 = /^[a-f0-9]{64}$/;
const RUN_ID = /^[a-z0-9][a-z0-9._-]{2,127}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/;
const METHOD_ID = /^(?:mssql|oracle)\.[a-z0-9][a-z0-9._-]{2,127}$/;
const SECRET_SHAPE = /(?:password|passwd|credential|secret|token|api[_-]?key|connection[_-]?string|dsn)/i;

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const exactKeys = (value, keys) => value
  && typeof value === 'object'
  && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());

const compare = (left, right) => Buffer.compare(Buffer.from(String(left), 'utf8'), Buffer.from(String(right), 'utf8'));
const sha256Value = (value) => typeof value === 'string' && SHA256.test(value);
const safeText = (value, max = 128) => typeof value === 'string'
  && value.length > 0 && value.length <= max
  && value === value.normalize('NFC')
  && !/[\u0000-\u001f\u007f]/.test(value)
  && !SECRET_SHAPE.test(value);
const identifier = (value) => safeText(value) && !/[;]|--|\/\*|\*\//.test(value);

function seal(body, hashKey) {
  const normalized = normalizeJsonValue(body);
  return {...normalized, [hashKey]: identitySha256(normalized)};
}

function assertSealed(value, hashKey, code) {
  if (!value || !sha256Value(value[hashKey])) fail(code);
  const {[hashKey]: expected, ...body} = value;
  if (identitySha256(body) !== expected) fail(code);
  return value;
}

function normalizeScope(scope) {
  if (!exactKeys(scope, ['database', 'container', 'schemas'])
    || !identifier(scope.database)
    || !(scope.container === null || identifier(scope.container))
    || !Array.isArray(scope.schemas) || scope.schemas.length === 0
    || scope.schemas.some((schema) => !identifier(schema))
    || new Set(scope.schemas).size !== scope.schemas.length) fail('DB_PROGRESSIVE_SCOPE_INVALID');
  return normalizeJsonValue({...scope, schemas: [...scope.schemas].sort(compare)});
}

function methodDescriptor({methodRef, engine, phase, targetKind, allowedArgumentKeys, readOnly, aggregateOnly, sourceManifestSha256, templateSha256}) {
  return normalizeJsonValue({
    methodRef,
    engine,
    phase,
    targetKind,
    allowedArgumentKeys: [...allowedArgumentKeys].sort(compare),
    readOnly,
    aggregateOnly,
    sourceManifestSha256,
    templateSha256,
    acceptsFreeSql: false,
    acceptsRawValues: false,
    acceptsCredentials: false,
  });
}

export function buildProgressiveMethodRegistry({structureManifest, profilingManifest = null, safeAnalysisManifest = null}) {
  validateQueryManifest(structureManifest);
  if (!['mssql', 'oracle'].includes(structureManifest.engine)) fail('DB_PROGRESSIVE_ENGINE_INVALID');
  const engine = structureManifest.engine;
  const structureManifestSha256 = identitySha256(structureManifest);
  const methods = structureManifest.queries.map((query) => {
    if (!METHOD_ID.test(query.id) || query.readOnly !== true) fail('DB_PROGRESSIVE_METHOD_INVALID');
    return methodDescriptor({
      methodRef: `${query.id}@${structureManifest.packVersion}`,
      engine,
      phase: query.category === 'preflight' ? 'PREFLIGHT' : 'BREADTH_INVENTORY',
      targetKind: 'SCOPE',
      allowedArgumentKeys: [],
      readOnly: true,
      aggregateOnly: false,
      sourceManifestSha256: structureManifestSha256,
      templateSha256: null,
    });
  });
  if (profilingManifest !== null) {
    validateProfilingQueryManifest(profilingManifest);
    if (profilingManifest.engine !== engine) fail('DB_PROGRESSIVE_METHOD_ENGINE_MISMATCH');
    const profilingManifestSha256 = identitySha256(profilingManifest);
    methods.push(...profilingManifest.queries.map((query) => methodDescriptor({
      methodRef: `${query.id}@${profilingManifest.packVersion}`,
      engine,
      phase: 'SAFE_AGGREGATES',
      targetKind: 'COLUMN',
      allowedArgumentKeys: [],
      readOnly: true,
      aggregateOnly: true,
      sourceManifestSha256: profilingManifestSha256,
      templateSha256: query.templateSha256,
    })));
  }
  if (safeAnalysisManifest !== null) {
    validateSafeAnalysisMethodManifest(safeAnalysisManifest);
    if (safeAnalysisManifest.engine !== engine) fail('DB_PROGRESSIVE_METHOD_ENGINE_MISMATCH');
    const safeManifestSha256 = identitySha256(safeAnalysisManifest);
    methods.push(...safeAnalysisManifest.methods.map((method) => methodDescriptor({
      methodRef: `${method.id}@${safeAnalysisManifest.packVersion}`,
      engine,
      phase: method.phase,
      targetKind: method.targetKind,
      allowedArgumentKeys: method.argumentKeys,
      readOnly: true,
      aggregateOnly: true,
      sourceManifestSha256: safeManifestSha256,
      templateSha256: method.templateSha256,
    })));
  }
  methods.sort((left, right) => compare(left.methodRef, right.methodRef));
  if (new Set(methods.map(({methodRef}) => methodRef)).size !== methods.length) fail('DB_PROGRESSIVE_METHOD_DUPLICATE');
  return seal({schemaVersion: PROGRESSIVE_METHOD_REGISTRY_SCHEMA, engine, methods}, 'registrySha256');
}

function validateMethodRegistry(registry) {
  assertSealed(registry, 'registrySha256', 'DB_PROGRESSIVE_METHOD_REGISTRY_TAMPERED');
  if (registry.schemaVersion !== PROGRESSIVE_METHOD_REGISTRY_SCHEMA
    || !['mssql', 'oracle'].includes(registry.engine)
    || !Array.isArray(registry.methods) || registry.methods.length === 0) fail('DB_PROGRESSIVE_METHOD_REGISTRY_INVALID');
  const refs = new Set();
  for (const method of registry.methods) {
    if (!exactKeys(method, [
      'methodRef', 'engine', 'phase', 'targetKind', 'allowedArgumentKeys', 'readOnly', 'aggregateOnly',
      'sourceManifestSha256', 'templateSha256', 'acceptsFreeSql', 'acceptsRawValues', 'acceptsCredentials',
    ]) || refs.has(method.methodRef) || method.engine !== registry.engine
      || !METHOD_ID.test(method.methodRef.split('@')[0]) || !/^\d+\.\d+\.\d+$/.test(method.methodRef.split('@')[1] ?? '')
      || !PROGRESSIVE_PHASES.includes(method.phase)
      || !['SCOPE', 'COLUMN', 'RELATIONSHIP'].includes(method.targetKind)
      || !Array.isArray(method.allowedArgumentKeys)
      || method.allowedArgumentKeys.some((key) => !/^[a-z][a-zA-Z0-9]{0,63}$/.test(key) || SECRET_SHAPE.test(key))
      || method.readOnly !== true || typeof method.aggregateOnly !== 'boolean'
      || !sha256Value(method.sourceManifestSha256)
      || !(method.templateSha256 === null || sha256Value(method.templateSha256))
      || method.acceptsFreeSql !== false || method.acceptsRawValues !== false || method.acceptsCredentials !== false) {
      fail('DB_PROGRESSIVE_METHOD_REGISTRY_INVALID');
    }
    refs.add(method.methodRef);
  }
  return registry;
}

const CATEGORY_KINDS = Object.freeze({
  schemas: 'SCHEMA', relations: 'RELATION', columns: 'COLUMN', constraints: 'CONSTRAINT', indexes: 'INDEX',
  sequences: 'SEQUENCE', synonyms: 'SYNONYM', partitions: 'PARTITION', lobs: 'LOB', tablespaces: 'TABLESPACE',
  statistics: 'STATISTIC', sizes: 'SIZE', 'stored-objects': 'STORED_OBJECT', 'stored-arguments': 'STORED_ARGUMENT',
  'stored-errors': 'STORED_ERROR', 'stored-dependencies': 'STORED_DEPENDENCY', operations: 'OPERATION', 'db-links': 'DB_LINK',
  dependencies: 'DEPENDENCY', comments: 'COMMENT',
});

function coverageState(state) {
  if (state === 'SUCCEEDED') return 'COMPLETE';
  if (state === 'PARTIAL') return 'PARTIAL';
  if (state === 'DENIED') return 'DENIED';
  if (state === 'UNSUPPORTED') return 'UNSUPPORTED';
  return 'UNKNOWN';
}

function objectRefFromRow(category, row) {
  const kind = CATEGORY_KINDS[category] ?? 'EVIDENCE_OBJECT';
  const schemaName = row.schema_name ?? row.source_schema_name ?? row.owner_name ?? null;
  const relationName = row.relation_name ?? row.source_relation_name ?? row.trigger_table_name ?? null;
  const columnName = row.column_name ?? row.source_column_name ?? null;
  const objectName = row.constraint_name ?? row.index_name ?? row.sequence_name ?? row.synonym_name
    ?? row.object_name ?? row.segment_name ?? row.tablespace_name ?? row.partition_name
    ?? row.collector_id ?? row.target_object_name ?? null;
  if (![schemaName, relationName, columnName].every((value) => value === null || identifier(String(value)))
    || !(objectName === null || safeText(String(objectName), 256))
    || !sha256Value(row.objectSha256)) fail('DB_PROGRESSIVE_VISIBLE_OBJECT_INVALID');
  return normalizeJsonValue({
    kind,
    schemaName: schemaName === null ? null : String(schemaName),
    relationName: relationName === null ? null : String(relationName),
    columnName: columnName === null ? null : String(columnName),
    objectName: objectName === null ? null : String(objectName),
    sourceObjectSha256: row.objectSha256,
  });
}

function validateCoverageEntry(entry) {
  if (!exactKeys(entry, ['objectKey', 'objectRef', 'state', 'reasonCode', 'sourceQueryId', 'evidenceRefs', 'absenceClaim'])
    || !sha256Value(entry.objectKey)
    || identitySha256(entry.objectRef) !== entry.objectKey
    || !PROGRESSIVE_COVERAGE_STATES.includes(entry.state)
    || !(entry.reasonCode === null || REASON_CODE.test(entry.reasonCode))
    || typeof entry.sourceQueryId !== 'string' || !METHOD_ID.test(entry.sourceQueryId)
    || !Array.isArray(entry.evidenceRefs) || entry.evidenceRefs.length === 0
    || entry.evidenceRefs.some((ref) => !sha256Value(ref))
    || new Set(entry.evidenceRefs).size !== entry.evidenceRefs.length
    || entry.absenceClaim !== 'NOT_CLAIMED') fail('DB_PROGRESSIVE_COVERAGE_ENTRY_INVALID');
  if (!exactKeys(entry.objectRef, ['kind', 'schemaName', 'relationName', 'columnName', 'objectName', 'sourceObjectSha256'])
    || !safeText(entry.objectRef.kind, 64)
    || ![entry.objectRef.schemaName, entry.objectRef.relationName, entry.objectRef.columnName]
      .every((value) => value === null || identifier(value))
    || !(entry.objectRef.objectName === null || safeText(entry.objectRef.objectName, 256))
    || !sha256Value(entry.objectRef.sourceObjectSha256)) fail('DB_PROGRESSIVE_COVERAGE_ENTRY_INVALID');
  return entry;
}

function finalizeCoverage({engine, structureSnapshotSha256, structureCoverageLedgerSha256, entries, queryCoverage}) {
  if (!['mssql', 'oracle'].includes(engine)
    || !sha256Value(structureSnapshotSha256) || !sha256Value(structureCoverageLedgerSha256)
    || !Array.isArray(entries) || !Array.isArray(queryCoverage)) fail('DB_PROGRESSIVE_COVERAGE_INVALID');
  entries.forEach(validateCoverageEntry);
  for (const query of queryCoverage) {
    if (!exactKeys(query, ['queryId', 'category', 'state', 'reasonCode', 'visibility', 'absenceClaim'])
      || !METHOD_ID.test(query.queryId) || !safeText(query.category, 64)
      || !['SUCCEEDED', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'TIMEOUT', 'ERROR'].includes(query.state)
      || !(query.reasonCode === null || REASON_CODE.test(query.reasonCode))
      || !safeText(query.visibility, 64) || query.absenceClaim !== 'NOT_CLAIMED') fail('DB_PROGRESSIVE_QUERY_COVERAGE_INVALID');
  }
  if (new Set(queryCoverage.map(({queryId}) => queryId)).size !== queryCoverage.length) fail('DB_PROGRESSIVE_QUERY_COVERAGE_INVALID');
  if (new Set(entries.map(({objectKey}) => objectKey)).size !== entries.length) fail('DB_PROGRESSIVE_COVERAGE_DUPLICATE');
  const sortedEntries = [...entries].sort((left, right) => compare(left.objectKey, right.objectKey));
  const stateCounts = Object.fromEntries(PROGRESSIVE_COVERAGE_STATES.map((state) => [state, sortedEntries.filter((entry) => entry.state === state).length]));
  const classifiedCount = sortedEntries.length - stateCounts.UNKNOWN;
  const coverageBps = sortedEntries.length === 0 ? 0 : Math.floor((classifiedCount * 10000) / sortedEntries.length);
  return seal({
    schemaVersion: PROGRESSIVE_COVERAGE_SCHEMA,
    engine,
    structureSnapshotSha256,
    structureCoverageLedgerSha256,
    thresholdBps: 9500,
    summary: {visibleObjectCount: sortedEntries.length, classifiedObjectCount: classifiedCount, coverageBps, stateCounts},
    entries: sortedEntries,
    queryCoverage: [...queryCoverage].sort((left, right) => compare(left.queryId, right.queryId)),
    missingPrivilegeMeansAbsent: false,
    evidenceStoreSchema: EXISTING_EVIDENCE_STORE_SCHEMA,
  }, 'coverageSha256');
}

export function buildProgressiveCoverage(structureEvidence) {
  if (!['mssql', 'oracle'].includes(structureEvidence?.engine)
    || !sha256Value(structureEvidence?.snapshotSha256)
    || structureEvidence?.coverageLedger?.schemaVersion !== 'chimpmaera.db/coverage-ledger/v1'
    || !Array.isArray(structureEvidence.extracts)) fail('DB_PROGRESSIVE_STRUCTURE_EVIDENCE_INVALID');
  const {snapshotSha256, ...structureBody} = structureEvidence;
  if (identitySha256(structureBody) !== snapshotSha256) fail('DB_PROGRESSIVE_STRUCTURE_EVIDENCE_TAMPERED');
  const structureCoverageLedgerSha256 = identitySha256(structureEvidence.coverageLedger);
  const coverageByQuery = new Map(structureEvidence.coverageLedger.entries.map((entry) => [entry.queryId, entry]));
  const queryCoverage = structureEvidence.coverageLedger.entries.map((entry) => normalizeJsonValue({
    queryId: entry.queryId,
    category: entry.category,
    state: entry.state,
    reasonCode: entry.reasonCode,
    visibility: entry.visibility,
    absenceClaim: 'NOT_CLAIMED',
  }));
  const entries = [];
  for (const extract of structureEvidence.extracts) {
    if (extract.category === 'preflight') continue;
    const queryState = coverageByQuery.get(extract.queryId);
    if (!queryState || !Array.isArray(extract.rows)) fail('DB_PROGRESSIVE_STRUCTURE_EVIDENCE_INVALID');
    for (const row of extract.rows) {
      const objectRef = objectRefFromRow(extract.category, row);
      entries.push(normalizeJsonValue({
        objectKey: identitySha256(objectRef),
        objectRef,
        state: coverageState(queryState.state),
        reasonCode: queryState.reasonCode,
        sourceQueryId: extract.queryId,
        evidenceRefs: [...new Set([snapshotSha256, structureCoverageLedgerSha256, row.objectSha256])].sort(compare),
        absenceClaim: 'NOT_CLAIMED',
      }));
    }
  }
  return finalizeCoverage({engine: structureEvidence.engine, structureSnapshotSha256: snapshotSha256, structureCoverageLedgerSha256, entries, queryCoverage});
}

export function createProgressiveCoverage({engine, structureSnapshotSha256, structureCoverageLedgerSha256, entries, queryCoverage}) {
  const normalizedEntries = entries.map((entry) => {
    if (!exactKeys(entry, ['objectRef', 'state', 'reasonCode', 'sourceQueryId', 'evidenceRefs'])
      || !PROGRESSIVE_COVERAGE_STATES.includes(entry.state)) fail('DB_PROGRESSIVE_COVERAGE_ENTRY_INVALID');
    return normalizeJsonValue({...entry, objectKey: identitySha256(entry.objectRef), absenceClaim: 'NOT_CLAIMED'});
  });
  return finalizeCoverage({engine, structureSnapshotSha256, structureCoverageLedgerSha256, entries: normalizedEntries, queryCoverage});
}

function validateCoverage(coverage) {
  assertSealed(coverage, 'coverageSha256', 'DB_PROGRESSIVE_COVERAGE_TAMPERED');
  const rebuilt = finalizeCoverage(coverage);
  if (canonicalJson(rebuilt) !== canonicalJson(coverage)) fail('DB_PROGRESSIVE_COVERAGE_INVALID');
  return coverage;
}

export function createProgressiveBreadthOverride({
  runId, scopeSha256, coverageSha256, reasonCode, actorId, recordedAt, allowedObjectKeys, maxDepthProbeCount,
}) {
  if (!RUN_ID.test(runId) || !sha256Value(scopeSha256) || !sha256Value(coverageSha256)
    || !REASON_CODE.test(reasonCode) || !safeText(actorId)
    || Number.isNaN(Date.parse(recordedAt)) || new Date(recordedAt).toISOString() !== recordedAt
    || !Array.isArray(allowedObjectKeys) || allowedObjectKeys.length === 0
    || allowedObjectKeys.some((key) => !sha256Value(key)) || new Set(allowedObjectKeys).size !== allowedObjectKeys.length
    || !Number.isInteger(maxDepthProbeCount) || maxDepthProbeCount < 1
    || maxDepthProbeCount > Number.MAX_SAFE_INTEGER) fail('DB_PROGRESSIVE_OVERRIDE_INVALID');
  return seal({
    schemaVersion: PROGRESSIVE_OVERRIDE_SCHEMA,
    runId,
    scopeSha256,
    coverageSha256,
    reasonCode,
    actorId,
    recordedAt,
    allowedObjectKeys: [...allowedObjectKeys].sort(compare),
    maxDepthProbeCount,
  }, 'overrideSha256');
}

function validateOverride(override, binding) {
  assertSealed(override, 'overrideSha256', 'DB_PROGRESSIVE_OVERRIDE_TAMPERED');
  if (override.schemaVersion !== PROGRESSIVE_OVERRIDE_SCHEMA
    || override.runId !== binding.runId || override.scopeSha256 !== binding.scopeSha256
    || override.coverageSha256 !== binding.coverageSha256
    || override.maxDepthProbeCount > binding.maxRunProbes) fail('DB_PROGRESSIVE_OVERRIDE_STALE');
  createProgressiveBreadthOverride(override);
  return override;
}

function sealRun(body) {
  return seal(body, 'stateSha256');
}

function validateRun(run) {
  assertSealed(run, 'stateSha256', 'DB_PROGRESSIVE_STATE_TAMPERED');
  if (run.schemaVersion !== PROGRESSIVE_RUN_SCHEMA || !RUN_ID.test(run.runId)
    || !['mssql', 'oracle'].includes(run.engine) || !PROGRESSIVE_PHASES.includes(run.phase)
    || !Array.isArray(run.completedPhases) || !Array.isArray(run.probes) || !Array.isArray(run.receipts)) {
    fail('DB_PROGRESSIVE_STATE_INVALID');
  }
  validateMethodRegistry(run.methodRegistry);
  validateCoverage(run.coverage);
  const phaseIndex = PROGRESSIVE_PHASES.indexOf(run.phase);
  if (canonicalJson(run.completedPhases) !== canonicalJson(PROGRESSIVE_PHASES.slice(0, phaseIndex))) {
    fail('DB_PROGRESSIVE_PHASE_STATE_INVALID');
  }
  if (run.methodRegistry.engine !== run.engine || run.coverage.engine !== run.engine
    || identitySha256(run.scope) !== run.scopeSha256
    || run.evidenceBinding.structureSnapshotSha256 !== run.coverage.structureSnapshotSha256
    || run.evidenceBinding.structureCoverageSha256 !== run.coverage.structureCoverageLedgerSha256
    || run.evidenceBinding.evidenceStoreSchema !== EXISTING_EVIDENCE_STORE_SCHEMA) fail('DB_PROGRESSIVE_BINDING_INVALID');
  if (!exactKeys(run.budget, ['maxRunProbes', 'maxObjectProbes', 'authorizedProbeCount', 'objectProbeCounts'])
    || ![run.budget.maxRunProbes, run.budget.maxObjectProbes, run.budget.authorizedProbeCount].every(Number.isInteger)
    || run.budget.maxRunProbes < 1 || run.budget.maxObjectProbes < 1
    || run.budget.authorizedProbeCount !== run.probes.length
    || run.budget.authorizedProbeCount > run.budget.maxRunProbes) fail('DB_PROGRESSIVE_BUDGET_STATE_INVALID');
  if (run.breadthOverride !== null) validateOverride(run.breadthOverride, {
    runId: run.runId, scopeSha256: run.scopeSha256, coverageSha256: run.coverage.coverageSha256, maxRunProbes: run.budget.maxRunProbes,
  });
  const probeKeys = new Set();
  const recomputedObjectCounts = new Map();
  for (const probe of run.probes) {
    if (!sha256Value(probe.probeKey) || probeKeys.has(probe.probeKey)) fail('DB_PROGRESSIVE_PROBE_STATE_INVALID');
    const {probeKey, ...body} = probe;
    if (identitySha256(body) !== probeKey) fail('DB_PROGRESSIVE_PROBE_STATE_INVALID');
    const method = run.methodRegistry.methods.find(({methodRef}) => methodRef === probe.methodRef);
    if (!method || method.phase !== probe.phase || PROGRESSIVE_PHASES.indexOf(probe.phase) > phaseIndex
      || probe.scopeSha256 !== run.scopeSha256 || probe.methodRegistrySha256 !== run.methodRegistry.registrySha256
      || probe.coverageSha256 !== run.coverage.coverageSha256) fail('DB_PROGRESSIVE_PROBE_STATE_INVALID');
    validateTarget(probe.target, method.targetKind, run.scope);
    validateMethodArguments(probe.arguments, method.allowedArgumentKeys);
    const objectKeys = targetCoverages(run, probe.target).map(({objectKey}) => objectKey);
    if (objectKeys.length === 0) objectKeys.push(identitySha256(probe.target));
    for (const objectKey of objectKeys) {
      recomputedObjectCounts.set(objectKey, (recomputedObjectCounts.get(objectKey) ?? 0) + 1);
    }
    probeKeys.add(probeKey);
  }
  const expectedObjectCounts = [...recomputedObjectCounts.entries()]
    .map(([objectKey, count]) => ({objectKey, count})).sort((left, right) => compare(left.objectKey, right.objectKey));
  if (canonicalJson(expectedObjectCounts) !== canonicalJson(run.budget.objectProbeCounts)
    || expectedObjectCounts.some(({count}) => count > run.budget.maxObjectProbes)) fail('DB_PROGRESSIVE_BUDGET_STATE_INVALID');
  const receiptKeys = new Set();
  for (const receipt of run.receipts) {
    assertSealed(receipt, 'receiptSha256', 'DB_PROGRESSIVE_RECEIPT_TAMPERED');
    if (receipt.schemaVersion !== PROGRESSIVE_RECEIPT_SCHEMA || receipt.runId !== run.runId
      || receipt.scopeSha256 !== run.scopeSha256 || !probeKeys.has(receipt.probeKey)
      || receiptKeys.has(receipt.probeKey) || receipt.blindRetryAllowed !== false
      || !RECEIPT_STATES.has(receipt.resultState)
      || !Array.isArray(receipt.evidenceRefs) || receipt.evidenceRefs.some((ref) => !sha256Value(ref))
      || new Set(receipt.evidenceRefs).size !== receipt.evidenceRefs.length) {
      fail('DB_PROGRESSIVE_RECEIPT_INVALID');
    }
    receiptKeys.add(receipt.probeKey);
  }
  return run;
}

export function createProgressiveRun({
  runId, engine, scope, methodRegistry, coverage, budgets, breadthOverride = null,
}) {
  if (!RUN_ID.test(runId) || !['mssql', 'oracle'].includes(engine)) fail('DB_PROGRESSIVE_RUN_INVALID');
  const normalizedScope = normalizeScope(scope);
  validateMethodRegistry(methodRegistry);
  validateCoverage(coverage);
  if (methodRegistry.engine !== engine || coverage.engine !== engine
    || !exactKeys(budgets, ['maxRunProbes', 'maxObjectProbes'])
    || !Number.isInteger(budgets.maxRunProbes) || budgets.maxRunProbes < 1
    || !Number.isInteger(budgets.maxObjectProbes) || budgets.maxObjectProbes < 1
    || budgets.maxObjectProbes > budgets.maxRunProbes) fail('DB_PROGRESSIVE_RUN_INVALID');
  const scopeSha256 = identitySha256(normalizedScope);
  if (breadthOverride !== null) validateOverride(breadthOverride, {
    runId, scopeSha256, coverageSha256: coverage.coverageSha256, maxRunProbes: budgets.maxRunProbes,
  });
  return sealRun({
    schemaVersion: PROGRESSIVE_RUN_SCHEMA,
    runId,
    engine,
    phase: 'PREFLIGHT',
    completedPhases: [],
    scope: normalizedScope,
    scopeSha256,
    methodRegistry,
    coverage,
    breadthOverride,
    budget: {maxRunProbes: budgets.maxRunProbes, maxObjectProbes: budgets.maxObjectProbes, authorizedProbeCount: 0, objectProbeCounts: []},
    probes: [],
    receipts: [],
    evidenceBinding: {
      structureSnapshotSha256: coverage.structureSnapshotSha256,
      structureCoverageSha256: coverage.structureCoverageLedgerSha256,
      evidenceStoreSchema: EXISTING_EVIDENCE_STORE_SCHEMA,
      canonicalHash: 'SHA-256',
    },
    safety: {
      allowlistedMethodsOnly: true,
      typedIdentifiersAndArgumentsOnly: true,
      freeSqlAccepted: false,
      rawValuesPersisted: false,
      credentialsPersisted: false,
      missingPrivilegeMeansAbsent: false,
      blindRetryAllowed: false,
    },
  });
}

function breadthGate(run) {
  let persistedOverride = null;
  if (run.breadthOverride !== null) {
    persistedOverride = validateOverride(run.breadthOverride, {
      runId: run.runId, scopeSha256: run.scopeSha256, coverageSha256: run.coverage.coverageSha256, maxRunProbes: run.budget.maxRunProbes,
    });
  }
  if (run.coverage.summary.coverageBps >= run.coverage.thresholdBps) return {mode: 'THRESHOLD', override: persistedOverride};
  if (run.breadthOverride === null) fail('DB_PROGRESSIVE_BREADTH_GATE_BLOCKED');
  return {mode: 'PERSISTED_OVERRIDE', override: persistedOverride};
}

export function advanceProgressivePhase(run, nextPhase) {
  validateRun(run);
  const index = PROGRESSIVE_PHASES.indexOf(run.phase);
  if (index < 0 || PROGRESSIVE_PHASES[index + 1] !== nextPhase) fail('DB_PROGRESSIVE_PHASE_TRANSITION_DENIED');
  if (run.phase === 'PREFLIGHT') {
    const preflight = run.coverage.queryCoverage.filter(({category}) => category === 'preflight');
    if (preflight.length === 0 || preflight.some(({state}) => ['TIMEOUT', 'ERROR'].includes(state))) fail('DB_PROGRESSIVE_PREFLIGHT_INCOMPLETE');
  }
  if (run.phase === 'BREADTH_INVENTORY') {
    if (run.coverage.summary.visibleObjectCount === 0
      || !run.coverage.queryCoverage.some(({category}) => category !== 'preflight')) fail('DB_PROGRESSIVE_BREADTH_EMPTY');
  }
  if (nextPhase === 'SAFE_AGGREGATES') breadthGate(run);
  const {stateSha256: _previousState, ...body} = run;
  return sealRun({
    ...body,
    completedPhases: [...run.completedPhases, run.phase],
    phase: nextPhase,
  });
}

function validateTarget(target, targetKind, scope) {
  if (targetKind === 'SCOPE') {
    if (!exactKeys(target, ['kind']) || target.kind !== 'SCOPE') fail('DB_PROGRESSIVE_TARGET_INVALID');
    return normalizeJsonValue(target);
  }
  if (targetKind === 'COLUMN') {
    if (!exactKeys(target, ['kind', 'schemaName', 'relationName', 'columnName']) || target.kind !== 'COLUMN'
      || ![target.schemaName, target.relationName, target.columnName].every(identifier)
      || !scope.schemas.includes(target.schemaName)) fail('DB_PROGRESSIVE_SCOPE_DENIED');
    return normalizeJsonValue(target);
  }
  if (targetKind === 'RELATIONSHIP') {
    if (!exactKeys(target, ['kind', 'source', 'target']) || target.kind !== 'RELATIONSHIP') fail('DB_PROGRESSIVE_TARGET_INVALID');
    const normalizeEndpoint = (endpoint) => {
      if (!exactKeys(endpoint, ['schemaName', 'relationName', 'columnName'])
        || ![endpoint.schemaName, endpoint.relationName, endpoint.columnName].every(identifier)
        || !scope.schemas.includes(endpoint.schemaName)) fail('DB_PROGRESSIVE_SCOPE_DENIED');
      return normalizeJsonValue(endpoint);
    };
    const source = normalizeEndpoint(target.source);
    const destination = normalizeEndpoint(target.target);
    if (canonicalJson(source) === canonicalJson(destination)) fail('DB_PROGRESSIVE_TARGET_INVALID');
    return normalizeJsonValue({kind: 'RELATIONSHIP', source, target: destination});
  }
  fail('DB_PROGRESSIVE_TARGET_INVALID');
}

function targetCoverages(run, target) {
  if (target.kind === 'SCOPE') return [];
  const endpoints = target.kind === 'RELATIONSHIP' ? [target.source, target.target] : [target];
  return endpoints.map((endpoint) => run.coverage.entries.find((entry) => entry.objectRef.kind === 'COLUMN'
    && entry.objectRef.schemaName === endpoint.schemaName
    && entry.objectRef.relationName === endpoint.relationName
    && entry.objectRef.columnName === endpoint.columnName) ?? null).filter(Boolean);
}

function validateMethodArguments(args, allowedArgumentKeys) {
  if (!args || typeof args !== 'object' || Array.isArray(args)
    || canonicalJson(Object.keys(args).sort()) !== canonicalJson(allowedArgumentKeys)) fail('DB_PROGRESSIVE_PROBE_REQUEST_INVALID');
  for (const [key, value] of Object.entries(args)) {
    if (SECRET_SHAPE.test(key)) fail('DB_PROGRESSIVE_PROBE_REQUEST_INVALID');
    if (key === 'maxSourceRows' && (!Number.isInteger(value) || value < 1 || value > 10000)) fail('DB_PROGRESSIVE_PROBE_REQUEST_INVALID');
    else if (key === 'typeFamily' && !['NUMERIC', 'TEMPORAL', 'CATEGORY', 'TEXT', 'BOOLEAN', 'PAIR'].includes(value)) fail('DB_PROGRESSIVE_PROBE_REQUEST_INVALID');
    else if (!['maxSourceRows', 'typeFamily'].includes(key)) fail('DB_PROGRESSIVE_PROBE_REQUEST_INVALID');
  }
  return args;
}

function updateObjectCounts(counts, objectKey) {
  const byKey = new Map(counts.map((entry) => [entry.objectKey, entry.count]));
  byKey.set(objectKey, (byKey.get(objectKey) ?? 0) + 1);
  return [...byKey.entries()].map(([key, count]) => ({objectKey: key, count})).sort((left, right) => compare(left.objectKey, right.objectKey));
}

export function authorizeProgressiveProbe(run, request) {
  validateRun(run);
  if (!exactKeys(request, ['phase', 'methodRef', 'target', 'arguments']) || request.phase !== run.phase) fail('DB_PROGRESSIVE_PROBE_REQUEST_INVALID');
  const method = run.methodRegistry.methods.find(({methodRef}) => methodRef === request.methodRef);
  if (!method || method.phase !== run.phase || method.engine !== run.engine || method.readOnly !== true
    || method.acceptsFreeSql !== false || method.acceptsRawValues !== false || method.acceptsCredentials !== false) {
    fail('DB_PROGRESSIVE_METHOD_DENIED');
  }
  validateMethodArguments(request.arguments, method.allowedArgumentKeys);
  const target = validateTarget(request.target, method.targetKind, run.scope);
  const gate = DEPTH_PHASES.has(run.phase) ? breadthGate(run) : {mode: 'NOT_DEPTH', override: null};
  const coverages = targetCoverages(run, target) ?? [];
  if (DEPTH_PHASES.has(run.phase)) {
    const expectedCoverageCount = target.kind === 'RELATIONSHIP' ? 2 : 1;
    if (coverages.length !== expectedCoverageCount) fail('DB_PROGRESSIVE_TARGET_NOT_VISIBLE');
    for (const coverage of coverages) {
      if (coverage.state !== 'COMPLETE' && (gate.override === null || !gate.override.allowedObjectKeys.includes(coverage.objectKey))) {
        fail('DB_PROGRESSIVE_TARGET_COVERAGE_DENIED');
      }
    }
  }
  const probeBody = normalizeJsonValue({
    runId: run.runId,
    scopeSha256: run.scopeSha256,
    methodRef: method.methodRef,
    phase: run.phase,
    target,
    arguments: request.arguments,
    methodRegistrySha256: run.methodRegistry.registrySha256,
    coverageSha256: run.coverage.coverageSha256,
  });
  const probeKey = identitySha256(probeBody);
  const receipt = run.receipts.find((entry) => entry.probeKey === probeKey);
  if (receipt?.resultState === 'SUCCEEDED') {
    return {state: run, authorization: normalizeJsonValue({disposition: 'REUSED_SUCCESS', probeKey, receiptSha256: receipt.receiptSha256})};
  }
  if (run.probes.some((entry) => entry.probeKey === probeKey)) {
    return {state: run, authorization: normalizeJsonValue({disposition: 'SUPPRESSED_DUPLICATE', probeKey, receiptSha256: receipt?.receiptSha256 ?? null})};
  }
  if (run.budget.authorizedProbeCount >= run.budget.maxRunProbes) fail('DB_PROGRESSIVE_RUN_BUDGET_EXCEEDED');
  const objectKeys = coverages.length > 0 ? coverages.map(({objectKey}) => objectKey) : [identitySha256(target)];
  if (objectKeys.some((objectKey) => (run.budget.objectProbeCounts.find((entry) => entry.objectKey === objectKey)?.count ?? 0) >= run.budget.maxObjectProbes)) {
    fail('DB_PROGRESSIVE_OBJECT_BUDGET_EXCEEDED');
  }
  if (gate.override !== null && coverages.some(({state}) => state !== 'COMPLETE')) {
    const overriddenCount = run.probes.filter((probe) => targetCoverages(run, probe.target)
      .some(({objectKey}) => gate.override.allowedObjectKeys.includes(objectKey))).length;
    if (overriddenCount >= gate.override.maxDepthProbeCount) fail('DB_PROGRESSIVE_OVERRIDE_BUDGET_EXCEEDED');
  }
  const probe = {...probeBody, probeKey};
  const {stateSha256: _previousState, ...body} = run;
  const state = sealRun({
    ...body,
    probes: [...run.probes, probe].sort((left, right) => compare(left.probeKey, right.probeKey)),
    budget: {
      ...run.budget,
      authorizedProbeCount: run.budget.authorizedProbeCount + 1,
      objectProbeCounts: objectKeys.reduce((counts, objectKey) => updateObjectCounts(counts, objectKey), run.budget.objectProbeCounts),
    },
  });
  return {state, authorization: normalizeJsonValue({disposition: 'AUTHORIZED', probeKey, receiptSha256: null})};
}

export function recordProgressiveReceipt(run, {probeKey, resultState, evidenceRefs}) {
  validateRun(run);
  if (!sha256Value(probeKey) || !RECEIPT_STATES.has(resultState)
    || !Array.isArray(evidenceRefs) || evidenceRefs.some((ref) => !sha256Value(ref))
    || new Set(evidenceRefs).size !== evidenceRefs.length) fail('DB_PROGRESSIVE_RECEIPT_INVALID');
  const probe = run.probes.find((entry) => entry.probeKey === probeKey);
  if (!probe || run.receipts.some((entry) => entry.probeKey === probeKey)) fail('DB_PROGRESSIVE_RECEIPT_DUPLICATE_OR_UNKNOWN');
  if (resultState === 'SUCCEEDED' && evidenceRefs.length === 0) fail('DB_PROGRESSIVE_RECEIPT_EVIDENCE_REQUIRED');
  const receipt = seal({
    schemaVersion: PROGRESSIVE_RECEIPT_SCHEMA,
    runId: run.runId,
    scopeSha256: run.scopeSha256,
    probeKey,
    methodRef: probe.methodRef,
    phase: probe.phase,
    target: probe.target,
    argumentsSha256: identitySha256(probe.arguments),
    resultState,
    evidenceRefs: [...evidenceRefs].sort(compare),
    blindRetryAllowed: false,
  }, 'receiptSha256');
  const {stateSha256: _previousState, ...body} = run;
  return sealRun({
    ...body,
    receipts: [...run.receipts, receipt].sort((left, right) => compare(left.probeKey, right.probeKey)),
  });
}

export function resumeProgressiveRun(snapshot) {
  const run = normalizeJsonValue(snapshot);
  validateRun(run);
  return run;
}

export function buildProgressiveReport(run) {
  validateRun(run);
  if (run.phase !== 'REPORT' || canonicalJson(run.completedPhases) !== canonicalJson(PROGRESSIVE_PHASES.slice(0, -1))) {
    fail('DB_PROGRESSIVE_REPORT_PHASE_INVALID');
  }
  const receiptStateCounts = Object.fromEntries([...RECEIPT_STATES].sort(compare)
    .map((state) => [state, run.receipts.filter((receipt) => receipt.resultState === state).length]));
  const phaseCapabilities = PROGRESSIVE_PHASES.map((phase) => {
    const methodRefs = run.methodRegistry.methods.filter((method) => method.phase === phase).map(({methodRef}) => methodRef).sort(compare);
    return normalizeJsonValue({
      phase,
      state: methodRefs.length > 0 || ['PRIORITIZATION', 'RELATIONSHIP_GRAPH', 'HYPOTHESIS_VALIDATION', 'REPORT'].includes(phase)
        ? 'COMPLETE' : 'UNSUPPORTED',
      methodRefs,
    });
  });
  return seal({
    schemaVersion: PROGRESSIVE_REPORT_SCHEMA,
    runId: run.runId,
    engine: run.engine,
    phases: PROGRESSIVE_PHASES,
    phaseCapabilities,
    evidenceBinding: run.evidenceBinding,
    methodRegistrySha256: run.methodRegistry.registrySha256,
    coverage: {
      coverageSha256: run.coverage.coverageSha256,
      thresholdBps: run.coverage.thresholdBps,
      summary: run.coverage.summary,
      entries: run.coverage.entries,
      queryCoverage: run.coverage.queryCoverage,
      missingPrivilegeMeansAbsent: false,
    },
    budget: run.budget,
    probes: run.probes.map(({probeKey, methodRef, phase, target}) => ({probeKey, methodRef, phase, target})),
    receipts: run.receipts,
    receiptStateCounts,
    breadthGate: {
      mode: run.coverage.summary.coverageBps >= run.coverage.thresholdBps ? 'THRESHOLD' : 'PERSISTED_OVERRIDE',
      overrideSha256: run.breadthOverride?.overrideSha256 ?? null,
    },
    disclosure: {rawValuesPersisted: false, credentialsPersisted: false, freeSqlAccepted: false},
    authority: {readOnlyEvidenceOnly: true, mutationAuthority: 'NONE', executionAuthority: 'ALLOWLISTED_METHODS_ONLY'},
    nonClaims: [
      'NO_PRODUCTION_OR_CUSTOMER_DATABASE_EVIDENCE',
      'NO_UNIVERSAL_COMPLETENESS',
      'NO_BUSINESS_SEMANTIC_TRUTH',
      'NO_INFERRED_FOREIGN_KEY_TRUTH',
      'NO_ADVANCED_INFORMATION_GAIN_OR_NEAR_DUPLICATE_PLANNER',
    ],
  }, 'controllerEvidenceSha256');
}
