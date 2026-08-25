import {
  canonicalJson,
  identitySha256,
  normalizeJsonValue,
  normalizeSql,
  sha256,
} from './core.mjs';

export const SAFE_ANALYSIS_MANIFEST_SCHEMA = 'kaleidosphere.analysis/safe-method-manifest/v1';
export const SAFE_ANALYSIS_EVIDENCE_SCHEMA = 'kaleidosphere.analysis/safe-method-evidence/v1';
export const SAFE_ANALYSIS_CAPABILITY_STATES = Object.freeze(['COMPLETE', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'UNKNOWN']);

const ENGINES = new Set(['mssql', 'oracle']);
const PHASES = new Set(['SAFE_AGGREGATES', 'RELATIONSHIP_GRAPH', 'HYPOTHESIS_VALIDATION']);
const TARGET_KINDS = new Set(['COLUMN', 'RELATIONSHIP']);
const SEMANTIC_METHODS = new Set(['COLUMN_SUMMARY', 'TEMPORAL_COVERAGE', 'QUALITY_INDICATORS', 'RELATIONSHIP_OVERLAP']);
const TYPE_FAMILIES = new Set(['NUMERIC', 'TEMPORAL', 'CATEGORY', 'TEXT', 'BOOLEAN', 'PAIR']);
const RESULT_STATES = new Set(['SUCCEEDED', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'TIMEOUT', 'CANCELLED', 'ERROR', 'UNKNOWN']);
const SHA256 = /^[a-f0-9]{64}$/;
const METHOD_ID = /^(?:mssql|oracle)\.safe\.[a-z0-9][a-z0-9-]{2,63}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/;
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$#]{0,127}$/;
const SECRET_SHAPE = /(?:password|passwd|credential|secret|token|api[_-]?key|connection[_-]?string|dsn)/i;
const FORBIDDEN_SQL = /\b(?:ALTER|BEGIN\s+TRAN|CALL|CREATE|DELETE|DROP|EXEC(?:UTE)?|GRANT|INSERT|MERGE|REVOKE|TRUNCATE|UPDATE|UPSERT)\b/i;

const OUTPUT_COLUMNS = Object.freeze({
  COLUMN_SUMMARY: Object.freeze(['rowCount', 'nullCount', 'distinctCount']),
  TEMPORAL_COVERAGE: Object.freeze(['rowCount', 'nullCount', 'distinctCount', 'minimum', 'maximum', 'freshnessMaximum']),
  QUALITY_INDICATORS: Object.freeze(['rowCount', 'nullCount', 'distinctCount']),
  RELATIONSHIP_OVERLAP: Object.freeze(['sourceNonNullCount', 'sourceDistinctCount', 'targetNonNullCount', 'targetDistinctCount', 'matchedDistinctCount']),
});

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());
const compare = (left, right) => Buffer.compare(Buffer.from(String(left), 'utf8'), Buffer.from(String(right), 'utf8'));
const sha256Value = (value) => typeof value === 'string' && SHA256.test(value);
const safeIdentifier = (value) => typeof value === 'string' && IDENTIFIER.test(value) && !SECRET_SHAPE.test(value);
const safeText = (value, max = 256) => typeof value === 'string' && value.length > 0 && value.length <= max
  && value === value.normalize('NFC') && !/[\u0000-\u001f\u007f]/.test(value) && !SECRET_SHAPE.test(value);

function seal(body, hashKey) {
  const normalized = normalizeJsonValue(body);
  return {...normalized, [hashKey]: identitySha256(normalized)};
}

function capabilityMap(method) {
  return new Map(method.capabilities.map((entry) => [entry.typeFamily, entry]));
}

export function validateSafeAnalysisMethodManifest(manifest, sqlByMethodId) {
  if (!exactKeys(manifest, ['schemaVersion', 'packId', 'packVersion', 'engine', 'methods'])
    || manifest.schemaVersion !== SAFE_ANALYSIS_MANIFEST_SCHEMA || !ENGINES.has(manifest.engine)
    || !safeText(manifest.packId, 128) || !/^\d+\.\d+\.\d+$/.test(manifest.packVersion)
    || !Array.isArray(manifest.methods) || manifest.methods.length !== 4) fail('DB_SAFE_METHOD_MANIFEST_INVALID');
  const ids = new Set();
  const semanticMethods = new Set();
  for (const method of manifest.methods) {
    if (!exactKeys(method, [
      'id', 'semanticMethod', 'phase', 'targetKind', 'file', 'templateSha256', 'argumentKeys', 'capabilities',
      'outputColumns', 'readOnly', 'aggregateOnly', 'rowSamples', 'exampleValues', 'maxOutputRows',
      'maxSourceRows', 'timeoutMs', 'provenance', 'engineDifferences',
    ]) || !METHOD_ID.test(method.id) || !method.id.startsWith(`${manifest.engine}.`) || ids.has(method.id)
      || !SEMANTIC_METHODS.has(method.semanticMethod) || semanticMethods.has(method.semanticMethod)
      || !PHASES.has(method.phase) || !TARGET_KINDS.has(method.targetKind)
      || method.targetKind !== (method.semanticMethod === 'RELATIONSHIP_OVERLAP' ? 'RELATIONSHIP' : 'COLUMN')
      || !safeText(method.file, 128) || /[/\\]|\.\./.test(method.file) || !sha256Value(method.templateSha256)
      || canonicalJson(method.argumentKeys) !== canonicalJson(['maxSourceRows', 'typeFamily'])
      || !Array.isArray(method.capabilities) || method.capabilities.length === 0
      || method.capabilities.some((entry) => !exactKeys(entry, ['typeFamily', 'state', 'reasonCode'])
        || !TYPE_FAMILIES.has(entry.typeFamily) || !['COMPLETE', 'UNSUPPORTED'].includes(entry.state)
        || !(entry.reasonCode === null || REASON_CODE.test(entry.reasonCode)))
      || new Set(method.capabilities.map(({typeFamily}) => typeFamily)).size !== method.capabilities.length
      || canonicalJson(method.outputColumns) !== canonicalJson(OUTPUT_COLUMNS[method.semanticMethod])
      || method.readOnly !== true || method.aggregateOnly !== true || method.rowSamples !== false
      || method.exampleValues !== false || method.maxOutputRows !== 1
      || !Number.isInteger(method.maxSourceRows) || method.maxSourceRows < 1 || method.maxSourceRows > 10000
      || !Number.isInteger(method.timeoutMs) || method.timeoutMs < 1 || method.timeoutMs > 10000
      || !exactKeys(method.provenance, ['sourceType', 'url', 'spdx', 'copiedCode', 'changeMarker'])
      || method.provenance.sourceType !== 'OFFICIAL_AGGREGATE_API_REFERENCE'
      || !safeText(method.provenance.url, 500) || method.provenance.spdx !== 'Apache-2.0'
      || method.provenance.copiedCode !== false || !/KS-authored/.test(method.provenance.changeMarker)
      || !Array.isArray(method.engineDifferences) || method.engineDifferences.some((entry) => !safeText(entry, 500))) {
      fail('DB_SAFE_METHOD_MANIFEST_INVALID');
    }
    ids.add(method.id);
    semanticMethods.add(method.semanticMethod);
    if (sqlByMethodId !== undefined) auditSafeAnalysisQuery({manifest, method, sql: sqlByMethodId[method.id]});
  }
  if (canonicalJson([...semanticMethods].sort(compare)) !== canonicalJson([...SEMANTIC_METHODS].sort(compare))) {
    fail('DB_SAFE_METHOD_MANIFEST_INVALID');
  }
  if (sqlByMethodId !== undefined && canonicalJson(Object.keys(sqlByMethodId).sort(compare)) !== canonicalJson([...ids].sort(compare))) {
    fail('DB_SAFE_METHOD_QUERY_PACK_DENIED');
  }
  return manifest;
}

export function auditSafeAnalysisQuery({manifest, method, sql}) {
  if (!ENGINES.has(manifest?.engine) || !method || typeof sql !== 'string'
    || sha256(normalizeSql(sql)) !== method.templateSha256) fail('DB_SAFE_METHOD_QUERY_PACK_DENIED');
  const normalized = normalizeSql(sql);
  const executable = normalized.replace(/'(?:''|[^'])*'/g, "''");
  const markers = [...normalized.matchAll(/\{\{([A-Z_]+)\}\}/g)].map((match) => match[1]);
  const expectedMarkers = method.targetKind === 'COLUMN'
    ? ['SCHEMA', 'RELATION', 'COLUMN']
    : ['SOURCE_SCHEMA', 'SOURCE_RELATION', 'SOURCE_COLUMN', 'TARGET_SCHEMA', 'TARGET_RELATION', 'TARGET_COLUMN'];
  const bindPattern = manifest.engine === 'mssql' ? /@maxSourceRows\b/g : /:maxSourceRows\b/g;
  const boundedPattern = manifest.engine === 'mssql'
    ? /TOP\s*\(\s*@maxSourceRows\s*\)/gi
    : /ROWNUM\s*<=\s*:maxSourceRows\b/gi;
  const requiredBounds = method.targetKind === 'RELATIONSHIP' ? 2 : 1;
  if (!/^(?:WITH|SELECT)\b/i.test(normalized) || FORBIDDEN_SQL.test(executable)
    || /SELECT\s+\*/i.test(executable) || /--|\/\*/.test(executable)
    || (executable.match(/;/g) ?? []).length !== 1 || !/;\s*$/.test(executable)
    || markers.some((marker) => !expectedMarkers.includes(marker))
    || expectedMarkers.some((marker) => !markers.includes(marker))
    || (normalized.match(bindPattern) ?? []).length < 1
    || (normalized.match(boundedPattern) ?? []).length !== requiredBounds
    || method.outputColumns.some((column) => !new RegExp(`(?:\\[|\")${column}(?:\\]|\")`, 'i').test(normalized))) {
    fail('DB_SAFE_METHOD_QUERY_PACK_DENIED');
  }
  return true;
}

const quoteIdentifier = (engine, value) => {
  if (!safeIdentifier(value)) fail('DB_SAFE_METHOD_SCOPE_DENIED');
  return engine === 'mssql' ? `[${value.replaceAll(']', ']]')}]` : `"${value.replaceAll('"', '""')}"`;
};

function normalizeColumnTarget(target) {
  if (!exactKeys(target, ['kind', 'schemaName', 'relationName', 'columnName']) || target.kind !== 'COLUMN'
    || ![target.schemaName, target.relationName, target.columnName].every(safeIdentifier)) fail('DB_SAFE_METHOD_TARGET_INVALID');
  return normalizeJsonValue(target);
}

function normalizeRelationshipTarget(target) {
  if (!exactKeys(target, ['kind', 'source', 'target']) || target.kind !== 'RELATIONSHIP') fail('DB_SAFE_METHOD_TARGET_INVALID');
  const {kind: _sourceKind, ...source} = normalizeColumnTarget({...target.source, kind: 'COLUMN'});
  const {kind: _targetKind, ...destination} = normalizeColumnTarget({...target.target, kind: 'COLUMN'});
  if (canonicalJson(source) === canonicalJson(destination)) fail('DB_SAFE_METHOD_TARGET_INVALID');
  return normalizeJsonValue({kind: 'RELATIONSHIP', source, target: destination});
}

function normalizeArguments(method, args) {
  if (!exactKeys(args, ['maxSourceRows', 'typeFamily']) || !Number.isInteger(args.maxSourceRows)
    || args.maxSourceRows < 1 || args.maxSourceRows > method.maxSourceRows || !TYPE_FAMILIES.has(args.typeFamily)) {
    fail('DB_SAFE_METHOD_ARGUMENT_INVALID');
  }
  const capability = capabilityMap(method).get(args.typeFamily);
  if (!capability) fail('DB_SAFE_METHOD_TYPE_UNSUPPORTED');
  return {arguments: normalizeJsonValue(args), capability};
}

export function compileSafeAnalysisMethod({manifest, sqlByMethodId, methodId, target, arguments: args}) {
  validateSafeAnalysisMethodManifest(manifest, sqlByMethodId);
  const method = manifest.methods.find((entry) => entry.id === methodId);
  if (!method) fail('DB_SAFE_METHOD_NOT_ALLOWLISTED');
  const normalizedTarget = method.targetKind === 'COLUMN' ? normalizeColumnTarget(target) : normalizeRelationshipTarget(target);
  const normalizedArguments = normalizeArguments(method, args);
  if (normalizedArguments.capability.state === 'UNSUPPORTED') {
    return normalizeJsonValue({
      methodId, semanticMethod: method.semanticMethod, engine: manifest.engine, target: normalizedTarget,
      arguments: normalizedArguments.arguments, capability: normalizedArguments.capability, statement: null, binds: {},
      timeoutMs: method.timeoutMs, maxOutputRows: method.maxOutputRows,
    });
  }
  const replacements = method.targetKind === 'COLUMN' ? {
    SCHEMA: quoteIdentifier(manifest.engine, normalizedTarget.schemaName),
    RELATION: quoteIdentifier(manifest.engine, normalizedTarget.relationName),
    COLUMN: quoteIdentifier(manifest.engine, normalizedTarget.columnName),
  } : {
    SOURCE_SCHEMA: quoteIdentifier(manifest.engine, normalizedTarget.source.schemaName),
    SOURCE_RELATION: quoteIdentifier(manifest.engine, normalizedTarget.source.relationName),
    SOURCE_COLUMN: quoteIdentifier(manifest.engine, normalizedTarget.source.columnName),
    TARGET_SCHEMA: quoteIdentifier(manifest.engine, normalizedTarget.target.schemaName),
    TARGET_RELATION: quoteIdentifier(manifest.engine, normalizedTarget.target.relationName),
    TARGET_COLUMN: quoteIdentifier(manifest.engine, normalizedTarget.target.columnName),
  };
  const statement = normalizeSql(sqlByMethodId[methodId].replace(/\{\{([A-Z_]+)\}\}/g, (_match, marker) => replacements[marker]));
  if (/\{\{/.test(statement)) fail('DB_SAFE_METHOD_QUERY_PACK_DENIED');
  return normalizeJsonValue({
    methodId, semanticMethod: method.semanticMethod, engine: manifest.engine, target: normalizedTarget,
    arguments: normalizedArguments.arguments, capability: normalizedArguments.capability, statement,
    binds: {maxSourceRows: normalizedArguments.arguments.maxSourceRows}, timeoutMs: method.timeoutMs, maxOutputRows: method.maxOutputRows,
  });
}

const integer = (value, code = 'DB_SAFE_METHOD_RESULT_INVALID') => {
  if (typeof value === 'number' && Object.is(value, -0)) fail(code);
  const normalized = typeof value === 'bigint' ? Number(value) : typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(normalized) || normalized < 0) fail(code);
  return normalized;
};

const rowValue = (row, key) => {
  const found = Object.keys(row).find((candidate) => candidate.toLowerCase() === key.toLowerCase());
  return found === undefined ? undefined : row[found];
};

function normalizeStatus(result) {
  if (!result || !RESULT_STATES.has(result.state) || !(result.reasonCode === null || REASON_CODE.test(result.reasonCode))) {
    fail('DB_SAFE_METHOD_RESULT_INVALID');
  }
  if (result.state === 'SUCCEEDED') return {state: 'COMPLETE', receiptState: 'SUCCEEDED'};
  if (result.state === 'PARTIAL') return {state: 'PARTIAL', receiptState: 'PARTIAL'};
  if (result.state === 'DENIED') return {state: 'DENIED', receiptState: 'DENIED'};
  if (result.state === 'UNSUPPORTED') return {state: 'UNSUPPORTED', receiptState: 'UNSUPPORTED'};
  if (result.state === 'TIMEOUT') return {state: 'UNKNOWN', receiptState: 'TIMEOUT'};
  if (result.state === 'CANCELLED') return {state: 'UNKNOWN', receiptState: 'CANCELLED'};
  return {state: 'UNKNOWN', receiptState: 'UNKNOWN'};
}

function aggregateClaims(method, row) {
  if (method.semanticMethod === 'RELATIONSHIP_OVERLAP') {
    const observed = Object.fromEntries(method.outputColumns.map((column) => [column, integer(rowValue(row, column))]));
    if (observed.sourceDistinctCount > observed.sourceNonNullCount || observed.targetDistinctCount > observed.targetNonNullCount
      || observed.matchedDistinctCount > observed.sourceDistinctCount || observed.matchedDistinctCount > observed.targetDistinctCount) {
      fail('DB_SAFE_METHOD_RESULT_INVALID');
    }
    const targetDuplicateCount = observed.targetNonNullCount - observed.targetDistinctCount;
    const unmatchedDistinctCount = observed.sourceDistinctCount - observed.matchedDistinctCount;
    const overlapBasisPoints = observed.sourceDistinctCount === 0 ? 0
      : Math.floor((observed.matchedDistinctCount * 10000) / observed.sourceDistinctCount);
    const eligible = observed.sourceDistinctCount > 0 && targetDuplicateCount === 0 && unmatchedDistinctCount === 0;
    return {
      observedClaims: [{observationKind: 'OBSERVED', aggregateKind: 'RELATIONSHIP_COUNTS', metrics: observed}],
      computedClaims: [{observationKind: 'COMPUTED', computationKind: 'RELATIONSHIP_OVERLAP', metrics: {targetDuplicateCount, unmatchedDistinctCount, overlapBasisPoints}, eligible}],
      inferredClaims: eligible ? [{observationKind: 'INFERRED', inferenceKind: 'RELATIONSHIP_CANDIDATE', claimStatus: 'PROPOSAL_ONLY', automaticForeignKey: false}] : [],
      counterevidence: [
        ...(targetDuplicateCount > 0 ? [{reasonCode: 'TARGET_NOT_UNIQUE', count: targetDuplicateCount}] : []),
        ...(unmatchedDistinctCount > 0 ? [{reasonCode: 'SOURCE_VALUES_UNMATCHED', count: unmatchedDistinctCount}] : []),
        ...(observed.sourceDistinctCount === 0 ? [{reasonCode: 'SOURCE_HAS_NO_DISTINCT_VALUES', count: 0}] : []),
      ],
    };
  }
  const rowCount = integer(rowValue(row, 'rowCount'));
  const nullCount = integer(rowValue(row, 'nullCount'));
  const distinctCount = integer(rowValue(row, 'distinctCount'));
  if (nullCount > rowCount || distinctCount > rowCount - nullCount) fail('DB_SAFE_METHOD_RESULT_INVALID');
  const observed = {rowCount, nullCount, distinctCount};
  if (method.semanticMethod === 'TEMPORAL_COVERAGE') {
    for (const key of ['minimum', 'maximum', 'freshnessMaximum']) {
      const value = rowValue(row, key);
      if (!(value === null || safeText(String(value), 128))) fail('DB_SAFE_METHOD_RESULT_INVALID');
      observed[key] = value === null ? null : String(value);
    }
    if (observed.freshnessMaximum !== observed.maximum) fail('DB_SAFE_METHOD_RESULT_INVALID');
    return {
      observedClaims: [{observationKind: 'OBSERVED', aggregateKind: 'TEMPORAL_COVERAGE', metrics: observed}],
      computedClaims: [{observationKind: 'COMPUTED', computationKind: 'TEMPORAL_COMPLETENESS', metrics: {nullRateBasisPoints: rowCount === 0 ? 0 : Math.floor((nullCount * 10000) / rowCount)}}],
      inferredClaims: [], counterevidence: [],
    };
  }
  const nonNullCount = rowCount - nullCount;
  const duplicateCount = nonNullCount - distinctCount;
  const nullRateBasisPoints = rowCount === 0 ? 0 : Math.floor((nullCount * 10000) / rowCount);
  const distinctRateBasisPoints = nonNullCount === 0 ? 0 : Math.floor((distinctCount * 10000) / nonNullCount);
  const keyEligible = rowCount > 0 && nullCount === 0 && duplicateCount === 0;
  return {
    observedClaims: [{observationKind: 'OBSERVED', aggregateKind: method.semanticMethod, metrics: observed}],
    computedClaims: [{observationKind: 'COMPUTED', computationKind: 'QUALITY_AND_KEY_METRICS', metrics: {nonNullCount, duplicateCount, nullRateBasisPoints, distinctRateBasisPoints}, keyEligible}],
    inferredClaims: keyEligible ? [{observationKind: 'INFERRED', inferenceKind: 'KEY_CANDIDATE', claimStatus: 'PROPOSAL_ONLY', compositeKeyCompletenessClaimed: false}] : [],
    counterevidence: [
      ...(nullCount > 0 ? [{reasonCode: 'NULLS_OBSERVED', count: nullCount}] : []),
      ...(duplicateCount > 0 ? [{reasonCode: 'DUPLICATES_OBSERVED', count: duplicateCount}] : []),
      ...(rowCount === 0 ? [{reasonCode: 'EMPTY_BOUNDED_SCOPE', count: 0}] : []),
    ],
  };
}

export function buildSafeAnalysisEvidence({controllerState, manifest, methodId, target, arguments: args, result, authorization}) {
  validateSafeAnalysisMethodManifest(manifest);
  const method = manifest.methods.find((entry) => entry.id === methodId);
  if (!method) fail('DB_SAFE_METHOD_NOT_ALLOWLISTED');
  const normalizedTarget = method.targetKind === 'COLUMN' ? normalizeColumnTarget(target) : normalizeRelationshipTarget(target);
  const normalizedArguments = normalizeArguments(method, args);
  const analysisState = controllerState?.controllerRun ? controllerState : null;
  const controllerRun = analysisState?.controllerRun ?? controllerState;
  const probeKey = authorization?.disposition === 'RESERVED' ? authorization.controllerProbeKey : authorization?.probeKey;
  const probe = controllerRun?.probes?.find((entry) => entry.probeKey === probeKey);
  const descriptor = controllerRun?.methodRegistry?.methods?.find((entry) => entry.methodRef === `${methodId}@${manifest.packVersion}`);
  if (!authorization || !sha256Value(probeKey) || !['AUTHORIZED', 'RESERVED'].includes(authorization.disposition)
    || !sha256Value(controllerRun?.stateSha256) || identitySha256(Object.fromEntries(Object.entries(controllerRun).filter(([key]) => key !== 'stateSha256'))) !== controllerRun.stateSha256
    || !probe || !descriptor || descriptor.sourceManifestSha256 !== identitySha256(manifest)
    || probe.methodRef !== descriptor.methodRef || canonicalJson(probe.target) !== canonicalJson(normalizedTarget)
    || canonicalJson(probe.arguments) !== canonicalJson(normalizedArguments.arguments)
    || (authorization.disposition === 'RESERVED' && !analysisState?.reservations?.some((entry) => entry.reservationSha256 === authorization.reservationSha256
      && entry.controllerProbeKey === probeKey))) fail('DB_SAFE_METHOD_CONTROLLER_AUTHORIZATION_REQUIRED');
  const status = normalizeStatus(result);
  let claims = {observedClaims: [], computedClaims: [], inferredClaims: [], counterevidence: []};
  if (status.state === 'COMPLETE' || status.state === 'PARTIAL') {
    if (!Array.isArray(result.rows) || result.rows.length !== 1 || !result.rows[0] || typeof result.rows[0] !== 'object') {
      fail('DB_SAFE_METHOD_RESULT_INVALID');
    }
    const allowed = new Set(method.outputColumns.map((column) => column.toLowerCase()));
    if (Object.keys(result.rows[0]).some((key) => !allowed.has(key.toLowerCase()) || SECRET_SHAPE.test(key))) {
      fail('DB_SAFE_METHOD_RAW_VALUE_DENIED');
    }
    claims = aggregateClaims(method, result.rows[0]);
  } else if (Array.isArray(result.rows) && result.rows.length > 0) {
    fail('DB_SAFE_METHOD_RAW_VALUE_DENIED');
  }
  const semanticBody = normalizeJsonValue({
    schemaVersion: 'kaleidosphere.analysis/safe-method-semantic-evidence/v1', semanticMethod: method.semanticMethod,
    target: normalizedTarget, arguments: normalizedArguments.arguments, state: status.state, reasonCode: result.reasonCode,
    ...claims, absenceClaim: 'NOT_CLAIMED', rawValuesPersisted: false, rowSamplesPersisted: false,
    automaticFactPromotion: false, automaticForeignKey: false,
  });
  const body = normalizeJsonValue({
    schemaVersion: SAFE_ANALYSIS_EVIDENCE_SCHEMA, engine: manifest.engine, methodId, semanticMethod: method.semanticMethod,
    target: normalizedTarget, arguments: normalizedArguments.arguments, state: status.state, receiptState: status.receiptState,
    reasonCode: result.reasonCode, controllerProbeKey: probeKey,
    semanticEvidenceSha256: identitySha256(semanticBody), observedClaims: claims.observedClaims,
    computedClaims: claims.computedClaims, inferredClaims: claims.inferredClaims, counterevidence: claims.counterevidence,
    engineDifferences: method.engineDifferences, bounds: {maxSourceRows: normalizedArguments.arguments.maxSourceRows, timeoutMs: method.timeoutMs, maxOutputRows: 1},
    absenceClaim: 'NOT_CLAIMED', rawValuesPersisted: false, rowSamplesPersisted: false, exampleValuesPersisted: false,
    automaticFactPromotion: false, automaticForeignKey: false,
  });
  return {...body, evidenceSha256: identitySha256(body)};
}

const mapExecutionError = (error) => {
  const code = String(error?.code ?? error?.name ?? 'SAFE_METHOD_EXECUTION_UNKNOWN').toUpperCase().replace(/[^A-Z0-9_]/g, '_').slice(0, 128);
  if (/DENIED|ORA_01031|EACCES|PERMISSION/.test(code)) return {state: 'DENIED', reasonCode: code || 'SAFE_METHOD_PERMISSION_DENIED', rows: []};
  if (/UNSUPPORTED|NOT_SUPPORTED/.test(code)) return {state: 'UNSUPPORTED', reasonCode: code || 'SAFE_METHOD_UNSUPPORTED', rows: []};
  if (/TIMEOUT|ETIMEOUT|ORA_01013/.test(code)) return {state: 'TIMEOUT', reasonCode: code || 'SAFE_METHOD_TIMEOUT', rows: []};
  if (/ABORT|CANCEL/.test(code)) return {state: 'CANCELLED', reasonCode: code || 'SAFE_METHOD_CANCELLED', rows: []};
  return {state: 'UNKNOWN', reasonCode: code || 'SAFE_METHOD_EXECUTION_UNKNOWN', rows: []};
};

export async function executeSafeAnalysisMethod({run, authorization, manifest, sqlByMethodId, session}) {
  const analysisState = run?.controllerRun ? run : null;
  const controllerRun = analysisState?.controllerRun ?? run;
  const probeKey = authorization?.disposition === 'RESERVED' ? authorization.controllerProbeKey : authorization?.probeKey;
  if (!controllerRun || !authorization || !sha256Value(probeKey)
    || !['AUTHORIZED', 'RESERVED'].includes(authorization.disposition)
    || (authorization.disposition === 'RESERVED' && !analysisState?.reservations?.some((entry) => entry.reservationSha256 === authorization.reservationSha256
      && entry.controllerProbeKey === probeKey))) fail('DB_SAFE_METHOD_CONTROLLER_AUTHORIZATION_REQUIRED');
  const evidenceAuthorization = authorization.disposition === 'RESERVED'
    ? authorization
    : {disposition: authorization.disposition, probeKey};
  const probe = controllerRun.probes?.find((entry) => entry.probeKey === probeKey);
  if (!probe || !session || session.engine !== controllerRun.engine || session.engine !== manifest.engine
    || session.readOnly !== true || typeof session.execute !== 'function'
    || Object.keys(session).some((key) => SECRET_SHAPE.test(key))) fail('DB_SAFE_METHOD_READ_ONLY_SESSION_REQUIRED');
  const compiled = compileSafeAnalysisMethod({
    manifest, sqlByMethodId, methodId: probe.methodRef.split('@')[0], target: probe.target, arguments: probe.arguments,
  });
  if (compiled.capability.state === 'UNSUPPORTED') {
    return buildSafeAnalysisEvidence({
      controllerState: analysisState ?? controllerRun, manifest, methodId: compiled.methodId, target: compiled.target, arguments: compiled.arguments,
      result: {state: 'UNSUPPORTED', reasonCode: compiled.capability.reasonCode, rows: []}, authorization: evidenceAuthorization,
    });
  }
  let result;
  try {
    result = await session.execute({statement: compiled.statement, binds: compiled.binds, timeoutMs: compiled.timeoutMs, maxRows: 1});
  } catch (error) {
    result = mapExecutionError(error);
  }
  return buildSafeAnalysisEvidence({
    controllerState: analysisState ?? controllerRun, manifest, methodId: compiled.methodId, target: compiled.target, arguments: compiled.arguments,
    result, authorization: evidenceAuthorization,
  });
}
