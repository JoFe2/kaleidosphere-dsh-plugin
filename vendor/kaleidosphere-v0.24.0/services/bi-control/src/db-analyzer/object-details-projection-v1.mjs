import {
  canonicalJson,
  identitySha256,
  normalizeJsonValue,
} from './core.mjs';

export const OBJECT_DETAILS_PROJECTION_SCHEMA = 'kaleidosphere.analysis/object-details-projection/v1';
export const OBJECT_DETAILS_EVIDENCE_RECEIPT_SCHEMA = 'kaleidosphere.analysis/object-details-evidence-receipt/v1';
const PROGRESSIVE_COVERAGE_SCHEMA = 'kaleidosphere.analysis/progressive-object-coverage/v1';

const SHA256 = /^[a-f0-9]{64}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/;
const IDENTIFIER_CLAIM = /(?:^|[_$])(verified|complete|exhaustive|authoritative|approved|trusted|confirmed)(?:[_$]|$)/i;
const UNSAFE_TEXT = /(?:[;]|--|\/\*|\*\/|https?:\/\/|file:\/\/|\\|\/|\$\(|`|\b(?:select|insert|update|delete|drop|alter|grant|revoke|execute|exec|call)\b)/i;
const SECRET_TEXT = /(?:password|passwd|credential|secret|token|api[_-]?key|connection[_-]?string|dsn)/i;
const CALLBACK_TEXT = /(?:callback|webhook|redirect|return[_-]?url)/i;
const AUTHORITY_TEXT = /(?:dispatch|approval|execution|mutation|cancel(?:lation)?[_-]?bypass)[_-]?authority/i;
const ENGINES = new Set(['mssql', 'oracle']);
const STATES = new Set(['COMPLETE', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'UNKNOWN']);
const QUERY_STATES = new Set(['SUCCEEDED', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'TIMEOUT', 'ERROR']);
const VISIBILITY = Object.freeze({
  COMPLETE: 'VISIBLE',
  PARTIAL: 'VISIBLE_PARTIAL',
  DENIED: 'INVISIBLE',
  UNSUPPORTED: 'NOT_APPLICABLE',
  UNKNOWN: 'UNKNOWN',
});
const OBJECT_KINDS = new Set([
  'SCHEMA', 'RELATION', 'COLUMN', 'CONSTRAINT', 'INDEX', 'SEQUENCE', 'SYNONYM', 'PARTITION', 'LOB',
  'TABLESPACE', 'STATISTIC', 'SIZE', 'STORED_OBJECT', 'STORED_ARGUMENT', 'STORED_ERROR',
  'STORED_DEPENDENCY', 'OPERATION', 'DB_LINK', 'DEPENDENCY', 'COMMENT', 'EVIDENCE_OBJECT',
]);

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const exactKeys = (value, keys) => value !== null
  && typeof value === 'object'
  && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());
const sha256Value = (value) => typeof value === 'string' && SHA256.test(value);
const compare = (left, right) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

function identifier(value, max = 128) {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && value === value.normalize('NFC')
    && !/[\u0000-\u001f\u007f]/.test(value)
    && !UNSAFE_TEXT.test(value) && !SECRET_TEXT.test(value) && !CALLBACK_TEXT.test(value) && !AUTHORITY_TEXT.test(value);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

function validateScope(scope, engine) {
  if (!exactKeys(scope, ['database', 'container', 'schemas'])
    || !identifier(scope.database)
    || !(scope.container === null || identifier(scope.container))
    || !Array.isArray(scope.schemas) || scope.schemas.length === 0 || scope.schemas.length > 256
    || scope.schemas.some((schema) => !identifier(schema))
    || new Set(scope.schemas).size !== scope.schemas.length) fail('DB_OBJECT_DETAILS_SCOPE_INVALID');
  const normalized = normalizeJsonValue({...scope, schemas: [...scope.schemas].sort(compare)});
  if (engine === 'oracle' && normalized.schemas.some((schema) => schema.length > 128)) fail('DB_OBJECT_DETAILS_SCOPE_INVALID');
  return normalized;
}

function validateEntry(entry) {
  if (entry === null || entry === undefined) fail('DB_OBJECT_DETAILS_COVERAGE_MISSING');
  if (!exactKeys(entry, ['objectKey', 'objectRef', 'state', 'reasonCode', 'sourceQueryId', 'evidenceRefs', 'absenceClaim'])
    || !sha256Value(entry.objectKey) || !STATES.has(entry.state)
    || entry.absenceClaim !== 'NOT_CLAIMED'
    || typeof entry.sourceQueryId !== 'string' || !/^(?:mssql|oracle)\.[a-z0-9][a-z0-9._-]{2,127}$/.test(entry.sourceQueryId)
    || (entry.state === 'COMPLETE' ? entry.reasonCode !== null : !REASON_CODE.test(entry.reasonCode ?? ''))) {
    fail('DB_OBJECT_DETAILS_COVERAGE_INVALID');
  }
  const ref = entry.objectRef;
  if (!exactKeys(ref, ['kind', 'schemaName', 'relationName', 'columnName', 'objectName', 'sourceObjectSha256'])
    || !OBJECT_KINDS.has(ref.kind) || !sha256Value(ref.sourceObjectSha256)) fail('DB_OBJECT_DETAILS_COVERAGE_INVALID');
  for (const [name, value] of Object.entries({schemaName: ref.schemaName, relationName: ref.relationName, columnName: ref.columnName, objectName: ref.objectName})) {
    if (!(value === null || identifier(value, name === 'objectName' ? 256 : 128))) fail('DB_OBJECT_DETAILS_IDENTIFIER_INVALID');
    if (value !== null && IDENTIFIER_CLAIM.test(value)) fail('DB_OBJECT_DETAILS_IDENTIFIER_CLAIM');
  }
  if (ref.schemaName === null
    || (ref.columnName !== null && ref.relationName === null)
    || (ref.relationName !== null && ref.objectName !== null)
    || (ref.columnName !== null && ref.objectName !== null)) fail('DB_OBJECT_DETAILS_IDENTIFIER_INVALID');
  if (identitySha256(ref) !== entry.objectKey) fail('DB_OBJECT_DETAILS_KEY_MISMATCH');
  if (!Array.isArray(entry.evidenceRefs) || entry.evidenceRefs.length === 0 || entry.evidenceRefs.length > 16
    || entry.evidenceRefs.some((value) => !sha256Value(value))
    || new Set(entry.evidenceRefs).size !== entry.evidenceRefs.length) fail('DB_OBJECT_DETAILS_EVIDENCE_INVALID');
  return ref;
}

function evidenceBody(value, digestKey, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(code);
  const normalized = normalizeJsonValue(value);
  if (Object.hasOwn(normalized, digestKey)) {
    if (!sha256Value(normalized[digestKey])) fail(code);
    const {[digestKey]: claimed, ...body} = normalized;
    if (identitySha256(body) !== claimed) fail(code);
    return {body, digest: claimed, sealed: normalized};
  }
  return {body: normalized, digest: identitySha256(normalized), sealed: {...normalized, [digestKey]: identitySha256(normalized)}};
}

const isNegativeZero = (value) => typeof value === 'number' && Object.is(value, -0);

function summaryNegativeZero(ledger) {
  if (ledger === null || typeof ledger !== 'object' || Array.isArray(ledger)) return false;
  const summary = ledger.summary;
  if (summary === null || typeof summary !== 'object' || Array.isArray(summary)) return false;
  const stateCounts = summary.stateCounts;
  const counts = stateCounts !== null && typeof stateCounts === 'object' && !Array.isArray(stateCounts)
    ? Object.values(stateCounts)
    : [];
  return [summary.visibleObjectCount, summary.classifiedObjectCount, summary.coverageBps, ...counts].some(isNegativeZero);
}

function validateCoverageLedger(value, engine) {
  // Reject negative zero on the raw summary before evidenceBody normalization coerces -0 to 0.
  if (summaryNegativeZero(value)) fail('DB_OBJECT_DETAILS_COVERAGE_LEDGER_INVALID');
  const evidence = evidenceBody(value, 'coverageSha256', 'DB_OBJECT_DETAILS_COVERAGE_LEDGER_TAMPERED');
  const ledger = evidence.sealed;
  if (!exactKeys(ledger, [
    'schemaVersion', 'engine', 'structureSnapshotSha256', 'structureCoverageLedgerSha256', 'thresholdBps',
    'summary', 'entries', 'queryCoverage', 'missingPrivilegeMeansAbsent', 'evidenceStoreSchema', 'coverageSha256',
  ]) || ledger.schemaVersion !== PROGRESSIVE_COVERAGE_SCHEMA || ledger.engine !== engine
    || !sha256Value(ledger.structureSnapshotSha256) || !sha256Value(ledger.structureCoverageLedgerSha256)
    || !Array.isArray(ledger.entries) || !Array.isArray(ledger.queryCoverage)
    || ledger.thresholdBps !== 9500 || ledger.missingPrivilegeMeansAbsent !== false
    || ledger.evidenceStoreSchema !== 'kaleidosphere.analysis/evidence-store/v1') {
    fail('DB_OBJECT_DETAILS_COVERAGE_LEDGER_INVALID');
  }
  const keys = new Set();
  for (const entry of ledger.entries) {
    validateEntry(entry);
    if (keys.has(entry.objectKey)) fail('DB_OBJECT_DETAILS_COVERAGE_LEDGER_INVALID');
    keys.add(entry.objectKey);
  }
  const queryIds = new Set();
  for (const query of ledger.queryCoverage) {
    if (!exactKeys(query, ['queryId', 'category', 'state', 'reasonCode', 'visibility', 'absenceClaim'])
      || typeof query.queryId !== 'string' || !/^(?:mssql|oracle)\.[a-z0-9][a-z0-9._-]{2,127}$/.test(query.queryId)
      || typeof query.category !== 'string' || query.category.length === 0 || query.category.length > 64
      || !QUERY_STATES.has(query.state) || !(query.reasonCode === null || REASON_CODE.test(query.reasonCode))
      || typeof query.visibility !== 'string' || query.visibility.length === 0 || query.visibility.length > 64
      || query.absenceClaim !== 'NOT_CLAIMED' || queryIds.has(query.queryId)) {
      fail('DB_OBJECT_DETAILS_COVERAGE_LEDGER_INVALID');
    }
    queryIds.add(query.queryId);
  }
  if (ledger.entries.some((entry) => !queryIds.has(entry.sourceQueryId))) fail('DB_OBJECT_DETAILS_COVERAGE_LEDGER_INVALID');
  const counts = Object.fromEntries([...STATES].map((state) => [state, ledger.entries.filter((entry) => entry.state === state).length]));
  const classified = ledger.entries.length - counts.UNKNOWN;
  if (!exactKeys(ledger.summary, ['visibleObjectCount', 'classifiedObjectCount', 'coverageBps', 'stateCounts'])
    || !exactKeys(ledger.summary.stateCounts, [...STATES])
    || canonicalJson(ledger.summary.stateCounts) !== canonicalJson(counts)
    || ledger.summary.visibleObjectCount !== ledger.entries.length || ledger.summary.classifiedObjectCount !== classified
    || ledger.summary.coverageBps !== (ledger.entries.length === 0 ? 0 : Math.floor(classified * 10000 / ledger.entries.length))) {
    fail('DB_OBJECT_DETAILS_COVERAGE_LEDGER_INVALID');
  }
  return evidence;
}

function validateReceipt(value, bindings, entry) {
  const evidence = evidenceBody(value, 'receiptSha256', 'DB_OBJECT_DETAILS_RECEIPT_TAMPERED');
  const receipt = evidence.sealed;
  if (!exactKeys(receipt, [
    'schemaVersion', 'engine', 'scopeSha256', 'inventorySnapshotSha256', 'coverageLedgerSha256',
    'objectKey', 'coverageEntrySha256', 'evidenceRefs', 'receiptSha256',
  ]) || receipt.schemaVersion !== OBJECT_DETAILS_EVIDENCE_RECEIPT_SCHEMA || receipt.engine !== bindings.engine
    || receipt.scopeSha256 !== bindings.scopeSha256 || receipt.inventorySnapshotSha256 !== bindings.inventorySnapshotSha256
    || receipt.coverageLedgerSha256 !== bindings.coverageLedgerSha256 || receipt.objectKey !== bindings.objectKey
    || receipt.coverageEntrySha256 !== identitySha256(entry)
    || !Array.isArray(receipt.evidenceRefs) || receipt.evidenceRefs.length === 0
    || receipt.evidenceRefs.some((ref) => !sha256Value(ref)) || new Set(receipt.evidenceRefs).size !== receipt.evidenceRefs.length
    || canonicalJson([...receipt.evidenceRefs].sort(compare)) !== canonicalJson([...entry.evidenceRefs].sort(compare))) {
    fail('DB_OBJECT_DETAILS_RECEIPT_BINDING_INVALID');
  }
  return evidence;
}

function validatedInput(input) {
  if (!exactKeys(input, [
    'engine', 'scope', 'scopeSha256', 'inventorySnapshotSha256', 'coverageLedger', 'receipt', 'objectKey',
  ])) fail('DB_OBJECT_DETAILS_INPUT_INVALID');
  if (!ENGINES.has(input.engine)) fail('DB_OBJECT_DETAILS_ENGINE_INVALID');
  if (![input.scopeSha256, input.inventorySnapshotSha256, input.objectKey].every(sha256Value)) {
    fail('DB_OBJECT_DETAILS_BINDING_INVALID');
  }
  const scope = validateScope(input.scope, input.engine);
  if (identitySha256(scope) !== input.scopeSha256) fail('DB_OBJECT_DETAILS_BINDING_DRIFT');
  const ledgerEvidence = validateCoverageLedger(input.coverageLedger, input.engine);
  if (ledgerEvidence.sealed.structureSnapshotSha256 !== input.inventorySnapshotSha256) fail('DB_OBJECT_DETAILS_EVIDENCE_DRIFT');
  const matches = ledgerEvidence.sealed.entries.filter((entry) => entry.objectKey === input.objectKey);
  if (matches.length !== 1) fail(matches.length === 0 ? 'DB_OBJECT_DETAILS_COVERAGE_MISSING' : 'DB_OBJECT_DETAILS_KEY_SUBSTITUTION');
  const coverageEntry = matches[0];
  const ref = validateEntry(coverageEntry);
  if (!scope.schemas.includes(ref.schemaName)) fail('DB_OBJECT_DETAILS_SCOPE_DENIED');
  if (!coverageEntry.sourceQueryId.startsWith(`${input.engine}.`)) fail('DB_OBJECT_DETAILS_ENGINE_MISMATCH');
  if (!coverageEntry.evidenceRefs.includes(input.inventorySnapshotSha256)
    || !coverageEntry.evidenceRefs.includes(ledgerEvidence.sealed.structureCoverageLedgerSha256)
    || !coverageEntry.evidenceRefs.includes(ref.sourceObjectSha256)) fail('DB_OBJECT_DETAILS_EVIDENCE_DRIFT');
  const receiptEvidence = validateReceipt(input.receipt, {
    engine: input.engine, scopeSha256: input.scopeSha256, inventorySnapshotSha256: input.inventorySnapshotSha256,
    coverageLedgerSha256: ledgerEvidence.digest, objectKey: input.objectKey,
  }, coverageEntry);
  return {ref, coverageEntry, coverageLedgerSha256: ledgerEvidence.digest, receiptSha256: receiptEvidence.digest};
}

function buildProjection(input) {
  const {ref, coverageEntry, coverageLedgerSha256, receiptSha256} = validatedInput(input);
  const identifierShape = ref.columnName !== null ? 'SCHEMA_RELATION_COLUMN'
    : ref.relationName !== null ? 'SCHEMA_RELATION'
      : ref.objectName !== null ? 'SCHEMA_OBJECT' : 'SCHEMA_ONLY';
  const body = normalizeJsonValue({
    schemaVersion: OBJECT_DETAILS_PROJECTION_SCHEMA,
    projectionKind: 'OBJECT_DETAILS',
    engine: input.engine,
    objectKey: input.objectKey,
    objectKind: ref.kind,
    identifiers: {
      schemaName: ref.schemaName,
      relationName: ref.relationName,
      columnName: ref.columnName,
      objectName: ref.objectName,
    },
    identifierShape,
    sourceObjectSha256: ref.sourceObjectSha256,
    coverage: {
      state: coverageEntry.state,
      reasonCode: coverageEntry.reasonCode,
      visibility: VISIBILITY[coverageEntry.state],
      absenceClaim: 'NOT_CLAIMED',
    },
    evidenceRefs: [...coverageEntry.evidenceRefs].sort(compare),
    bindings: {
      scopeSha256: input.scopeSha256,
      inventorySnapshotSha256: input.inventorySnapshotSha256,
      coverageLedgerSha256,
      receiptSha256,
      coverageEntrySha256: identitySha256(coverageEntry),
    },
    safety: {
      rawValuesIncluded: false,
      credentialsIncluded: false,
      freeSqlAccepted: false,
      dispatchAuthority: false,
      approvalAuthority: false,
      executionAuthority: false,
      mutationAuthority: false,
      cancellationBypass: false,
      completenessClaimed: false,
      missingPrivilegeMeansAbsent: false,
    },
  });
  return deepFreeze({...body, projectionSha256: identitySha256(body)});
}

export function projectObjectDetails(input) {
  return buildProjection(input);
}

export function verifyObjectDetailsProjection(projection, input) {
  try {
    const expected = buildProjection(input);
    if (canonicalJson(projection) !== canonicalJson(expected)) fail('DB_OBJECT_DETAILS_FORGED');
    return projection;
  } catch (error) {
    if (error?.code === 'DB_OBJECT_DETAILS_FORGED') throw error;
    fail('DB_OBJECT_DETAILS_FORGED');
  }
}
