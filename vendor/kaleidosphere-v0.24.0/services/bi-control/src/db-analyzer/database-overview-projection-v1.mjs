import {canonicalJson, identitySha256, normalizeJsonValue} from './core.mjs';

export const DATABASE_OVERVIEW_PROJECTION_SCHEMA = 'kaleidosphere.analysis/database-overview-projection/v1';

const SHA256 = /^[a-f0-9]{64}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/;
const ENGINES = new Set(['mssql', 'oracle']);
const STATES = Object.freeze(['COMPLETE', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'UNKNOWN']);
export const DATABASE_OVERVIEW_KINDS = Object.freeze([
  'COLUMN', 'COMMENT', 'CONSTRAINT', 'DB_LINK', 'DEPENDENCY', 'EVIDENCE_OBJECT', 'INDEX', 'LOB',
  'OPERATION', 'PARTITION', 'RELATION', 'SCHEMA', 'SEQUENCE', 'SIZE', 'STATISTIC', 'STORED_ARGUMENT',
  'STORED_DEPENDENCY', 'STORED_ERROR', 'STORED_OBJECT', 'SYNONYM', 'TABLESPACE',
]);

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};
const compare = (a, b) => Buffer.compare(Buffer.from(String(a), 'utf8'), Buffer.from(String(b), 'utf8'));
const hash = (value) => typeof value === 'string' && SHA256.test(value);
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());

function assertJson(value, code = 'DB_OVERVIEW_UNSAFE_JSON') {
  const seen = new Set();
  const visit = (item, key = '') => {
    if (/password|passwd|credential|secret|token|api[_-]?key|connection[_-]?string|dsn|path|url|uri|callback/i.test(key)
      || /^(?:sql|queryText|statement)$/i.test(key)) fail(code);
    if (typeof item === 'string' && (/(?:https?:\/\/|file:\/\/|(?:^|[=:\s])\/(?:[^/\s]+\/)+|\b(?:select|insert|update|delete|merge|drop|alter|create)\b[\s;])/i.test(item)
      || /(?:password|passwd|secret|token|api[_-]?key)\s*[:=]/i.test(item))) fail(code);
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return;
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || !Number.isSafeInteger(item) || Object.is(item, -0)) fail(code);
      return;
    }
    if (typeof item !== 'object' || Array.isArray(item) && item.length > 100000 || seen.has(item)) fail(code);
    seen.add(item);
    for (const [childKey, child] of Object.entries(item)) visit(child, childKey);
    seen.delete(item);
  };
  visit(value);
}

function assertSeal(value, digestKey, code) {
  if (!value || !hash(value[digestKey])) fail(code);
  const {[digestKey]: expected, ...body} = value;
  if (identitySha256(body) !== expected) fail(code);
}

function validateSource(run) {
  assertJson(run);
  assertSeal(run, 'stateSha256', 'DB_OVERVIEW_RUN_TAMPERED');
  if (!ENGINES.has(run.engine) || !hash(run.scopeSha256) || identitySha256(run.scope) !== run.scopeSha256
    || !run.coverage || !Array.isArray(run.coverage.entries) || !Array.isArray(run.coverage.queryCoverage)
    || !Array.isArray(run.probes) || !Array.isArray(run.receipts)) fail('DB_OVERVIEW_SOURCE_INVALID');
  const identifiers = [run.scope?.database, run.scope?.container, ...(run.scope?.schemas ?? [])].filter((item) => item !== null);
  if (identifiers.some((item) => typeof item !== 'string' || !/^[A-Za-z][A-Za-z0-9_$#]{0,127}$/.test(item)
    || /(?:^|[_$#-])(complete|absent|authoritative|verified|truth|trusted)(?:$|[_$#-])/i.test(item))) {
    fail('DB_OVERVIEW_CLAIM_BEARING_IDENTIFIER');
  }
  assertSeal(run.coverage, 'coverageSha256', 'DB_OVERVIEW_COVERAGE_TAMPERED');
  if (run.coverage.engine !== run.engine || !hash(run.coverage.structureSnapshotSha256)
    || !hash(run.coverage.structureCoverageLedgerSha256)
    || run.evidenceBinding?.structureSnapshotSha256 !== run.coverage.structureSnapshotSha256
    || run.evidenceBinding?.structureCoverageSha256 !== run.coverage.structureCoverageLedgerSha256) {
    fail('DB_OVERVIEW_BINDING_DRIFT');
  }
  const objectKeys = new Set();
  for (const entry of run.coverage.entries) {
    if (!exactKeys(entry, ['objectKey', 'objectRef', 'state', 'reasonCode', 'sourceQueryId', 'evidenceRefs', 'absenceClaim'])
      || !hash(entry.objectKey) || identitySha256(entry.objectRef) !== entry.objectKey || objectKeys.has(entry.objectKey)
      || !DATABASE_OVERVIEW_KINDS.includes(entry.objectRef?.kind) || !STATES.includes(entry.state)
      || !(entry.reasonCode === null || REASON_CODE.test(entry.reasonCode)) || entry.absenceClaim !== 'NOT_CLAIMED'
      || !Array.isArray(entry.evidenceRefs) || entry.evidenceRefs.length === 0
      || entry.evidenceRefs.some((item) => !hash(item)) || new Set(entry.evidenceRefs).size !== entry.evidenceRefs.length) {
      fail('DB_OVERVIEW_COVERAGE_INVALID');
    }
    objectKeys.add(entry.objectKey);
  }
  const queryIds = new Set();
  for (const query of run.coverage.queryCoverage) {
    if (queryIds.has(query.queryId) || !(query.reasonCode === null || REASON_CODE.test(query.reasonCode))) fail('DB_OVERVIEW_COVERAGE_INVALID');
    queryIds.add(query.queryId);
  }
  const probes = new Map(run.probes.map((probe) => [probe.probeKey, probe]));
  if (probes.size !== run.probes.length
    || run.probes.some((probe) => probe.coverageSha256 !== run.coverage.coverageSha256)) {
    fail('DB_OVERVIEW_PROBE_INVALID');
  }
  const receiptProbes = new Set();
  for (const receipt of run.receipts) {
    assertSeal(receipt, 'receiptSha256', 'DB_OVERVIEW_RECEIPT_TAMPERED');
    const probe = probes.get(receipt.probeKey);
    if (!probe || receiptProbes.has(receipt.probeKey) || receipt.runId !== run.runId
      || receipt.scopeSha256 !== run.scopeSha256
      || receipt.coverageSha256 !== run.coverage.coverageSha256 || receipt.coverageSha256 !== probe.coverageSha256
      || receipt.methodRef !== probe.methodRef
      || receipt.phase !== probe.phase || canonicalJson(receipt.target) !== canonicalJson(probe.target)
      || receipt.argumentsSha256 !== identitySha256(probe.arguments)
      || !Array.isArray(receipt.evidenceRefs) || receipt.evidenceRefs.some((item) => !hash(item))
      || new Set(receipt.evidenceRefs).size !== receipt.evidenceRefs.length || receipt.blindRetryAllowed !== false) {
      fail('DB_OVERVIEW_RECEIPT_INVALID');
    }
    receiptProbes.add(receipt.probeKey);
  }
  return run;
}

function receiptChain(run) {
  let previousSha256 = identitySha256({runId: run.runId, scopeSha256: run.scopeSha256});
  const links = [...run.receipts].sort((a, b) => compare(a.probeKey, b.probeKey)).map((receipt) => {
    const link = {previousSha256, receiptSha256: receipt.receiptSha256};
    previousSha256 = identitySha256(link);
    return link;
  });
  return {receiptCount: links.length, receiptChainSha256: identitySha256({links, terminalSha256: previousSha256})};
}

function build(run) {
  validateSource(run);
  const byKind = DATABASE_OVERVIEW_KINDS.map((kind) => {
    const entries = run.coverage.entries.filter((entry) => entry.objectRef.kind === kind);
    const count = (state) => entries.filter((entry) => entry.state === state).length;
    return {
      kind,
      visibleCount: count('COMPLETE'),
      partialCount: count('PARTIAL'),
      deniedCount: count('DENIED'),
      unsupportedCount: count('UNSUPPORTED'),
      unknownCount: count('UNKNOWN'),
    };
  });
  const totals = byKind.reduce((sum, item) => ({
    visibleCount: sum.visibleCount + item.visibleCount,
    partialCount: sum.partialCount + item.partialCount,
    deniedCount: sum.deniedCount + item.deniedCount,
    unsupportedCount: sum.unsupportedCount + item.unsupportedCount,
    unknownCount: sum.unknownCount + item.unknownCount,
  }), {visibleCount: 0, partialCount: 0, deniedCount: 0, unsupportedCount: 0, unknownCount: 0});
  const classifiedCount = totals.visibleCount + totals.partialCount + totals.deniedCount + totals.unsupportedCount;
  const totalCount = classifiedCount + totals.unknownCount;
  const coverageBasisPoints = totalCount === 0 ? 0 : Math.floor(classifiedCount * 10000 / totalCount);
  if (totalCount !== run.coverage.summary.visibleObjectCount
    || classifiedCount !== run.coverage.summary.classifiedObjectCount
    || coverageBasisPoints !== run.coverage.summary.coverageBps) fail('DB_OVERVIEW_TOTALS_INCONSISTENT');
  const blindSpotCodes = [...new Set([
    ...run.coverage.entries.filter((entry) => entry.state !== 'COMPLETE').map((entry) => entry.reasonCode ?? `${entry.state}_WITHOUT_REASON`),
    ...run.coverage.queryCoverage.filter((query) => query.state !== 'SUCCEEDED').map((query) => query.reasonCode ?? `${query.state}_WITHOUT_REASON`),
  ])].sort(compare);
  if (blindSpotCodes.some((code) => !REASON_CODE.test(code))) fail('DB_OVERVIEW_BLIND_SPOT_CODE_INVALID');
  const chain = receiptChain(run);
  const cancelledReceiptCount = run.receipts.filter((receipt) => receipt.resultState === 'CANCELLED').length;
  const cancellationState = cancelledReceiptCount === 0 ? 'NOT_CANCELLED' : 'CANCELLED';
  return normalizeJsonValue({
    schemaVersion: DATABASE_OVERVIEW_PROJECTION_SCHEMA,
    projectionKind: 'DATABASE_OVERVIEW',
    bindings: {
      engine: run.engine,
      scopeSha256: run.scopeSha256,
      inventorySnapshotSha256: run.coverage.structureSnapshotSha256,
      coverageLedgerSha256: run.coverage.structureCoverageLedgerSha256,
      coverageSha256: run.coverage.coverageSha256,
      receiptChainSha256: chain.receiptChainSha256,
    },
    countsByKind: byKind,
    totals: {...totals, totalCount},
    coverageBasisPoints,
    blindSpotCodes,
    cancellation: {state: cancellationState, cancelledReceiptCount, receiptCount: chain.receiptCount},
    claims: {completeness: false, absence: false, businessTruth: false},
    authority: {sqlAuthority: 'NONE', dispatchAuthority: 'NONE', mutationAuthority: 'NONE'},
  });
}

export function buildDatabaseOverviewProjection(run) {
  const body = build(run);
  return {...body, projectionSha256: identitySha256(body)};
}

export function verifyDatabaseOverviewProjection(projection, run) {
  assertJson(projection);
  assertSeal(projection, 'projectionSha256', 'DB_OVERVIEW_PROJECTION_TAMPERED');
  const expected = buildDatabaseOverviewProjection(run);
  if (canonicalJson(projection) !== canonicalJson(expected)) fail('DB_OVERVIEW_PROJECTION_MISMATCH');
  return normalizeJsonValue(projection);
}
