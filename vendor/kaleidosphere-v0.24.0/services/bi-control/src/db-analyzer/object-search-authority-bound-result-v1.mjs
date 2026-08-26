import {canonicalJson, identitySha256, normalizeJsonValue} from './core.mjs';
import {verifyObjectNameAuthority} from './object-name-authority-v1.mjs';
import {resumeObjectSearchEnvelope} from './object-search-envelope-v1.mjs';

export const OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_SCHEMA = 'chimpmaera.db/object-search-authority-bound-result/v1';
export const OBJECT_SEARCH_AUTHORITY_BOUND_CURSOR_SCHEMA = 'chimpmaera.db/object-search-authority-bound-cursor/v1';
export const OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_TYPE = 'OBJECT_SEARCH_AUTHORITY_BOUND_RESULT';
export const OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_STATE = 'PROJECTED';

const RELATION_KINDS = Object.freeze(['TABLE', 'VIEW']);
const INPUT_KEYS = Object.freeze([
  'controllerRun', 'inventoryAuthorityProjection', 'relationKindAuthorityProjection',
  'objectNameAuthorityProjection', 'structureEvidence', 'request',
]);
const CONTINUATION_INPUT_KEYS = Object.freeze([...INPUT_KEYS, 'cursor']);
const VISIBILITY = Object.freeze({
  COMPLETE: 'VISIBLE',
  PARTIAL: 'VISIBLE_PARTIAL',
  DENIED: 'INVISIBLE',
  UNSUPPORTED: 'NOT_APPLICABLE',
  UNKNOWN: 'UNKNOWN',
});
const CLAIMS = Object.freeze({
  absenceClaimed: false,
  businessTruthEstablished: false,
  completenessClaimed: false,
  replayPreventionClaimed: false,
  sourceRowsIncluded: false,
});
const AUTHORITY = Object.freeze({
  approvalAuthority: false,
  credentialsIncluded: false,
  dispatchAuthority: false,
  executionAuthority: false,
  mutationAuthority: false,
  queryExecution: false,
  rawValuesIncluded: false,
  replayPreventionClaimed: false,
  sqlAuthority: false,
  readOnlyEvidenceOnly: true,
});

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const compare = (left, right) => Buffer.compare(Buffer.from(String(left), 'utf8'), Buffer.from(String(right), 'utf8'));
const exactKeys = (value, keys) => value
  && typeof value === 'object'
  && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

function validateSources(input) {
  if (!exactKeys(input, INPUT_KEYS)) fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_INPUT_INVALID');
  const objectNameAuthority = verifyObjectNameAuthority({
    controllerRun: input.controllerRun,
    inventoryAuthorityProjection: input.inventoryAuthorityProjection,
    relationKindAuthorityProjection: input.relationKindAuthorityProjection,
    structureEvidence: input.structureEvidence,
    projection: input.objectNameAuthorityProjection,
  });
  const request = resumeObjectSearchEnvelope(input.request);
  if (request.engine !== objectNameAuthority.engine) fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_ENGINE_DRIFT');
  if (request.kindFilters.some((kind) => !RELATION_KINDS.includes(kind))) {
    fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_KIND_UNSUPPORTED');
  }
  const run = input.controllerRun;
  const runSchemas = new Set(run.scope.schemas);
  if (!request.scope.schemas.every((schema) => runSchemas.has(schema))) {
    fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_SCOPE_DRIFT');
  }
  const entryByKey = new Map(run.coverage.entries.map((entry) => [entry.objectKey, entry]));
  const mappings = objectNameAuthority.mappings.map((mapping) => {
    const entry = entryByKey.get(mapping.objectKey);
    if (!entry || entry.objectRef.kind !== 'RELATION' || entry.objectRef.schemaName === null) {
      fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_SOURCE_MISMATCH');
    }
    return {mapping, entry};
  });
  return {run, request, objectNameAuthority, mappings};
}

function selectMatches({request, mappings}) {
  const schemas = new Set(request.scope.schemas);
  const kinds = new Set(request.kindFilters);
  return mappings.filter(({mapping, entry}) => (
    schemas.has(entry.objectRef.schemaName)
    && kinds.has(mapping.relationKind)
    && mapping.objectName.startsWith(request.prefix)
  )).sort((left, right) => compare(left.mapping.objectName, right.mapping.objectName)
    || compare(left.mapping.objectKey, right.mapping.objectKey));
}

function itemFor({mapping, entry}) {
  const body = normalizeJsonValue({
    objectKey: mapping.objectKey,
    objectName: mapping.objectName,
    relationKind: mapping.relationKind,
    coverage: {
      state: entry.state,
      reasonCode: entry.reasonCode,
      visibility: VISIBILITY[entry.state],
    },
    evidenceRefs: entry.evidenceRefs.filter((ref) => ref !== entry.objectRef.sourceObjectSha256),
  });
  return {...body, itemSha256: identitySha256(body)};
}

function nextCursor({request, run, objectNameAuthority}) {
  const body = normalizeJsonValue({
    schemaVersion: OBJECT_SEARCH_AUTHORITY_BOUND_CURSOR_SCHEMA,
    pageIndex: 1,
    envelopeSha256: request.envelopeSha256,
    controllerStateSha256: run.stateSha256,
    objectNameAuthoritySha256: objectNameAuthority.objectNameAuthoritySha256,
    consumesState: false,
    replayPreventionClaimed: false,
  });
  return {...body, cursorSha256: identitySha256(body)};
}

export function buildObjectSearchAuthorityBoundResult(input) {
  const sources = validateSources(input);
  const matches = selectMatches(sources);
  const matchCount = matches.length;
  const items = matches.slice(0, sources.request.pageSize).map(itemFor);
  const remainingCount = matchCount - items.length;
  const page = normalizeJsonValue({
    pageIndex: 0,
    pageSize: sources.request.pageSize,
    startOrdinal: 0,
    endOrdinal: items.length === 0 ? -1 : items.length - 1,
    itemCount: items.length,
    matchCount,
    remainingCount,
    hasNext: remainingCount > 0,
  });
  const cursor = page.hasNext ? nextCursor(sources) : null;
  const body = normalizeJsonValue({
    schemaVersion: OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_SCHEMA,
    type: OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_TYPE,
    state: OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_STATE,
    engine: sources.run.engine,
    bindings: {
      controllerStateSha256: sources.run.stateSha256,
      controllerCoverageSha256: sources.run.coverage.coverageSha256,
      inventoryAuthorityDigestSha256: sources.objectNameAuthority.inventoryAuthorityDigestSha256,
      relationKindAuthoritySha256: sources.objectNameAuthority.relationKindAuthoritySha256,
      objectNameAuthoritySha256: sources.objectNameAuthority.objectNameAuthoritySha256,
      structureSnapshotSha256: sources.objectNameAuthority.structureSnapshotSha256,
      envelopeSha256: sources.request.envelopeSha256,
      inventorySnapshotSha256: sources.request.inventory.inventorySha256,
    },
    page,
    items,
    nextCursor: cursor,
    claims: {...CLAIMS},
    authority: {...AUTHORITY},
  });
  return deepFreeze({...body, projectionSha256: identitySha256(body)});
}

export function continueObjectSearchAuthorityBoundResult(input) {
  if (!exactKeys(input, CONTINUATION_INPUT_KEYS)) fail('DB_OBJECT_SEARCH_AUTHORITY_CURSOR_INPUT_INVALID');
  const {cursor, ...baseInput} = input;
  const first = buildObjectSearchAuthorityBoundResult(baseInput);
  if (first.nextCursor === null) fail('DB_OBJECT_SEARCH_AUTHORITY_CURSOR_EXHAUSTED');
  if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)
      || canonicalJson(cursor) !== canonicalJson(first.nextCursor)) {
    fail('DB_OBJECT_SEARCH_AUTHORITY_CURSOR_FORGED');
  }
  const sources = validateSources(baseInput);
  const matches = selectMatches(sources);
  const startOrdinal = sources.request.pageSize;
  const items = matches.slice(startOrdinal, startOrdinal + sources.request.pageSize).map(itemFor);
  const remainingCount = matches.length - startOrdinal - items.length;
  if (remainingCount > 0) fail('DB_OBJECT_SEARCH_AUTHORITY_CURSOR_WINDOW_EXCEEDED');
  const page = normalizeJsonValue({
    pageIndex: 1,
    pageSize: sources.request.pageSize,
    startOrdinal,
    endOrdinal: startOrdinal + items.length - 1,
    itemCount: items.length,
    matchCount: matches.length,
    remainingCount,
    hasNext: false,
  });
  const body = normalizeJsonValue({
    schemaVersion: OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_SCHEMA,
    type: OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_TYPE,
    state: OBJECT_SEARCH_AUTHORITY_BOUND_RESULT_STATE,
    engine: sources.run.engine,
    bindings: {...first.bindings},
    page,
    items,
    nextCursor: null,
    claims: {...CLAIMS},
    authority: {...AUTHORITY},
  });
  return deepFreeze({...body, projectionSha256: identitySha256(body)});
}

function rejectNegativeZero(value) {
  if (typeof value === 'number') {
    if (Object.is(value, -0)) fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_FORGED');
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(rejectNegativeZero);
    return;
  }
  if (value && typeof value === 'object') Object.values(value).forEach(rejectNegativeZero);
}

export function verifyObjectSearchAuthorityBoundResult(projection, input) {
  try {
    // canonicalJson normalizes negative zero to zero, so reject it on the supplied projection before the canonical comparison.
    rejectNegativeZero(projection);
    const expected = buildObjectSearchAuthorityBoundResult(input);
    if (canonicalJson(projection) !== canonicalJson(expected)) fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_FORGED');
    return projection;
  } catch (error) {
    if (error?.code === 'DB_OBJECT_SEARCH_AUTHORITY_RESULT_FORGED') throw error;
    fail('DB_OBJECT_SEARCH_AUTHORITY_RESULT_FORGED');
  }
}
