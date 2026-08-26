import {
  COVERAGE_LEDGER_SCHEMA,
  COVERAGE_STATES,
  canonicalJson,
  identitySha256,
  normalizeJsonValue,
} from './core.mjs';

export const OBJECT_SEARCH_ENVELOPE_SCHEMA = 'chimpmaera.db/object-search-envelope/v1';
export const OBJECT_SEARCH_CURSOR_SCHEMA = 'chimpmaera.db/object-search-cursor/v1';
export const OBJECT_INVENTORY_SNAPSHOT_SCHEMA = 'chimpmaera.db/object-inventory-snapshot/v1';
export const OBJECT_SEARCH_ENGINES = Object.freeze(['mssql', 'oracle', 'postgresql']);
export const OBJECT_SEARCH_KINDS = Object.freeze(['COLUMN', 'INDEX', 'SEQUENCE', 'SYNONYM', 'TABLE', 'VIEW']);
export const OBJECT_SEARCH_MAX_PAGE_SIZE = 500;
export const OBJECT_SEARCH_MAX_PREFIX_LENGTH = 64;
export const OBJECT_SEARCH_MAX_SCHEMAS = 64;

const SHA256 = /^[a-f0-9]{64}$/;
const PREFIX = /^[A-Za-z_][A-Za-z0-9_$]{0,63}$/;
const SECRET_SHAPE = /(?:password|passwd|credential|secret|token|api[_-]?key|connection[_-]?string|dsn)/i;
const UNSAFE_MATERIAL = /sample[_-]?value|raw[_-]?value|password|passwd|credential|secret|token|api[_-]?key|connection[_-]?string|callback|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bEXEC(?:UTE)?\b/i;
const UNSAFE_PATH = /^(?:[A-Za-z]:[\\/]|[/~]|\.{1,2}[\\/])/;
const ENVELOPE_KEYS = [
  'schemaVersion', 'state', 'engine', 'scope', 'prefix', 'kindFilters', 'pageSize', 'inventory', 'coverage',
  'authority', 'envelopeSha256',
];
const CURSOR_KEYS = ['schemaVersion', 'envelopeSha256', 'inventorySnapshotSha256', 'pageIndex', 'opaqueDigest', 'cursorSha256'];
const ENVELOPE_AUTHORITY = Object.freeze({
  callbacksIncluded: false,
  credentialsIncluded: false,
  dispatchAuthorized: false,
  mutationAuthorized: false,
  pathsIncluded: false,
  rowsIncluded: false,
  sqlAccepted: false,
  readOnly: true,
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
const isSafeCount = (value) => Number.isInteger(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;

function seal(body, hashKey) {
  const normalized = normalizeJsonValue(body);
  return {...normalized, [hashKey]: identitySha256(normalized)};
}

function assertSealed(value, hashKey, code) {
  if (!value || !SHA256.test(value[hashKey] ?? '')) fail(code);
  const {[hashKey]: expected, ...body} = value;
  if (identitySha256(body) !== expected) fail(code);
  return value;
}

function assertSafeMaterial(value) {
  if (Array.isArray(value)) {
    value.forEach(assertSafeMaterial);
    return;
  }
  if (value && typeof value === 'object') {
    Object.values(value).forEach(assertSafeMaterial);
    return;
  }
  if (typeof value === 'string' && (UNSAFE_MATERIAL.test(value) || UNSAFE_PATH.test(value))) {
    fail('DB_OBJECT_SEARCH_UNSAFE_MATERIAL');
  }
}

function assertEngine(engine) {
  if (!OBJECT_SEARCH_ENGINES.includes(engine)) fail('DB_OBJECT_SEARCH_ENGINE_INVALID');
}

function assertScope(scope) {
  if (!exactKeys(scope, ['schemas']) || !Array.isArray(scope.schemas) || scope.schemas.length === 0
    || scope.schemas.length > OBJECT_SEARCH_MAX_SCHEMAS
    || scope.schemas.some((schema) => typeof schema !== 'string' || schema.length < 1 || schema.length > 128
      || schema !== schema.normalize('NFC') || /[\0-]/.test(schema) || SECRET_SHAPE.test(schema))
    || new Set(scope.schemas).size !== scope.schemas.length) fail('DB_OBJECT_SEARCH_SCOPE_INVALID');
  return normalizeJsonValue(scope);
}

function normalizePrefix(value) {
  if (typeof value !== 'string' || !PREFIX.test(value) || SECRET_SHAPE.test(value)) fail('DB_OBJECT_SEARCH_PREFIX_INVALID');
  return value;
}

function normalizeKindFilters(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > OBJECT_SEARCH_KINDS.length
    || value.some((kind) => !OBJECT_SEARCH_KINDS.includes(kind))
    || new Set(value).size !== value.length) fail('DB_OBJECT_SEARCH_KIND_FILTERS_INVALID');
  return [...value].sort(compare);
}

function assertPageSize(value) {
  if (!Number.isInteger(value) || value < 1 || value > OBJECT_SEARCH_MAX_PAGE_SIZE) fail('DB_OBJECT_SEARCH_PAGE_SIZE_INVALID');
}

function assertAuthority(authority) {
  if (!exactKeys(authority, Object.keys(ENVELOPE_AUTHORITY))
    || Object.entries(ENVELOPE_AUTHORITY).some(([key, expected]) => authority[key] !== expected)) {
    fail('DB_OBJECT_SEARCH_AUTHORITY_INVALID');
  }
}

function assertInventorySnapshot(inventory, engine) {
  if (!exactKeys(inventory, ['schemaVersion', 'engine', 'objectCount', 'kindCounts', 'inventorySha256'])
    || inventory.schemaVersion !== OBJECT_INVENTORY_SNAPSHOT_SCHEMA
    || inventory.engine !== engine
    || !isSafeCount(inventory.objectCount)
    || !exactKeys(inventory.kindCounts, OBJECT_SEARCH_KINDS)
    || !OBJECT_SEARCH_KINDS.every((kind) => isSafeCount(inventory.kindCounts[kind]))
    || OBJECT_SEARCH_KINDS.reduce((total, kind) => total + inventory.kindCounts[kind], 0) !== inventory.objectCount) {
    fail('DB_OBJECT_SEARCH_INVENTORY_INVALID');
  }
  assertSealed(inventory, 'inventorySha256', 'DB_OBJECT_SEARCH_INVENTORY_TAMPERED');
  return inventory;
}

function assertCoverageBinding(coverage) {
  if (!exactKeys(coverage, ['schemaVersion', 'totalQueries', 'stateCounts', 'coverageSha256'])
    || coverage.schemaVersion !== COVERAGE_LEDGER_SCHEMA
    || !isSafeCount(coverage.totalQueries)
    || !exactKeys(coverage.stateCounts, COVERAGE_STATES)
    || !COVERAGE_STATES.every((state) => isSafeCount(coverage.stateCounts[state]))
    || COVERAGE_STATES.reduce((total, state) => total + coverage.stateCounts[state], 0) !== coverage.totalQueries) {
    fail('DB_OBJECT_SEARCH_COVERAGE_INVALID');
  }
  assertSealed(coverage, 'coverageSha256', 'DB_OBJECT_SEARCH_COVERAGE_TAMPERED');
  return coverage;
}

export function createObjectInventorySnapshot({engine, kindCounts}) {
  assertEngine(engine);
  if (!kindCounts || typeof kindCounts !== 'object' || Array.isArray(kindCounts)
    || Object.keys(kindCounts).some((kind) => !OBJECT_SEARCH_KINDS.includes(kind))
    || Object.values(kindCounts).some((count) => !isSafeCount(count))) {
    fail('DB_OBJECT_SEARCH_INVENTORY_INVALID');
  }
  const counts = Object.fromEntries(OBJECT_SEARCH_KINDS.map((kind) => [kind, kindCounts[kind] ?? 0]));
  const objectCount = Object.values(counts).reduce((total, count) => total + count, 0);
  if (!isSafeCount(objectCount)) fail('DB_OBJECT_SEARCH_INVENTORY_INVALID');
  return seal({
    schemaVersion: OBJECT_INVENTORY_SNAPSHOT_SCHEMA,
    engine,
    objectCount,
    kindCounts: counts,
  }, 'inventorySha256');
}

export function createObjectSearchCoverageBinding({stateCounts}) {
  if (!exactKeys(stateCounts, COVERAGE_STATES)
    || !COVERAGE_STATES.every((state) => isSafeCount(stateCounts[state]))) {
    fail('DB_OBJECT_SEARCH_COVERAGE_INVALID');
  }
  const totalQueries = COVERAGE_STATES.reduce((total, state) => total + stateCounts[state], 0);
  if (!isSafeCount(totalQueries)) fail('DB_OBJECT_SEARCH_COVERAGE_INVALID');
  return seal({
    schemaVersion: COVERAGE_LEDGER_SCHEMA,
    totalQueries,
    stateCounts,
  }, 'coverageSha256');
}

function validateEnvelope(state) {
  assertSealed(state, 'envelopeSha256', 'DB_OBJECT_SEARCH_ENVELOPE_TAMPERED');
  if (!exactKeys(state, ENVELOPE_KEYS) || state.schemaVersion !== OBJECT_SEARCH_ENVELOPE_SCHEMA
    || state.state !== 'SEARCH_REQUESTED' || !OBJECT_SEARCH_ENGINES.includes(state.engine)) {
    fail('DB_OBJECT_SEARCH_ENVELOPE_INVALID');
  }
  assertAuthority(state.authority);
  assertScope(state.scope);
  normalizePrefix(state.prefix);
  if (canonicalJson(normalizeKindFilters(state.kindFilters)) !== canonicalJson(state.kindFilters)) {
    fail('DB_OBJECT_SEARCH_KIND_FILTERS_INVALID');
  }
  assertPageSize(state.pageSize);
  assertInventorySnapshot(state.inventory, state.engine);
  assertCoverageBinding(state.coverage);
  assertSafeMaterial(state);
  return state;
}

export function createObjectSearchEnvelope(input) {
  if (!exactKeys(input, ['engine', 'scope', 'prefix', 'kindFilters', 'pageSize', 'inventory', 'coverage'])) {
    fail('DB_OBJECT_SEARCH_INPUT_INVALID');
  }
  assertEngine(input.engine);
  const scope = assertScope(input.scope);
  const prefix = normalizePrefix(input.prefix);
  const kindFilters = normalizeKindFilters(input.kindFilters);
  assertPageSize(input.pageSize);
  const inventory = assertInventorySnapshot(normalizeJsonValue(input.inventory), input.engine);
  const coverage = assertCoverageBinding(normalizeJsonValue(input.coverage));
  const body = normalizeJsonValue({
    schemaVersion: OBJECT_SEARCH_ENVELOPE_SCHEMA,
    state: 'SEARCH_REQUESTED',
    engine: input.engine,
    scope,
    prefix,
    kindFilters,
    pageSize: input.pageSize,
    inventory,
    coverage,
    authority: {...ENVELOPE_AUTHORITY},
  });
  assertSafeMaterial(body);
  return seal(body, 'envelopeSha256');
}

export function resumeObjectSearchEnvelope(snapshot) {
  return validateEnvelope(normalizeJsonValue(snapshot));
}

function maxPageIndex(state) {
  return Math.ceil(state.inventory.objectCount / state.pageSize) - 1;
}

function makeCursor(state, pageIndex) {
  if (!isSafeCount(pageIndex)) fail('DB_OBJECT_SEARCH_CURSOR_INVALID');
  if (pageIndex > maxPageIndex(state)) fail('DB_OBJECT_SEARCH_CURSOR_EXHAUSTED');
  const envelopeSha256 = state.envelopeSha256;
  const inventorySnapshotSha256 = state.inventory.inventorySha256;
  return seal({
    schemaVersion: OBJECT_SEARCH_CURSOR_SCHEMA,
    envelopeSha256,
    inventorySnapshotSha256,
    pageIndex,
    opaqueDigest: identitySha256({envelopeSha256, inventorySnapshotSha256, pageIndex}),
  }, 'cursorSha256');
}

export function buildObjectSearchCursor(envelope, {pageIndex = 0} = {}) {
  return makeCursor(resumeObjectSearchEnvelope(envelope), pageIndex);
}

export function resumeObjectSearchCursor(envelope, cursor) {
  const state = resumeObjectSearchEnvelope(envelope);
  const value = normalizeJsonValue(cursor);
  if (!exactKeys(value, CURSOR_KEYS) || value.schemaVersion !== OBJECT_SEARCH_CURSOR_SCHEMA
    || !SHA256.test(value.envelopeSha256 ?? '') || !SHA256.test(value.inventorySnapshotSha256 ?? '')
    || !SHA256.test(value.opaqueDigest ?? '')) fail('DB_OBJECT_SEARCH_CURSOR_INVALID');
  assertSealed(value, 'cursorSha256', 'DB_OBJECT_SEARCH_CURSOR_TAMPERED');
  if (value.envelopeSha256 !== state.envelopeSha256
    || value.inventorySnapshotSha256 !== state.inventory.inventorySha256
    || !isSafeCount(value.pageIndex)
    || value.pageIndex > maxPageIndex(state)
    || value.opaqueDigest !== identitySha256({
      envelopeSha256: value.envelopeSha256,
      inventorySnapshotSha256: value.inventorySnapshotSha256,
      pageIndex: value.pageIndex,
    })) fail('DB_OBJECT_SEARCH_CURSOR_BINDING_INVALID');
  return value;
}

export function nextObjectSearchCursor(envelope, cursor) {
  const state = resumeObjectSearchEnvelope(envelope);
  const current = resumeObjectSearchCursor(envelope, cursor);
  return makeCursor(state, current.pageIndex + 1);
}
