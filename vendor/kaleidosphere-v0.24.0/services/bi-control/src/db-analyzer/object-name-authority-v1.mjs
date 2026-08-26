import {canonicalJson, identitySha256, normalizeJsonValue} from './core.mjs';
import {verifyObjectInventoryAuthorityDigest} from './object-inventory-authority-digest-v1.mjs';
import {verifyObjectRelationKindAuthority} from './object-relation-kind-authority-v1.mjs';
import {buildProgressiveCoverage, resumeProgressiveRun} from './progressive-controller.mjs';

export const OBJECT_NAME_AUTHORITY_SCHEMA = 'chimpmaera.db/object-name-authority/v1';
export const OBJECT_NAME_AUTHORITY_ENVELOPE_SCHEMA = 'chimpmaera.db/object-name-authority-envelope/v1';
export const OBJECT_NAME_AUTHORITY_TYPE = 'OBJECT_NAME_AUTHORITY';
export const OBJECT_NAME_AUTHORITY_STATE = 'VERIFIED';

const SHA256 = /^[a-f0-9]{64}$/;
const ENGINES = Object.freeze(['mssql', 'oracle']);
const RELATION_KINDS = Object.freeze(['TABLE', 'VIEW']);
const IDENTIFIER_CLAIM = /(?:^|[_$#-])(verified|complete|exhaustive|authoritative|approved|trusted|confirmed|absent|truth)(?:[_$#-]|$)/i;
const SECRET_SHAPE = /(?:password|passwd|credential|secret|token|api[_-]?key|connection[_-]?string|dsn)/i;
const invalidUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const INPUT_KEYS = Object.freeze(['controllerRun', 'inventoryAuthorityProjection', 'relationKindAuthorityProjection', 'structureEvidence']);
const VERIFY_KEYS = Object.freeze([...INPUT_KEYS, 'projection']);
const MAPPING_KEYS = Object.freeze(['objectKey', 'objectName', 'relationKind']);
const PROJECTION_KEYS = Object.freeze([
  'schemaVersion', 'type', 'state', 'engine',
  'controllerStateSha256', 'controllerCoverageSha256',
  'inventoryIdentityCommitmentSha256', 'inventoryAuthorityDigestSha256',
  'relationKindAuthoritySha256',
  'structureSnapshotSha256', 'structureCoverageLedgerSha256',
  'relationsQuerySha256', 'relationsEvidenceSha256',
  'objectNameEnvelopeSchema', 'mappings', 'objectNameAuthoritySha256',
]);

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
const validObjectName = (value) => typeof value === 'string'
  && value.length > 0 && value.length <= 128
  && value === value.normalize('NFC')
  && !invalidUnicode.test(value)
  && !/[\u0000-\u001f\u007f]/.test(value)
  && !IDENTIFIER_CLAIM.test(value)
  && !SECRET_SHAPE.test(value)
  && !/[;]|--|\/\*|\*\//.test(value);

function validateSources(input) {
  if (!exactKeys(input, INPUT_KEYS)) fail('DB_OBJECT_NAME_AUTHORITY_INPUT_INVALID');
  const run = resumeProgressiveRun(input.controllerRun);
  if (!ENGINES.includes(run.engine)) fail('DB_OBJECT_NAME_AUTHORITY_ENGINE_INVALID');
  const inventory = verifyObjectInventoryAuthorityDigest({
    controllerRun: input.controllerRun,
    projection: input.inventoryAuthorityProjection,
  });
  const relationKind = verifyObjectRelationKindAuthority({
    controllerRun: input.controllerRun,
    inventoryAuthorityProjection: input.inventoryAuthorityProjection,
    structureEvidence: input.structureEvidence,
    projection: input.relationKindAuthorityProjection,
  });
  const structureCoverage = buildProgressiveCoverage(input.structureEvidence);
  if (input.structureEvidence.engine !== run.engine
    || structureCoverage.engine !== run.engine
    || structureCoverage.structureSnapshotSha256 !== run.coverage.structureSnapshotSha256
    || structureCoverage.structureCoverageLedgerSha256 !== run.coverage.structureCoverageLedgerSha256
    || canonicalJson(structureCoverage.queryCoverage) !== canonicalJson(run.coverage.queryCoverage)
    || inventory.engine !== run.engine
    || inventory.controllerStateSha256 !== run.stateSha256
    || relationKind.engine !== run.engine
    || relationKind.controllerStateSha256 !== run.stateSha256
    || relationKind.controllerCoverageSha256 !== run.coverage.coverageSha256
    || relationKind.structureSnapshotSha256 !== run.coverage.structureSnapshotSha256) {
    fail('DB_OBJECT_NAME_AUTHORITY_SOURCE_MISMATCH');
  }

  const originalByKey = new Map(structureCoverage.entries.map((entry) => [entry.objectKey, entry]));
  if (originalByKey.size !== run.coverage.entries.length) fail('DB_OBJECT_NAME_AUTHORITY_STRUCTURE_MISMATCH');
  for (const entry of run.coverage.entries) {
    const original = originalByKey.get(entry.objectKey);
    if (!original
      || canonicalJson(original.objectRef) !== canonicalJson(entry.objectRef)
      || original.sourceQueryId !== entry.sourceQueryId
      || canonicalJson(original.evidenceRefs) !== canonicalJson(entry.evidenceRefs)) {
      fail('DB_OBJECT_NAME_AUTHORITY_STRUCTURE_MISMATCH');
    }
  }

  const relationExtracts = input.structureEvidence.extracts.filter((extract) => extract.category === 'relations');
  if (relationExtracts.length !== 1) fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
  const relations = relationExtracts[0];
  const relationEntries = run.coverage.entries.filter((entry) => entry.objectRef.kind === 'RELATION');
  if (relations.rows.length !== relationEntries.length) fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
  const entryBySourceDigest = new Map(relationEntries.map((entry) => [entry.objectRef.sourceObjectSha256, entry]));
  if (entryBySourceDigest.size !== relationEntries.length) fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
  const mappings = relations.rows.map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)
      || !SHA256.test(row.objectSha256 ?? '') || !RELATION_KINDS.includes(row.relation_kind)) {
      fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
    }
    const entry = entryBySourceDigest.get(row.objectSha256);
    if (!entry) fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
    const objectName = normalizeJsonValue(row.relation_name);
    if (!validObjectName(objectName) || objectName !== entry.objectRef.relationName) {
      fail('DB_OBJECT_NAME_AUTHORITY_NAME_INVALID');
    }
    return {objectKey: entry.objectKey, objectName, relationKind: row.relation_kind};
  }).sort((left, right) => compare(left.objectKey, right.objectKey));
  if (new Set(mappings.map(({objectKey}) => objectKey)).size !== mappings.length) {
    fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
  }
  // Cross-check the derived names/kinds against the independently verified W19 relation-kind authority.
  const kindByKey = new Map(relationKind.mappings.map(({objectKey, relationKind: kind}) => [objectKey, kind]));
  for (const mapping of mappings) {
    if (kindByKey.get(mapping.objectKey) !== mapping.relationKind) fail('DB_OBJECT_NAME_AUTHORITY_SOURCE_MISMATCH');
    if (!kindByKey.has(mapping.objectKey)) fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
  }
  if (kindByKey.size !== mappings.length) fail('DB_OBJECT_NAME_AUTHORITY_RELATIONS_INVALID');
  return {run, inventory, relationKind, structureCoverage, relations, mappings};
}

function buildProjection(sources) {
  const {run, inventory, relationKind, structureCoverage, relations, mappings} = sources;
  const evidence = normalizeJsonValue({
    controllerStateSha256: run.stateSha256,
    controllerCoverageSha256: run.coverage.coverageSha256,
    inventoryIdentityCommitmentSha256: inventory.identityCommitmentSha256,
    inventoryAuthorityDigestSha256: inventory.authorityDigestSha256,
    relationKindAuthoritySha256: relationKind.relationKindAuthoritySha256,
    structureSnapshotSha256: inputDigest(run.coverage.structureSnapshotSha256),
    structureCoverageLedgerSha256: structureCoverage.structureCoverageLedgerSha256,
    relationsQuerySha256: relations.querySha256,
    relationsEvidenceSha256: identitySha256(relations),
  });
  const envelope = normalizeJsonValue({
    schemaVersion: OBJECT_NAME_AUTHORITY_ENVELOPE_SCHEMA,
    type: 'OBJECT_NAME_AUTHORITY_ENVELOPE',
    engine: run.engine,
    ...evidence,
    mappings,
  });
  return normalizeJsonValue({
    schemaVersion: OBJECT_NAME_AUTHORITY_SCHEMA,
    type: OBJECT_NAME_AUTHORITY_TYPE,
    state: OBJECT_NAME_AUTHORITY_STATE,
    engine: run.engine,
    ...evidence,
    objectNameEnvelopeSchema: OBJECT_NAME_AUTHORITY_ENVELOPE_SCHEMA,
    mappings,
    objectNameAuthoritySha256: identitySha256(envelope),
  });
}

function inputDigest(value) {
  if (!SHA256.test(value ?? '')) fail('DB_OBJECT_NAME_AUTHORITY_DIGEST_INVALID');
  return value;
}

function assertCandidate(candidate, canonical) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
    || !exactKeys(candidate, PROJECTION_KEYS)
    || candidate.schemaVersion !== OBJECT_NAME_AUTHORITY_SCHEMA
    || candidate.type !== OBJECT_NAME_AUTHORITY_TYPE
    || candidate.state !== OBJECT_NAME_AUTHORITY_STATE
    || !ENGINES.includes(candidate.engine)
    || candidate.objectNameEnvelopeSchema !== OBJECT_NAME_AUTHORITY_ENVELOPE_SCHEMA
    || !Array.isArray(candidate.mappings)
    || candidate.mappings.length > 100000
    || candidate.mappings.some((mapping) => !exactKeys(mapping, MAPPING_KEYS)
      || !SHA256.test(mapping.objectKey ?? '') || !validObjectName(mapping.objectName ?? '')
      || !RELATION_KINDS.includes(mapping.relationKind))
    || PROJECTION_KEYS.filter((key) => key.endsWith('Sha256')).some((key) => !SHA256.test(candidate[key] ?? ''))) {
    fail('DB_OBJECT_NAME_AUTHORITY_PROJECTION_INVALID');
  }
  if (canonicalJson(candidate) !== canonicalJson(canonical)) fail('DB_OBJECT_NAME_AUTHORITY_CANDIDATE_MISMATCH');
}

function assertNoLeakage(projection, run) {
  const forbidden = new Set([run.runId, ...run.coverage.entries.map((entry) => (
    entry.objectRef.sourceObjectSha256
  ))].filter(Boolean));
  const projectedValues = [];
  const visit = (value) => {
    if (typeof value === 'string') projectedValues.push(value);
    else if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === 'object') Object.values(value).forEach(visit);
  };
  visit(projection);
  if (projectedValues.some((value) => forbidden.has(value))) fail('DB_OBJECT_NAME_AUTHORITY_IDENTIFIER_LEAKED');
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

export function buildObjectNameAuthority(input) {
  const sources = validateSources(input);
  const projection = buildProjection(sources);
  assertNoLeakage(projection, sources.run);
  return deepFreeze(projection);
}

export function verifyObjectNameAuthority(input) {
  if (!exactKeys(input, VERIFY_KEYS)) fail('DB_OBJECT_NAME_AUTHORITY_INPUT_INVALID');
  const {projection, ...sourcesInput} = input;
  const sources = validateSources(sourcesInput);
  const canonical = buildProjection(sources);
  assertCandidate(projection, canonical);
  assertNoLeakage(canonical, sources.run);
  return deepFreeze(canonical);
}