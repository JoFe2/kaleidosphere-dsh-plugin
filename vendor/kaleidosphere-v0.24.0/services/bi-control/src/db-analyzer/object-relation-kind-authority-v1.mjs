import {canonicalJson, identitySha256, normalizeJsonValue} from './core.mjs';
import {verifyObjectInventoryAuthorityDigest} from './object-inventory-authority-digest-v1.mjs';
import {buildProgressiveCoverage, resumeProgressiveRun} from './progressive-controller.mjs';

export const OBJECT_RELATION_KIND_AUTHORITY_SCHEMA = 'chimpmaera.db/object-relation-kind-authority/v1';
export const OBJECT_RELATION_KIND_ENVELOPE_SCHEMA = 'chimpmaera.db/object-relation-kind-authority-envelope/v1';
export const OBJECT_RELATION_KIND_AUTHORITY_TYPE = 'OBJECT_RELATION_KIND_AUTHORITY';
export const OBJECT_RELATION_KIND_AUTHORITY_STATE = 'VERIFIED';

const SHA256 = /^[a-f0-9]{64}$/;
const ENGINES = Object.freeze(['mssql', 'oracle']);
const RELATION_KINDS = Object.freeze(['TABLE', 'VIEW']);
const INPUT_KEYS = Object.freeze(['controllerRun', 'inventoryAuthorityProjection', 'structureEvidence']);
const VERIFY_KEYS = Object.freeze([...INPUT_KEYS, 'projection']);
const PROJECTION_KEYS = Object.freeze([
  'schemaVersion', 'type', 'state', 'engine',
  'controllerStateSha256', 'controllerCoverageSha256',
  'inventoryIdentityCommitmentSha256', 'inventoryAuthorityDigestSha256',
  'structureSnapshotSha256', 'structureCoverageLedgerSha256',
  'relationsQuerySha256', 'relationsEvidenceSha256',
  'relationKindEnvelopeSchema', 'mappings', 'relationKindAuthoritySha256',
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

function validateSources(input) {
  if (!exactKeys(input, INPUT_KEYS)) fail('DB_RELATION_KIND_AUTHORITY_INPUT_INVALID');
  const run = resumeProgressiveRun(input.controllerRun);
  if (!ENGINES.includes(run.engine)) fail('DB_RELATION_KIND_AUTHORITY_ENGINE_INVALID');
  const inventory = verifyObjectInventoryAuthorityDigest({
    controllerRun: input.controllerRun,
    projection: input.inventoryAuthorityProjection,
  });
  const structureCoverage = buildProgressiveCoverage(input.structureEvidence);
  if (input.structureEvidence.engine !== run.engine
    || structureCoverage.engine !== run.engine
    || structureCoverage.structureSnapshotSha256 !== run.coverage.structureSnapshotSha256
    || structureCoverage.structureCoverageLedgerSha256 !== run.coverage.structureCoverageLedgerSha256
    || canonicalJson(structureCoverage.queryCoverage) !== canonicalJson(run.coverage.queryCoverage)
    || inventory.engine !== run.engine
    || inventory.controllerStateSha256 !== run.stateSha256) {
    fail('DB_RELATION_KIND_AUTHORITY_SOURCE_MISMATCH');
  }

  const originalByKey = new Map(structureCoverage.entries.map((entry) => [entry.objectKey, entry]));
  if (originalByKey.size !== run.coverage.entries.length) fail('DB_RELATION_KIND_AUTHORITY_STRUCTURE_MISMATCH');
  for (const entry of run.coverage.entries) {
    const original = originalByKey.get(entry.objectKey);
    if (!original
      || canonicalJson(original.objectRef) !== canonicalJson(entry.objectRef)
      || original.sourceQueryId !== entry.sourceQueryId
      || canonicalJson(original.evidenceRefs) !== canonicalJson(entry.evidenceRefs)) {
      fail('DB_RELATION_KIND_AUTHORITY_STRUCTURE_MISMATCH');
    }
  }

  const relationExtracts = input.structureEvidence.extracts.filter((extract) => extract.category === 'relations');
  if (relationExtracts.length !== 1) fail('DB_RELATION_KIND_AUTHORITY_RELATIONS_INVALID');
  const relations = relationExtracts[0];
  const relationEntries = run.coverage.entries.filter((entry) => entry.objectRef.kind === 'RELATION');
  if (relations.rows.length !== relationEntries.length) fail('DB_RELATION_KIND_AUTHORITY_RELATIONS_INVALID');
  const entryBySourceDigest = new Map(relationEntries.map((entry) => [entry.objectRef.sourceObjectSha256, entry]));
  if (entryBySourceDigest.size !== relationEntries.length) fail('DB_RELATION_KIND_AUTHORITY_RELATIONS_INVALID');
  const mappings = relations.rows.map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)
      || !SHA256.test(row.objectSha256 ?? '') || !RELATION_KINDS.includes(row.relation_kind)) {
      fail('DB_RELATION_KIND_AUTHORITY_RELATIONS_INVALID');
    }
    const entry = entryBySourceDigest.get(row.objectSha256);
    if (!entry) fail('DB_RELATION_KIND_AUTHORITY_RELATIONS_INVALID');
    return {objectKey: entry.objectKey, relationKind: row.relation_kind};
  }).sort((left, right) => compare(left.objectKey, right.objectKey));
  if (new Set(mappings.map(({objectKey}) => objectKey)).size !== mappings.length) {
    fail('DB_RELATION_KIND_AUTHORITY_RELATIONS_INVALID');
  }
  return {run, inventory, structureCoverage, relations, mappings};
}

function buildProjection(sources) {
  const {run, inventory, structureCoverage, relations, mappings} = sources;
  const evidence = normalizeJsonValue({
    controllerStateSha256: run.stateSha256,
    controllerCoverageSha256: run.coverage.coverageSha256,
    inventoryIdentityCommitmentSha256: inventory.identityCommitmentSha256,
    inventoryAuthorityDigestSha256: inventory.authorityDigestSha256,
    structureSnapshotSha256: inputDigest(run.coverage.structureSnapshotSha256),
    structureCoverageLedgerSha256: structureCoverage.structureCoverageLedgerSha256,
    relationsQuerySha256: relations.querySha256,
    relationsEvidenceSha256: identitySha256(relations),
  });
  const envelope = normalizeJsonValue({
    schemaVersion: OBJECT_RELATION_KIND_ENVELOPE_SCHEMA,
    type: 'OBJECT_RELATION_KIND_AUTHORITY_ENVELOPE',
    engine: run.engine,
    ...evidence,
    mappings,
  });
  return normalizeJsonValue({
    schemaVersion: OBJECT_RELATION_KIND_AUTHORITY_SCHEMA,
    type: OBJECT_RELATION_KIND_AUTHORITY_TYPE,
    state: OBJECT_RELATION_KIND_AUTHORITY_STATE,
    engine: run.engine,
    ...evidence,
    relationKindEnvelopeSchema: OBJECT_RELATION_KIND_ENVELOPE_SCHEMA,
    mappings,
    relationKindAuthoritySha256: identitySha256(envelope),
  });
}

function inputDigest(value) {
  if (!SHA256.test(value ?? '')) fail('DB_RELATION_KIND_AUTHORITY_DIGEST_INVALID');
  return value;
}

function assertCandidate(candidate, canonical) {
  if (!exactKeys(candidate, PROJECTION_KEYS)
    || candidate.schemaVersion !== OBJECT_RELATION_KIND_AUTHORITY_SCHEMA
    || candidate.type !== OBJECT_RELATION_KIND_AUTHORITY_TYPE
    || candidate.state !== OBJECT_RELATION_KIND_AUTHORITY_STATE
    || !ENGINES.includes(candidate.engine)
    || candidate.relationKindEnvelopeSchema !== OBJECT_RELATION_KIND_ENVELOPE_SCHEMA
    || !Array.isArray(candidate.mappings)
    || candidate.mappings.length > 100000
    || candidate.mappings.some((mapping) => !exactKeys(mapping, ['objectKey', 'relationKind'])
      || !SHA256.test(mapping.objectKey ?? '') || !RELATION_KINDS.includes(mapping.relationKind))
    || PROJECTION_KEYS.filter((key) => key.endsWith('Sha256')).some((key) => !SHA256.test(candidate[key] ?? ''))) {
    fail('DB_RELATION_KIND_AUTHORITY_PROJECTION_INVALID');
  }
  if (canonicalJson(candidate) !== canonicalJson(canonical)) fail('DB_RELATION_KIND_AUTHORITY_CANDIDATE_MISMATCH');
}

function assertNoLeakage(projection, run) {
  const forbidden = new Set([run.runId, ...run.coverage.entries.flatMap((entry) => [
    entry.objectRef.schemaName, entry.objectRef.relationName, entry.objectRef.sourceObjectSha256,
  ])].filter(Boolean));
  const projectedValues = [];
  const visit = (value) => {
    if (typeof value === 'string') projectedValues.push(value);
    else if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === 'object') Object.values(value).forEach(visit);
  };
  visit(projection);
  if (projectedValues.some((value) => forbidden.has(value))) fail('DB_RELATION_KIND_AUTHORITY_IDENTIFIER_LEAKED');
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

export function buildObjectRelationKindAuthority(input) {
  const sources = validateSources(input);
  const projection = buildProjection(sources);
  assertNoLeakage(projection, sources.run);
  return deepFreeze(projection);
}

export function verifyObjectRelationKindAuthority(input) {
  if (!exactKeys(input, VERIFY_KEYS)) fail('DB_RELATION_KIND_AUTHORITY_INPUT_INVALID');
  const {projection, ...sourcesInput} = input;
  const sources = validateSources(sourcesInput);
  const canonical = buildProjection(sources);
  assertCandidate(projection, canonical);
  assertNoLeakage(canonical, sources.run);
  return deepFreeze(canonical);
}
