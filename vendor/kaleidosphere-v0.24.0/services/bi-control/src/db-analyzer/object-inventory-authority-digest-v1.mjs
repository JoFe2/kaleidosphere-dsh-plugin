import {canonicalJson, identitySha256, normalizeJsonValue} from './core.mjs';
import {resumeProgressiveRun} from './progressive-controller.mjs';

export const OBJECT_INVENTORY_AUTHORITY_DIGEST_SCHEMA = 'chimpmaera.db/object-inventory-authority-digest/v1';
export const OBJECT_INVENTORY_IDENTITY_ENVELOPE_SCHEMA = 'chimpmaera.db/object-inventory-identity-envelope/v1';
export const OBJECT_INVENTORY_AUTHORITY_ENVELOPE_SCHEMA = 'chimpmaera.db/object-inventory-authority-envelope/v1';
export const OBJECT_INVENTORY_AUTHORITY_DIGEST_TYPE = 'OBJECT_INVENTORY_AUTHORITY_DIGEST';
export const OBJECT_INVENTORY_AUTHORITY_DIGEST_STATE = 'VERIFIED';

const SHA256 = /^[a-f0-9]{64}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,127}$/;
const SCHEMA_VERSION = /^[a-z0-9][a-z0-9._-]{0,127}(?:\/[a-z0-9][a-z0-9._-]{0,127}){0,4}$/;
const IDENTIFIER_CLAIM = /(?:^|[_$#-])(verified|complete|exhaustive|authoritative|approved|trusted|confirmed|absent|truth)(?:[_$#-]|$)/i;
const ENGINES = Object.freeze(['mssql', 'oracle']);
const COVERAGE_STATES = Object.freeze(['COMPLETE', 'PARTIAL', 'DENIED', 'UNSUPPORTED', 'UNKNOWN']);
const IDENTITY_ENVELOPE_TYPE = 'OBJECT_INVENTORY_IDENTITY_ENVELOPE';
const AUTHORITY_ENVELOPE_TYPE = 'OBJECT_INVENTORY_AUTHORITY_ENVELOPE';
const AUTHORITY_FLAGS = Object.freeze({
  approvalAuthority: false,
  callerIdentifiersIncluded: false,
  credentialsIncluded: false,
  cursorAuthority: false,
  dispatchAuthority: false,
  executionAuthority: false,
  mutationAuthority: false,
  pageConstruction: false,
  queryExecution: false,
  rawValuesIncluded: false,
  replayPreventionClaimed: false,
  readOnlyEvidenceOnly: true,
  sqlAuthority: false,
});
const NON_CLAIMS = Object.freeze([
  'NO_RUN_ID',
  'NO_OBJECT_IDENTITY',
  'NO_CALLER_CONTROLLED_PUBLIC_IDENTIFIER',
  'NO_REPLAY_PREVENTION_CLAIM',
  'NO_COMPLETENESS_CLAIM',
  'NO_ABSENCE_CLAIM',
  'NO_BUSINESS_SEMANTIC_TRUTH',
  'NO_SQL_AUTHORITY',
  'NO_DISPATCH_AUTHORITY',
  'NO_MUTATION_AUTHORITY',
]);
const PROJECTION_KEYS = Object.freeze([
  'schemaVersion', 'type', 'state', 'engine',
  'controllerStateSha256', 'identityCommitmentSha256', 'authorityDigestSha256',
  'envelopeSchemas', 'authority', 'nonClaims',
]);
const DIGEST_KEYS = Object.freeze(['controllerStateSha256', 'identityCommitmentSha256', 'authorityDigestSha256']);

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

function validateControllerRun(snapshot) {
  const run = resumeProgressiveRun(snapshot);
  if (!ENGINES.includes(run.engine)) fail('DB_OBJECT_INVENTORY_AUTHORITY_ENGINE_INVALID');
  const scopeIdentifiers = [run.scope.database, run.scope.container, ...run.scope.schemas];
  if (scopeIdentifiers.some((value) => value !== null && IDENTIFIER_CLAIM.test(value))) {
    fail('DB_OBJECT_INVENTORY_AUTHORITY_IDENTIFIER_CLAIM_FORBIDDEN');
  }
  const keys = [];
  for (const entry of run.coverage.entries) {
    const {schemaName, relationName, columnName, objectName} = entry.objectRef;
    if ([schemaName, relationName, columnName, objectName]
      .some((value) => value !== null && IDENTIFIER_CLAIM.test(value))) {
      fail('DB_OBJECT_INVENTORY_AUTHORITY_IDENTIFIER_CLAIM_FORBIDDEN');
    }
    if (identitySha256(entry.objectRef) !== entry.objectKey) fail('DB_OBJECT_INVENTORY_AUTHORITY_IDENTITY_MISMATCH');
    if (entry.absenceClaim !== 'NOT_CLAIMED') fail('DB_OBJECT_INVENTORY_AUTHORITY_CLAIM_FORBIDDEN');
    keys.push(entry.objectKey);
  }
  for (const query of run.coverage.queryCoverage) {
    if (query.absenceClaim !== 'NOT_CLAIMED') fail('DB_OBJECT_INVENTORY_AUTHORITY_CLAIM_FORBIDDEN');
  }
  if (new Set(keys).size !== keys.length) fail('DB_OBJECT_INVENTORY_AUTHORITY_IDENTITY_DUPLICATE');
  if (canonicalJson([...keys].sort(compare)) !== canonicalJson(keys)) fail('DB_OBJECT_INVENTORY_AUTHORITY_IDENTITY_ORDER_INVALID');
  if (identitySha256(run.scope) !== run.scopeSha256) fail('DB_OBJECT_INVENTORY_AUTHORITY_SCOPE_DRIFT');
  if (run.methodRegistry.engine !== run.engine || run.coverage.engine !== run.engine
    || run.evidenceBinding.structureSnapshotSha256 !== run.coverage.structureSnapshotSha256
    || run.evidenceBinding.structureCoverageSha256 !== run.coverage.structureCoverageLedgerSha256) {
    fail('DB_OBJECT_INVENTORY_AUTHORITY_EVIDENCE_DRIFT');
  }
  return run;
}

function buildProjection(run) {
  const entries = run.coverage.entries;
  const identities = entries.map((entry) => normalizeJsonValue({
    objectKey: entry.objectKey,
    evidenceBindings: entry.evidenceRefs,
  }));
  const stateCounts = Object.fromEntries(COVERAGE_STATES.map((state) => [state, entries.filter((entry) => entry.state === state).length]));
  const evidenceDigests = {
    controllerStateSha256: run.stateSha256,
    scopeSha256: run.scopeSha256,
    methodRegistrySha256: run.methodRegistry.registrySha256,
    coverageSha256: run.coverage.coverageSha256,
    structureSnapshotSha256: run.coverage.structureSnapshotSha256,
    structureCoverageLedgerSha256: run.coverage.structureCoverageLedgerSha256,
  };
  const identityEnvelope = normalizeJsonValue({
    schemaVersion: OBJECT_INVENTORY_IDENTITY_ENVELOPE_SCHEMA,
    type: IDENTITY_ENVELOPE_TYPE,
    engine: run.engine,
    ...evidenceDigests,
    identityCount: entries.length,
    stateCounts,
    identities,
  });
  const identityCommitmentSha256 = identitySha256(identityEnvelope);
  const authorityEnvelope = normalizeJsonValue({
    schemaVersion: OBJECT_INVENTORY_AUTHORITY_ENVELOPE_SCHEMA,
    type: AUTHORITY_ENVELOPE_TYPE,
    engine: run.engine,
    ...evidenceDigests,
    identityCommitmentSha256,
  });
  const authorityDigestSha256 = identitySha256(authorityEnvelope);
  return normalizeJsonValue({
    schemaVersion: OBJECT_INVENTORY_AUTHORITY_DIGEST_SCHEMA,
    type: OBJECT_INVENTORY_AUTHORITY_DIGEST_TYPE,
    state: OBJECT_INVENTORY_AUTHORITY_DIGEST_STATE,
    engine: run.engine,
    controllerStateSha256: run.stateSha256,
    identityCommitmentSha256,
    authorityDigestSha256,
    envelopeSchemas: {
      identityEnvelope: OBJECT_INVENTORY_IDENTITY_ENVELOPE_SCHEMA,
      authorityEnvelope: OBJECT_INVENTORY_AUTHORITY_ENVELOPE_SCHEMA,
    },
    authority: {...AUTHORITY_FLAGS},
    nonClaims: [...NON_CLAIMS],
  });
}

function assertCandidate(candidate, canonical) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) fail('DB_OBJECT_INVENTORY_AUTHORITY_PROJECTION_INVALID');
  if (!exactKeys(candidate, PROJECTION_KEYS)) fail('DB_OBJECT_INVENTORY_AUTHORITY_PROJECTION_INVALID');
  if (candidate.schemaVersion !== OBJECT_INVENTORY_AUTHORITY_DIGEST_SCHEMA
    || candidate.type !== OBJECT_INVENTORY_AUTHORITY_DIGEST_TYPE
    || candidate.state !== OBJECT_INVENTORY_AUTHORITY_DIGEST_STATE) {
    fail('DB_OBJECT_INVENTORY_AUTHORITY_PROJECTION_INVALID');
  }
  if (!DIGEST_KEYS.every((key) => SHA256.test(candidate[key] ?? ''))) fail('DB_OBJECT_INVENTORY_AUTHORITY_DIGEST_INVALID');
  if (candidate.engine !== 'mssql' && candidate.engine !== 'oracle') fail('DB_OBJECT_INVENTORY_AUTHORITY_UNSAFE_MATERIAL');
  if (!exactKeys(candidate.envelopeSchemas, ['identityEnvelope', 'authorityEnvelope'])
    || !SCHEMA_VERSION.test(candidate.envelopeSchemas.identityEnvelope ?? '')
    || !SCHEMA_VERSION.test(candidate.envelopeSchemas.authorityEnvelope ?? '')
    || !Array.isArray(candidate.nonClaims) || candidate.nonClaims.some((claim) => !REASON_CODE.test(claim ?? ''))) {
    fail('DB_OBJECT_INVENTORY_AUTHORITY_UNSAFE_MATERIAL');
  }
  if (!exactKeys(candidate.authority, Object.keys(AUTHORITY_FLAGS))
    || Object.entries(AUTHORITY_FLAGS).some(([key, expected]) => candidate.authority[key] !== expected)) {
    fail('DB_OBJECT_INVENTORY_AUTHORITY_CANDIDATE_MISMATCH');
  }
  if (canonicalJson(candidate) !== canonicalJson(canonical)) fail('DB_OBJECT_INVENTORY_AUTHORITY_CANDIDATE_MISMATCH');
  return candidate;
}

function assertNoIdentityLeakage(output, run) {
  const bytes = canonicalJson(output);
  if (bytes.includes(run.runId)) fail('DB_OBJECT_INVENTORY_AUTHORITY_IDENTITY_LEAKED');
  const allowed = new Set([output.controllerStateSha256, output.identityCommitmentSha256, output.authorityDigestSha256]);
  if ((bytes.match(/[a-f0-9]{64}/g) ?? []).some((value) => !allowed.has(value))) fail('DB_OBJECT_INVENTORY_AUTHORITY_IDENTITY_LEAKED');
  return output;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

export function buildObjectInventoryAuthorityDigest(controllerRun) {
  return deepFreeze(buildProjection(validateControllerRun(controllerRun)));
}

export function verifyObjectInventoryAuthorityDigest(input) {
  if (!exactKeys(input, ['controllerRun', 'projection']) || !input.controllerRun || !input.projection) {
    fail('DB_OBJECT_INVENTORY_AUTHORITY_INPUT_INVALID');
  }
  const run = validateControllerRun(input.controllerRun);
  const canonical = buildProjection(run);
  assertCandidate(input.projection, canonical);
  return deepFreeze(assertNoIdentityLeakage(canonical, run));
}
