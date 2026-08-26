import { createHash } from 'node:crypto';

export const QUERY_MANIFEST_SCHEMA = 'chimpmaera.db/query-manifest/v1';
export const PREFLIGHT_EVIDENCE_SCHEMA = 'chimpmaera.db/preflight-evidence/v1';
export const ANALYZE_PROFILE_SCHEMA = 'chimpmaera.db/analyze-profile/v1';
export const PROFILING_POLICY_SCHEMA = 'chimpmaera.db/profiling-policy/v1';
export const PROFILING_QUERY_MANIFEST_SCHEMA = 'chimpmaera.db/profiling-query-manifest/v1';
export const SYNTHETIC_AGGREGATE_RESULTS_SCHEMA = 'chimpmaera.db/synthetic-aggregate-results/v1';
export const AGGREGATE_EVIDENCE_SCHEMA = 'chimpmaera.db/aggregate-evidence/v1';
export const PROFILING_CANDIDATE_SET_SCHEMA = 'chimpmaera.db/profiling-candidate-set/v1';
export const PROFILING_COVERAGE_LEDGER_SCHEMA = 'chimpmaera.db/profiling-coverage-ledger/v1';
export const PROFILING_REVIEW_RECEIPT_SCHEMA = 'chimpmaera.db/profiling-review-receipt/v1';
export const PROFILING_KNOWLEDGE_PACK_SCHEMA = 'chimpmaera.db/profiling-knowledge-pack/v1';
export const PROFILING_SUPERSET_RESULT_SCHEMA = 'chimpmaera.db/profiling-superset-result/v1';
export const POSTGRESQL_WAVE2_POLICY_SCHEMA = 'kaleidosphere.analysis/postgresql-wave2-policy/v1';
export const PROFILING_COVERAGE_STATES = Object.freeze([
  'SUCCEEDED',
  'PARTIAL',
  'DENIED',
  'UNSUPPORTED',
  'TIMEOUT',
  'TAMPER',
]);
export const IDENTITY_CONTRACT_SCHEMA = 'chimpmaera.db/canonical-identity/v1';
export const IDENTITY_CONTRACT = Object.freeze({
  schemaVersion: IDENTITY_CONTRACT_SCHEMA,
  algorithm: 'SHA-256',
  encoding: 'UTF-8',
  stringNormalization: 'NFC',
  lineEndings: 'LF',
  excludedObservationFields: Object.freeze(['observationTimestamp', 'observation_timestamp', 'observedAt']),
});
export const COVERAGE_STATES = Object.freeze([
  'SUCCEEDED',
  'PARTIAL',
  'DENIED',
  'UNSUPPORTED',
  'TIMEOUT',
  'ERROR',
]);
export const COVERAGE_LEDGER_SCHEMA = 'chimpmaera.db/coverage-ledger/v1';
export const CATALOG_SCAN_POLICY_SCHEMA = 'chimpmaera.db/catalog-scan-policy/v1';
export const STORED_LOGIC_EVIDENCE_SCHEMA = 'chimpmaera.db/stored-logic-evidence/v1';
export const STORED_LOGIC_DEFINITION_FINGERPRINT = 'CM-CANONICAL-SHA-256-OF-NATIVE-COMPONENTS/V1';
export const STORED_LOGIC_POLICY_SCHEMA = 'chimpmaera.db/stored-logic-policy/v1';
export const PARSER_ENRICHMENT_POLICY_SCHEMA = 'chimpmaera.db/parser-enrichment-policy/v1';
export const PARSER_ENRICHMENT_EVIDENCE_SCHEMA = 'chimpmaera.db/parser-enrichment-evidence/v1';
export const STORED_LOGIC_LINEAGE_EVIDENCE_SCHEMA = 'chimpmaera.db/stored-logic-lineage-evidence/v1';
export const STORED_LOGIC_IMPACT_REPORT_SCHEMA = 'chimpmaera.db/stored-logic-impact-report/v1';
const COVERAGE_VISIBILITY = Object.freeze({
  SUCCEEDED: 'VISIBLE_COMPLETE',
  PARTIAL: 'VISIBLE_PARTIAL',
  DENIED: 'INVISIBLE',
  UNSUPPORTED: 'NOT_APPLICABLE',
  TIMEOUT: 'UNKNOWN',
  ERROR: 'UNKNOWN',
});
const QUERY_CATEGORIES = new Set([
  'preflight',
  'schemas',
  'relations',
  'columns',
  'comments',
  'constraints',
  'indexes',
  'sequences',
  'synonyms',
  'partitions',
  'lobs',
  'tablespaces',
  'statistics',
  'sizes',
  'stored-objects',
  'stored-arguments',
  'stored-errors',
  'stored-dependencies',
  'dependencies',
  'operations',
  'db-links',
]);

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const invalidUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const normalizeString = (value) => {
  if (invalidUnicode.test(value)) fail('DB_CANONICAL_UNICODE_INVALID');
  return value.replace(/\r\n?/g, '\n').normalize('NFC');
};

export const normalizeJsonValue = (value) => {
  if (typeof value === 'string') return normalizeString(value);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('DB_CANONICAL_NUMBER_INVALID');
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) return value.map(normalizeJsonValue);
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('DB_CANONICAL_VALUE_INVALID');
  const entries = Object.keys(value).map((key) => [normalizeString(key), normalizeJsonValue(value[key])]);
  if (new Set(entries.map(([key]) => key)).size !== entries.length) fail('DB_CANONICAL_KEY_COLLISION');
  return Object.fromEntries(entries.sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0));
};

export const canonicalJson = (value) => `${JSON.stringify(normalizeJsonValue(value))}\n`;
export const sha256 = (value) => createHash('sha256').update(typeof value === 'string' ? value : canonicalJson(value)).digest('hex');
export const normalizeSql = (sql) => `${normalizeString(sql).trim()}\n`;

const withoutObservationFields = (value) => Array.isArray(value)
  ? value.map(withoutObservationFields)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.entries(value)
      .filter(([key]) => !IDENTITY_CONTRACT.excludedObservationFields.includes(key))
      .map(([key, entry]) => [key, withoutObservationFields(entry)]))
    : value;

export const identitySha256 = (value) => sha256(withoutObservationFields(value));

const hasExactKeys = (value, expected) => value
  && typeof value === 'object'
  && !Array.isArray(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort());

const validScopedName = (value) => typeof value === 'string'
  && value.length > 0
  && value.length <= 128
  && value === value.normalize('NFC')
  && !invalidUnicode.test(value)
  && !/[\u0000-\u001f\u007f]/.test(value);

const postgresqlScopedIdentifier = (value) => typeof value === 'string'
  && /^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(value);

const PROFILING_OUTPUT_COLUMNS = Object.freeze({
  NUMERIC: Object.freeze(['rowCount', 'nullCount', 'distinctCount', 'minimum', 'maximum']),
  TEMPORAL: Object.freeze(['rowCount', 'nullCount', 'distinctCount', 'minimum', 'maximum', 'freshnessMaximum']),
  CATEGORY: Object.freeze(['rowCount', 'nullCount', 'distinctCount']),
  TEXT: Object.freeze(['rowCount', 'nullCount', 'distinctCount']),
  BOOLEAN: Object.freeze(['rowCount', 'nullCount', 'distinctCount']),
});
const PROFILING_TEMPLATE_MARKERS = Object.freeze(['SCHEMA', 'RELATION', 'COLUMN']);
const PROFILING_FORBIDDEN_SQL = /\b(?:ALTER|CREATE|DELETE|DROP|EXEC(?:UTE)?|GRANT|INSERT|MERGE|REVOKE|TRUNCATE|UPDATE)\b/i;

export function validateProfilingQueryManifest(manifest, sqlByQueryId) {
  if (!hasExactKeys(manifest, ['schemaVersion', 'packId', 'packVersion', 'engine', 'queries'])
    || manifest.schemaVersion !== PROFILING_QUERY_MANIFEST_SCHEMA
    || !['mssql', 'oracle'].includes(manifest.engine)
    || typeof manifest.packId !== 'string' || manifest.packId.length === 0
    || typeof manifest.packVersion !== 'string' || !/^\d+\.\d+\.\d+$/.test(manifest.packVersion)
    || !Array.isArray(manifest.queries) || manifest.queries.length === 0) fail('DB_PROFILING_QUERY_MANIFEST_INVALID');
  const ids = new Set();
  const families = new Set();
  for (const query of manifest.queries) {
    if (!hasExactKeys(query, ['id', 'category', 'file', 'templateSha256', 'typeFamilies', 'nativeTypes', 'outputColumns', 'sortKeys', 'readOnly', 'aggregateOnly', 'rowSamples', 'labelDistributions', 'cost', 'timeoutMs', 'privilege', 'fallback', 'provenance'])
      || typeof query.id !== 'string' || ids.has(query.id)
      || !['numeric-aggregate', 'temporal-aggregate', 'category-aggregate', 'text-aggregate', 'boolean-aggregate'].includes(query.category)
      || typeof query.file !== 'string' || pathLike(query.file)
      || typeof query.templateSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(query.templateSha256)
      || !Array.isArray(query.typeFamilies) || query.typeFamilies.length !== 1
      || !Object.hasOwn(PROFILING_OUTPUT_COLUMNS, query.typeFamilies[0])
      || query.category !== `${query.typeFamilies[0].toLowerCase()}-aggregate`
      || query.typeFamilies.some((family) => families.has(family))
      || !Array.isArray(query.nativeTypes) || query.nativeTypes.length === 0
      || query.nativeTypes.some((type) => typeof type !== 'string' || type.length === 0)
      || canonicalJson(query.outputColumns) !== canonicalJson(PROFILING_OUTPUT_COLUMNS[query.typeFamilies[0]])
      || canonicalJson(query.sortKeys) !== canonicalJson([])
      || query.readOnly !== true || query.aggregateOnly !== true
      || query.rowSamples !== false || query.labelDistributions !== false
      || query.cost !== 'BOUNDED_SCAN' || !Number.isInteger(query.timeoutMs) || query.timeoutMs < 1
      || typeof query.privilege?.minimum !== 'string' || query.privilege.minimum.length === 0
      || typeof query.fallback?.onDenied !== 'string' || query.fallback.onDenied.length === 0
      || query.provenance?.sourceType !== 'OFFICIAL_AGGREGATE_API_REFERENCE'
      || typeof query.provenance?.url !== 'string' || query.provenance.spdx !== 'Apache-2.0'
      || query.provenance.copiedCode !== false
      || !/CM-authored/.test(query.provenance.changeMarker ?? '')) fail('DB_PROFILING_QUERY_MANIFEST_INVALID');
    ids.add(query.id);
    query.typeFamilies.forEach((family) => families.add(family));
    if (sqlByQueryId !== undefined) {
      const sql = sqlByQueryId[query.id];
      const markers = [...(sql?.matchAll(/\{\{([A-Z]+)\}\}/g) ?? [])].map((match) => match[1]);
      const executable = sql?.replace(/'(?:''|[^'])*'/g, "''") ?? '';
      const semicolons = executable.match(/;/g) ?? [];
      if (typeof sql !== 'string' || sha256(normalizeSql(sql)) !== query.templateSha256
        || !/^SELECT\b/i.test(normalizeSql(sql))
        || PROFILING_FORBIDDEN_SQL.test(executable)
        || /\b(?:TOP|SAMPLE|FETCH)\b/i.test(executable)
        || /SELECT\s+\*/i.test(executable)
        || (executable.match(/\bSELECT\b/gi) ?? []).length !== 1
        || (executable.match(/\bFROM\b/gi) ?? []).length !== 1
        || semicolons.length !== 1 || !/;\s*$/.test(executable)
        || /--|\/\*/.test(executable)
        || markers.some((marker) => !PROFILING_TEMPLATE_MARKERS.includes(marker))
        || !PROFILING_TEMPLATE_MARKERS.every((marker) => markers.includes(marker))) fail('DB_PROFILING_QUERY_TEMPLATE_DENIED');
    }
  }
  if (sqlByQueryId !== undefined
    && canonicalJson(Object.keys(sqlByQueryId).sort()) !== canonicalJson([...ids].sort())) fail('DB_PROFILING_QUERY_TEMPLATE_DENIED');
  return manifest;
}

const quoteProfilingIdentifier = (engine, value) => {
  if (!validScopedName(value)) fail('DB_PROFILING_QUERY_SCOPE_INVALID');
  return engine === 'mssql' ? `[${value.replaceAll(']', ']]')}]` : `"${value.replaceAll('"', '""')}"`;
};

export function compileProfilingQuery({ manifest, sqlByQueryId, target }) {
  validateProfilingQueryManifest(manifest, sqlByQueryId);
  if (!hasExactKeys(target, ['schemaName', 'relationName', 'columnName', 'typeFamily'])) fail('DB_PROFILING_QUERY_TARGET_INVALID');
  const query = manifest.queries.find((entry) => entry.typeFamilies.includes(target.typeFamily));
  if (!query) fail('DB_PROFILING_TYPE_FAMILY_UNSUPPORTED');
  const replacements = {
    SCHEMA: quoteProfilingIdentifier(manifest.engine, target.schemaName),
    RELATION: quoteProfilingIdentifier(manifest.engine, target.relationName),
    COLUMN: quoteProfilingIdentifier(manifest.engine, target.columnName),
  };
  const sql = normalizeSql(sqlByQueryId[query.id].replace(/\{\{([A-Z]+)\}\}/g, (_match, marker) => replacements[marker]));
  if (/\{\{/.test(sql)) fail('DB_PROFILING_QUERY_TEMPLATE_DENIED');
  return normalizeJsonValue({
    queryId: query.id,
    schemaName: target.schemaName,
    relationName: target.relationName,
    columnName: target.columnName,
    typeFamily: target.typeFamily,
    timeoutMs: query.timeoutMs,
    outputColumns: query.outputColumns,
    querySha256: sha256(sql),
  });
}

function validateProfilingPolicy(profile) {
  const profiling = profile.policy.profiling;
  if (!hasExactKeys(profiling, ['schemaVersion', 'enabled', 'scope', 'budgets', 'disclosure', 'cancellation', 'aggregateFixture'])
    || profiling.schemaVersion !== PROFILING_POLICY_SCHEMA
    || profiling.enabled !== true
    || !Array.isArray(profiling.scope) || profiling.scope.length === 0) fail('DB_PROFILING_POLICY_INVALID');
  const targets = new Set();
  let columnCount = 0;
  for (const target of profiling.scope) {
    if (!hasExactKeys(target, ['schemaName', 'relationName', 'columns'])
      || !profile.scope.schemas.includes(target.schemaName)
      || !validScopedName(target.relationName)
      || !Array.isArray(target.columns) || target.columns.length === 0
      || target.columns.some((column) => !validScopedName(column))
      || new Set(target.columns).size !== target.columns.length) fail('DB_PROFILING_SCOPE_INVALID');
    const targetKey = `${target.schemaName}\u0000${target.relationName}`;
    if (targets.has(targetKey)) fail('DB_PROFILING_SCOPE_INVALID');
    targets.add(targetKey);
    columnCount += target.columns.length;
  }
  const budgets = profiling.budgets;
  if (!hasExactKeys(budgets, ['maxRelations', 'maxColumns', 'maxQueries', 'maxDistributionBuckets', 'maxQueryTimeoutMs'])
    || !Object.values(budgets).every(Number.isInteger)
    || budgets.maxRelations < profiling.scope.length
    || budgets.maxColumns < columnCount
    || budgets.maxQueries < columnCount
    || budgets.maxDistributionBuckets < 0
    || budgets.maxQueryTimeoutMs < 1
    || budgets.maxQueryTimeoutMs > profile.policy.maxQueryTimeoutMs) fail('DB_PROFILING_BUDGET_INVALID');
  if (!hasExactKeys(profiling.disclosure, ['allowRowSamples', 'allowLabelDistributions', 'maxLabelCardinality', 'sensitiveTargets'])
    || profiling.disclosure.allowRowSamples !== false
    || profiling.disclosure.allowLabelDistributions !== false
    || profiling.disclosure.maxLabelCardinality !== 0
    || !Array.isArray(profiling.disclosure.sensitiveTargets)
    || budgets.maxDistributionBuckets !== 0) fail('DB_PROFILING_DISCLOSURE_DENIED');
  const sensitiveTargets = new Set();
  const allowedColumns = new Set(profiling.scope.flatMap((target) => target.columns
    .map((columnName) => `${target.schemaName}\u0000${target.relationName}\u0000${columnName}`)));
  for (const target of profiling.disclosure.sensitiveTargets) {
    if (!hasExactKeys(target, ['schemaName', 'relationName', 'columnName', 'classification'])
      || target.classification !== 'SENSITIVE') fail('DB_PROFILING_DISCLOSURE_DENIED');
    const key = `${target.schemaName}\u0000${target.relationName}\u0000${target.columnName}`;
    if (!allowedColumns.has(key) || sensitiveTargets.has(key)) fail('DB_PROFILING_DISCLOSURE_DENIED');
    sensitiveTargets.add(key);
  }
  if (!hasExactKeys(profiling.cancellation, ['onTimeout', 'onAbort'])
    || profiling.cancellation.onTimeout !== 'FAIL_CLOSED'
    || profiling.cancellation.onAbort !== 'FAIL_CLOSED') fail('DB_PROFILING_CANCELLATION_INVALID');
  if (profile.mode === 'SYNTHETIC') {
    if (typeof profiling.aggregateFixture !== 'string' || pathLike(profiling.aggregateFixture)) fail('DB_PROFILING_FIXTURE_INVALID');
  } else if (profiling.aggregateFixture !== null) fail('DB_PROFILING_FIXTURE_INVALID');
  return profiling;
}

function validateStoredLogicPolicy(profile) {
  const storedLogic = profile.policy.storedLogic;
  const keys = ['schemaVersion', 'enabled', 'definitionDisclosure', 'fixture'];
  if (storedLogic && Object.hasOwn(storedLogic, 'parserEnrichment')) keys.push('parserEnrichment');
  if (!hasExactKeys(storedLogic, keys)
    || storedLogic.schemaVersion !== STORED_LOGIC_POLICY_SCHEMA
    || storedLogic.enabled !== true
    || storedLogic.definitionDisclosure !== 'HASH_ONLY') fail('DB_STORED_LOGIC_POLICY_INVALID');
  if (profile.mode === 'SYNTHETIC') {
    if (typeof storedLogic.fixture !== 'string' || pathLike(storedLogic.fixture)) fail('DB_STORED_LOGIC_FIXTURE_INVALID');
  } else if (storedLogic.fixture !== null) fail('DB_STORED_LOGIC_FIXTURE_INVALID');
  if (Object.hasOwn(storedLogic, 'parserEnrichment')) {
    const enrichment = storedLogic.parserEnrichment;
    if (!hasExactKeys(enrichment, ['schemaVersion', 'enabled', 'mode', 'onUnavailable', 'fixture'])
      || enrichment.schemaVersion !== PARSER_ENRICHMENT_POLICY_SCHEMA
      || enrichment.enabled !== true
      || enrichment.mode !== 'OPTIONAL'
      || enrichment.onUnavailable !== 'CONTINUE_NATIVE_ONLY') fail('DB_PARSER_POLICY_INVALID');
    if (profile.mode === 'SYNTHETIC') {
      if (typeof enrichment.fixture !== 'string' || pathLike(enrichment.fixture)) fail('DB_PARSER_FIXTURE_INVALID');
    } else if (enrichment.fixture !== null) fail('DB_PARSER_FIXTURE_INVALID');
  }
  return storedLogic;
}

function validateCatalogScanPolicy(policy) {
  if (!hasExactKeys(policy, [
    'schemaVersion', 'allowedQueryIds', 'maxQueries', 'maxRowsPerQuery', 'maxTotalRows',
  ])
    || policy.schemaVersion !== CATALOG_SCAN_POLICY_SCHEMA
    || !Array.isArray(policy.allowedQueryIds) || policy.allowedQueryIds.length === 0
    || policy.allowedQueryIds.some((queryId) => typeof queryId !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(queryId))
    || new Set(policy.allowedQueryIds).size !== policy.allowedQueryIds.length
    || ![policy.maxQueries, policy.maxRowsPerQuery, policy.maxTotalRows].every(Number.isInteger)
    || policy.maxQueries < 1 || policy.maxRowsPerQuery < 1 || policy.maxTotalRows < 1
    || policy.allowedQueryIds.length > policy.maxQueries) fail('DB_CATALOG_SCAN_POLICY_INVALID');
  return policy;
}

export function validatePostgresqlWave2Policy(profile) {
  const policy = profile?.policy?.postgresqlAnalysis;
  if (!hasExactKeys(policy, [
    'schemaVersion', 'enabled', 'profileTargets', 'sensitiveTargets',
    'relationshipCandidates', 'budgets', 'disclosure',
  ]) || policy.schemaVersion !== POSTGRESQL_WAVE2_POLICY_SCHEMA
    || policy.enabled !== true
    || profile.engine !== 'postgresql' || profile.mode !== 'RUNTIME'
    || !Array.isArray(policy.profileTargets) || policy.profileTargets.length === 0
    || !Array.isArray(policy.sensitiveTargets)) fail('DB_WAVE2_POLICY_INVALID');

  const targetKey = (target) => `${target.schemaName}\u0000${target.relationName}\u0000${target.columnName}`;
  const targets = new Set();
  for (const target of policy.profileTargets) {
    if (!hasExactKeys(target, ['schemaName', 'relationName', 'columnName'])
      || !profile.scope.schemas.includes(target.schemaName)
      || ![target.schemaName, target.relationName, target.columnName].every(postgresqlScopedIdentifier)
      || targets.has(targetKey(target))) fail('DB_WAVE2_PROFILE_SCOPE_INVALID');
    targets.add(targetKey(target));
  }
  const sensitive = new Set();
  for (const target of policy.sensitiveTargets) {
    if (!hasExactKeys(target, ['schemaName', 'relationName', 'columnName', 'classification'])
      || target.classification !== 'SENSITIVE'
      || !profile.scope.schemas.includes(target.schemaName)
      || ![target.schemaName, target.relationName, target.columnName].every(postgresqlScopedIdentifier)
      || sensitive.has(targetKey(target))) fail('DB_WAVE2_DISCLOSURE_INVALID');
    sensitive.add(targetKey(target));
  }
  if ([...targets].some((key) => sensitive.has(key))) fail('DB_WAVE2_SENSITIVE_TARGET_DENIED');

  const relationship = policy.relationshipCandidates;
  if (!hasExactKeys(relationship, ['enabled', 'nameMatch', 'minimumConfidenceBasisPoints'])
    || relationship.enabled !== true
    || relationship.nameMatch !== 'EXACT_COLUMN_NAME'
    || !Number.isInteger(relationship.minimumConfidenceBasisPoints)
    || relationship.minimumConfidenceBasisPoints < 1
    || relationship.minimumConfidenceBasisPoints > 10000) fail('DB_WAVE2_RELATIONSHIP_POLICY_INVALID');

  const budgets = policy.budgets;
  if (!hasExactKeys(budgets, [
    'maxProfileTargets', 'maxRelationshipCandidates', 'maxQueries', 'maxQueryTimeoutMs',
  ]) || !Object.values(budgets).every(Number.isInteger)
    || budgets.maxProfileTargets < policy.profileTargets.length
    || budgets.maxRelationshipCandidates < 1
    || budgets.maxQueries < policy.profileTargets.length + budgets.maxRelationshipCandidates
    || budgets.maxQueryTimeoutMs < 1000
    || budgets.maxQueryTimeoutMs > profile.policy.maxQueryTimeoutMs) fail('DB_WAVE2_BUDGET_INVALID');

  if (!hasExactKeys(policy.disclosure, ['allowRawValues', 'allowExampleValues', 'allowDistributions'])
    || policy.disclosure.allowRawValues !== false
    || policy.disclosure.allowExampleValues !== false
    || policy.disclosure.allowDistributions !== false) fail('DB_WAVE2_DISCLOSURE_INVALID');
  return policy;
}

export function validateAnalyzeProfile(profile) {
  if (profile?.schemaVersion !== ANALYZE_PROFILE_SCHEMA) fail('DB_ANALYZE_PROFILE_SCHEMA_INVALID');
  if (!hasExactKeys(profile, ['schemaVersion', 'profileId', 'engine', 'mode', 'queryPack', 'scope', 'policy', 'adapter'])) fail('DB_ANALYZE_PROFILE_FIELDS_INVALID');
  if (typeof profile.profileId !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(profile.profileId)) fail('DB_ANALYZE_PROFILE_ID_INVALID');
  if (!['mssql', 'oracle', 'postgresql'].includes(profile.engine)) fail('DB_ANALYZE_PROFILE_ENGINE_INVALID');
  if (!['SYNTHETIC', 'RUNTIME'].includes(profile.mode)) fail('DB_ANALYZE_PROFILE_MODE_UNSUPPORTED');
  if (!hasExactKeys(profile.queryPack, ['version']) || profile.queryPack.version !== 'v1') fail('DB_ANALYZE_PROFILE_PACK_INVALID');
  if (!hasExactKeys(profile.scope, ['database', 'container', 'schemas'])
    || typeof profile.scope.database !== 'string' || profile.scope.database.length === 0
    || !(profile.scope.container === null || typeof profile.scope.container === 'string')
    || !Array.isArray(profile.scope.schemas) || profile.scope.schemas.length === 0
    || profile.scope.schemas.some((schema) => typeof schema !== 'string' || schema.length === 0)
    || new Set(profile.scope.schemas).size !== profile.scope.schemas.length) fail('DB_ANALYZE_PROFILE_SCOPE_INVALID');
  const policyKeys = ['access', 'allowRowSamples', 'maxQueryTimeoutMs'];
  if (profile.policy && Object.hasOwn(profile.policy, 'catalogScan')) policyKeys.push('catalogScan');
  if (profile.policy && Object.hasOwn(profile.policy, 'profiling')) policyKeys.push('profiling');
  if (profile.policy && Object.hasOwn(profile.policy, 'storedLogic')) policyKeys.push('storedLogic');
  if (profile.policy && Object.hasOwn(profile.policy, 'postgresqlAnalysis')) policyKeys.push('postgresqlAnalysis');
  if (!hasExactKeys(profile.policy, policyKeys)
    || profile.policy.access !== 'READ_ONLY' || profile.policy.allowRowSamples !== false
    || !Number.isInteger(profile.policy.maxQueryTimeoutMs) || profile.policy.maxQueryTimeoutMs < 1) fail('DB_ANALYZE_PROFILE_POLICY_INVALID');
  if (Object.hasOwn(profile.policy, 'profiling')) validateProfilingPolicy(profile);
  if (Object.hasOwn(profile.policy, 'storedLogic')) validateStoredLogicPolicy(profile);
  if (Object.hasOwn(profile.policy, 'catalogScan')) validateCatalogScanPolicy(profile.policy.catalogScan);
  if (Object.hasOwn(profile.policy, 'postgresqlAnalysis')) validatePostgresqlWave2Policy(profile);
  if (profile.mode === 'SYNTHETIC') {
    if (!hasExactKeys(profile.adapter, ['kind', 'fixture']) || profile.adapter.kind !== 'synthetic'
      || typeof profile.adapter.fixture !== 'string' || pathLike(profile.adapter.fixture)) fail('DB_ANALYZE_PROFILE_ADAPTER_INVALID');
  } else {
    const commonInvalid = typeof profile.adapter?.host !== 'string' || profile.adapter.host.length === 0
      || !Number.isInteger(profile.adapter.port) || profile.adapter.port < 1 || profile.adapter.port > 65535
      || typeof profile.adapter.user !== 'string' || profile.adapter.user.length === 0
      || typeof profile.adapter.passwordEnv !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(profile.adapter.passwordEnv);
    const mssqlInvalid = profile.engine === 'mssql' && (!hasExactKeys(profile.adapter, ['kind', 'host', 'port', 'user', 'passwordEnv', 'encrypt', 'trustServerCertificate'])
      || profile.adapter.kind !== 'mssql'
      || typeof profile.adapter.encrypt !== 'boolean' || typeof profile.adapter.trustServerCertificate !== 'boolean');
    const oracleInvalid = profile.engine === 'oracle' && (!hasExactKeys(profile.adapter, ['kind', 'host', 'port', 'user', 'passwordEnv', 'protocol', 'serviceName', 'serverDn', 'connectTimeoutMs'])
      || profile.adapter.kind !== 'oracle'
      || !['tcp', 'tcps'].includes(profile.adapter.protocol)
      || typeof profile.adapter.serviceName !== 'string' || profile.adapter.serviceName.length === 0
      || !(profile.adapter.serverDn === null || typeof profile.adapter.serverDn === 'string')
      || !Number.isInteger(profile.adapter.connectTimeoutMs) || profile.adapter.connectTimeoutMs < 1);
    const postgresqlInvalid = profile.engine === 'postgresql' && (!hasExactKeys(profile.adapter, ['kind', 'host', 'port', 'user', 'passwordEnv', 'ssl', 'connectTimeoutMs'])
      || profile.adapter.kind !== 'postgresql'
      || typeof profile.adapter.ssl !== 'boolean'
      || !Number.isInteger(profile.adapter.connectTimeoutMs) || profile.adapter.connectTimeoutMs < 1000 || profile.adapter.connectTimeoutMs > 120000
      || profile.policy.maxQueryTimeoutMs < 1000 || profile.policy.maxQueryTimeoutMs > 120000
      || !postgresqlScopedIdentifier(profile.scope.database) || !postgresqlScopedIdentifier(profile.adapter.user)
      || profile.scope.schemas.some((schema) => !postgresqlScopedIdentifier(schema)));
    if (commonInvalid || mssqlInvalid || oracleInvalid || postgresqlInvalid) fail('DB_ANALYZE_PROFILE_ADAPTER_INVALID');
  }
  return profile;
}

const pathLike = (value) => value !== value.split(/[\\/]/).at(-1) || value === '.' || value === '..';

const profilingTarget = (value) => ({
  schemaName: value.schemaName,
  relationName: value.relationName,
  columnName: value.columnName,
});

const profilingTargetKey = (value) => `${value.schemaName}\u0000${value.relationName}\u0000${value.columnName}`;

export function buildProfilingCoverageLedger({ profile, attempts }) {
  const profiling = validateProfilingPolicy(profile);
  if (!Array.isArray(attempts) || attempts.length === 0 || attempts.length > profiling.budgets.maxQueries) {
    fail('DB_PROFILING_COVERAGE_INVALID');
  }
  const allowed = new Set(profiling.scope.flatMap((target) => target.columns
    .map((columnName) => `${target.schemaName}\u0000${target.relationName}\u0000${columnName}`)));
  const seen = new Set();
  const entries = attempts.map((attempt) => {
    if (!hasExactKeys(attempt, ['schemaName', 'relationName', 'columnName', 'typeFamily', 'state', 'reasonCode', 'factSha256'])
      || !Object.hasOwn(PROFILING_OUTPUT_COLUMNS, attempt.typeFamily)
      || !PROFILING_COVERAGE_STATES.includes(attempt.state)) fail('DB_PROFILING_COVERAGE_TAMPERED');
    const key = profilingTargetKey(attempt);
    if (!allowed.has(key) || seen.has(key)) fail('DB_PROFILING_COVERAGE_SCOPE_INVALID');
    seen.add(key);
    const visible = attempt.state === 'SUCCEEDED' || attempt.state === 'PARTIAL';
    if ((attempt.state === 'SUCCEEDED' && attempt.reasonCode !== null)
      || (attempt.state !== 'SUCCEEDED' && (typeof attempt.reasonCode !== 'string' || !/^[A-Z][A-Z0-9_]{2,127}$/.test(attempt.reasonCode)))
      || (visible && !/^[a-f0-9]{64}$/.test(attempt.factSha256 ?? ''))
      || (!visible && attempt.factSha256 !== null)) fail('DB_PROFILING_COVERAGE_TAMPERED');
    return normalizeJsonValue({
      target: profilingTarget(attempt),
      typeFamily: attempt.typeFamily,
      state: attempt.state,
      reasonCode: attempt.reasonCode,
      visibility: visible ? (attempt.state === 'SUCCEEDED' ? 'VISIBLE_COMPLETE' : 'VISIBLE_PARTIAL') : 'NOT_VISIBLE',
      factSha256: attempt.factSha256,
      reviewState: 'REVIEW_REQUIRED',
    });
  }).sort((left, right) => compareRows(['schemaName', 'relationName', 'columnName'])(left.target, right.target));
  const stateCounts = Object.fromEntries(PROFILING_COVERAGE_STATES.map((state) => [state, entries.filter((entry) => entry.state === state).length]));
  const body = normalizeJsonValue({
    schemaVersion: PROFILING_COVERAGE_LEDGER_SCHEMA,
    publicationState: 'REVIEW_REQUIRED',
    totalAttempts: entries.length,
    stateCounts,
    completeAttempts: stateCounts.SUCCEEDED,
    partialAttempts: stateCounts.PARTIAL,
    nonClaimedAttempts: entries.length - stateCounts.SUCCEEDED,
    entries,
  });
  return { ...body, coverageSha256: identitySha256(body) };
}

const candidateEntry = ({ aggregateSha256, fact, plan, candidateType, ruleId, signals }) => {
  const body = normalizeJsonValue({
    candidateType,
    classificationState: 'UNKNOWN',
    reviewState: 'REVIEW_REQUIRED',
    semanticClaim: 'NOT_ESTABLISHED',
    target: profilingTarget(fact),
    ruleId,
    metrics: {
      rowCount: fact.rowCount,
      nullCount: fact.nullCount,
      distinctCount: fact.distinctCount,
    },
    signals,
    evidenceRefs: {
      aggregateSha256,
      factSha256: fact.objectSha256,
      querySha256: plan.querySha256,
    },
  });
  return { ...body, candidateSha256: identitySha256(body) };
};

export function deriveProfilingCandidates(aggregateEvidence) {
  if (!hasExactKeys(aggregateEvidence, [
    'schemaVersion', 'engine', 'runtimeValidation', 'policySha256', 'queryPack', 'queryPlan', 'coverage', 'factCount', 'facts', 'aggregateSha256',
  ]) || aggregateEvidence.schemaVersion !== AGGREGATE_EVIDENCE_SCHEMA
    || !['mssql', 'oracle'].includes(aggregateEvidence.engine)
    || aggregateEvidence.runtimeValidation !== 'SYNTHETIC_UNVALIDATED'
    || !Array.isArray(aggregateEvidence.facts)
    || !Array.isArray(aggregateEvidence.queryPlan)
    || aggregateEvidence.factCount !== aggregateEvidence.facts.length) fail('DB_PROFILING_CANDIDATE_SOURCE_INVALID');
  const { aggregateSha256, ...aggregateBody } = aggregateEvidence;
  if (identitySha256(aggregateBody) !== aggregateSha256) fail('DB_PROFILING_CANDIDATE_SOURCE_TAMPERED');
  const plans = new Map(aggregateEvidence.queryPlan.map((plan) => [profilingTargetKey(plan), plan]));
  if (plans.size !== aggregateEvidence.queryPlan.length) fail('DB_PROFILING_CANDIDATE_SOURCE_INVALID');

  const semanticCandidates = [];
  const qualityCandidates = [];
  for (const fact of aggregateEvidence.facts) {
    const { objectSha256, ...factBody } = fact;
    if (identitySha256({ engine: aggregateEvidence.engine, fact: factBody }) !== objectSha256) fail('DB_PROFILING_CANDIDATE_SOURCE_TAMPERED');
    const plan = plans.get(profilingTargetKey(fact));
    if (!plan || plan.typeFamily !== fact.typeFamily || !/^[a-f0-9]{64}$/.test(plan.querySha256 ?? '')) fail('DB_PROFILING_CANDIDATE_SOURCE_INVALID');
    const nonNullCount = fact.rowCount - fact.nullCount;
    const isUniqueComplete = fact.rowCount > 0 && fact.nullCount === 0 && fact.distinctCount === fact.rowCount;
    const common = { aggregateSha256, fact, plan };
    if (isUniqueComplete) {
      semanticCandidates.push(candidateEntry({ ...common, candidateType: 'KEY', ruleId: 'UNIQUE_COMPLETE_AGGREGATE_V1', signals: ['ALL_ROWS_NON_NULL', 'ALL_ROWS_DISTINCT'] }));
    } else if (fact.typeFamily === 'NUMERIC') {
      semanticCandidates.push(candidateEntry({ ...common, candidateType: 'AMOUNT', ruleId: 'NON_UNIQUE_NUMERIC_FAMILY_V1', signals: ['NUMERIC_TYPE_FAMILY', 'NOT_UNIQUE_COMPLETE'] }));
    }
    if (fact.typeFamily === 'TEMPORAL') {
      semanticCandidates.push(candidateEntry({ ...common, candidateType: 'TIME', ruleId: 'TEMPORAL_FAMILY_V1', signals: ['TEMPORAL_TYPE_FAMILY'] }));
    }
    if (['CATEGORY', 'BOOLEAN'].includes(fact.typeFamily)) {
      semanticCandidates.push(candidateEntry({ ...common, candidateType: 'CATEGORY', ruleId: 'BOUNDED_CARDINALITY_FAMILY_V1', signals: [`${fact.typeFamily}_TYPE_FAMILY`] }));
    }
    qualityCandidates.push(candidateEntry({
      ...common,
      candidateType: 'QUALITY',
      ruleId: 'NULL_AND_DISTINCT_OBSERVATION_V1',
      signals: [
        fact.nullCount === 0 ? 'NO_NULLS_OBSERVED' : 'NULLS_OBSERVED',
        nonNullCount > 0 && fact.distinctCount === nonNullCount ? 'ALL_NON_NULL_VALUES_DISTINCT' : 'REPEATED_NON_NULL_VALUES',
      ],
    }));
  }
  const compareCandidates = compareRows(['schemaName', 'relationName', 'columnName', 'candidateType']);
  const sortCandidate = (left, right) => compareCandidates(
    { ...left.target, candidateType: left.candidateType },
    { ...right.target, candidateType: right.candidateType },
  );
  semanticCandidates.sort(sortCandidate);
  qualityCandidates.sort(sortCandidate);
  const body = normalizeJsonValue({
    schemaVersion: PROFILING_CANDIDATE_SET_SCHEMA,
    publicationState: 'REVIEW_REQUIRED',
    source: {
      engine: aggregateEvidence.engine,
      runtimeValidation: aggregateEvidence.runtimeValidation,
      aggregateSha256,
      policySha256: aggregateEvidence.policySha256,
      manifestSha256: aggregateEvidence.queryPack.manifestSha256,
    },
    summary: {
      semanticCandidateCount: semanticCandidates.length,
      qualityCandidateCount: qualityCandidates.length,
      unknownClassificationCount: semanticCandidates.length + qualityCandidates.length,
      reviewRequiredCount: semanticCandidates.length + qualityCandidates.length,
    },
    semanticCandidates,
    qualityCandidates,
  });
  return { ...body, candidateSetSha256: identitySha256(body) };
}

export function buildAggregateProfilingEvidence({ profile, resultSets, profilingManifest, profilingSqlByQueryId }) {
  const profiling = profile?.policy?.profiling;
  if (!profiling) return undefined;
  validateProfilingPolicy(profile);
  if (!hasExactKeys(resultSets, ['schemaVersion', 'engine', 'runtimeValidated', 'facts'])
    || resultSets.schemaVersion !== SYNTHETIC_AGGREGATE_RESULTS_SCHEMA
    || resultSets.engine !== profile.engine
    || resultSets.runtimeValidated !== false
    || !Array.isArray(resultSets.facts)) fail('DB_PROFILING_RESULT_CONTRACT_INVALID');
  if (resultSets.facts.length > profiling.budgets.maxQueries) fail('DB_PROFILING_BUDGET_EXCEEDED');
  const allowed = new Set(profiling.scope.flatMap((target) => target.columns
    .map((column) => `${target.schemaName}\u0000${target.relationName}\u0000${column}`)));
  const sensitive = new Set(profiling.disclosure.sensitiveTargets.map(profilingTargetKey));
  const seen = new Set();
  const facts = resultSets.facts.map((fact) => {
    const factKeys = {
      NUMERIC: ['schemaName', 'relationName', 'columnName', 'typeFamily', 'rowCount', 'nullCount', 'distinctCount', 'minimum', 'maximum', 'distribution'],
      TEMPORAL: ['schemaName', 'relationName', 'columnName', 'typeFamily', 'rowCount', 'nullCount', 'distinctCount', 'minimum', 'maximum', 'freshnessMaximum', 'distribution'],
      CATEGORY: ['schemaName', 'relationName', 'columnName', 'typeFamily', 'rowCount', 'nullCount', 'distinctCount', 'distribution'],
      TEXT: ['schemaName', 'relationName', 'columnName', 'typeFamily', 'rowCount', 'nullCount', 'distinctCount', 'distribution'],
      BOOLEAN: ['schemaName', 'relationName', 'columnName', 'typeFamily', 'rowCount', 'nullCount', 'distinctCount', 'distribution'],
    }[fact?.typeFamily];
    if (!factKeys || !hasExactKeys(fact, factKeys)
      || !allowed.has(`${fact.schemaName}\u0000${fact.relationName}\u0000${fact.columnName}`)
      || !Object.hasOwn(PROFILING_OUTPUT_COLUMNS, fact.typeFamily)
      || ![fact.rowCount, fact.nullCount, fact.distinctCount].every(Number.isInteger)
      || fact.rowCount < 0 || fact.nullCount < 0 || fact.nullCount > fact.rowCount
      || fact.distinctCount < 0 || fact.distinctCount > fact.rowCount - fact.nullCount
      || (Object.hasOwn(fact, 'minimum') && !([null, 'string'].includes(fact.minimum === null ? null : typeof fact.minimum)))
      || (Object.hasOwn(fact, 'maximum') && !([null, 'string'].includes(fact.maximum === null ? null : typeof fact.maximum)))
      || (fact.typeFamily === 'TEMPORAL'
        && (!([null, 'string'].includes(fact.freshnessMaximum === null ? null : typeof fact.freshnessMaximum))
          || fact.freshnessMaximum !== fact.maximum))
      ) fail('DB_PROFILING_RESULT_INVALID');
    const key = `${fact.schemaName}\u0000${fact.relationName}\u0000${fact.columnName}`;
    if (sensitive.has(key)) fail('DB_PROFILING_SENSITIVE_TARGET_DENIED');
    if (fact.distribution !== null) fail('DB_PROFILING_DISTRIBUTION_DENIED');
    if (seen.has(key)) fail('DB_PROFILING_RESULT_INVALID');
    seen.add(key);
    const normalized = normalizeJsonValue(fact);
    return { ...normalized, objectSha256: identitySha256({ engine: profile.engine, fact: normalized }) };
  }).sort(compareRows(['schemaName', 'relationName', 'columnName']));
  validateProfilingQueryManifest(profilingManifest, profilingSqlByQueryId);
  if (profilingManifest.engine !== profile.engine
    || profilingManifest.queries.some((query) => query.timeoutMs > profiling.budgets.maxQueryTimeoutMs)) fail('DB_PROFILING_QUERY_POLICY_DENIED');
  const queryPlan = facts.map((fact) => compileProfilingQuery({
    manifest: profilingManifest,
    sqlByQueryId: profilingSqlByQueryId,
    target: {
      schemaName: fact.schemaName,
      relationName: fact.relationName,
      columnName: fact.columnName,
      typeFamily: fact.typeFamily,
    },
  }));
  const policySha256 = identitySha256(profiling);
  const coverage = buildProfilingCoverageLedger({
    profile,
    attempts: facts.map((fact) => ({
      ...profilingTarget(fact),
      typeFamily: fact.typeFamily,
      state: 'SUCCEEDED',
      reasonCode: null,
      factSha256: fact.objectSha256,
    })),
  });
  const body = normalizeJsonValue({
    schemaVersion: AGGREGATE_EVIDENCE_SCHEMA,
    engine: profile.engine,
    runtimeValidation: 'SYNTHETIC_UNVALIDATED',
    policySha256,
    queryPack: {
      packId: profilingManifest.packId,
      packVersion: profilingManifest.packVersion,
      manifestSha256: identitySha256(profilingManifest),
      queryCount: profilingManifest.queries.length,
      plannedQueryCount: queryPlan.length,
    },
    queryPlan,
    coverage,
    factCount: facts.length,
    facts,
  });
  const aggregate = { ...body, aggregateSha256: identitySha256(body) };
  return { ...aggregate, candidates: deriveProfilingCandidates(aggregate) };
}

const profilingReviewBinding = (evidence) => {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)
    || typeof evidence.snapshotSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(evidence.snapshotSha256)
    || !['mssql', 'oracle'].includes(evidence.engine)
    || !evidence.profile || !evidence.profiling) fail('DB_PROFILING_REVIEW_SOURCE_INVALID');
  const { snapshotSha256, ...analysisBody } = evidence;
  if (identitySha256(analysisBody) !== snapshotSha256) fail('DB_PROFILING_REVIEW_SOURCE_TAMPERED');
  const { candidates, ...aggregate } = evidence.profiling;
  if (canonicalJson(deriveProfilingCandidates(aggregate)) !== canonicalJson(candidates)) {
    fail('DB_PROFILING_REVIEW_SOURCE_TAMPERED');
  }
  const profile = evidence.profile;
  if (typeof profile.profileId !== 'string' || profile.profileId.length === 0
    || !profile.scope || typeof profile.scope.database !== 'string'
    || !(profile.scope.container === null || typeof profile.scope.container === 'string')
    || !Array.isArray(profile.scope.schemas) || profile.scope.schemas.length === 0) {
    fail('DB_PROFILING_REVIEW_SOURCE_INVALID');
  }
  const structureSnapshotSha256 = identitySha256({
    engine: evidence.engine,
    runtimeValidation: evidence.runtimeValidation,
    packId: evidence.packId,
    packVersion: evidence.packVersion,
    coverageLedger: evidence.coverageLedger,
    extracts: evidence.extracts,
  });
  return normalizeJsonValue({
    scope: {
      profileId: profile.profileId,
      engine: evidence.engine,
      database: profile.scope.database,
      container: profile.scope.container,
      schemas: profile.scope.schemas,
    },
    evidence: {
      analysisSnapshotSha256: snapshotSha256,
      structureSnapshotSha256,
      profilingPolicySha256: aggregate.policySha256,
      queryManifestSha256: aggregate.queryPack.manifestSha256,
      aggregateSha256: aggregate.aggregateSha256,
      candidateSetSha256: candidates.candidateSetSha256,
    },
  });
};

export function buildProfilingReviewBinding(evidence) {
  return profilingReviewBinding(evidence);
}

export function authorizeProfilingProjection({ evidence, receipt }) {
  const binding = profilingReviewBinding(evidence);
  if (!hasExactKeys(receipt, [
    'schemaVersion', 'receiptId', 'authority', 'reviewedAt', 'scope', 'evidence', 'decisions', 'projectionDecision', 'receiptSha256',
  ]) || receipt.schemaVersion !== PROFILING_REVIEW_RECEIPT_SCHEMA
    || typeof receipt.receiptId !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(receipt.receiptId)
    || !hasExactKeys(receipt.authority, ['type', 'reviewerId', 'identityAssurance', 'analyzerMayIssue', 'productionAuthority'])
    || receipt.authority.type !== 'SYNTHETIC_HUMAN_REVIEW_FIXTURE'
    || typeof receipt.authority.reviewerId !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(receipt.authority.reviewerId)
    || receipt.authority.identityAssurance !== 'TEST_FIXTURE_ONLY'
    || receipt.authority.analyzerMayIssue !== false
    || receipt.authority.productionAuthority !== false
    || typeof receipt.reviewedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.reviewedAt)
    || Number.isNaN(Date.parse(receipt.reviewedAt))
    || canonicalJson(receipt.scope) !== canonicalJson(binding.scope)
    || canonicalJson(receipt.evidence) !== canonicalJson(binding.evidence)
    || !hasExactKeys(receipt.projectionDecision, ['state', 'externalPublicationAuthority', 'directSourceDatabaseAccess'])
    || receipt.projectionDecision.state !== 'APPROVED_FOR_CURATED_PROJECTION'
    || receipt.projectionDecision.externalPublicationAuthority !== false
    || receipt.projectionDecision.directSourceDatabaseAccess !== false
    || !Array.isArray(receipt.decisions) || receipt.decisions.length === 0) {
    fail('DB_PROFILING_REVIEW_RECEIPT_INVALID');
  }
  const { receiptSha256, ...receiptBody } = receipt;
  if (!/^[a-f0-9]{64}$/.test(receiptSha256 ?? '') || identitySha256(receiptBody) !== receiptSha256) {
    fail('DB_PROFILING_REVIEW_RECEIPT_TAMPERED');
  }
  const candidates = [...evidence.profiling.candidates.semanticCandidates, ...evidence.profiling.candidates.qualityCandidates];
  const candidateBySha = new Map(candidates.map((candidate) => [candidate.candidateSha256, candidate]));
  const seen = new Set();
  for (const decision of receipt.decisions) {
    if (!hasExactKeys(decision, ['candidateSha256', 'candidateType', 'target', 'disposition', 'reasonCode'])
      || !['APPROVED', 'REJECTED'].includes(decision.disposition)
      || typeof decision.reasonCode !== 'string' || !/^[A-Z][A-Z0-9_]{2,127}$/.test(decision.reasonCode)
      || seen.has(decision.candidateSha256)) fail('DB_PROFILING_REVIEW_DECISIONS_INVALID');
    const candidate = candidateBySha.get(decision.candidateSha256);
    if (!candidate || decision.candidateType !== candidate.candidateType
      || canonicalJson(decision.target) !== canonicalJson(candidate.target)) fail('DB_PROFILING_REVIEW_DECISIONS_INVALID');
    seen.add(decision.candidateSha256);
  }
  if (seen.size !== candidateBySha.size || receipt.decisions.every((decision) => decision.disposition !== 'APPROVED')) {
    fail('DB_PROFILING_REVIEW_DECISIONS_INCOMPLETE');
  }
  const approvedCandidateSha256 = receipt.decisions
    .filter((decision) => decision.disposition === 'APPROVED')
    .map((decision) => decision.candidateSha256)
    .sort();
  return normalizeJsonValue({
    schemaVersion: 'chimpmaera.db/profiling-projection-authorization/v1',
    state: 'CURATED_PROJECTION_AUTHORIZED',
    authority: 'SYNTHETIC_FIXTURE_ONLY',
    productionAuthority: false,
    receiptSha256,
    candidateSetSha256: binding.evidence.candidateSetSha256,
    approvedCandidateSha256,
  });
}

export function buildProfilingKnowledgePack({ evidence, receipt }) {
  const authorization = authorizeProfilingProjection({ evidence, receipt });
  const binding = profilingReviewBinding(evidence);
  const candidates = [
    ...evidence.profiling.candidates.semanticCandidates,
    ...evidence.profiling.candidates.qualityCandidates,
  ];
  const candidateBySha = new Map(candidates.map((candidate) => [candidate.candidateSha256, candidate]));
  const approved = new Set(authorization.approvedCandidateSha256);
  if (candidateBySha.size !== candidates.length
    || approved.size !== authorization.approvedCandidateSha256.length
    || [...approved].some((candidateSha256) => !candidateBySha.has(candidateSha256))) {
    fail('DB_PROFILING_KNOWLEDGE_SOURCE_INVALID');
  }
  const entries = authorization.approvedCandidateSha256.map((candidateSha256) => {
    const candidate = candidateBySha.get(candidateSha256);
    return normalizeJsonValue({
      candidateSha256,
      candidateType: candidate.candidateType,
      target: candidate.target,
      classificationState: candidate.classificationState,
      semanticClaim: candidate.semanticClaim,
      reviewState: 'APPROVED_BY_BOUND_RECEIPT',
      signals: candidate.signals,
      metrics: candidate.metrics,
      evidenceRefs: candidate.evidenceRefs,
      receiptSha256: authorization.receiptSha256,
    });
  });
  if (entries.some((entry) => !approved.has(entry.candidateSha256)
    || entry.classificationState !== 'UNKNOWN'
    || entry.semanticClaim !== 'NOT_ESTABLISHED')) {
    fail('DB_PROFILING_KNOWLEDGE_INVENTION_DENIED');
  }
  const body = normalizeJsonValue({
    schemaVersion: PROFILING_KNOWLEDGE_PACK_SCHEMA,
    state: 'CURATED_SYNTHETIC_FIXTURE',
    scope: binding.scope,
    source: {
      ...binding.evidence,
      receiptSha256: authorization.receiptSha256,
      runtimeValidation: evidence.runtimeValidation,
      profilingCoverageSha256: evidence.profiling.coverage.coverageSha256,
    },
    authority: {
      reviewAuthority: authorization.authority,
      productionAuthority: false,
      externalPublicationAuthority: false,
      directSourceDatabaseAccess: false,
    },
    claims: {
      semanticTruthEstablished: false,
      runtimeProfilingValidated: false,
      rowSamplesIncluded: false,
    },
    summary: {
      approvedCandidateCount: entries.length,
      knowledgeEntryCount: entries.length,
    },
    entries,
  });
  return { ...body, knowledgePackSha256: identitySha256(body) };
}

export function buildProfilingSupersetResult({ knowledgePack }) {
  if (!hasExactKeys(knowledgePack, [
    'schemaVersion', 'state', 'scope', 'source', 'authority', 'claims', 'summary', 'entries', 'knowledgePackSha256',
  ]) || knowledgePack.schemaVersion !== PROFILING_KNOWLEDGE_PACK_SCHEMA
    || knowledgePack.state !== 'CURATED_SYNTHETIC_FIXTURE'
    || !/^[a-f0-9]{64}$/.test(knowledgePack.knowledgePackSha256 ?? '')) {
    fail('DB_PROFILING_SUPERSET_SOURCE_INVALID');
  }
  const { knowledgePackSha256, ...knowledgeBody } = knowledgePack;
  if (identitySha256(knowledgeBody) !== knowledgePackSha256
    || knowledgePack.authority?.productionAuthority !== false
    || knowledgePack.authority?.externalPublicationAuthority !== false
    || knowledgePack.authority?.directSourceDatabaseAccess !== false
    || knowledgePack.claims?.semanticTruthEstablished !== false
    || knowledgePack.claims?.rowSamplesIncluded !== false
    || !Array.isArray(knowledgePack.entries)
    || knowledgePack.entries.length !== knowledgePack.summary?.knowledgeEntryCount) {
    fail('DB_PROFILING_SUPERSET_SOURCE_TAMPERED');
  }
  const candidateSha256 = new Set();
  const rows = knowledgePack.entries.map((entry) => {
    if (!hasExactKeys(entry, [
      'candidateSha256', 'candidateType', 'target', 'classificationState', 'semanticClaim', 'reviewState',
      'signals', 'metrics', 'evidenceRefs', 'receiptSha256',
    ]) || !/^[a-f0-9]{64}$/.test(entry.candidateSha256 ?? '')
      || candidateSha256.has(entry.candidateSha256)
      || entry.classificationState !== 'UNKNOWN'
      || entry.semanticClaim !== 'NOT_ESTABLISHED'
      || entry.reviewState !== 'APPROVED_BY_BOUND_RECEIPT'
      || !['KEY', 'TIME', 'AMOUNT', 'CATEGORY', 'QUALITY'].includes(entry.candidateType)) {
      fail('DB_PROFILING_SUPERSET_ENTRY_INVALID');
    }
    candidateSha256.add(entry.candidateSha256);
    return normalizeJsonValue({
      candidateSha256: entry.candidateSha256,
      candidateType: entry.candidateType,
      schemaName: entry.target.schemaName,
      relationName: entry.target.relationName,
      columnName: entry.target.columnName,
      classificationState: entry.classificationState,
      semanticClaim: entry.semanticClaim,
      reviewState: entry.reviewState,
      rowCount: entry.metrics.rowCount,
      distinctCount: entry.metrics.distinctCount,
      nullCount: entry.metrics.nullCount,
      signals: entry.signals,
      evidenceRefs: entry.evidenceRefs,
    });
  });
  const countsByType = Object.fromEntries(['AMOUNT', 'CATEGORY', 'KEY', 'QUALITY', 'TIME']
    .map((candidateType) => [candidateType, rows.filter((row) => row.candidateType === candidateType).length]));
  const body = normalizeJsonValue({
    schemaVersion: PROFILING_SUPERSET_RESULT_SCHEMA,
    state: 'CURATED_SYNTHETIC_FIXTURE',
    scope: knowledgePack.scope,
    source: {
      knowledgePackSha256,
      receiptSha256: knowledgePack.source.receiptSha256,
      runtimeValidation: knowledgePack.source.runtimeValidation,
    },
    authority: {
      productionAuthority: false,
      externalPublicationAuthority: false,
      automaticPublication: false,
      directSourceDatabaseAccess: false,
    },
    dataset: {
      datasetId: `${knowledgePack.scope.profileId}-curated-profile`,
      materialization: 'CONTENT_ADDRESSED_EMBEDDED_JSON',
      sourceConnection: null,
      sourceSql: null,
      rowSamplesIncluded: false,
      rowCount: rows.length,
      rows,
    },
    dashboard: {
      dashboardId: `${knowledgePack.scope.profileId}-data-understanding`,
      publicationState: 'DISCONNECTED_REVIEW_FIXTURE',
      charts: [
        { chartId: 'candidate-count-by-type', visualization: 'BAR', metric: 'candidateCount', values: countsByType },
        { chartId: 'null-observation-summary', visualization: 'TABLE', metric: 'nullCount', candidateSha256: rows.map((row) => row.candidateSha256) },
      ],
      drillThrough: {
        target: 'EMBEDDED_CURATED_DATASET',
        key: 'candidateSha256',
        sourceRoute: null,
      },
    },
    claims: {
      semanticTruthEstablished: false,
      runtimeProfilingValidated: false,
      supersetRuntimeValidated: false,
      rowSamplesIncluded: false,
    },
    summary: {
      curatedRowCount: rows.length,
      candidateCountsByType: countsByType,
    },
  });
  if (/sampleValue|sample_value|password|credential/i.test(canonicalJson(body))) {
    fail('DB_PROFILING_SUPERSET_UNSAFE_MATERIAL_DENIED');
  }
  return { ...body, supersetResultSha256: identitySha256(body) };
}

export function validateQueryManifest(manifest) {
  if (manifest?.schemaVersion !== QUERY_MANIFEST_SCHEMA) fail('DB_QUERY_MANIFEST_SCHEMA_INVALID');
  if (!['mssql', 'oracle', 'postgresql'].includes(manifest.engine)) fail('DB_QUERY_MANIFEST_ENGINE_INVALID');
  if (!manifest.packId || !manifest.packVersion || !Array.isArray(manifest.queries) || manifest.queries.length === 0) fail('DB_QUERY_MANIFEST_INCOMPLETE');
  if (manifest.blindSpots !== undefined) {
    if (!Array.isArray(manifest.blindSpots) || manifest.blindSpots.length === 0) fail('DB_QUERY_MANIFEST_BLIND_SPOTS_INVALID');
    const codes = new Set();
    for (const blindSpot of manifest.blindSpots) {
      if (!hasExactKeys(blindSpot, ['code', 'description'])
        || typeof blindSpot.code !== 'string' || !/^[A-Z][A-Z0-9_]{2,127}$/.test(blindSpot.code)
        || codes.has(blindSpot.code)
        || typeof blindSpot.description !== 'string' || blindSpot.description.length === 0) {
        fail('DB_QUERY_MANIFEST_BLIND_SPOTS_INVALID');
      }
      codes.add(blindSpot.code);
    }
  } else if (manifest.engine === 'postgresql') fail('DB_QUERY_MANIFEST_BLIND_SPOTS_INVALID');
  const ids = new Set();
  for (const query of manifest.queries) {
    if (!query.id || ids.has(query.id)) fail('DB_QUERY_MANIFEST_QUERY_ID_INVALID');
    ids.add(query.id);
    if (!QUERY_CATEGORIES.has(query.category) || query.readOnly !== true || !query.file) fail('DB_QUERY_MANIFEST_QUERY_BOUNDARY_INVALID');
    if (!Array.isArray(query.outputColumns) || query.outputColumns.length === 0 || new Set(query.outputColumns).size !== query.outputColumns.length) fail('DB_QUERY_MANIFEST_OUTPUT_INVALID');
    if (!Array.isArray(query.sortKeys) || query.sortKeys.some((key) => !query.outputColumns.includes(key))) fail('DB_QUERY_MANIFEST_SORT_KEY_INVALID');
    if (!(query.scopeColumn === null || query.outputColumns.includes(query.scopeColumn))) fail('DB_QUERY_MANIFEST_SCOPE_INVALID');
    if (!Number.isInteger(query.timeoutMs) || query.timeoutMs < 1 || !['LOW', 'BOUNDED'].includes(query.cost)) fail('DB_QUERY_MANIFEST_BUDGET_INVALID');
    if (!query.privilege?.minimum || !query.fallback?.onDenied || !query.provenance?.url || query.provenance.copiedCode !== false) fail('DB_QUERY_MANIFEST_PROVENANCE_INVALID');
  }
  return manifest;
}

function compareRows(keys) {
  return (left, right) => {
    for (const key of keys) {
      const comparison = Buffer.compare(Buffer.from(String(left[key] ?? ''), 'utf8'), Buffer.from(String(right[key] ?? ''), 'utf8'));
      if (comparison !== 0) return comparison;
    }
    return Buffer.compare(Buffer.from(canonicalJson(left), 'utf8'), Buffer.from(canonicalJson(right), 'utf8'));
  };
}

function normalizeRows(query, rows) {
  return rows.map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) fail('DB_QUERY_RESULT_ROW_INVALID');
    const actual = Object.keys(row).sort();
    const expected = [...query.outputColumns].sort();
    if (canonicalJson(actual) !== canonicalJson(expected)) fail('DB_QUERY_RESULT_COLUMNS_INVALID');
    const normalized = normalizeJsonValue(Object.fromEntries(query.outputColumns.map((column) => [column, row[column]])));
    return { ...normalized, objectSha256: identitySha256({ queryId: query.id, object: normalized }) };
  }).sort(compareRows(query.sortKeys));
}

const hasAllowedKeys = (value, allowed) => value
  && typeof value === 'object'
  && !Array.isArray(value)
  && Object.keys(value).every((key) => allowed.includes(key));

function normalizeQueryResult(query, result) {
  if (!hasAllowedKeys(result, ['state', 'reasonCode', 'rows']) || !COVERAGE_STATES.includes(result.state)) {
    fail('DB_QUERY_RESULT_TAMPERED');
  }
  const hasVisibleRows = result.state === 'SUCCEEDED' || result.state === 'PARTIAL';
  if (hasVisibleRows && !Array.isArray(result.rows)) fail('DB_QUERY_RESULT_ROWS_MISSING');
  if (!hasVisibleRows && Array.isArray(result.rows) && result.rows.length > 0) fail('DB_QUERY_FAILED_STATE_ROWS_DENIED');
  if (result.state === 'SUCCEEDED' && ![undefined, null].includes(result.reasonCode)) fail('DB_QUERY_RESULT_REASON_INVALID');
  if (result.state !== 'SUCCEEDED'
    && (typeof result.reasonCode !== 'string' || !/^[A-Z][A-Z0-9_]{2,127}$/.test(result.reasonCode))) {
    fail('DB_QUERY_RESULT_REASON_INVALID');
  }
  const rows = hasVisibleRows ? normalizeRows(query, result.rows) : [];
  return {
    state: result.state,
    reasonCode: result.reasonCode ?? null,
    rows,
    visibility: COVERAGE_VISIBILITY[result.state],
    emptyInterpretation: result.state === 'SUCCEEDED' && rows.length === 0 ? 'VERIFIED_EMPTY' : 'NOT_CLAIMED',
  };
}

function buildCoverageLedger(extracts) {
  const stateCounts = Object.fromEntries(COVERAGE_STATES.map((state) => [state, extracts.filter((entry) => entry.state === state).length]));
  const entries = extracts.map((entry) => ({
    queryId: entry.queryId,
    category: entry.category,
    state: entry.state,
    reasonCode: entry.reasonCode,
    visibility: entry.visibility,
    rowCount: entry.rows.length,
    emptyInterpretation: entry.emptyInterpretation,
  }));
  return {
    schemaVersion: COVERAGE_LEDGER_SCHEMA,
    totalQueries: extracts.length,
    stateCounts,
    completeQueries: stateCounts.SUCCEEDED,
    partialQueries: stateCounts.PARTIAL,
    invisibleOrUnknownQueries: stateCounts.DENIED + stateCounts.TIMEOUT + stateCounts.ERROR,
    verifiedEmptyQueries: entries.filter((entry) => entry.emptyInterpretation === 'VERIFIED_EMPTY').length,
    allComplete: stateCounts.SUCCEEDED === extracts.length,
    entries,
  };
}

function enforceCatalogScanPolicy({ manifest, resultSets, profileContext }) {
  const policy = profileContext?.policy?.catalogScan;
  if (policy === undefined) return;
  validateCatalogScanPolicy(policy);
  if (manifest.queries.length > policy.maxQueries
    || manifest.queries.some((query) => !policy.allowedQueryIds.includes(query.id))) {
    fail('DB_CATALOG_SCAN_ALLOWLIST_DENIED');
  }
  let totalRows = 0;
  for (const query of manifest.queries) {
    const rows = resultSets?.results?.[query.id]?.rows;
    const rowCount = Array.isArray(rows) ? rows.length : 0;
    if (rowCount > policy.maxRowsPerQuery) fail('DB_CATALOG_SCAN_BUDGET_EXCEEDED');
    totalRows += rowCount;
  }
  if (totalRows > policy.maxTotalRows) fail('DB_CATALOG_SCAN_BUDGET_EXCEEDED');
}

function buildBlindSpots(manifest, coverageLedger) {
  const declared = (manifest.blindSpots ?? []).map((blindSpot) => ({
    ...blindSpot,
    source: 'QUERY_PACK_DECLARATION',
    queryId: null,
    coverageState: null,
    reasonCode: null,
  }));
  const observed = coverageLedger.entries
    .filter((entry) => entry.state !== 'SUCCEEDED')
    .map((entry) => ({
      code: `QUERY_${entry.state}`,
      description: 'Catalog visibility is incomplete; absence must not be interpreted as verified empty.',
      source: 'COVERAGE_LEDGER',
      queryId: entry.queryId,
      coverageState: entry.state,
      reasonCode: entry.reasonCode,
    }));
  return [...declared, ...observed];
}

export function buildPreflightEvidence({ manifest, sqlByQueryId, resultSets, profileContext, profilingEvidence, storedLogicEvidence }) {
  validateQueryManifest(manifest);
  enforceCatalogScanPolicy({ manifest, resultSets, profileContext });
  const synthetic = resultSets?.schemaVersion === 'chimpmaera.db/synthetic-query-results/v1' && resultSets.runtimeValidated === false;
  const runtime = resultSets?.schemaVersion === 'chimpmaera.db/runtime-query-results/v1' && resultSets.runtimeValidated === true;
  if ((!synthetic && !runtime) || resultSets.engine !== manifest.engine
    || !hasAllowedKeys(resultSets, ['schemaVersion', 'engine', 'runtimeValidated', 'observedAt', 'results'])
    || !resultSets.results || typeof resultSets.results !== 'object' || Array.isArray(resultSets.results)) {
    fail('DB_QUERY_RESULT_CONTRACT_INVALID');
  }
  const expectedQueryIds = manifest.queries.map((query) => query.id).sort();
  if (canonicalJson(Object.keys(resultSets.results).sort()) !== canonicalJson(expectedQueryIds)) fail('DB_QUERY_RESULT_SET_TAMPERED');
  const extracts = manifest.queries.map((query) => {
    const sql = sqlByQueryId[query.id];
    const result = resultSets.results?.[query.id];
    if (typeof sql !== 'string' || !result) fail('DB_QUERY_RESULT_MISSING');
    const normalizedResult = normalizeQueryResult(query, result);
    const { rows } = normalizedResult;
    if (query.scopeColumn && profileContext
      && rows.some((row) => !profileContext.scope.schemas.includes(row[query.scopeColumn]))) fail('DB_QUERY_RESULT_SCOPE_INVALID');
    if (manifest.engine === 'postgresql' && profileContext && query.category === 'constraints'
      && rows.some((row) => row.constraint_kind === 'FOREIGN_KEY'
        && !profileContext.scope.schemas.includes(row.referenced_schema_name))) fail('DB_QUERY_RESULT_SCOPE_INVALID');
    if (manifest.engine === 'postgresql' && query.category === 'dependencies') {
      if (rows.some((row) => row.relationship_authority !== 'CATALOG_DECLARED' || row.inferred !== false)) {
        fail('DB_DECLARED_RELATIONSHIP_INVALID');
      }
      if (profileContext && rows.some((row) => !profileContext.scope.schemas.includes(row.source_schema_name)
        || !profileContext.scope.schemas.includes(row.target_schema_name))) fail('DB_QUERY_RESULT_SCOPE_INVALID');
    }
    return {
      queryId: query.id,
      category: query.category,
      querySha256: sha256(normalizeSql(sql)),
      ...normalizedResult,
    };
  });
  const coverageLedger = buildCoverageLedger(extracts);
  const blindSpots = buildBlindSpots(manifest, coverageLedger);
  const body = normalizeJsonValue({
    schemaVersion: PREFLIGHT_EVIDENCE_SCHEMA,
    packId: manifest.packId,
    packVersion: manifest.packVersion,
    engine: manifest.engine,
    runtimeValidation: runtime ? 'RUNTIME_VALIDATED' : 'SYNTHETIC_UNVALIDATED',
    identityContract: IDENTITY_CONTRACT,
    ...(resultSets.observedAt === undefined ? {} : { observedAt: resultSets.observedAt }),
    ...(profileContext === undefined ? {} : { profile: profileContext }),
    ...(profilingEvidence === undefined ? {} : { profiling: profilingEvidence }),
    ...(storedLogicEvidence === undefined ? {} : { storedLogic: storedLogicEvidence }),
    coverage: coverageLedger.stateCounts,
    coverageLedger,
    ...(blindSpots.length === 0 ? {} : { blindSpots }),
    extracts,
  });
  return { ...body, snapshotSha256: identitySha256(body) };
}

const storedLogicKey = (row) => canonicalJson({
  schemaName: row.schema_name,
  objectName: row.object_name,
  objectKind: row.object_kind,
});

export function buildStoredLogicEvidence({ manifest, sqlByQueryId, resultSets, profileContext }) {
  validateQueryManifest(manifest);
  if (manifest.queries.length !== 2
    || manifest.queries[0].category !== 'stored-objects'
    || manifest.queries[1].category !== 'stored-dependencies') {
    fail('DB_STORED_LOGIC_MANIFEST_INVALID');
  }
  const source = buildPreflightEvidence({ manifest, sqlByQueryId, resultSets, profileContext });
  const rows = source.extracts.find(({ category }) => category === 'stored-objects')?.rows ?? [];
  const groups = new Map();
  for (const row of rows) {
    if (!['PROCEDURE', 'FUNCTION', 'TRIGGER'].includes(row.object_kind)
      || !validScopedName(row.schema_name) || !validScopedName(row.object_name)
      || typeof row.native_object_id !== 'string' || row.native_object_id.length === 0
      || !['ENABLED', 'DISABLED', 'NOT_APPLICABLE'].includes(row.enablement_state)
      || !['VISIBLE_HASHED', 'ENCRYPTED_OR_INVISIBLE'].includes(row.definition_visibility)
      || !((row.parent_schema_name === null && row.parent_object_name === null)
        || (validScopedName(row.parent_schema_name) && validScopedName(row.parent_object_name)))) {
      fail('DB_STORED_LOGIC_OBJECT_INVALID');
    }
    const visible = row.definition_visibility === 'VISIBLE_HASHED';
    if ((visible && (!Number.isInteger(row.definition_component_ordinal) || row.definition_component_ordinal < 1
      || !/^[a-f0-9]{64}$/.test(row.definition_component_hash ?? '')
      || typeof row.definition_component_hash_algorithm !== 'string' || row.definition_component_hash_algorithm.length === 0))
      || (!visible && (row.definition_component_ordinal !== null || row.definition_component_hash !== null
        || row.definition_component_hash_algorithm !== null))) {
      fail('DB_STORED_LOGIC_DEFINITION_INVALID');
    }
    const key = storedLogicKey(row);
    const group = groups.get(key) ?? {
      metadata: {
        schemaName: row.schema_name,
        objectName: row.object_name,
        objectKind: row.object_kind,
        nativeObjectId: row.native_object_id,
        parentSchemaName: row.parent_schema_name,
        parentObjectName: row.parent_object_name,
        enablementState: row.enablement_state,
        definitionVisibility: row.definition_visibility,
      },
      algorithm: row.definition_component_hash_algorithm,
      components: [],
    };
    if (canonicalJson(group.metadata) !== canonicalJson({
      schemaName: row.schema_name,
      objectName: row.object_name,
      objectKind: row.object_kind,
      nativeObjectId: row.native_object_id,
      parentSchemaName: row.parent_schema_name,
      parentObjectName: row.parent_object_name,
      enablementState: row.enablement_state,
      definitionVisibility: row.definition_visibility,
    }) || group.algorithm !== row.definition_component_hash_algorithm) fail('DB_STORED_LOGIC_OBJECT_CONFLICT');
    if (visible) group.components.push({ ordinal: row.definition_component_ordinal, sha256: row.definition_component_hash });
    groups.set(key, group);
  }
  const objects = [...groups.values()].map((group) => {
    group.components.sort((left, right) => left.ordinal - right.ordinal);
    if (new Set(group.components.map(({ ordinal }) => ordinal)).size !== group.components.length) {
      fail('DB_STORED_LOGIC_DEFINITION_INVALID');
    }
    const visible = group.metadata.definitionVisibility === 'VISIBLE_HASHED';
    if (visible && (group.components.length === 0
      || group.components.some(({ ordinal }, index) => ordinal !== index + 1))) {
      fail('DB_STORED_LOGIC_DEFINITION_INVALID');
    }
    const objectIdentitySha256 = identitySha256({
      engine: manifest.engine,
      scope: profileContext?.scope ?? null,
      schemaName: group.metadata.schemaName,
      objectName: group.metadata.objectName,
      objectKind: group.metadata.objectKind,
    });
    const object = normalizeJsonValue({
      ...group.metadata,
      objectIdentitySha256,
      definitionComponentCount: group.components.length,
      definitionComponentHashAlgorithm: group.algorithm,
      definitionFingerprintAlgorithm: visible ? STORED_LOGIC_DEFINITION_FINGERPRINT : null,
      definitionFingerprintSha256: visible ? identitySha256({
        contract: STORED_LOGIC_DEFINITION_FINGERPRINT,
        nativeAlgorithm: group.algorithm,
        components: group.components,
      }) : null,
    });
    return { ...object, objectSha256: identitySha256(object) };
  }).sort((left, right) => compareRows(['schemaName', 'objectName', 'objectKind'])(left, right));
  const typeCounts = Object.fromEntries(['PROCEDURE', 'FUNCTION', 'TRIGGER']
    .map((kind) => [kind, objects.filter((object) => object.objectKind === kind).length]));
  const objectByKey = new Map(objects.map((object) => [canonicalJson({
    schemaName: object.schemaName,
    objectName: object.objectName,
    objectKind: object.objectKind,
  }), object]));
  const dependencyRows = source.extracts.find(({ category }) => category === 'stored-dependencies')?.rows ?? [];
  const edges = [];
  const edgeHashes = new Set();
  const columnEdges = [];
  const gaps = [];
  for (const row of dependencyRows) {
    if (!['PROCEDURE', 'FUNCTION', 'TRIGGER'].includes(row.source_object_kind)
      || !validScopedName(row.source_schema_name) || !validScopedName(row.source_object_name)
      || !['RESOLVED', 'UNRESOLVED'].includes(row.resolution_state)
      || !['PROVEN', 'NOT_PROVEN'].includes(row.column_resolution_state)
      || typeof row.native_dependency_kind !== 'string' || row.native_dependency_kind.length === 0
      || ![true, false, null].includes(row.is_schema_bound)
      || ![true, false, null].includes(row.is_caller_dependent)
      || !((row.target_server_or_link_name === null) || validScopedName(row.target_server_or_link_name))
      || !((row.target_database_name === null) || validScopedName(row.target_database_name))
      || !((row.target_column_name === null) || validScopedName(row.target_column_name))) {
      fail('DB_STORED_LOGIC_DEPENDENCY_INVALID');
    }
    const sourceObject = objectByKey.get(canonicalJson({
      schemaName: row.source_schema_name,
      objectName: row.source_object_name,
      objectKind: row.source_object_kind,
    }));
    if (!sourceObject) fail('DB_STORED_LOGIC_DEPENDENCY_SOURCE_INVALID');
    const resolved = row.resolution_state === 'RESOLVED';
    if ((resolved && (!validScopedName(row.target_schema_name)
      || !validScopedName(row.target_object_name)
      || !validScopedName(row.target_object_kind)
      || row.target_database_name !== null
      || row.target_server_or_link_name !== null))
      || (!resolved && (!validScopedName(row.target_object_name)
        || (row.target_schema_name !== null && !validScopedName(row.target_schema_name))
        || (row.target_object_kind !== null && !validScopedName(row.target_object_kind))))
      || (row.column_resolution_state === 'PROVEN' && (!resolved || !validScopedName(row.target_column_name)))
      || (row.column_resolution_state === 'NOT_PROVEN' && row.target_column_name !== null)) {
      fail('DB_STORED_LOGIC_DEPENDENCY_INVALID');
    }
    const common = normalizeJsonValue({
      sourceObjectIdentitySha256: sourceObject.objectIdentitySha256,
      sourceSchemaName: row.source_schema_name,
      sourceObjectName: row.source_object_name,
      sourceObjectKind: row.source_object_kind,
      targetSchemaName: row.target_schema_name,
      targetObjectName: row.target_object_name,
      targetObjectKind: row.target_object_kind,
      targetDatabaseName: row.target_database_name,
      targetServerOrLinkName: row.target_server_or_link_name,
      nativeDependencyKind: row.native_dependency_kind,
      isSchemaBound: row.is_schema_bound,
      isCallerDependent: row.is_caller_dependent,
    });
    if (resolved) {
      const edge = normalizeJsonValue({
        ...common,
        proofState: 'PROVEN_NATIVE',
        targetObjectIdentitySha256: identitySha256({
          engine: manifest.engine,
          scope: profileContext?.scope ?? null,
          schemaName: row.target_schema_name,
          objectName: row.target_object_name,
          objectKind: row.target_object_kind,
        }),
      });
      const edgeSha256 = identitySha256(edge);
      if (!edgeHashes.has(edgeSha256)) {
        edges.push({ ...edge, edgeSha256 });
        edgeHashes.add(edgeSha256);
      }
      if (row.column_resolution_state === 'PROVEN') {
        const columnEdge = normalizeJsonValue({
          sourceObjectIdentitySha256: sourceObject.objectIdentitySha256,
          sourceSchemaName: row.source_schema_name,
          sourceObjectName: row.source_object_name,
          sourceObjectKind: row.source_object_kind,
          targetSchemaName: row.target_schema_name,
          targetObjectName: row.target_object_name,
          targetObjectKind: row.target_object_kind,
          targetColumnName: row.target_column_name,
          targetColumnIdentitySha256: identitySha256({
            engine: manifest.engine,
            scope: profileContext?.scope ?? null,
            schemaName: row.target_schema_name,
            objectName: row.target_object_name,
            objectKind: row.target_object_kind,
            columnName: row.target_column_name,
          }),
          nativeDependencyKind: row.native_dependency_kind,
          granularity: 'TARGET_COLUMN',
          proofState: 'PROVEN_NATIVE_COLUMN',
        });
        columnEdges.push({ ...columnEdge, edgeSha256: identitySha256(columnEdge) });
      }
    } else {
      const gap = normalizeJsonValue({
        ...common,
        gapState: 'UNRESOLVED_NATIVE_REFERENCE',
      });
      gaps.push({ ...gap, gapSha256: identitySha256(gap) });
    }
  }
  if (new Set(columnEdges.map(({ edgeSha256 }) => edgeSha256)).size !== columnEdges.length
    || new Set(gaps.map(({ gapSha256 }) => gapSha256)).size !== gaps.length) {
    fail('DB_STORED_LOGIC_DEPENDENCY_DUPLICATE');
  }
  edges.sort(compareRows(['sourceSchemaName', 'sourceObjectName', 'sourceObjectKind', 'targetSchemaName', 'targetObjectName', 'targetObjectKind', 'nativeDependencyKind']));
  columnEdges.sort(compareRows(['sourceSchemaName', 'sourceObjectName', 'sourceObjectKind', 'targetSchemaName', 'targetObjectName', 'targetObjectKind', 'targetColumnName', 'nativeDependencyKind']));
  gaps.sort(compareRows(['sourceSchemaName', 'sourceObjectName', 'sourceObjectKind', 'targetServerOrLinkName', 'targetDatabaseName', 'targetSchemaName', 'targetObjectName', 'nativeDependencyKind']));
  const body = normalizeJsonValue({
    schemaVersion: STORED_LOGIC_EVIDENCE_SCHEMA,
    packId: manifest.packId,
    packVersion: manifest.packVersion,
    engine: manifest.engine,
    runtimeValidation: source.runtimeValidation,
    scope: profileContext?.scope ?? null,
    identityContract: IDENTITY_CONTRACT,
    definitionFingerprintContract: STORED_LOGIC_DEFINITION_FINGERPRINT,
    coverage: source.coverage,
    coverageLedger: source.coverageLedger,
    queryBindings: source.extracts.map(({ queryId, category, querySha256, state, reasonCode }) => ({
      queryId, category, querySha256, state, reasonCode,
    })),
    summary: {
      objectCount: objects.length,
      typeCounts,
      visibleHashedObjects: objects.filter((object) => object.definitionVisibility === 'VISIBLE_HASHED').length,
      encryptedOrInvisibleObjects: objects.filter((object) => object.definitionVisibility === 'ENCRYPTED_OR_INVISIBLE').length,
      provenNativeDependencyEdges: edges.length,
      provenNativeColumnEdges: columnEdges.length,
      unresolvedNativeDependencyGaps: gaps.length,
      rawDefinitionsIncluded: false,
    },
    objects,
    nativeDependencies: {
      edges,
      columnEdges,
      gaps,
    },
    parserEnrichment: emptyParserEnrichmentEvidence(),
  });
  const withLineage = normalizeJsonValue({ ...body, lineage: buildStoredLogicLineageEvidence(body) });
  return { ...withLineage, storedLogicSha256: identitySha256(withLineage) };
}

export function buildStoredLogicLineageEvidence(storedLogicEvidence) {
  const relationships = [];
  const blindSpots = [];
  const addRelationship = (relationship) => {
    const normalized = normalizeJsonValue(relationship);
    relationships.push({ ...normalized, relationshipSha256: identitySha256(normalized) });
  };
  const addBlindSpot = (blindSpot) => {
    const normalized = normalizeJsonValue(blindSpot);
    blindSpots.push({ ...normalized, blindSpotSha256: identitySha256(normalized) });
  };
  const provenColumnObjectPairs = new Set(storedLogicEvidence.nativeDependencies.columnEdges.map((edge) => canonicalJson({
    sourceObjectIdentitySha256: edge.sourceObjectIdentitySha256,
    targetObjectIdentitySha256: edge.targetColumnIdentitySha256,
  })));
  const columnTargets = new Set(storedLogicEvidence.nativeDependencies.columnEdges.map((edge) => canonicalJson({
    sourceObjectIdentitySha256: edge.sourceObjectIdentitySha256,
    targetSchemaName: edge.targetSchemaName,
    targetObjectName: edge.targetObjectName,
    targetObjectKind: edge.targetObjectKind,
  })));
  for (const edge of storedLogicEvidence.nativeDependencies.edges) {
    addRelationship({
      relationshipClass: 'PROVEN_OBJECT_NATIVE',
      granularity: 'OBJECT',
      proofState: 'PROVEN_NATIVE',
      sourceObjectIdentitySha256: edge.sourceObjectIdentitySha256,
      targetIdentitySha256: edge.targetObjectIdentitySha256,
      targetSchemaName: edge.targetSchemaName,
      targetObjectName: edge.targetObjectName,
      targetObjectKind: edge.targetObjectKind,
      evidenceKind: 'NATIVE_CATALOG',
      evidenceSha256: edge.edgeSha256,
    });
    const pair = canonicalJson({
      sourceObjectIdentitySha256: edge.sourceObjectIdentitySha256,
      targetSchemaName: edge.targetSchemaName,
      targetObjectName: edge.targetObjectName,
      targetObjectKind: edge.targetObjectKind,
    });
    if (!columnTargets.has(pair)) {
      addBlindSpot({
        blindSpotClass: 'COLUMN_RELATIONSHIP_UNKNOWN',
        sourceObjectIdentitySha256: edge.sourceObjectIdentitySha256,
        evidenceKind: 'NATIVE_CATALOG',
        evidenceSha256: edge.edgeSha256,
      });
    }
  }
  for (const edge of storedLogicEvidence.nativeDependencies.columnEdges) {
    addRelationship({
      relationshipClass: 'PROVEN_COLUMN_NATIVE',
      granularity: 'TARGET_COLUMN',
      proofState: 'PROVEN_NATIVE_COLUMN',
      sourceObjectIdentitySha256: edge.sourceObjectIdentitySha256,
      targetIdentitySha256: edge.targetColumnIdentitySha256,
      targetSchemaName: edge.targetSchemaName,
      targetObjectName: edge.targetObjectName,
      targetObjectKind: edge.targetObjectKind,
      targetColumnName: edge.targetColumnName,
      evidenceKind: 'NATIVE_CATALOG',
      evidenceSha256: edge.edgeSha256,
    });
  }
  for (const edge of storedLogicEvidence.parserEnrichment.edges) {
    addRelationship({
      relationshipClass: 'INFERRED_OBJECT_PARSER',
      granularity: 'OBJECT',
      proofState: 'INFERRED_PARSER',
      sourceObjectIdentitySha256: edge.sourceObjectIdentitySha256,
      targetIdentitySha256: null,
      targetSchemaName: edge.targetSchemaName,
      targetObjectName: edge.targetObjectName,
      targetObjectKind: edge.targetObjectKind,
      evidenceKind: 'OPTIONAL_PARSER',
      evidenceSha256: edge.edgeSha256,
    });
  }
  for (const gap of storedLogicEvidence.nativeDependencies.gaps) {
    addBlindSpot({
      blindSpotClass: 'UNKNOWN_NATIVE_RELATIONSHIP',
      sourceObjectIdentitySha256: gap.sourceObjectIdentitySha256,
      evidenceKind: 'NATIVE_CATALOG',
      evidenceSha256: gap.gapSha256,
    });
  }
  for (const gap of storedLogicEvidence.parserEnrichment.gaps) {
    addBlindSpot({
      blindSpotClass: gap.gapState === 'DYNAMIC_SQL_BLIND_SPOT'
        ? 'DYNAMIC_RELATIONSHIP_UNKNOWN'
        : 'UNSUPPORTED_RELATIONSHIP_UNKNOWN',
      sourceObjectIdentitySha256: gap.sourceObjectIdentitySha256,
      evidenceKind: 'OPTIONAL_PARSER',
      evidenceSha256: gap.gapSha256,
    });
  }
  relationships.sort(compareRows(['relationshipClass', 'sourceObjectIdentitySha256', 'targetSchemaName', 'targetObjectName', 'targetObjectKind', 'targetColumnName', 'evidenceSha256']));
  blindSpots.sort(compareRows(['blindSpotClass', 'sourceObjectIdentitySha256', 'evidenceSha256']));
  if (new Set(relationships.map(({ relationshipSha256 }) => relationshipSha256)).size !== relationships.length
    || new Set(blindSpots.map(({ blindSpotSha256 }) => blindSpotSha256)).size !== blindSpots.length
    || provenColumnObjectPairs.size !== storedLogicEvidence.nativeDependencies.columnEdges.length) {
    fail('DB_STORED_LOGIC_LINEAGE_DUPLICATE');
  }
  const relationshipClassCounts = Object.fromEntries([
    'PROVEN_OBJECT_NATIVE', 'PROVEN_COLUMN_NATIVE', 'INFERRED_OBJECT_PARSER',
  ].map((relationshipClass) => [relationshipClass, relationships.filter((entry) => entry.relationshipClass === relationshipClass).length]));
  const body = normalizeJsonValue({
    schemaVersion: STORED_LOGIC_LINEAGE_EVIDENCE_SCHEMA,
    summary: {
      relationshipCount: relationships.length,
      relationshipClassCounts,
      blindSpotCount: blindSpots.length,
      rawDefinitionsIncluded: false,
      promotionPolicy: 'CLASS_PRESERVING_NO_PROMOTION',
    },
    relationships,
    blindSpots,
  });
  return { ...body, lineageSha256: identitySha256(body) };
}

function verifyKnowledgeAndSupersetBinding(knowledgePack, supersetResult) {
  if (!hasExactKeys(knowledgePack ?? {}, [
    'schemaVersion', 'state', 'scope', 'source', 'authority', 'claims', 'summary', 'entries', 'knowledgePackSha256',
  ]) || knowledgePack.schemaVersion !== PROFILING_KNOWLEDGE_PACK_SCHEMA
    || knowledgePack.state !== 'CURATED_SYNTHETIC_FIXTURE'
    || !/^[a-f0-9]{64}$/.test(knowledgePack.knowledgePackSha256 ?? '')) {
    fail('DB_STORED_LOGIC_IMPACT_BI_SOURCE_INVALID');
  }
  const { knowledgePackSha256, ...knowledgeBody } = knowledgePack;
  if (identitySha256(knowledgeBody) !== knowledgePackSha256
    || knowledgePack.authority?.productionAuthority !== false
    || knowledgePack.authority?.externalPublicationAuthority !== false
    || knowledgePack.authority?.directSourceDatabaseAccess !== false
    || knowledgePack.claims?.semanticTruthEstablished !== false
    || knowledgePack.claims?.rowSamplesIncluded !== false
    || !Array.isArray(knowledgePack.entries)
    || knowledgePack.entries.length !== knowledgePack.summary?.knowledgeEntryCount
    || !/^[a-f0-9]{64}$/.test(knowledgePack.source?.structureSnapshotSha256 ?? '')) {
    fail('DB_STORED_LOGIC_IMPACT_BI_SOURCE_TAMPERED');
  }
  const expectedSuperset = buildProfilingSupersetResult({ knowledgePack });
  if (canonicalJson(expectedSuperset) !== canonicalJson(supersetResult)
    || supersetResult.dataset?.sourceConnection !== null
    || supersetResult.dataset?.sourceSql !== null
    || supersetResult.dashboard?.drillThrough?.sourceRoute !== null) {
    fail('DB_STORED_LOGIC_IMPACT_BI_SOURCE_TAMPERED');
  }
}

function comparableScope(storedLogicEvidence) {
  return normalizeJsonValue({
    engine: storedLogicEvidence.engine,
    database: storedLogicEvidence.scope?.database ?? null,
    container: storedLogicEvidence.scope?.container ?? null,
    schemas: storedLogicEvidence.scope?.schemas ?? [],
  });
}

export function buildStoredLogicImpactReport({ before, after, knowledgePack, supersetResult }) {
  verifyStoredLogicEvidence(before);
  verifyStoredLogicEvidence(after);
  if (before.coverageLedger?.allComplete !== true || after.coverageLedger?.allComplete !== true
    || before.coverageLedger?.totalQueries !== 2 || after.coverageLedger?.totalQueries !== 2
    || before.queryBindings?.some(({ state }) => state !== 'SUCCEEDED')
    || after.queryBindings?.some(({ state }) => state !== 'SUCCEEDED')) {
    fail('DB_STORED_LOGIC_IMPACT_COVERAGE_INCOMPLETE');
  }
  verifyKnowledgeAndSupersetBinding(knowledgePack, supersetResult);
  const evidenceScope = comparableScope(before);
  const afterScope = comparableScope(after);
  const biScope = normalizeJsonValue({
    engine: knowledgePack.scope?.engine,
    database: knowledgePack.scope?.database ?? null,
    container: knowledgePack.scope?.container ?? null,
    schemas: knowledgePack.scope?.schemas ?? [],
  });
  if (canonicalJson(evidenceScope) !== canonicalJson(afterScope)
    || canonicalJson(evidenceScope) !== canonicalJson(biScope)
    || before.packId !== after.packId
    || before.packVersion !== after.packVersion
    || before.runtimeValidation !== after.runtimeValidation) {
    fail('DB_STORED_LOGIC_IMPACT_SCOPE_INVALID');
  }

  const beforeObjects = new Map(before.objects.map((object) => [object.objectIdentitySha256, object]));
  const afterObjects = new Map(after.objects.map((object) => [object.objectIdentitySha256, object]));
  const allObjectIdentities = [...new Set([...beforeObjects.keys(), ...afterObjects.keys()])].sort();
  const changedObjects = [];
  for (const objectIdentitySha256 of allObjectIdentities) {
    const previous = beforeObjects.get(objectIdentitySha256);
    const current = afterObjects.get(objectIdentitySha256);
    if (previous?.objectSha256 === current?.objectSha256) continue;
    const reference = current ?? previous;
    const changeType = previous === undefined ? 'ADDED' : current === undefined ? 'REMOVED' : 'MODIFIED';
    const change = normalizeJsonValue({
      objectIdentitySha256,
      schemaName: reference.schemaName,
      objectName: reference.objectName,
      objectKind: reference.objectKind,
      changeType,
      beforeObjectSha256: previous?.objectSha256 ?? null,
      afterObjectSha256: current?.objectSha256 ?? null,
      beforeDefinitionFingerprintSha256: previous?.definitionFingerprintSha256 ?? null,
      afterDefinitionFingerprintSha256: current?.definitionFingerprintSha256 ?? null,
    });
    changedObjects.push({ ...change, changeSha256: identitySha256(change) });
  }
  if (changedObjects.length === 0) fail('DB_STORED_LOGIC_IMPACT_NO_CHANGE_DENIED');

  const changedIdentities = new Set(changedObjects.map(({ objectIdentitySha256 }) => objectIdentitySha256));
  const nativeRelationships = [...before.lineage.relationships, ...after.lineage.relationships]
    .filter((relationship) => changedIdentities.has(relationship.sourceObjectIdentitySha256)
      && ['PROVEN_OBJECT_NATIVE', 'PROVEN_COLUMN_NATIVE'].includes(relationship.relationshipClass));
  const relationshipBySha = new Map(nativeRelationships.map((relationship) => [relationship.relationshipSha256, relationship]));
  const exactRelationships = [...relationshipBySha.values()].sort(compareRows([
    'sourceObjectIdentitySha256', 'relationshipClass', 'targetSchemaName', 'targetObjectName', 'targetColumnName',
  ]));
  const affectedBiByCandidate = new Map();
  for (const relationship of exactRelationships) {
    for (const entry of knowledgePack.entries) {
      if (entry.target.schemaName !== relationship.targetSchemaName
        || entry.target.relationName !== relationship.targetObjectName
        || (relationship.relationshipClass === 'PROVEN_COLUMN_NATIVE'
          && entry.target.columnName !== relationship.targetColumnName)) continue;
      const impactClass = relationship.relationshipClass === 'PROVEN_COLUMN_NATIVE'
        ? 'AFFECTED_NATIVE_COLUMN'
        : 'POTENTIALLY_AFFECTED_NATIVE_OBJECT';
      const candidate = normalizeJsonValue({
        candidateSha256: entry.candidateSha256,
        candidateType: entry.candidateType,
        target: entry.target,
        reviewState: entry.reviewState,
        impactClass,
        sourceObjectIdentitySha256: relationship.sourceObjectIdentitySha256,
        relationshipSha256: relationship.relationshipSha256,
      });
      const existing = affectedBiByCandidate.get(entry.candidateSha256);
      if (existing === undefined
        || (existing.impactClass === 'POTENTIALLY_AFFECTED_NATIVE_OBJECT'
          && impactClass === 'AFFECTED_NATIVE_COLUMN')) {
        affectedBiByCandidate.set(entry.candidateSha256, {
          ...candidate,
          impactSha256: identitySha256(candidate),
        });
      }
    }
  }
  const affectedBi = [...affectedBiByCandidate.values()].sort(compareRows(['candidateSha256']));
  const changedBlindSpots = [...before.lineage.blindSpots, ...after.lineage.blindSpots]
    .filter((blindSpot) => changedIdentities.has(blindSpot.sourceObjectIdentitySha256));
  const blindSpotBySha = new Map(changedBlindSpots.map((blindSpot) => [blindSpot.blindSpotSha256, blindSpot]));
  const impactBlindSpots = [...blindSpotBySha.values()].sort(compareRows([
    'sourceObjectIdentitySha256', 'blindSpotClass', 'blindSpotSha256',
  ]));
  const body = normalizeJsonValue({
    schemaVersion: STORED_LOGIC_IMPACT_REPORT_SCHEMA,
    engine: before.engine,
    runtimeValidation: before.runtimeValidation,
    scope: before.scope,
    source: {
      beforeStoredLogicSha256: before.storedLogicSha256,
      afterStoredLogicSha256: after.storedLogicSha256,
      structureSnapshotSha256: knowledgePack.source.structureSnapshotSha256,
      knowledgePackSha256: knowledgePack.knowledgePackSha256,
      supersetResultSha256: supersetResult.supersetResultSha256,
    },
    policy: {
      affectedBiRule: 'EXACT_APPROVED_IDENTITIES_MATCHED_BY_PROVEN_NATIVE_TARGET/V1',
      inferredParserPromotionAllowed: false,
      rawDefinitionsIncluded: false,
      sourceRoutesIncluded: false,
      reviewRequired: true,
    },
    summary: {
      changedObjectCount: changedObjects.length,
      provenNativeRelationshipCount: exactRelationships.length,
      affectedApprovedBiCount: affectedBi.length,
      impactBlindSpotCount: impactBlindSpots.length,
    },
    changedObjects,
    provenNativeRelationships: exactRelationships,
    affectedBi,
    impactBlindSpots,
    authority: {
      productionAuthority: false,
      automaticPublication: false,
      directSourceDatabaseAccess: false,
    },
  });
  if (/source_text|definition_text|raw_definition|CREATE\s+(?:PROCEDURE|FUNCTION|TRIGGER)|password|credential/i.test(canonicalJson(body))) {
    fail('DB_STORED_LOGIC_IMPACT_UNSAFE_MATERIAL_DENIED');
  }
  return { ...body, impactReportSha256: identitySha256(body) };
}

export function verifyStoredLogicImpactReport(report, sources) {
  if (!hasExactKeys(report ?? {}, [
    'schemaVersion', 'engine', 'runtimeValidation', 'scope', 'source', 'policy', 'summary', 'changedObjects',
    'provenNativeRelationships', 'affectedBi', 'impactBlindSpots', 'authority', 'impactReportSha256',
  ]) || report.schemaVersion !== STORED_LOGIC_IMPACT_REPORT_SCHEMA
    || !/^[a-f0-9]{64}$/.test(report.impactReportSha256 ?? '')) {
    fail('DB_STORED_LOGIC_IMPACT_REPORT_INVALID');
  }
  const expected = buildStoredLogicImpactReport(sources);
  if (canonicalJson(expected) !== canonicalJson(report)) fail('DB_STORED_LOGIC_IMPACT_REPORT_TAMPERED');
  return report;
}

function emptyParserEnrichmentEvidence() {
  const body = normalizeJsonValue({
    schemaVersion: PARSER_ENRICHMENT_EVIDENCE_SCHEMA,
    state: 'NOT_REQUESTED',
    optional: true,
    parser: null,
    summary: {
      parsedObjectCount: 0,
      inferredEdgeCount: 0,
      blindSpotGapCount: 0,
      rawDefinitionsIncluded: false,
    },
    edges: [],
    gaps: [],
  });
  return { ...body, enrichmentSha256: identitySha256(body) };
}

export function attachParserEnrichmentEvidence(storedLogicEvidence, parserEnrichment) {
  verifyStoredLogicEvidence(storedLogicEvidence);
  verifyParserEnrichmentEvidence(parserEnrichment, storedLogicEvidence);
  const { storedLogicSha256: ignored, lineage: ignoredLineage, ...body } = storedLogicEvidence;
  const nextBase = normalizeJsonValue({ ...body, parserEnrichment });
  const next = normalizeJsonValue({ ...nextBase, lineage: buildStoredLogicLineageEvidence(nextBase) });
  return { ...next, storedLogicSha256: identitySha256(next) };
}

function verifyParserEnrichmentEvidence(enrichment, storedLogicEvidence) {
  if (!hasExactKeys(enrichment, [
    'schemaVersion', 'state', 'optional', 'parser', 'summary', 'edges', 'gaps', 'enrichmentSha256',
  ]) || enrichment.schemaVersion !== PARSER_ENRICHMENT_EVIDENCE_SCHEMA
    || !['NOT_REQUESTED', 'SUCCEEDED', 'PARTIAL', 'UNAVAILABLE'].includes(enrichment.state)
    || enrichment.optional !== true
    || !Array.isArray(enrichment.edges) || !Array.isArray(enrichment.gaps)
    || !/^[a-f0-9]{64}$/.test(enrichment.enrichmentSha256 ?? '')) fail('DB_PARSER_EVIDENCE_INVALID');
  const { enrichmentSha256, ...body } = enrichment;
  if (identitySha256(body) !== enrichmentSha256) fail('DB_PARSER_EVIDENCE_TAMPERED');
  if (!hasExactKeys(enrichment.summary, [
    'parsedObjectCount', 'inferredEdgeCount', 'blindSpotGapCount', 'rawDefinitionsIncluded',
  ]) || !Number.isInteger(enrichment.summary.parsedObjectCount) || enrichment.summary.parsedObjectCount < 0
    || enrichment.summary.inferredEdgeCount !== enrichment.edges.length
    || enrichment.summary.blindSpotGapCount !== enrichment.gaps.length
    || enrichment.summary.rawDefinitionsIncluded !== false) fail('DB_PARSER_EVIDENCE_INVALID');
  if (enrichment.state === 'NOT_REQUESTED') {
    if (enrichment.parser !== null || enrichment.edges.length !== 0 || enrichment.gaps.length !== 0) fail('DB_PARSER_EVIDENCE_INVALID');
    return enrichment;
  }
  if (!hasExactKeys(enrichment.parser, [
    'packageName', 'version', 'spdx', 'integrity', 'sourceUrl', 'dialectContract',
    'requiredForNativeCollector', 'promotionPolicy',
  ]) || enrichment.parser.packageName !== 'node-sql-parser'
    || enrichment.parser.version !== '5.4.0'
    || enrichment.parser.spdx !== 'Apache-2.0'
    || enrichment.parser.requiredForNativeCollector !== false
    || enrichment.parser.promotionPolicy !== 'NEVER_PROVEN') fail('DB_PARSER_EVIDENCE_INVALID');
  const knownIdentities = new Set(storedLogicEvidence.objects.map(({ objectIdentitySha256 }) => objectIdentitySha256));
  for (const edge of enrichment.edges) {
    if (!hasExactKeys(edge, [
      'sourceObjectIdentitySha256', 'sourceSchemaName', 'sourceObjectName', 'sourceObjectKind',
      'sourceTextSha256', 'parserContractSha256', 'targetSchemaName', 'targetObjectName',
      'targetObjectKind', 'proofState', 'edgeSha256',
    ]) || edge.proofState !== 'INFERRED_PARSER' || edge.targetObjectKind !== 'RELATION_UNKNOWN'
      || !knownIdentities.has(edge.sourceObjectIdentitySha256)) fail('DB_PARSER_EVIDENCE_INVALID');
    const { edgeSha256, ...edgeBody } = edge;
    if (edgeSha256 !== identitySha256(edgeBody)) fail('DB_PARSER_EVIDENCE_TAMPERED');
  }
  for (const gap of enrichment.gaps) {
    if (!hasExactKeys(gap, [
      'sourceObjectIdentitySha256', 'sourceSchemaName', 'sourceObjectName', 'sourceObjectKind',
      'sourceTextSha256', 'parserContractSha256', 'gapState', 'gapSha256',
    ]) || !['DYNAMIC_SQL_BLIND_SPOT', 'UNSUPPORTED_SYNTAX_BLIND_SPOT'].includes(gap.gapState)
      || !knownIdentities.has(gap.sourceObjectIdentitySha256)) fail('DB_PARSER_EVIDENCE_INVALID');
    const { gapSha256, ...gapBody } = gap;
    if (gapSha256 !== identitySha256(gapBody)) fail('DB_PARSER_EVIDENCE_TAMPERED');
  }
  if (/"(?:sourceText|source_text|rawDefinition|raw_definition)"\s*:|CREATE\s+(?:PROCEDURE|FUNCTION|TRIGGER)/i.test(canonicalJson(enrichment))) {
    fail('DB_PARSER_EVIDENCE_INVALID');
  }
  return enrichment;
}

export function verifyStoredLogicEvidence(evidence) {
  if (!hasExactKeys(evidence, [
    'schemaVersion', 'packId', 'packVersion', 'engine', 'runtimeValidation', 'scope', 'identityContract',
    'definitionFingerprintContract', 'coverage', 'coverageLedger', 'queryBindings', 'summary', 'objects', 'nativeDependencies', 'parserEnrichment',
    'lineage',
    'storedLogicSha256',
  ]) || evidence.schemaVersion !== STORED_LOGIC_EVIDENCE_SCHEMA
    || !['mssql', 'oracle'].includes(evidence.engine)
    || !Array.isArray(evidence.objects)
    || !/^[a-f0-9]{64}$/.test(evidence.storedLogicSha256 ?? '')) {
    fail('DB_STORED_LOGIC_EVIDENCE_INVALID');
  }
  const { storedLogicSha256, ...body } = evidence;
  if (identitySha256(body) !== storedLogicSha256) fail('DB_STORED_LOGIC_EVIDENCE_TAMPERED');
  const identities = new Set();
  for (const object of evidence.objects) {
    if (!hasExactKeys(object, [
      'schemaName', 'objectName', 'objectKind', 'nativeObjectId', 'parentSchemaName', 'parentObjectName',
      'enablementState', 'definitionVisibility', 'objectIdentitySha256', 'definitionComponentCount',
      'definitionComponentHashAlgorithm', 'definitionFingerprintAlgorithm', 'definitionFingerprintSha256',
      'objectSha256',
    ])) fail('DB_STORED_LOGIC_EVIDENCE_INVALID');
    const { objectSha256, ...objectBody } = object;
    const expectedIdentity = identitySha256({
      engine: evidence.engine,
      scope: evidence.scope,
      schemaName: object.schemaName,
      objectName: object.objectName,
      objectKind: object.objectKind,
    });
    if (object.objectIdentitySha256 !== expectedIdentity
      || objectSha256 !== identitySha256(objectBody)
      || identities.has(object.objectIdentitySha256)) fail('DB_STORED_LOGIC_EVIDENCE_TAMPERED');
    identities.add(object.objectIdentitySha256);
  }
  const expectedTypeCounts = Object.fromEntries(['PROCEDURE', 'FUNCTION', 'TRIGGER']
    .map((kind) => [kind, evidence.objects.filter((object) => object.objectKind === kind).length]));
  if (!hasExactKeys(evidence.nativeDependencies ?? {}, ['edges', 'columnEdges', 'gaps'])
    || !Array.isArray(evidence.nativeDependencies.edges)
    || !Array.isArray(evidence.nativeDependencies.columnEdges)
    || !Array.isArray(evidence.nativeDependencies.gaps)) fail('DB_STORED_LOGIC_EVIDENCE_INVALID');
  const edgeIdentities = new Set();
  for (const edge of evidence.nativeDependencies.edges) {
    if (!hasExactKeys(edge, [
      'sourceObjectIdentitySha256', 'sourceSchemaName', 'sourceObjectName', 'sourceObjectKind',
      'targetSchemaName', 'targetObjectName', 'targetObjectKind', 'targetDatabaseName',
      'targetServerOrLinkName', 'nativeDependencyKind', 'isSchemaBound', 'isCallerDependent',
      'proofState', 'targetObjectIdentitySha256', 'edgeSha256',
    ]) || edge.proofState !== 'PROVEN_NATIVE') fail('DB_STORED_LOGIC_EVIDENCE_INVALID');
    const { edgeSha256, ...edgeBody } = edge;
    const expectedSourceIdentity = identitySha256({
      engine: evidence.engine,
      scope: evidence.scope,
      schemaName: edge.sourceSchemaName,
      objectName: edge.sourceObjectName,
      objectKind: edge.sourceObjectKind,
    });
    const expectedTargetIdentity = identitySha256({
      engine: evidence.engine,
      scope: evidence.scope,
      schemaName: edge.targetSchemaName,
      objectName: edge.targetObjectName,
      objectKind: edge.targetObjectKind,
    });
    if (edgeSha256 !== identitySha256(edgeBody)
      || edgeIdentities.has(edgeSha256)
      || edge.sourceObjectIdentitySha256 !== expectedSourceIdentity
      || edge.targetObjectIdentitySha256 !== expectedTargetIdentity
      || !identities.has(edge.sourceObjectIdentitySha256)
      || !['PROCEDURE', 'FUNCTION', 'TRIGGER'].includes(edge.sourceObjectKind)
      || !validScopedName(edge.targetObjectKind)
      || edge.targetDatabaseName !== null
      || edge.targetServerOrLinkName !== null) {
      fail('DB_STORED_LOGIC_EVIDENCE_TAMPERED');
    }
    edgeIdentities.add(edgeSha256);
  }
  const columnEdgeIdentities = new Set();
  for (const edge of evidence.nativeDependencies.columnEdges) {
    if (!hasExactKeys(edge, [
      'sourceObjectIdentitySha256', 'sourceSchemaName', 'sourceObjectName', 'sourceObjectKind',
      'targetSchemaName', 'targetObjectName', 'targetObjectKind', 'targetColumnName',
      'targetColumnIdentitySha256', 'nativeDependencyKind', 'granularity', 'proofState', 'edgeSha256',
    ]) || edge.granularity !== 'TARGET_COLUMN' || edge.proofState !== 'PROVEN_NATIVE_COLUMN') {
      fail('DB_STORED_LOGIC_EVIDENCE_INVALID');
    }
    const { edgeSha256, ...edgeBody } = edge;
    const expectedSourceIdentity = identitySha256({
      engine: evidence.engine, scope: evidence.scope, schemaName: edge.sourceSchemaName,
      objectName: edge.sourceObjectName, objectKind: edge.sourceObjectKind,
    });
    const expectedColumnIdentity = identitySha256({
      engine: evidence.engine, scope: evidence.scope, schemaName: edge.targetSchemaName,
      objectName: edge.targetObjectName, objectKind: edge.targetObjectKind, columnName: edge.targetColumnName,
    });
    if (edgeSha256 !== identitySha256(edgeBody)
      || columnEdgeIdentities.has(edgeSha256)
      || edge.sourceObjectIdentitySha256 !== expectedSourceIdentity
      || edge.targetColumnIdentitySha256 !== expectedColumnIdentity
      || !identities.has(edge.sourceObjectIdentitySha256)
      || !validScopedName(edge.targetColumnName)) fail('DB_STORED_LOGIC_EVIDENCE_TAMPERED');
    columnEdgeIdentities.add(edgeSha256);
  }
  const gapIdentities = new Set();
  for (const gap of evidence.nativeDependencies.gaps) {
    if (!hasExactKeys(gap, [
      'sourceObjectIdentitySha256', 'sourceSchemaName', 'sourceObjectName', 'sourceObjectKind',
      'targetSchemaName', 'targetObjectName', 'targetObjectKind', 'targetDatabaseName',
      'targetServerOrLinkName', 'nativeDependencyKind', 'isSchemaBound', 'isCallerDependent',
      'gapState', 'gapSha256',
    ]) || gap.gapState !== 'UNRESOLVED_NATIVE_REFERENCE') fail('DB_STORED_LOGIC_EVIDENCE_INVALID');
    const { gapSha256, ...gapBody } = gap;
    const expectedSourceIdentity = identitySha256({
      engine: evidence.engine,
      scope: evidence.scope,
      schemaName: gap.sourceSchemaName,
      objectName: gap.sourceObjectName,
      objectKind: gap.sourceObjectKind,
    });
    if (gapSha256 !== identitySha256(gapBody)
      || gapIdentities.has(gapSha256)
      || gap.sourceObjectIdentitySha256 !== expectedSourceIdentity
      || !identities.has(gap.sourceObjectIdentitySha256)
      || !['PROCEDURE', 'FUNCTION', 'TRIGGER'].includes(gap.sourceObjectKind)
      || !validScopedName(gap.targetObjectName)
      || (gap.targetSchemaName !== null && !validScopedName(gap.targetSchemaName))
      || (gap.targetObjectKind !== null && !validScopedName(gap.targetObjectKind))) {
      fail('DB_STORED_LOGIC_EVIDENCE_TAMPERED');
    }
    gapIdentities.add(gapSha256);
  }
  verifyParserEnrichmentEvidence(evidence.parserEnrichment, evidence);
  if (canonicalJson(buildStoredLogicLineageEvidence(evidence)) !== canonicalJson(evidence.lineage)) {
    fail('DB_STORED_LOGIC_LINEAGE_TAMPERED');
  }
  if (!hasExactKeys(evidence.summary ?? {}, [
    'objectCount', 'typeCounts', 'visibleHashedObjects', 'encryptedOrInvisibleObjects',
    'provenNativeDependencyEdges', 'provenNativeColumnEdges', 'unresolvedNativeDependencyGaps', 'rawDefinitionsIncluded',
  ]) || evidence.summary.objectCount !== evidence.objects.length
    || canonicalJson(evidence.summary.typeCounts) !== canonicalJson(expectedTypeCounts)
    || evidence.summary.visibleHashedObjects !== evidence.objects.filter((object) => object.definitionVisibility === 'VISIBLE_HASHED').length
    || evidence.summary.encryptedOrInvisibleObjects !== evidence.objects.filter((object) => object.definitionVisibility === 'ENCRYPTED_OR_INVISIBLE').length
    || evidence.summary.provenNativeDependencyEdges !== evidence.nativeDependencies.edges.length
    || evidence.summary.provenNativeColumnEdges !== evidence.nativeDependencies.columnEdges.length
    || evidence.summary.unresolvedNativeDependencyGaps !== evidence.nativeDependencies.gaps.length
    || evidence.summary.rawDefinitionsIncluded !== false
    || /source_text|definition_text|raw_definition|CREATE\s+(?:PROCEDURE|FUNCTION|TRIGGER)/i.test(canonicalJson(evidence))) {
    fail('DB_STORED_LOGIC_EVIDENCE_INVALID');
  }
  return evidence;
}
