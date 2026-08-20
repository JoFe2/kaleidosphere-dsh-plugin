import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  attachParserEnrichmentEvidence,
  buildAggregateProfilingEvidence,
  buildPreflightEvidence,
  buildStoredLogicEvidence,
  canonicalJson,
  validateAnalyzeProfile,
  validateProfilingQueryManifest,
  validateQueryManifest,
} from './core.mjs';
import { buildOptionalParserEnrichment } from './parser-enrichment.mjs';
import { auditQueryPackSafety } from './query-safety.mjs';
import { runPostgresqlQueries } from './postgresql-runtime.mjs';
import { buildOracleConnectString } from '../runtime-config.mjs';

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const readJson = async (file) => JSON.parse(await readFile(file, 'utf8'));

// SQL Server exposes these empty built-in principal schemas through sys.schemas even
// when an analysis intentionally scopes only application schemas.
const MSSQL_AMBIENT_PRINCIPAL_SCHEMAS = new Set([
  'db_accessadmin',
  'db_backupoperator',
  'db_datareader',
  'db_datawriter',
  'db_ddladmin',
  'db_denydatareader',
  'db_denydatawriter',
  'db_owner',
  'db_securityadmin',
  'guest',
]);

export function normalizeMssqlRuntimeScopeResult({ profile, query, result }) {
  if (query.id !== 'mssql.structure.schemas' || result.state !== 'SUCCEEDED' || !Array.isArray(result.rows)) return result;
  const declaredSchemas = new Set(profile.scope.schemas);
  return {
    ...result,
    rows: result.rows.filter((row) => declaredSchemas.has(row?.schema_name)
      || !MSSQL_AMBIENT_PRINCIPAL_SCHEMAS.has(row?.schema_name)),
  };
}

async function runMssqlQueries({ profile, manifest, entries }) {
  const password = process.env[profile.adapter.passwordEnv];
  if (!password) fail('DB_ANALYZE_CREDENTIAL_MISSING');
  const { default: sql } = await import('mssql');
  const pool = await sql.connect({
    server: profile.adapter.host,
    port: profile.adapter.port,
    user: profile.adapter.user,
    password,
    database: profile.scope.database,
    connectionTimeout: profile.policy.maxQueryTimeoutMs,
    requestTimeout: profile.policy.maxQueryTimeoutMs,
    options: {
      encrypt: profile.adapter.encrypt,
      trustServerCertificate: profile.adapter.trustServerCertificate,
      readOnlyIntent: true,
      enableArithAbort: true,
    },
  });
  try {
    const results = {};
    for (const query of manifest.queries) {
      const statement = entries.find(([id]) => id === query.id)?.[1];
      if (typeof statement !== 'string' || !/^\s*SELECT\b/i.test(statement)) fail('DB_ANALYZE_PACK_POLICY_DENIED');
      try {
        const response = await pool.request().query(statement);
        results[query.id] = normalizeMssqlRuntimeScopeResult({
          profile,
          query,
          result: { state: 'SUCCEEDED', reasonCode: null, rows: response.recordset },
        });
      } catch (error) {
        results[query.id] = {
          state: error?.code === 'ETIMEOUT' ? 'TIMEOUT' : error?.number === 229 ? 'DENIED' : 'ERROR',
          reasonCode: error?.code ?? `MSSQL_${error?.number ?? 'QUERY_FAILED'}`,
          rows: [],
        };
      }
    }
    return { schemaVersion: 'chimpmaera.db/runtime-query-results/v1', engine: 'mssql', runtimeValidated: true, results };
  } finally {
    await pool.close();
  }
}

const oracleReasonCode = (error) => {
  const source = String(error?.code ?? error?.errorNum ?? 'ORACLE_QUERY_FAILED').toUpperCase();
  return source.replace(/[^A-Z0-9_]/g, '_').slice(0, 128) || 'ORACLE_QUERY_FAILED';
};

const oracleResultRows = (result, query) => (result.rows ?? []).map((row) => Object.fromEntries(
  query.outputColumns.map((column) => {
    const key = Object.keys(row).find((candidate) => candidate.toLowerCase() === column.toLowerCase());
    return [column, key === undefined ? undefined : row[key]];
  }),
));

export function compileOracleScopedQuery(query, statement, schemas) {
  if (query.scopeColumn === null) return {statement, binds: {}};
  if (!Array.isArray(schemas) || schemas.length === 0 || schemas.some((schema) => !/^[A-Z][A-Z0-9_$#]{0,127}$/.test(schema))) {
    fail('DB_ANALYZE_SCOPE_INVALID');
  }
  const inner = statement.trim().replace(/;\s*$/, '');
  const columns = query.outputColumns.map((column) => `scope.${column} AS ${column}`).join(', ');
  const placeholders = schemas.map((_schema, index) => `:scope${index}`);
  const binds = Object.fromEntries(schemas.map((schema, index) => [`scope${index}`, schema]));
  return {statement: `SELECT ${columns} FROM (${inner}) scope WHERE scope.${query.scopeColumn} IN (${placeholders.join(', ')}) ORDER BY ${query.sortKeys.map((key) => `scope.${key}`).join(', ')};`, binds};
}

export function assertOracleIdentity(profile, rows) {
  if (!Array.isArray(rows) || rows.length === 0 || rows.some((row) => row.engine !== 'oracle'
    || row.database_name !== profile.scope.database || row.container_name !== profile.scope.container
    || typeof row.engine_version !== 'string' || row.engine_version.length === 0)) {
    fail('DB_ANALYZE_SCOPE_MISMATCH');
  }
}

export function assertOracleReadOnlyCapabilities(profile, rows) {
  if (!Array.isArray(rows) || !rows.some((row) => row.permission_name === 'SYSTEM:CREATE SESSION')) {
    fail('DB_ANALYZE_ORACLE_PREFLIGHT_FAILED');
  }
  for (const row of rows) {
    if (row.has_permission !== 1 || typeof row.permission_name !== 'string') fail('DB_ANALYZE_ORACLE_PREFLIGHT_FAILED');
    if (row.permission_name.startsWith('SYSTEM:') && !['SYSTEM:CREATE SESSION', 'SYSTEM:SET CONTAINER'].includes(row.permission_name)) {
      fail('DB_ANALYZE_PRINCIPAL_NOT_READ_ONLY');
    }
    const object = /^(?:OBJECT|COLUMN_OBJECT|ROLE_OBJECT):([^:]+):([^.]+)\./.exec(row.permission_name);
    if (object && (!['EXECUTE', 'READ', 'SELECT'].includes(object[1]) || !profile.scope.schemas.includes(object[2]))) {
      fail('DB_ANALYZE_PRINCIPAL_NOT_READ_ONLY');
    }
    if (!row.permission_name.startsWith('SYSTEM:') && !object) fail('DB_ANALYZE_ORACLE_PREFLIGHT_FAILED');
  }
}

export async function runOracleQueries({ profile, manifest, entries, driver }) {
  const password = process.env[profile.adapter.passwordEnv];
  if (!password) fail('DB_ANALYZE_CREDENTIAL_MISSING');
  const oracle = driver ?? (await import('oracledb')).default;
  if (oracle.thin === false) fail('DB_ANALYZE_ORACLE_THIN_REQUIRED');
  let pool;
  let connection;
  try {
    pool = await oracle.createPool({
      user: profile.adapter.user,
      password,
      connectString: buildOracleConnectString(profile.adapter),
      poolMin: 0,
      poolMax: 2,
      poolIncrement: 1,
      poolTimeout: 30,
      queueTimeout: profile.adapter.connectTimeoutMs,
    });
    connection = await pool.getConnection();
    connection.callTimeout = profile.policy.maxQueryTimeoutMs;
    const results = {};
    for (const query of manifest.queries) {
      const source = entries.find(([id]) => id === query.id)?.[1];
      if (typeof source !== 'string' || !/^\s*SELECT\b/i.test(source)) fail('DB_ANALYZE_PACK_POLICY_DENIED');
      const compiled = compileOracleScopedQuery(query, source, profile.scope.schemas);
      auditQueryPackSafety({manifest: {...manifest, queries: [query]}, sqlByQueryId: {[query.id]: compiled.statement}});
      try {
        const response = await connection.execute(compiled.statement, compiled.binds, {outFormat: oracle.OUT_FORMAT_OBJECT});
        const rows = oracleResultRows(response, query);
        results[query.id] = {state: 'SUCCEEDED', reasonCode: null, rows};
        if (query.id === 'oracle.preflight.identity') assertOracleIdentity(profile, rows);
        if (query.id === 'oracle.preflight.rights') assertOracleReadOnlyCapabilities(profile, rows);
        if (query.id === 'oracle.structure.schemas') {
          const observed = rows.map((row) => row.schema_name).sort();
          const expected = [...profile.scope.schemas].sort();
          if (canonicalJson(observed) !== canonicalJson(expected)) fail('DB_ANALYZE_SCOPE_MISMATCH');
        }
      } catch (error) {
        if (String(error?.code ?? error?.message).startsWith('DB_ANALYZE_')) throw error;
        if (query.category === 'preflight' || query.id === 'oracle.structure.schemas') fail('DB_ANALYZE_ORACLE_PREFLIGHT_FAILED');
        results[query.id] = {
          state: ['NJS-040', 'ORA-01013'].includes(error?.code) ? 'TIMEOUT' : error?.errorNum === 1031 ? 'DENIED' : 'ERROR',
          reasonCode: oracleReasonCode(error),
          rows: [],
        };
      }
    }
    return {schemaVersion: 'chimpmaera.db/runtime-query-results/v1', engine: 'oracle', runtimeValidated: true, results};
  } finally {
    if (connection) await connection.close().catch(() => {});
    if (pool) await pool.close(0).catch(() => {});
  }
}

function assertScope(profile, evidence) {
  const identity = evidence.extracts.find((entry) => entry.queryId === `${profile.engine}.preflight.identity`);
  if (identity?.state !== 'SUCCEEDED' || identity.rows.length === 0) fail('DB_ANALYZE_SCOPE_UNVERIFIED');
  for (const row of identity.rows) {
    if (row.engine !== profile.engine || typeof row.engine_version !== 'string' || row.engine_version.length === 0
      || row.database_name !== profile.scope.database) fail('DB_ANALYZE_SCOPE_MISMATCH');
    if (profile.scope.container !== null && row.container_name !== profile.scope.container) fail('DB_ANALYZE_SCOPE_MISMATCH');
  }
}

export async function runAnalyzeProfile(profileFile, options = {}) {
  if (options.signal !== undefined && typeof options.signal?.aborted !== 'boolean') fail('DB_ANALYZE_CANCELLATION_INVALID');
  const assertActive = () => {
    if (options.signal?.aborted) fail('DB_ANALYZE_CANCELLED');
  };
  assertActive();
  const repositoryRoot = path.resolve(options.repositoryRoot ?? REPOSITORY_ROOT);
  const resolvedProfile = path.resolve(profileFile);
  const profile = validateAnalyzeProfile(await readJson(resolvedProfile));
  assertActive();
  if (profile.mode === 'RUNTIME' && profile.policy.profiling !== undefined) fail('DB_PROFILING_RUNTIME_NOT_AUTHORIZED');
  if (profile.mode === 'RUNTIME' && profile.policy.storedLogic !== undefined) fail('DB_STORED_LOGIC_RUNTIME_NOT_AUTHORIZED');
  const packDirectory = path.join(repositoryRoot, 'query-packs', 'db-analyzer', profile.queryPack.version, profile.engine);
  const manifest = validateQueryManifest(await readJson(path.join(packDirectory, 'manifest.json')));
  if (manifest.engine !== profile.engine || manifest.queries.some((query) => query.timeoutMs > profile.policy.maxQueryTimeoutMs)) fail('DB_ANALYZE_PACK_POLICY_DENIED');

  const entries = await Promise.all(manifest.queries.map(async (query) => [query.id, await readFile(path.join(packDirectory, query.file), 'utf8')]));
  auditQueryPackSafety({ manifest, sqlByQueryId: Object.fromEntries(entries) });
  const resultSets = profile.mode === 'SYNTHETIC'
    ? await readJson(path.join(path.dirname(resolvedProfile), profile.adapter.fixture))
    : profile.engine === 'mssql'
      ? await runMssqlQueries({ profile, manifest, entries })
      : profile.engine === 'postgresql'
        ? await runPostgresqlQueries({ profile, manifest, entries, signal: options.signal, driver: options.postgresqlDriver })
        : await runOracleQueries({ profile, manifest, entries, driver: options.oracleDriver });
  assertActive();
  let profilingEvidence;
  if (profile.policy.profiling !== undefined) {
    const profilingManifest = validateProfilingQueryManifest(await readJson(path.join(packDirectory, 'profiling-manifest.json')));
    const profilingEntries = await Promise.all(profilingManifest.queries
      .map(async (query) => [query.id, await readFile(path.join(packDirectory, query.file), 'utf8')]));
    const profilingSqlByQueryId = Object.fromEntries(profilingEntries);
    validateProfilingQueryManifest(profilingManifest, profilingSqlByQueryId);
    profilingEvidence = buildAggregateProfilingEvidence({
      profile,
      profilingManifest,
      profilingSqlByQueryId,
      resultSets: await readJson(path.join(path.dirname(resolvedProfile), profile.policy.profiling.aggregateFixture)),
    });
  }
  let storedLogicEvidence;
  if (profile.policy.storedLogic !== undefined) {
    const storedLogicManifest = validateQueryManifest(await readJson(path.join(packDirectory, 'stored-logic-manifest.json')));
    if (storedLogicManifest.engine !== profile.engine
      || storedLogicManifest.queries.some((query) => query.timeoutMs > profile.policy.maxQueryTimeoutMs)) {
      fail('DB_ANALYZE_PACK_POLICY_DENIED');
    }
    const storedLogicEntries = await Promise.all(storedLogicManifest.queries
      .map(async (query) => [query.id, await readFile(path.join(packDirectory, query.file), 'utf8')]));
    const storedLogicSqlByQueryId = Object.fromEntries(storedLogicEntries);
    auditQueryPackSafety({ manifest: storedLogicManifest, sqlByQueryId: storedLogicSqlByQueryId });
    storedLogicEvidence = buildStoredLogicEvidence({
      manifest: storedLogicManifest,
      sqlByQueryId: storedLogicSqlByQueryId,
      resultSets: await readJson(path.join(path.dirname(resolvedProfile), profile.policy.storedLogic.fixture)),
      profileContext: {
        profileId: profile.profileId,
        mode: profile.mode,
        scope: profile.scope,
        policy: profile.policy,
        adapter: profile.adapter.kind,
      },
    });
    if (profile.policy.storedLogic.parserEnrichment !== undefined) {
      const storedLogicLock = await readJson(path.join(packDirectory, '..', 'stored-logic-provenance-license-lock.json'));
      const parserEnrichment = await buildOptionalParserEnrichment({
        storedLogicEvidence,
        sourceFixture: await readJson(path.join(path.dirname(resolvedProfile), profile.policy.storedLogic.parserEnrichment.fixture)),
        parserLock: storedLogicLock.parserDependency,
      });
      storedLogicEvidence = attachParserEnrichmentEvidence(storedLogicEvidence, parserEnrichment);
    }
  }
  assertActive();
  const evidence = buildPreflightEvidence({
    manifest,
    sqlByQueryId: Object.fromEntries(entries),
    resultSets,
    profilingEvidence,
    storedLogicEvidence,
    profileContext: {
      profileId: profile.profileId,
      mode: profile.mode,
      scope: profile.scope,
      policy: profile.policy,
      adapter: profile.adapter.kind,
    },
  });
  assertScope(profile, evidence);
  return evidence;
}

export const renderAnalyzeEvidence = (evidence) => canonicalJson(evidence);
