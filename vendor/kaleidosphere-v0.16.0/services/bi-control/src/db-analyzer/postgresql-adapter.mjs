import { auditCatalogQuery } from './query-safety.mjs';

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const identifier = (value) => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(value);
const boundedTimeout = (value) => Number.isInteger(value) && value >= 1000 && value <= 120000;

export function buildPostgresqlConnectionOptions(profile, password) {
  if (profile?.engine !== 'postgresql' || profile.adapter?.kind !== 'postgresql'
    || profile.policy?.access !== 'READ_ONLY' || profile.policy?.allowRowSamples !== false
    || !identifier(profile.scope?.database) || !identifier(profile.adapter?.user)
    || typeof profile.adapter?.host !== 'string' || profile.adapter.host.length === 0
    || !Number.isInteger(profile.adapter?.port) || profile.adapter.port < 1 || profile.adapter.port > 65535
    || typeof profile.adapter?.ssl !== 'boolean'
    || !boundedTimeout(profile.adapter?.connectTimeoutMs) || !boundedTimeout(profile.policy?.maxQueryTimeoutMs)
    || typeof password !== 'string' || password.length === 0) fail('DB_ANALYZE_POSTGRESQL_CONFIG_INVALID');
  return {
    host: profile.adapter.host,
    port: profile.adapter.port,
    user: profile.adapter.user,
    password,
    database: profile.scope.database,
    ssl: profile.adapter.ssl ? {rejectUnauthorized: true} : false,
    connectionTimeoutMillis: profile.adapter.connectTimeoutMs,
    query_timeout: profile.policy.maxQueryTimeoutMs,
    statement_timeout: profile.policy.maxQueryTimeoutMs,
    application_name: 'kaleidosphere-read-only-analyzer',
    options: '-c default_transaction_read_only=on',
  };
}

export function compilePostgresqlScopedQuery(query, statement, schemas) {
  if (typeof statement !== 'string') fail('DB_ANALYZE_PACK_POLICY_DENIED');
  auditCatalogQuery({engine: 'postgresql', queryId: query?.id ?? 'postgresql.scoped-query', sql: statement});
  if (!Array.isArray(query?.outputColumns) || query.outputColumns.length === 0
    || query.outputColumns.some((column) => !identifier(column))
    || !Array.isArray(query?.sortKeys) || query.sortKeys.length === 0
    || query.sortKeys.some((key) => !identifier(key))
    || !(query?.scopeColumn === null || identifier(query?.scopeColumn))) fail('DB_ANALYZE_QUERY_CONTRACT_INVALID');
  if (query.scopeColumn === null) return {statement, values: []};
  if (!Array.isArray(schemas) || schemas.length === 0 || schemas.some((schema) => !identifier(schema))) {
    fail('DB_ANALYZE_SCOPE_INVALID');
  }
  const inner = statement.trim().replace(/;\s*$/, '');
  const columns = query.outputColumns.map((column) => `scope."${column}" AS "${column}"`).join(', ');
  const placeholders = schemas.map((_schema, index) => `$${index + 1}`);
  const compiled = {
    statement: `SELECT ${columns} FROM (${inner}) AS scope WHERE scope."${query.scopeColumn}" IN (${placeholders.join(', ')}) ORDER BY ${query.sortKeys.map((key) => `scope."${key}"`).join(', ')};`,
    values: [...schemas],
  };
  auditCatalogQuery({engine: 'postgresql', queryId: query?.id ?? 'postgresql.scoped-query', sql: compiled.statement});
  return compiled;
}

export function compilePostgresqlProfileQuery({profile, query, statement, requestedSchemas = profile?.scope?.schemas}) {
  if (!Array.isArray(profile?.scope?.schemas) || !Array.isArray(requestedSchemas)
    || profile.scope.schemas.length !== requestedSchemas.length
    || profile.scope.schemas.some((schema, index) => schema !== requestedSchemas[index])) {
    fail('DB_ANALYZE_SCOPE_OVERRIDE_DENIED');
  }
  return compilePostgresqlScopedQuery(query, statement, requestedSchemas);
}

export function assertPostgresqlReadOnlySession(rows) {
  if (!Array.isArray(rows) || rows.length !== 1
    || rows[0]?.transaction_read_only !== 'on'
    || rows[0]?.default_transaction_read_only !== 'on') fail('DB_ANALYZE_PRINCIPAL_NOT_READ_ONLY');
}
