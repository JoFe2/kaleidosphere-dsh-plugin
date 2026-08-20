const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const MUTATING_OR_PRIVILEGED_TOKENS = new Set([
  'ALTER', 'BACKUP', 'BEGIN', 'BULK', 'CALL', 'CREATE', 'DBCC', 'DELETE', 'DENY',
  'DROP', 'EXEC', 'EXECUTE', 'GRANT', 'INSERT', 'MERGE', 'OPENROWSET',
  'OPENDATASOURCE', 'RESTORE', 'REVOKE', 'SET', 'TRUNCATE', 'UPDATE', 'USE',
]);

const CATALOG_SOURCES = Object.freeze({
  mssql: new Set([
    'SYS.CHECK_CONSTRAINTS', 'SYS.COLUMNS', 'SYS.COMPUTED_COLUMNS',
    'SYS.DATABASES', 'SYS.DATA_SPACES', 'SYS.DEFAULT_CONSTRAINTS',
    'SYS.FOREIGN_KEYS', 'SYS.FOREIGN_KEY_COLUMNS', 'SYS.IDENTITY_COLUMNS',
    'SYS.INDEX_COLUMNS', 'SYS.INDEXES', 'SYS.KEY_CONSTRAINTS', 'SYS.OBJECTS',
    'SYS.PARTITIONS', 'SYS.PARTITION_SCHEMES', 'SYS.SCHEMAS', 'SYS.SEQUENCES',
    'SYS.SQL_EXPRESSION_DEPENDENCIES', 'SYS.SQL_MODULES', 'SYS.SYNONYMS', 'SYS.TABLES', 'SYS.TRIGGERS', 'SYS.TYPES',
  ]),
  oracle: new Set([
    'ALL_ARGUMENTS', 'ALL_COL_COMMENTS', 'ALL_COL_PRIVS', 'ALL_CONSTRAINTS', 'ALL_CONS_COLUMNS',
    'ALL_DB_LINKS', 'ALL_DEPENDENCIES', 'ALL_ERRORS', 'ALL_INDEXES', 'ALL_IND_COLUMNS',
    'ALL_IND_EXPRESSIONS', 'ALL_IND_STATISTICS', 'ALL_LOBS', 'ALL_MVIEWS', 'ALL_OBJECTS',
    'ALL_PART_INDEXES', 'ALL_PART_KEY_COLUMNS', 'ALL_PART_TABLES', 'ALL_SCHEDULER_JOBS',
    'ALL_SCHEDULER_PROGRAMS', 'ALL_SCHEDULER_SCHEDULES', 'ALL_SEGMENTS', 'ALL_SEQUENCES',
    'ALL_SOURCE', 'ALL_SYNONYMS', 'ALL_TABLES', 'ALL_TABLESPACES', 'ALL_TAB_COLS',
    'ALL_TAB_COLUMNS', 'ALL_TAB_COMMENTS', 'ALL_TAB_IDENTITY_COLS', 'ALL_TAB_PARTITIONS',
    'ALL_TAB_STATISTICS', 'ALL_TAB_SUBPARTITIONS', 'ALL_TRIGGERS',
    'ALL_TAB_PRIVS', 'PRODUCT_COMPONENT_VERSION', 'ROLE_TAB_PRIVS', 'SESSION_PRIVS', 'SESSION_ROLES',
  ]),
  postgresql: new Set([
    'INFORMATION_SCHEMA.COLUMNS', 'INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS',
    'INFORMATION_SCHEMA.TABLES', 'INFORMATION_SCHEMA.TABLE_CONSTRAINTS',
    'PG_CATALOG.PG_ATTRIBUTE', 'PG_CATALOG.PG_CLASS', 'PG_CATALOG.PG_CONSTRAINT',
    'PG_CATALOG.PG_DEPEND', 'PG_CATALOG.PG_NAMESPACE', 'PG_CATALOG.PG_REWRITE',
    'PG_CATALOG.PG_ROLES', 'PG_CATALOG.PG_SETTINGS', 'PG_CATALOG.PG_TYPE',
  ]),
});

function lexicalSql(sql) {
  if (typeof sql !== 'string' || sql.length === 0) fail('DB_QUERY_SQL_INVALID');
  let output = '';
  for (let index = 0; index < sql.length;) {
    const current = sql[index];
    const next = sql[index + 1];
    if (current === "'") {
      output += " '' ";
      index += 1;
      let closed = false;
      while (index < sql.length) {
        if (sql[index] === "'" && sql[index + 1] === "'") {
          index += 2;
        } else if (sql[index] === "'") {
          index += 1;
          closed = true;
          break;
        } else {
          index += 1;
        }
      }
      if (!closed) fail('DB_QUERY_SQL_LEXICAL_INVALID');
      continue;
    }
    if (current === '-' && next === '-') {
      index += 2;
      while (index < sql.length && sql[index] !== '\n') index += 1;
      output += '\n';
      continue;
    }
    if (current === '/' && next === '*') {
      index += 2;
      let depth = 1;
      while (index < sql.length && depth > 0) {
        if (sql[index] === '/' && sql[index + 1] === '*') {
          depth += 1;
          index += 2;
        } else if (sql[index] === '*' && sql[index + 1] === '/') {
          depth -= 1;
          index += 2;
        } else {
          index += 1;
        }
      }
      if (depth !== 0) fail('DB_QUERY_SQL_LEXICAL_INVALID');
      output += ' ';
      continue;
    }
    if (current === '[' || current === '"') {
      const closing = current === '[' ? ']' : '"';
      let identifier = '';
      index += 1;
      let closed = false;
      while (index < sql.length) {
        if (sql[index] === closing && sql[index + 1] === closing) {
          identifier += closing;
          index += 2;
        } else if (sql[index] === closing) {
          index += 1;
          closed = true;
          break;
        } else {
          identifier += sql[index];
          index += 1;
        }
      }
      if (!closed || !/^[A-Za-z_][A-Za-z0-9_$#]*$/.test(identifier)) fail('DB_QUERY_SQL_LEXICAL_INVALID');
      output += ` ${identifier} `;
      continue;
    }
    output += current;
    index += 1;
  }
  return output;
}

function tokensFor(sql) {
  return lexicalSql(sql).match(/[A-Za-z_][A-Za-z0-9_$#]*|[0-9]+|[().,;*]/g)?.map((token) => token.toUpperCase()) ?? [];
}

function catalogSourceAt(tokens, offset) {
  if (tokens[offset] === '(' && ['SELECT', 'VALUES'].includes(tokens[offset + 1])) return null;
  if (!/^[A-Z_][A-Z0-9_$#]*$/.test(tokens[offset] ?? '')) fail('DB_QUERY_SOURCE_BOUNDARY_DENIED');
  let source = tokens[offset];
  if (tokens[offset + 1] === '.' && /^[A-Z_][A-Z0-9_$#]*$/.test(tokens[offset + 2] ?? '')) {
    source += `.${tokens[offset + 2]}`;
  }
  return source;
}

export function auditCatalogQuery({ engine, queryId, sql }) {
  const allowedSources = CATALOG_SOURCES[engine];
  if (!allowedSources || typeof queryId !== 'string') fail('DB_QUERY_SAFETY_INPUT_INVALID');
  const tokens = tokensFor(sql);
  if (tokens[0] !== 'SELECT') fail('DB_QUERY_SELECT_ONLY_DENIED');
  if (tokens.some((token) => MUTATING_OR_PRIVILEGED_TOKENS.has(token)) || tokens.includes('INTO')) fail('DB_QUERY_MUTATION_DENIED');
  const semicolons = tokens.reduce((positions, token, index) => token === ';' ? [...positions, index] : positions, []);
  if (semicolons.length > 1 || (semicolons.length === 1 && semicolons[0] !== tokens.length - 1)) fail('DB_QUERY_MULTI_STATEMENT_DENIED');
  if (tokens.some((token, index) => token === '*' && tokens[index - 1] === 'SELECT')) fail('DB_QUERY_WILDCARD_DENIED');

  const sources = [];
  let derivedSources = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    if (!['FROM', 'JOIN'].includes(tokens[index])) continue;
    const source = catalogSourceAt(tokens, index + 1);
    if (source === null) derivedSources += 1;
    else sources.push(source);
  }
  if (sources.length === 0 && derivedSources === 0) fail('DB_QUERY_CATALOG_SOURCE_MISSING');
  const denied = sources.find((source) => !allowedSources.has(source));
  if (denied) fail('DB_QUERY_ROW_SOURCE_DENIED');
  return { engine, queryId, statementKind: 'SELECT', catalogSources: [...new Set(sources)].sort(), derivedSources, rowSamples: false, mutations: false };
}

export function auditQueryPackSafety({ manifest, sqlByQueryId }) {
  if (!manifest || !sqlByQueryId || typeof sqlByQueryId !== 'object') fail('DB_QUERY_SAFETY_INPUT_INVALID');
  const queries = manifest.queries.map((query) => {
    if (query.readOnly !== true) fail('DB_QUERY_MANIFEST_READ_ONLY_DENIED');
    return auditCatalogQuery({ engine: manifest.engine, queryId: query.id, sql: sqlByQueryId[query.id] });
  });
  return {
    schemaVersion: 'chimpmaera.db/query-safety-audit/v1',
    engine: manifest.engine,
    queryCount: queries.length,
    zeroMutatingStatements: true,
    zeroRowSamples: true,
    queries,
  };
}
