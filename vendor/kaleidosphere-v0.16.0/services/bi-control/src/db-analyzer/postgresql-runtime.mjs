import {
  assertPostgresqlReadOnlySession,
  buildPostgresqlConnectionOptions,
  compilePostgresqlProfileQuery,
} from './postgresql-adapter.mjs';

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const SESSION_PROOF_SQL = `SELECT
  current_setting('transaction_read_only') AS transaction_read_only,
  current_setting('default_transaction_read_only') AS default_transaction_read_only;`;

const CONTROLLED_PROBES = Object.freeze({
  timeout: 'SELECT pg_catalog.pg_sleep(2);',
  cancel: 'SELECT pg_catalog.pg_sleep(2);',
});

const sanitizeReasonCode = (error) => {
  const code = String(error?.code ?? 'POSTGRESQL_QUERY_FAILED').toUpperCase();
  return /^[A-Z0-9_]{2,128}$/.test(code) ? code : 'POSTGRESQL_QUERY_FAILED';
};

const normalizedRows = (response, query) => (response?.rows ?? []).map((row) => Object.fromEntries(
  query.outputColumns.map((column) => [column, row[column]]),
));

const driverTypes = async (driver) => {
  const resolved = driver ?? await import('pg');
  const Pool = resolved.Pool ?? resolved.default?.Pool;
  const Client = resolved.Client ?? resolved.default?.Client;
  if (typeof Pool !== 'function' || typeof Client !== 'function') fail('DB_ANALYZE_POSTGRESQL_DRIVER_INVALID');
  return {Pool, Client};
};

export async function runPostgresqlQueries({profile, manifest, entries, signal, driver}) {
  const password = process.env[profile.adapter.passwordEnv];
  if (!password) fail('DB_ANALYZE_CREDENTIAL_MISSING');
  const {Pool} = await driverTypes(driver);
  const pool = new Pool({
    ...buildPostgresqlConnectionOptions(profile, password),
    min: 0,
    max: 1,
    idleTimeoutMillis: 1000,
    allowExitOnIdle: true,
  });
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN READ ONLY');
    assertPostgresqlReadOnlySession((await client.query(SESSION_PROOF_SQL)).rows);
    const results = {};
    for (let index = 0; index < manifest.queries.length; index += 1) {
      if (signal?.aborted) fail('DB_ANALYZE_CANCELLED');
      const query = manifest.queries[index];
      const source = entries.find(([id]) => id === query.id)?.[1];
      const compiled = compilePostgresqlProfileQuery({profile, query, statement: source});
      const savepoint = `ks_query_${index}`;
      await client.query(`SAVEPOINT ${savepoint}`);
      try {
        const response = await client.query({text: compiled.statement, values: compiled.values, signal});
        results[query.id] = {state: 'SUCCEEDED', reasonCode: null, rows: normalizedRows(response, query)};
        await client.query(`RELEASE SAVEPOINT ${savepoint}`);
      } catch (error) {
        if (String(error?.code ?? error?.message).startsWith('DB_ANALYZE_')) throw error;
        await client.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
        if (query.category === 'preflight') fail('DB_ANALYZE_POSTGRESQL_PREFLIGHT_FAILED');
        results[query.id] = {
          state: error?.code === '57014' ? 'TIMEOUT' : error?.code === '42501' ? 'DENIED' : 'ERROR',
          reasonCode: sanitizeReasonCode(error),
          rows: [],
        };
      }
    }
    await client.query('COMMIT');
    return {schemaVersion: 'chimpmaera.db/runtime-query-results/v1', engine: 'postgresql', runtimeValidated: true, results};
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    if (client) client.release(true);
    await pool.end().catch(() => {});
  }
}

export async function readPostgresqlSessionProof({profile, password, driver}) {
  const {Client} = await driverTypes(driver);
  const client = new Client(buildPostgresqlConnectionOptions(profile, password));
  try {
    await client.connect();
    await client.query('BEGIN READ ONLY');
    const settings = (await client.query(SESSION_PROOF_SQL)).rows;
    assertPostgresqlReadOnlySession(settings);
    const role = (await client.query(`SELECT
      role_row.rolname AS role_name,
      role_row.rolsuper AS is_superuser,
      role_row.rolcreatedb AS can_create_database,
      role_row.rolcreaterole AS can_create_role,
      role_row.rolreplication AS can_replicate,
      role_row.rolbypassrls AS can_bypass_rls,
      current_setting('statement_timeout') AS statement_timeout,
      current_setting('lock_timeout') AS lock_timeout
    FROM pg_catalog.pg_roles AS role_row
    WHERE role_row.rolname = current_user;`)).rows;
    if (role.length !== 1 || role[0].role_name !== profile.adapter.user
      || [role[0].is_superuser, role[0].can_create_database, role[0].can_create_role,
        role[0].can_replicate, role[0].can_bypass_rls].some(Boolean)) {
      fail('DB_ANALYZE_PRINCIPAL_NOT_READ_ONLY');
    }
    await client.query('ROLLBACK');
    return {
      transactionReadOnly: settings[0].transaction_read_only,
      defaultTransactionReadOnly: settings[0].default_transaction_read_only,
      roleName: role[0].role_name,
      adminCapabilities: false,
      statementTimeout: role[0].statement_timeout,
      lockTimeout: role[0].lock_timeout,
    };
  } finally {
    await client.end().catch(() => {});
  }
}

export async function runPostgresqlControlledProbe({profile, password, probeId, abortAfterMs = 100, driver}) {
  const statement = CONTROLLED_PROBES[probeId];
  if (!statement || (probeId === 'cancel' && (!Number.isInteger(abortAfterMs) || abortAfterMs < 25 || abortAfterMs > 500))) {
    fail('DB_ANALYZE_POSTGRESQL_PROBE_INVALID');
  }
  const {Client} = await driverTypes(driver);
  const applicationName = `kaleidosphere-ks23-${probeId}-probe`;
  const options = {...buildPostgresqlConnectionOptions(profile, password), application_name: applicationName};
  const client = new Client(options);
  let canceller;
  let timer;
  let cancellation;
  const started = process.hrtime.bigint();
  let caught;
  let healthy = false;
  try {
    await client.connect();
    await client.query('BEGIN READ ONLY');
    const backendPid = (await client.query('SELECT pg_catalog.pg_backend_pid() AS backend_pid;')).rows[0].backend_pid;
    if (probeId === 'cancel') {
      cancellation = new Promise((resolve, reject) => {
        timer = setTimeout(async () => {
          try {
            canceller = new Client({...options, application_name: `${applicationName}-canceller`});
            await canceller.connect();
            const response = await canceller.query('SELECT pg_catalog.pg_cancel_backend($1) AS cancelled;', [backendPid]);
            if (response.rows[0]?.cancelled !== true) fail('DB_ANALYZE_POSTGRESQL_CANCEL_FAILED');
            resolve();
          } catch (error) {
            reject(error);
          } finally {
            if (canceller) await canceller.end().catch(() => {});
          }
        }, abortAfterMs);
      });
    }
    try {
      await client.query(statement);
    } catch (error) {
      caught = error;
    }
    if (cancellation) await cancellation;
    if (caught?.code !== '57014') fail('DB_ANALYZE_POSTGRESQL_PROBE_DID_NOT_FAIL_CLOSED');
    await client.query('ROLLBACK');
    healthy = (await client.query('SELECT 1 AS healthy;')).rows[0]?.healthy === 1;
  } finally {
    if (timer) clearTimeout(timer);
    await client.end().catch(() => {});
  }
  const observer = new Client({...options, application_name: `${applicationName}-observer`});
  let activeFollowers;
  try {
    await observer.connect();
    activeFollowers = Number((await observer.query(`SELECT count(*)::integer AS active_count
      FROM pg_catalog.pg_stat_activity
      WHERE application_name = $1 AND pid <> pg_catalog.pg_backend_pid();`, [applicationName])).rows[0].active_count);
  } finally {
    await observer.end().catch(() => {});
  }
  return {
    probeId,
    state: probeId === 'timeout' ? 'TIMEOUT' : 'CANCELLED',
    sqlState: caught.code,
    elapsedMs: Number((process.hrtime.bigint() - started) / 1000000n),
    postProbeHealthy: healthy,
    activeFollowers,
    poolClosed: true,
  };
}
