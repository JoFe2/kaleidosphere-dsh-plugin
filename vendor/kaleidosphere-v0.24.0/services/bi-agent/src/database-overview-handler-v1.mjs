import {canonicalJson, identitySha256} from '../../bi-control/src/db-analyzer/core.mjs';
import {
  buildDatabaseOverviewProjection,
  verifyDatabaseOverviewProjection,
} from '../../bi-control/src/db-analyzer/database-overview-projection-v1.mjs';
import {
  assertObjectCapabilityDataTreeV1,
  KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
  buildObjectCapabilityContractV1,
} from './object-capability-contract-v1.mjs';

export const DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID = 'bi.database.overview.read';
export const DATABASE_OVERVIEW_HANDLER_SCHEMA = 'kaleidosphere.object-capabilities/database-overview-handler/v1';

const CLAIM_KEYS = Object.freeze(['absenceClaimed', 'completenessClaimed', 'replayPreventionClaimed', 'sourceRowsIncluded']);
const AUTHORITY_KEYS = Object.freeze([
  'credentialsIncluded', 'dispatchAuthority', 'executionAuthority', 'mutationAuthority',
  'queryExecution', 'rawValuesIncluded', 'sqlAuthority',
]);

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};
const isDeepFrozen = (value) => {
  if (value === null || typeof value !== 'object') return true;
  if (!Object.isFrozen(value)) return false;
  return Object.values(value).every(isDeepFrozen);
};
function deepFreeze(value) {
  if (value && typeof value === 'object' && !ArrayBuffer.isView(value) && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function validateInputs(request, run) {
  assertObjectCapabilityDataTreeV1(request, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED');
  assertObjectCapabilityDataTreeV1(run, 'DB_OVERVIEW_HANDLER_INPUT_INVALID');
  if (!isDeepFrozen(run)) fail('DB_OVERVIEW_HANDLER_INPUT_INVALID');
}

function authoritativeRequest(run, projection) {
  const receiptChainSha256 = projection.bindings.receiptChainSha256;
  return {
    capabilityId: DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID,
    bindings: {
      engine: projection.bindings.engine,
      runStateSha256: run.stateSha256,
      snapshotSha256: projection.bindings.inventorySnapshotSha256,
      coverageSha256: projection.bindings.coverageSha256,
      receiptChainSha256,
      cancellationSha256: identitySha256({
        schemaVersion: 'kaleidosphere.object-capabilities/cancellation-binding/v1',
        receiptChainSha256,
        cancellation: projection.cancellation,
      }),
    },
    scope: {schemas: [...run.scope.schemas]},
  };
}

function buildResultEnvelope(request, requestSha256, projectionSha256, bindings) {
  const envelope = {
    schemaVersion: KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
    requestSha256,
    capabilityId: DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID,
    state: 'PROJECTED_READ_ONLY',
    projectionSha256,
    bindings: {...bindings},
    claims: Object.fromEntries(CLAIM_KEYS.map((key) => [key, false])),
    authority: Object.fromEntries(AUTHORITY_KEYS.map((key) => [key, false])),
  };
  buildObjectCapabilityContractV1().validateResult(envelope, {
    capabilityId: DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID,
    requestSha256,
    projectionSha256,
    bindings,
  });
  return envelope;
}

export function handleDatabaseOverviewRequestV1(request, run) {
  validateInputs(request, run);
  if (Object.hasOwn(run, 'authority') || Object.hasOwn(run, 'claims')) {
    fail('DB_OVERVIEW_HANDLER_AUTHORITY_CLAIM_DENIED');
  }
  const projection = buildDatabaseOverviewProjection(run);
  verifyDatabaseOverviewProjection(projection, run);
  const authoritative = authoritativeRequest(run, projection);
  buildObjectCapabilityContractV1().validateRequest(request, authoritative);
  const requestSha256 = identitySha256(request);
  const projectionSha256 = projection.projectionSha256;
  const envelope = buildResultEnvelope(request, requestSha256, projectionSha256, authoritative.bindings);
  return deepFreeze({
    schemaVersion: DATABASE_OVERVIEW_HANDLER_SCHEMA,
    capabilityId: DATABASE_OVERVIEW_HANDLER_CAPABILITY_ID,
    state: 'PROJECTED_READ_ONLY',
    requestSha256,
    projectionSha256,
    resultSha256: identitySha256(envelope),
    envelope,
    bytes: {
      request: canonicalJson(request),
      projection: canonicalJson(projection),
      result: canonicalJson(envelope),
    },
  });
}
