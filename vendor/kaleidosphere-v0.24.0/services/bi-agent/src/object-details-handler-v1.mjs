import {identitySha256, normalizeJsonValue} from '../../bi-control/src/db-analyzer/core.mjs';
import {projectObjectDetails} from '../../bi-control/src/db-analyzer/object-details-projection-v1.mjs';
import {
  assertObjectCapabilityDataTreeV1, KS_OBJECT_CAPABILITY_RESULT_SCHEMA, buildObjectCapabilityContractV1,
} from './object-capability-contract-v1.mjs';

export const KS_OBJECT_DETAILS_HANDLER_CAPABILITY = 'bi.object.details.read';
export const KS_OBJECT_DETAILS_HANDLER_FAIL_CLOSED_CODES = Object.freeze([
  'KS_OBJECT_DETAILS_HANDLER_CAPABILITY_DENIED',
  'KS_OBJECT_DETAILS_HANDLER_REQUEST_DIGEST_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_PROJECTION_INPUT_INVALID',
  'KS_OBJECT_DETAILS_HANDLER_ENGINE_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_SCOPE_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_BINDING_DRIFT',
  'KS_OBJECT_DETAILS_HANDLER_PROJECTION_DIGEST_DRIFT',
]);

const CLAIM_KEYS = Object.freeze(['absenceClaimed', 'completenessClaimed', 'replayPreventionClaimed', 'sourceRowsIncluded']);
const AUTHORITY_KEYS = Object.freeze([
  'credentialsIncluded', 'dispatchAuthority', 'executionAuthority', 'mutationAuthority',
  'queryExecution', 'rawValuesIncluded', 'sqlAuthority',
]);

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function authoritativeRequest(projectionInput, projection) {
  return {
    capabilityId: KS_OBJECT_DETAILS_HANDLER_CAPABILITY,
    bindings: {
      engine: projection.engine,
      snapshotSha256: projection.bindings.inventorySnapshotSha256,
      receiptSha256: projection.bindings.receiptSha256,
      coverageSha256: projection.bindings.coverageLedgerSha256,
    },
    scope: {schemas: [...projectionInput.scope.schemas]},
  };
}

export function handleObjectDetailsV1(request, projectionInput) {
  assertObjectCapabilityDataTreeV1(request, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED');
  assertObjectCapabilityDataTreeV1(projectionInput, 'KS_OBJECT_DETAILS_HANDLER_PROJECTION_INPUT_INVALID');
  const projection = projectObjectDetails(projectionInput);
  const authoritative = authoritativeRequest(projectionInput, projection);
  const contract = buildObjectCapabilityContractV1();
  contract.validateRequest(request, authoritative);
  const requestSha256 = identitySha256(normalizeJsonValue(request));
  const result = {
    schemaVersion: KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
    state: 'PROJECTED_READ_ONLY',
    capabilityId: KS_OBJECT_DETAILS_HANDLER_CAPABILITY,
    requestSha256,
    projectionSha256: projection.projectionSha256,
    bindings: {...authoritative.bindings},
    claims: Object.fromEntries(CLAIM_KEYS.map((key) => [key, false])),
    authority: Object.fromEntries(AUTHORITY_KEYS.map((key) => [key, false])),
  };
  contract.validateResult(result, {
    capabilityId: result.capabilityId,
    requestSha256,
    projectionSha256: result.projectionSha256,
    bindings: authoritative.bindings,
  });
  return deepFreeze(result);
}
