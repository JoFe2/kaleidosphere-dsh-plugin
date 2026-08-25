import {canonicalJson, identitySha256} from '../../bi-control/src/db-analyzer/core.mjs';
import {
  buildObjectSearchAuthorityBoundResult, continueObjectSearchAuthorityBoundResult,
} from '../../bi-control/src/db-analyzer/object-search-authority-bound-result-v1.mjs';
import {
  assertObjectCapabilityDataTreeV1, buildObjectCapabilityContractV1,
  KS_OBJECT_CAPABILITY_REQUEST_SCHEMA, KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
} from './object-capability-contract-v1.mjs';

export const KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID = 'bi.object.search.read';
export const KS_OBJECT_SEARCH_HANDLER_STATE = 'PROJECTED_READ_ONLY';
const INPUT_INVALID = 'KS_OBJECT_SEARCH_HANDLER_INPUT_INVALID';
const PROJECTION_FORGED = 'KS_OBJECT_SEARCH_HANDLER_PROJECTION_FORGED';
const CAPABILITY_MISMATCH = 'KS_OBJECT_SEARCH_HANDLER_CAPABILITY_MISMATCH';
const BINDING_DRIFT = 'KS_OBJECT_SEARCH_HANDLER_BINDING_DRIFT';
const INPUT_KEYS = Object.freeze(['request', 'projection', 'projectionInput']);
const REQUEST_KEYS = Object.freeze(['schemaVersion', 'requestId', 'capabilityId', 'bindings', 'scope']);
const PROJECTION_SOURCE_KEYS = Object.freeze([
  'controllerRun', 'inventoryAuthorityProjection', 'relationKindAuthorityProjection',
  'objectNameAuthorityProjection', 'structureEvidence', 'request',
]);
const CLAIMS = Object.freeze({
  absenceClaimed: false, completenessClaimed: false, replayPreventionClaimed: false, sourceRowsIncluded: false,
});
const AUTHORITY = Object.freeze({
  credentialsIncluded: false, dispatchAuthority: false, executionAuthority: false,
  mutationAuthority: false, queryExecution: false, rawValuesIncluded: false, sqlAuthority: false,
});
const CONTRACT = buildObjectCapabilityContractV1();

const fail = (code) => {
  const error = new Error(code);
  error.code = code;
  throw error;
};

const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype;
const exactKeys = (value, keys) => plain(value)
  && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function rejectNegativeZero(value) {
  if (typeof value === 'number') {
    if (Object.is(value, -0)) fail(PROJECTION_FORGED);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(rejectNegativeZero);
    return;
  }
  if (value && typeof value === 'object') Object.values(value).forEach(rejectNegativeZero);
}

function validateClosedInput(input) {
  assertObjectCapabilityDataTreeV1(input, INPUT_INVALID);
  if (!exactKeys(input, INPUT_KEYS)) fail(INPUT_INVALID);
  const {request} = input;
  if (!plain(request) || !exactKeys(request, REQUEST_KEYS)
      || request.schemaVersion !== KS_OBJECT_CAPABILITY_REQUEST_SCHEMA) {
    fail('KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED');
  }
  if (request.capabilityId !== KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID) fail(CAPABILITY_MISMATCH);
  return input;
}

function validateProjectionInput(projectionInput) {
  if (!plain(projectionInput)) fail(PROJECTION_FORGED);
  const keys = Object.hasOwn(projectionInput, 'cursor') ? [...PROJECTION_SOURCE_KEYS, 'cursor'] : PROJECTION_SOURCE_KEYS;
  if (!exactKeys(projectionInput, keys)) fail(PROJECTION_FORGED);
  return projectionInput;
}

function verifyProjection(projection, projectionInput) {
  const projectionSha256 = projection?.projectionSha256;
  let recomputed;
  try {
    recomputed = Object.hasOwn(projectionInput, 'cursor')
      ? continueObjectSearchAuthorityBoundResult(projectionInput)
      : buildObjectSearchAuthorityBoundResult(projectionInput);
  } catch {
    fail(PROJECTION_FORGED);
  }
  rejectNegativeZero(projection);
  if (!plain(projection) || canonicalJson(projection) !== canonicalJson(recomputed)
      || projectionSha256 !== recomputed.projectionSha256) fail(PROJECTION_FORGED);
  return recomputed;
}

function authoritativeRequest(recomputed, projectionInput) {
  const bound = recomputed.bindings;
  return {
    capabilityId: KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID,
    bindings: {
      engine: recomputed.engine,
      snapshotSha256: bound.structureSnapshotSha256,
      receiptSha256: bound.envelopeSha256,
      coverageSha256: bound.controllerCoverageSha256,
      inventoryAuthoritySha256: bound.inventoryAuthorityDigestSha256,
      relationKindAuthoritySha256: bound.relationKindAuthoritySha256,
      objectNameAuthoritySha256: bound.objectNameAuthoritySha256,
      cancellationSha256: identitySha256({cancellation: 'NONE', engine: recomputed.engine}),
    },
    scope: {schemas: [...projectionInput.request.scope.schemas]},
  };
}

export function handleObjectSearchV1(input) {
  const {request, projection, projectionInput} = validateClosedInput(input);
  const recomputed = verifyProjection(projection, validateProjectionInput(projectionInput));
  const authoritative = authoritativeRequest(recomputed, projectionInput);
  CONTRACT.validateRequest(request, authoritative);
  const result = {
    schemaVersion: KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
    requestSha256: identitySha256(request),
    capabilityId: KS_OBJECT_SEARCH_HANDLER_CAPABILITY_ID,
    state: KS_OBJECT_SEARCH_HANDLER_STATE,
    projectionSha256: recomputed.projectionSha256,
    bindings: {...authoritative.bindings},
    claims: {...CLAIMS},
    authority: {...AUTHORITY},
  };
  CONTRACT.validateResult(result, {
    capabilityId: result.capabilityId,
    requestSha256: result.requestSha256,
    projectionSha256: result.projectionSha256,
    bindings: authoritative.bindings,
  });
  return deepFreeze(result);
}
