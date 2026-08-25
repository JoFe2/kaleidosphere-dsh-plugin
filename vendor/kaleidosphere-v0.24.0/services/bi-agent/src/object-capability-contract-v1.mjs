import {canonicalJson} from './external-api-v2.mjs';
import {types as utilTypes} from 'node:util';

export const KS_OBJECT_CAPABILITY_CONTRACT_SCHEMA = 'kaleidosphere.object-capabilities/handler-contract/v1';
export const KS_OBJECT_CAPABILITY_REQUEST_SCHEMA = 'kaleidosphere.object-capabilities/request/v1';
export const KS_OBJECT_CAPABILITY_RESULT_SCHEMA = 'kaleidosphere.object-capabilities/result/v1';

const HASH = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z][A-Za-z0-9._:-]{2,127}$/;
const SCHEMA = /^[A-Za-z][A-Za-z0-9_$#]{0,127}$/;
const CAPABILITIES = Object.freeze([
  Object.freeze({
    id: 'bi.object.search.read',
    projectionSchema: 'chimpmaera.db/object-search-authority-bound-result/v1',
    bindingProfileSchema: 'kaleidosphere.object-capabilities/binding-profile/object-search/v1',
    bindingKeys: Object.freeze([
      'engine', 'snapshotSha256', 'receiptSha256', 'coverageSha256', 'inventoryAuthoritySha256',
      'relationKindAuthoritySha256', 'objectNameAuthoritySha256', 'cancellationSha256',
    ]),
  }),
  Object.freeze({
    id: 'bi.object.details.read',
    projectionSchema: 'kaleidosphere.analysis/object-details-projection/v1',
    bindingProfileSchema: 'kaleidosphere.object-capabilities/binding-profile/object-details/v1',
    bindingKeys: Object.freeze(['engine', 'snapshotSha256', 'receiptSha256', 'coverageSha256']),
  }),
  Object.freeze({
    id: 'bi.database.overview.read',
    projectionSchema: 'kaleidosphere.analysis/database-overview-projection/v1',
    bindingProfileSchema: 'kaleidosphere.object-capabilities/binding-profile/database-overview/v1',
    bindingKeys: Object.freeze([
      'engine', 'runStateSha256', 'snapshotSha256', 'coverageSha256', 'receiptChainSha256', 'cancellationSha256',
    ]),
  }),
]);
const CAPABILITY_BY_ID = new Map(CAPABILITIES.map((item) => [item.id, item]));
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

const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value) && !utilTypes.isProxy(value)
  && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys, code) => {
  if (!plain(value)) fail(code);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key !== 'string' || descriptor?.enumerable !== true
      || !Object.hasOwn(descriptor ?? {}, 'value');
  }) || canonicalJson(ownKeys.sort()) !== canonicalJson([...keys].sort())) fail(code);
};
const hash = (value) => typeof value === 'string' && HASH.test(value);
const same = (left, right) => canonicalJson(left) === canonicalJson(right);

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export function assertObjectCapabilityDataTreeV1(value, code) {
  const seen = new Set();
  const visit = (item) => {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return;
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || Object.is(item, -0)) fail(code);
      return;
    }
    if (!item || typeof item !== 'object' || utilTypes.isProxy(item) || seen.has(item)) fail(code);
    seen.add(item);
    const array = Array.isArray(item);
    if (!array && Object.getPrototypeOf(item) !== Object.prototype) fail(code);
    for (const key of Reflect.ownKeys(item)) {
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (typeof key !== 'string' || !Object.hasOwn(descriptor ?? {}, 'value')) fail(code);
      if (array && key === 'length') continue;
      if (descriptor.enumerable !== true) fail(code);
      visit(descriptor.value);
    }
    seen.delete(item);
  };
  visit(value);
  return value;
}

function capabilityProfile(capabilityId, code) {
  const profile = CAPABILITY_BY_ID.get(capabilityId);
  if (!profile) fail(code);
  return profile;
}

function validateBindings(value, expected, capabilityId, code) {
  const profile = capabilityProfile(capabilityId, code);
  exact(value, profile.bindingKeys, code);
  if (!['mssql', 'oracle'].includes(value.engine)
      || profile.bindingKeys.filter((key) => key !== 'engine').some((key) => !hash(value[key]))
      || !plain(expected) || !same(value, expected)) fail(code);
  return value;
}

function validateScope(value) {
  exact(value, ['schemas'], 'KS_OBJECT_CAPABILITY_SCOPE_DENIED');
  if (!Array.isArray(value.schemas) || value.schemas.length < 1 || value.schemas.length > 256
      || value.schemas.some((item) => typeof item !== 'string' || !SCHEMA.test(item))
      || new Set(value.schemas).size !== value.schemas.length) fail('KS_OBJECT_CAPABILITY_SCOPE_DENIED');
  return value;
}

function validateRequest(value, authoritative) {
  assertObjectCapabilityDataTreeV1(value, 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED');
  assertObjectCapabilityDataTreeV1(authoritative, 'KS_OBJECT_CAPABILITY_REQUEST_IDENTITY_DENIED');
  exact(value, ['schemaVersion', 'requestId', 'capabilityId', 'bindings', 'scope'], 'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED');
  exact(authoritative, ['capabilityId', 'bindings', 'scope'], 'KS_OBJECT_CAPABILITY_REQUEST_IDENTITY_DENIED');
  if (value.schemaVersion !== KS_OBJECT_CAPABILITY_REQUEST_SCHEMA || !ID.test(value.requestId ?? '')
      || !CAPABILITY_BY_ID.has(value.capabilityId)
      || value.capabilityId !== authoritative.capabilityId) fail('KS_OBJECT_CAPABILITY_REQUEST_IDENTITY_DENIED');
  validateBindings(value.bindings, authoritative.bindings, value.capabilityId, 'KS_OBJECT_CAPABILITY_BINDING_DENIED');
  validateScope(value.scope);
  if (!plain(authoritative.scope) || !same(value.scope, authoritative.scope)) fail('KS_OBJECT_CAPABILITY_SCOPE_DENIED');
  return deepFreeze(structuredClone(value));
}

function validateResult(value, authoritative) {
  assertObjectCapabilityDataTreeV1(value, 'KS_OBJECT_CAPABILITY_RESULT_SURFACE_DENIED');
  assertObjectCapabilityDataTreeV1(authoritative, 'KS_OBJECT_CAPABILITY_RESULT_IDENTITY_DENIED');
  exact(value, ['schemaVersion', 'requestSha256', 'capabilityId', 'state', 'projectionSha256', 'bindings', 'claims', 'authority'],
    'KS_OBJECT_CAPABILITY_RESULT_SURFACE_DENIED');
  exact(authoritative, ['capabilityId', 'requestSha256', 'projectionSha256', 'bindings'],
    'KS_OBJECT_CAPABILITY_RESULT_IDENTITY_DENIED');
  if (value.schemaVersion !== KS_OBJECT_CAPABILITY_RESULT_SCHEMA || !CAPABILITY_BY_ID.has(value.capabilityId)
      || value.state !== 'PROJECTED_READ_ONLY' || !hash(value.requestSha256) || !hash(value.projectionSha256)
      || value.capabilityId !== authoritative.capabilityId
      || value.requestSha256 !== authoritative.requestSha256
      || value.projectionSha256 !== authoritative.projectionSha256) fail('KS_OBJECT_CAPABILITY_RESULT_IDENTITY_DENIED');
  validateBindings(value.bindings, authoritative.bindings, value.capabilityId, 'KS_OBJECT_CAPABILITY_RESULT_BINDING_DENIED');
  exact(value.claims, CLAIM_KEYS, 'KS_OBJECT_CAPABILITY_CLAIM_DENIED');
  exact(value.authority, AUTHORITY_KEYS, 'KS_OBJECT_CAPABILITY_AUTHORITY_DENIED');
  if (CLAIM_KEYS.some((key) => value.claims[key] !== false)) fail('KS_OBJECT_CAPABILITY_CLAIM_DENIED');
  if (AUTHORITY_KEYS.some((key) => value.authority[key] !== false)) fail('KS_OBJECT_CAPABILITY_AUTHORITY_DENIED');
  return deepFreeze(structuredClone(value));
}

function contractData() {
  return {
    schemaVersion: KS_OBJECT_CAPABILITY_CONTRACT_SCHEMA,
    capabilities: CAPABILITIES.map(({bindingKeys, ...item}) => ({
      ...item,
      requestSchema: KS_OBJECT_CAPABILITY_REQUEST_SCHEMA,
      resultSchema: KS_OBJECT_CAPABILITY_RESULT_SCHEMA,
      authority: 'read-only-evidence-projection',
      requiredBindings: [...bindingKeys],
    })),
    failClosedCodes: [
      'KS_OBJECT_CAPABILITY_REQUEST_SURFACE_DENIED', 'KS_OBJECT_CAPABILITY_REQUEST_IDENTITY_DENIED',
      'KS_OBJECT_CAPABILITY_BINDING_DENIED', 'KS_OBJECT_CAPABILITY_SCOPE_DENIED',
      'KS_OBJECT_CAPABILITY_RESULT_SURFACE_DENIED', 'KS_OBJECT_CAPABILITY_RESULT_IDENTITY_DENIED',
      'KS_OBJECT_CAPABILITY_RESULT_BINDING_DENIED', 'KS_OBJECT_CAPABILITY_CLAIM_DENIED',
      'KS_OBJECT_CAPABILITY_AUTHORITY_DENIED',
    ],
    integration: {
      mode: 'separate-versioned-extension',
      externalApiV2Changed: false,
      externalApiV2Actions: ['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'],
    },
    boundaries: {
      credentialsAccepted: false,
      freeSqlAccepted: false,
      handlerDispatchIncluded: false,
      mutationAuthority: false,
      rawRowsAccepted: false,
      replayPreventionClaimed: false,
    },
  };
}

export function getObjectCapabilityBindingProfileV1(capabilityId) {
  const profile = capabilityProfile(capabilityId, 'KS_OBJECT_CAPABILITY_CAPABILITY_DENIED');
  return deepFreeze({schemaVersion: profile.bindingProfileSchema, requiredBindings: [...profile.bindingKeys]});
}

export function buildObjectCapabilityContractV1() {
  const value = contractData();
  Object.defineProperties(value, {
    validateRequest: {value: validateRequest, enumerable: false},
    validateResult: {value: validateResult, enumerable: false},
  });
  return deepFreeze(value);
}

export function validateObjectCapabilityContractV1(value) {
  if (!plain(value) || !same(value, contractData())) fail('KS_OBJECT_CAPABILITY_CONTRACT_DENIED');
  return value;
}
