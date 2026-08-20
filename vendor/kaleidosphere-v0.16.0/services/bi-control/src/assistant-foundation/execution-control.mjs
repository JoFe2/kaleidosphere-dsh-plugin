import { canonicalJson } from '../canonical-json.js';
import { sha256Digest } from './core-contracts.mjs';

export const APPROVAL_GRANT_VERSION = 'chimpmaera.bi/approval-grant/v1';
export const TOOL_EXECUTION_RECEIPT_VERSION = 'chimpmaera.bi/tool-execution-receipt/v1';
export const RETRY_POLICY_VERSION = 'chimpmaera.bi/retry-policy/v1';
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const fail = (code) => { const error = new Error(code); error.code = code; throw error; };

export function assertRetryPolicy(policy) {
  if (!policy || policy.schemaVersion !== RETRY_POLICY_VERSION || !['never', 'bounded'].includes(policy.mode)) fail('RETRY_POLICY_INVALID');
  if (policy.mode === 'never') {
    if (policy.maxAttempts !== 1) fail('RETRY_NEVER_ATTEMPTS_INVALID');
    return policy;
  }
  if (!Number.isSafeInteger(policy.maxAttempts) || policy.maxAttempts < 1 || policy.maxAttempts > 3) fail('RETRY_BUDGET_INVALID');
  if (!Array.isArray(policy.retryCodes) || policy.retryCodes.length === 0 || policy.retryCodes.some((code) => !['TIMEOUT_BEFORE_DISPATCH', 'RATE_LIMIT', 'TRANSPORT'].includes(code))) fail('RETRY_CODE_DENIED');
  if (policy.idempotencyRequired !== true || policy.onOutcomeUnknown !== 'stop') fail('RETRY_SIDE_EFFECT_SAFETY_REQUIRED');
  return policy;
}

export function createApprovalGrant({ grantId, executionId, capabilityId, args, resource, policy, issuedAt, expiresAt, channel = 'trusted_ui' }) {
  if (channel !== 'trusted_ui') fail('APPROVAL_TRUSTED_UI_REQUIRED');
  const grant = {
    schemaVersion: APPROVAL_GRANT_VERSION, grantId, executionId, capabilityId,
    argsDigest: sha256Digest(args), resourceDigest: sha256Digest(resource), policyDigest: sha256Digest(policy),
    issuedAt, expiresAt, channel, oneShot: true,
  };
  assertApprovalGrant(grant);
  return Object.freeze(grant);
}

export function assertApprovalGrant(grant) {
  if (!grant || grant.schemaVersion !== APPROVAL_GRANT_VERSION || !grant.grantId || !grant.executionId || !grant.capabilityId) fail('APPROVAL_GRANT_INVALID');
  if (![grant.argsDigest, grant.resourceDigest, grant.policyDigest].every((digest) => DIGEST.test(digest ?? ''))) fail('APPROVAL_BINDING_DIGEST_INVALID');
  if (grant.channel !== 'trusted_ui' || grant.oneShot !== true) fail('APPROVAL_TRUSTED_UI_REQUIRED');
  if (Number.isNaN(Date.parse(grant.issuedAt ?? '')) || Number.isNaN(Date.parse(grant.expiresAt ?? '')) || Date.parse(grant.expiresAt) <= Date.parse(grant.issuedAt)) fail('APPROVAL_TIME_INVALID');
  return grant;
}

export class ExecutionController {
  #grants = new Map();
  #consumed = new Set();

  registerGrant(grant) {
    assertApprovalGrant(grant);
    if (this.#grants.has(grant.grantId) || this.#consumed.has(grant.grantId)) fail('APPROVAL_GRANT_REPLAY');
    this.#grants.set(grant.grantId, grant);
  }

  authorize({ grantId, executionId, capabilityId, args, resource, policy, guards, now }) {
    if (!Array.isArray(guards) || guards.length === 0) fail('PRE_GUARD_REQUIRED');
    if (guards.some((guard) => guard.mandatory !== true || !['allow', 'deny'].includes(guard.decision))) fail('PRE_GUARD_INVALID');
    if (guards.some((guard) => guard.decision === 'deny')) fail('MANDATORY_POLICY_DENY');
    const grant = this.#grants.get(grantId);
    if (!grant || this.#consumed.has(grantId)) fail('APPROVAL_GRANT_REPLAY');
    if (Number.isNaN(Date.parse(now))) fail('APPROVAL_TIME_INVALID');
    if (Date.parse(now) >= Date.parse(grant.expiresAt)) fail('APPROVAL_GRANT_EXPIRED');
    if (grant.executionId !== executionId || grant.capabilityId !== capabilityId) fail('APPROVAL_SCOPE_MISMATCH');
    if (grant.argsDigest !== sha256Digest(args) || grant.resourceDigest !== sha256Digest(resource) || grant.policyDigest !== sha256Digest(policy)) fail('APPROVAL_BINDING_MISMATCH');
    this.#grants.delete(grantId);
    this.#consumed.add(grantId);
    return Object.freeze({ executionId, capabilityId, authorized: true, grantId });
  }
}

export function createExecutionReceipt({ executionId, capabilityId, status, startedAt, finishedAt, args, resource, policy, sideEffect, idempotencyKey, observations = [], rollback = null }) {
  if (!['succeeded', 'denied', 'failed', 'cancelled', 'outcome_unknown'].includes(status)) fail('EXECUTION_STATUS_INVALID');
  if (status === 'outcome_unknown' && sideEffect === 'none') fail('OUTCOME_UNKNOWN_SIDE_EFFECT_INVALID');
  if (status === 'outcome_unknown' && rollback?.automaticRetry === true) fail('OUTCOME_UNKNOWN_BLIND_RETRY_DENIED');
  const receipt = {
    schemaVersion: TOOL_EXECUTION_RECEIPT_VERSION, executionId, capabilityId, status,
    startedAt, finishedAt, argsDigest: sha256Digest(args), resourceDigest: sha256Digest(resource),
    policyDigest: sha256Digest(policy), sideEffect, idempotencyKey, observations, rollback,
    retryAllowed: status === 'failed' && ['none', 'reversible'].includes(sideEffect),
  };
  canonicalJson(receipt);
  return Object.freeze(receipt);
}
