import {
  SBA_ATTESTATION_SCHEMA,
  SBA_EXTERNAL_CAPABILITIES,
  SBA_EXTERNAL_CONTRACT_ID,
  SBA_EXTERNAL_CONTRACT_VERSION,
  SBA_INTENT_RESULT_SCHEMA,
  SBA_PRODUCT_ID,
  SBA_PRODUCT_VERSION,
  capabilityAttestationV2,
  canonicalJson,
  sha256Digest as externalDigest,
  validateExternalIntentV2,
} from './external-api-v2.mjs';
import {
  EVENT_ENVELOPE_VERSION,
  VERSION_IDENTITY_VERSION,
  assertEventEnvelope,
  sha256Digest,
} from '../../bi-control/src/assistant-foundation/core-contracts.mjs';
import {
  createExecutionReceipt,
} from '../../bi-control/src/assistant-foundation/execution-control.mjs';

export const EXTERNAL_INTENT_EVIDENCE_BRIDGE_VERSION = 'kaleidosphere/external-intent-evidence-bridge/v1';

export const EXTERNAL_INTENT_CAPABILITY_MAP = Object.freeze({
  status: Object.freeze({capabilityId: 'bi.status.read', authority: 'read-only'}),
  discovery: Object.freeze({capabilityId: 'bi.discovery.run', authority: 'local-evidence-write'}),
  analyze: Object.freeze({capabilityId: 'bi.analysis.run', authority: 'source-read-only'}),
  plan: Object.freeze({capabilityId: 'bi.graph.adaptive-v1.plan', authority: 'proposal-only'}),
  preview: Object.freeze({capabilityId: 'bi.preview.create', authority: 'proposal-only'}),
  readback: Object.freeze({capabilityId: 'bi.readback.read', authority: 'read-only'}),
});

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SAFE_TERMINALS = Object.freeze({
  succeeded: new Set(['RESULT_VERIFIED']),
  denied: new Set(['POLICY_DENIED', 'CAPABILITY_DENIED']),
  failed: new Set(['TIMEOUT_BEFORE_DISPATCH', 'TRANSPORT_BEFORE_DISPATCH', 'REMOTE_FAILURE']),
  cancelled: new Set(['CANCELLED_BEFORE_DISPATCH', 'CANCELLED_AFTER_DISPATCH']),
  outcome_unknown: new Set(['TRANSPORT_AFTER_DISCOVERY_DISPATCH', 'DISCOVERY_OUTCOME_UNKNOWN']),
});
const FORBIDDEN_RESULT_KEY = /(?:^|_)(?:sql|query|url|uri|host|port|credential|password|secret|token|cookie|raw_rows?|source_rows?|chain_of_thought|reasoning|internal_response)(?:$|_)/i;
const FORBIDDEN_RESULT_VALUE = /(?:\b(?:select|insert|update|delete|merge|drop|alter|create|truncate|grant|revoke|exec(?:ute)?)\b|\bBearer\s+[A-Za-z0-9._~+\/-]+=*|-----BEGIN [A-Z ]+PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{12,})/i;
const SAFE_BOUNDARY_FLAG = Object.freeze({
  query_pack_select_only: true,
  free_sql_returned: false,
  credentials_returned: false,
  raw_source_rows_returned: false,
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function exact(value, allowed, required = allowed, code = 'EVIDENCE_BRIDGE_SURFACE_DENIED') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(code);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) fail(code);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return value;
}

function denyUnsafeResult(value) {
  if (typeof value === 'string') {
    if (FORBIDDEN_RESULT_VALUE.test(value)) fail('EVIDENCE_BRIDGE_UNSAFE_RESULT_DENIED');
    return;
  }
  if (Array.isArray(value)) return value.forEach(denyUnsafeResult);
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return;
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('EVIDENCE_BRIDGE_NON_JSON_RESULT_DENIED');
  for (const [key, item] of Object.entries(value)) {
    const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[ .-]+/g, '_').toLowerCase();
    if (FORBIDDEN_RESULT_KEY.test(normalized) && SAFE_BOUNDARY_FLAG[normalized] !== item) fail('EVIDENCE_BRIDGE_UNSAFE_RESULT_DENIED');
    denyUnsafeResult(item);
  }
}

export function assertCapabilityAttestationForEvidence(attestation) {
  exact(attestation, ['schemaVersion', 'product', 'contract', 'capabilities', 'graph', 'boundaries', 'attestation']);
  if (attestation.schemaVersion !== SBA_ATTESTATION_SCHEMA) fail('EVIDENCE_BRIDGE_ATTESTATION_VERSION_DENIED');
  exact(attestation.product, ['id', 'version', 'component']);
  exact(attestation.contract, ['id', 'version']);
  exact(attestation.attestation, ['algorithm', 'digest']);
  if (attestation.product.id !== SBA_PRODUCT_ID || attestation.product.version !== SBA_PRODUCT_VERSION || attestation.product.component !== 'bi-agent-runtime') fail('EVIDENCE_BRIDGE_PRODUCT_IDENTITY_DENIED');
  if (attestation.contract.id !== SBA_EXTERNAL_CONTRACT_ID || attestation.contract.version !== SBA_EXTERNAL_CONTRACT_VERSION) fail('EVIDENCE_BRIDGE_CONTRACT_IDENTITY_DENIED');
  if (attestation.attestation.algorithm !== 'sha256-canonical-json' || !DIGEST.test(attestation.attestation.digest ?? '')) fail('EVIDENCE_BRIDGE_ATTESTATION_DIGEST_DENIED');
  const body = Object.fromEntries(Object.entries(attestation).filter(([key]) => key !== 'attestation'));
  if (externalDigest(body) !== attestation.attestation.digest) fail('EVIDENCE_BRIDGE_ATTESTATION_TAMPERED');
  const expected = capabilityAttestationV2();
  if (attestation.attestation.digest !== expected.attestation.digest || canonicalJson(attestation.capabilities) !== canonicalJson(SBA_EXTERNAL_CAPABILITIES)) fail('EVIDENCE_BRIDGE_CAPABILITY_DRIFT_DENIED');
  for (const [action, mapping] of Object.entries(EXTERNAL_INTENT_CAPABILITY_MAP)) {
    const capability = attestation.capabilities.find((item) => item.action === action);
    if (!capability || capability.id !== mapping.capabilityId || capability.authority !== mapping.authority || capability.externalIntent === false) fail('EVIDENCE_BRIDGE_CAPABILITY_DRIFT_DENIED');
  }
  return attestation;
}

function assertVerifiedResult(request, response, attestation) {
  exact(response, ['schemaVersion', 'requestId', 'action', 'runtime', 'capabilityAttestationDigest', 'result', 'integrity']);
  exact(response.runtime, ['product', 'contract']);
  exact(response.runtime.product, ['id', 'version', 'component']);
  exact(response.runtime.contract, ['id', 'version']);
  exact(response.integrity, ['algorithm', 'digest']);
  if (response.schemaVersion !== SBA_INTENT_RESULT_SCHEMA || response.requestId !== request.requestId || response.action !== request.action) fail('EVIDENCE_BRIDGE_RESULT_CORRELATION_DENIED');
  if (canonicalJson(response.runtime.product) !== canonicalJson(attestation.product) || canonicalJson(response.runtime.contract) !== canonicalJson(attestation.contract)) fail('EVIDENCE_BRIDGE_RUNTIME_IDENTITY_DENIED');
  if (response.capabilityAttestationDigest !== attestation.attestation.digest) fail('EVIDENCE_BRIDGE_ATTESTATION_BINDING_DENIED');
  if (response.integrity.algorithm !== 'sha256-canonical-json' || !DIGEST.test(response.integrity.digest ?? '')) fail('EVIDENCE_BRIDGE_RESULT_DIGEST_DENIED');
  const body = Object.fromEntries(Object.entries(response).filter(([key]) => key !== 'integrity'));
  if (externalDigest(body) !== response.integrity.digest) fail('EVIDENCE_BRIDGE_RESULT_TAMPERED');
  denyUnsafeResult(response.result);
  return response;
}

function assertContext(context, requestId) {
  exact(context, ['eventId', 'streamId', 'correlationId', 'seq', 'occurredAt', 'producerArtifactDigest', 'startedAt', 'finishedAt', 'idempotencyKey']);
  if (context.correlationId !== requestId) fail('EVIDENCE_BRIDGE_CORRELATION_DENIED');
  if (!DIGEST.test(context.producerArtifactDigest ?? '')) fail('EVIDENCE_BRIDGE_PRODUCER_DIGEST_DENIED');
  for (const key of ['occurredAt', 'startedAt', 'finishedAt']) if (Number.isNaN(Date.parse(context[key] ?? ''))) fail('EVIDENCE_BRIDGE_TIME_DENIED');
  if (Date.parse(context.finishedAt) < Date.parse(context.startedAt) || Date.parse(context.occurredAt) < Date.parse(context.finishedAt)) fail('EVIDENCE_BRIDGE_TIME_ORDER_DENIED');
  return context;
}

export function buildExternalIntentEvidence({request, response, attestation, terminal = {status: 'succeeded', code: 'RESULT_VERIFIED'}, context}) {
  const accepted = validateExternalIntentV2(structuredClone(request));
  assertCapabilityAttestationForEvidence(attestation);
  assertContext(context, accepted.requestId);
  exact(terminal, ['status', 'code']);
  if (!SAFE_TERMINALS[terminal.status]?.has(terminal.code)) fail('EVIDENCE_BRIDGE_TERMINAL_DENIED');
  if ((terminal.status === 'succeeded') !== (response !== undefined)) fail('EVIDENCE_BRIDGE_RESULT_PRESENCE_DENIED');
  if (terminal.status === 'outcome_unknown' && accepted.action !== 'discovery') fail('EVIDENCE_BRIDGE_OUTCOME_UNKNOWN_SCOPE_DENIED');
  if (response !== undefined) assertVerifiedResult(accepted, response, attestation);

  const mapping = EXTERNAL_INTENT_CAPABILITY_MAP[accepted.action];
  const resultDigest = response?.integrity.digest ?? null;
  const sideEffect = accepted.action === 'discovery' ? 'reversible' : 'none';
  const receipt = createExecutionReceipt({
    executionId: accepted.requestId,
    capabilityId: mapping.capabilityId,
    status: terminal.status,
    startedAt: context.startedAt,
    finishedAt: context.finishedAt,
    args: accepted.input ?? {},
    resource: {productId: SBA_PRODUCT_ID, contractId: SBA_EXTERNAL_CONTRACT_ID, contractVersion: SBA_EXTERNAL_CONTRACT_VERSION},
    policy: {bridgeVersion: EXTERNAL_INTENT_EVIDENCE_BRIDGE_VERSION, action: accepted.action, authority: mapping.authority, externalIntent: true},
    sideEffect,
    idempotencyKey: context.idempotencyKey,
    observations: [{type: 'external-intent-terminal', code: terminal.code, resultDigest}],
    rollback: terminal.status === 'outcome_unknown' ? {automaticRetry: false, disposition: 'manual-readback-required'} : null,
  });

  const payload = {
    bridgeSchemaVersion: EXTERNAL_INTENT_EVIDENCE_BRIDGE_VERSION,
    requestId: accepted.requestId,
    action: accepted.action,
    authority: mapping.authority,
    capabilityAttestationDigest: attestation.attestation.digest,
    resultIntegrityDigest: resultDigest,
    receipt,
  };
  const event = {
    schemaVersion: EVENT_ENVELOPE_VERSION,
    eventId: context.eventId,
    streamId: context.streamId,
    correlationId: context.correlationId,
    causationId: null,
    eventType: 'tool.execution.receipt',
    channel: 'durable',
    seq: context.seq,
    occurredAt: context.occurredAt,
    version: {
      schemaVersion: VERSION_IDENTITY_VERSION,
      contract: 'kaleidosphere.external-intent-evidence',
      version: 'v1',
      producer: {id: SBA_PRODUCT_ID, version: SBA_PRODUCT_VERSION.slice(1), artifactDigest: context.producerArtifactDigest},
    },
    sensitivity: {dataClass: 'internal', categories: ['none'], redaction: 'none'},
    ignorable: false,
    payload,
    payloadDigest: sha256Digest(payload),
  };
  assertEventEnvelope(event);
  return deepFreeze({event, receipt, evidenceDigest: sha256Digest({event, receipt})});
}

export class ExternalIntentEvidenceBridge {
  #consumed = new Set();

  consume(input) {
    const evidence = buildExternalIntentEvidence(input);
    const replayKey = `${evidence.receipt.executionId}:${evidence.receipt.status}:${evidence.event.payload.resultIntegrityDigest ?? input.terminal?.code}`;
    if (this.#consumed.has(replayKey)) fail('EVIDENCE_BRIDGE_REPLAY_DENIED');
    this.#consumed.add(replayKey);
    return evidence;
  }
}
