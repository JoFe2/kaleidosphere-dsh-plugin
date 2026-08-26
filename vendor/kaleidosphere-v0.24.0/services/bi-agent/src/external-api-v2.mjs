import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const SBA_PRODUCT_ID = 'superset-bi-agent';
const runtimePackage = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
export const SBA_PRODUCT_VERSION = `v${runtimePackage.version}`;
export const SBA_EXTERNAL_CONTRACT_ID = 'superset-bi-agent.external';
export const SBA_EXTERNAL_CONTRACT_VERSION = '2.0.0';
export const SBA_ATTESTATION_SCHEMA = 'superset-bi-agent.external/capability-attestation/v2';
export const SBA_INTENT_REQUEST_SCHEMA = 'superset-bi-agent.external/intent-request/v2';
export const SBA_INTENT_RESULT_SCHEMA = 'superset-bi-agent.external/intent-result/v2';

export const SBA_EXTERNAL_CAPABILITIES = Object.freeze([
  Object.freeze({ id: 'bi.status.read', action: 'status', authority: 'read-only' }),
  Object.freeze({ id: 'bi.discovery.run', action: 'discovery', authority: 'local-evidence-write' }),
  Object.freeze({ id: 'bi.analysis.run', action: 'analyze', authority: 'source-read-only' }),
  Object.freeze({ id: 'bi.graph.adaptive-v1.plan', action: 'plan', authority: 'proposal-only' }),
  Object.freeze({ id: 'bi.preview.create', action: 'preview', authority: 'proposal-only' }),
  Object.freeze({ id: 'bi.readback.read', action: 'readback', authority: 'read-only' }),
  Object.freeze({ id: 'superset.trusted-apply', action: 'trusted-apply', authority: 'trusted-approval-only', externalIntent: false }),
  Object.freeze({ id: 'superset.trusted-readback', action: 'trusted-readback', authority: 'trusted-approval-only', externalIntent: false }),
  Object.freeze({ id: 'superset.trusted-rollback', action: 'trusted-rollback', authority: 'trusted-approval-only', externalIntent: false }),
]);

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_TEXT = /^[^\u0000-\u001f\u007f]{3,500}$/;
const UNSAFE_TEXT = /(?:\b(?:select|insert|update|delete|merge|drop|alter|create|truncate|grant|revoke|exec(?:ute)?|dbcc|backup|restore)\b|\braw\s+sql\b|\bsql\s*lab\b|password|credential|secret|api[_ -]?key|bearer|token|cookie|all\s+raw\s+rows?|ignore\s+(?:all\s+)?previous|system\s+prompt)/i;
const FORBIDDEN_KEYS = /(?:^|_)(?:sql|query|credential|password|secret|token|cookie|raw|rows?|url|uri|host|port)(?:$|_)/i;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('EXTERNAL_BI_NON_JSON_VALUE_DENIED');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('EXTERNAL_BI_NON_JSON_VALUE_DENIED');
  return `{${Object.keys(value).sort().map((key) => {
    if (value[key] === undefined) fail('EXTERNAL_BI_NON_JSON_VALUE_DENIED');
    return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
  }).join(',')}}`;
}

export const sha256Digest = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;

function exact(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail('EXTERNAL_BI_REQUEST_INVALID');
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) fail('EXTERNAL_BI_REQUEST_SURFACE_DENIED');
}

function denyUnsafeSurface(value) {
  if (typeof value === 'string') {
    if (UNSAFE_TEXT.test(value)) fail('EXTERNAL_BI_UNSAFE_INPUT_DENIED');
    return;
  }
  if (Array.isArray(value)) return value.forEach(denyUnsafeSurface);
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[ .-]+/g, '_').toLowerCase();
    if (FORBIDDEN_KEYS.test(normalized)) fail('EXTERNAL_BI_FORBIDDEN_FIELD_DENIED');
    denyUnsafeSurface(item);
  }
}

function validateObjective(value) {
  if (typeof value !== 'string' || !SAFE_TEXT.test(value) || UNSAFE_TEXT.test(value)) fail('EXTERNAL_BI_OBJECTIVE_DENIED');
  return value.trim();
}

export function capabilityAttestationV2() {
  const body = {
    schemaVersion: SBA_ATTESTATION_SCHEMA,
    product: { id: SBA_PRODUCT_ID, version: SBA_PRODUCT_VERSION, component: 'bi-agent-runtime' },
    contract: { id: SBA_EXTERNAL_CONTRACT_ID, version: SBA_EXTERNAL_CONTRACT_VERSION },
    capabilities: SBA_EXTERNAL_CAPABILITIES,
    graph: { acceptedIncumbent: 'adaptive-v1', candidatePromotion: 'none' },
    boundaries: {
      sourceDatabaseCredentialsAccepted: false,
      freeSqlAccepted: false,
      rawSourceRowsReturned: false,
      modelMutationAuthority: false,
      directSupersetMutationIntentAccepted: false,
      persistentSupersetWorkflow: 'trusted-preview-approval-apply-readback-rollback-only',
    },
  };
  return Object.freeze({ ...body, attestation: { algorithm: 'sha256-canonical-json', digest: sha256Digest(body) } });
}

export function validateExternalIntentV2(value) {
  exact(value, ['schemaVersion', 'requestId', 'action', 'input'], ['schemaVersion', 'requestId', 'action']);
  if (value.schemaVersion !== SBA_INTENT_REQUEST_SCHEMA || !ID.test(value.requestId ?? '')) fail('EXTERNAL_BI_REQUEST_IDENTITY_DENIED');
  const input = value.input ?? {};
  const action = value.action;
  if (!['status', 'discovery', 'analyze', 'plan', 'preview', 'readback'].includes(action)) fail('EXTERNAL_BI_ACTION_DENIED');
  if (['status', 'analyze', 'readback'].includes(action)) exact(input, [], []);
  if (action === 'discovery') {
    exact(input, ['command', 'sessionId', 'field', 'value'], ['command', 'sessionId']);
    if (!['start', 'resume', 'status', 'answer', 'revise', 'confirm', 'export'].includes(input.command) || !/^[a-z0-9][a-z0-9_-]{2,63}$/.test(input.sessionId ?? '')) fail('EXTERNAL_BI_DISCOVERY_INPUT_DENIED');
    const hasAnswer = ['answer', 'revise'].includes(input.command);
    if (hasAnswer !== (typeof input.field === 'string' && Object.hasOwn(input, 'value'))) fail('EXTERNAL_BI_DISCOVERY_INPUT_DENIED');
    if (input.field !== undefined && !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(input.field)) fail('EXTERNAL_BI_DISCOVERY_INPUT_DENIED');
  }
  if (action === 'plan' || action === 'preview') {
    exact(input, ['objective', 'receiptId'], ['objective']);
    input.objective = validateObjective(input.objective);
    if (input.receiptId !== undefined && !ID.test(input.receiptId)) fail('EXTERNAL_BI_RECEIPT_ID_DENIED');
  }
  denyUnsafeSurface(input);
  canonicalJson(value);
  return value;
}

function publicAnalyze(value) {
  return {
    schemaVersion: 'superset-bi-agent.external/analysis-readback/v2',
    receiptId: value.receiptId,
    status: value.status,
    sourceMode: value.sourceMode,
    engine: value.engine,
    scope: value.scope,
    safety: {
      sourceReadOnly: value.safety?.source_read_only ?? value.safety?.sourceReadOnly ?? true,
      queryPackSelectOnly: value.safety?.queryPackSelectOnly === true,
      rawSourceRowsReturned: false,
      credentialsReturned: false,
    },
    evidence: {
      runtimeValidation: value.analysis?.runtimeValidation,
      snapshotSha256: value.analysis?.snapshotSha256,
      projectionSha256: value.projection?.sha256,
    },
  };
}

function publicReadback(value) {
  return {
    schemaVersion: 'superset-bi-agent.external/superset-readback/v2',
    receiptId: value.receiptId,
    source: {
      engine: value.summary?.source_engine,
      mode: value.summary?.source_mode,
      status: value.summary?.status,
      snapshotSha256: value.summary?.snapshot_sha256,
      sourceReadOnly: value.summary?.source_read_only === 1,
    },
    catalog: value.catalogSnapshot,
    technicalOverview: value.technicalOverview,
    superset: value.publication ? { status: value.publication.status, readback: value.publication.readback ?? null } : { status: 'NOT_APPLIED' },
    disclosure: { rawSourceRowsReturned: false, credentialsReturned: false, freeSqlReturned: false },
  };
}

export async function executeExternalIntentV2(request, handlers) {
  const accepted = validateExternalIntentV2(structuredClone(request));
  let result;
  if (accepted.action === 'status') result = await handlers.status();
  else if (accepted.action === 'analyze') result = publicAnalyze(await handlers.analyze());
  else if (accepted.action === 'readback') result = publicReadback(await handlers.readback());
  else if (accepted.action === 'discovery') result = await handlers.discovery(accepted.input);
  else if (accepted.action === 'plan') result = await handlers.plan(accepted.input);
  else result = await handlers.preview(accepted.input);
  const attestation = capabilityAttestationV2();
  const body = {
    schemaVersion: SBA_INTENT_RESULT_SCHEMA,
    requestId: accepted.requestId,
    action: accepted.action,
    runtime: { product: attestation.product, contract: attestation.contract },
    capabilityAttestationDigest: attestation.attestation.digest,
    result,
  };
  return { ...body, integrity: { algorithm: 'sha256-canonical-json', digest: sha256Digest(body) } };
}
