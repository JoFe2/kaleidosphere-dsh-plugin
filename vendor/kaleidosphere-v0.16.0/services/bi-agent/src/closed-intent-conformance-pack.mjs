import {
  SBA_EXTERNAL_CONTRACT_VERSION,
  canonicalJson,
  capabilityAttestationV2,
  executeExternalIntentV2,
  sha256Digest,
  validateExternalIntentV2,
} from './external-api-v2.mjs';
import {
  ExternalIntentEvidenceBridge,
  assertCapabilityAttestationForEvidence,
  buildExternalIntentEvidence,
} from './external-intent-evidence-bridge.mjs';

export const CLOSED_INTENT_CONFORMANCE_PACK_VERSION = 'kaleidosphere/closed-intent-conformance-pack/v1';
export const CLOSED_INTENT_CONSUMER_VERSION = 'kaleidosphere/closed-intent-consumer/v1';
export const CLOSED_INTENTS = Object.freeze(['status', 'discovery', 'analyze', 'plan', 'preview', 'readback']);

const NON_CLAIMS = Object.freeze([
  'LOCAL_STUB_ONLY_NOT_REAL_HARNESS_E2E',
  'NO_DEEPSEEK_HARNESS_API_ABI_OR_PLUGIN_COMPATIBILITY',
  'NO_RUNTIME_ACTIVATION_OR_NETWORK_AUTHENTICATION',
  'NO_PRODUCTION_PROVIDER_DATABASE_OR_SUPERSET_CONNECTION',
  'NO_SQL_MUTATION_CREDENTIAL_OR_RAW_ROW_AUTHORITY',
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function exact(value, allowed, required = allowed, code = 'CONFORMANCE_SURFACE_DENIED') {
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

function assertFixture(fixture) {
  exact(fixture, ['schemaVersion', 'requests', 'contexts', 'stubResults']);
  if (fixture.schemaVersion !== CLOSED_INTENT_CONFORMANCE_PACK_VERSION) fail('CONFORMANCE_FIXTURE_VERSION_DENIED');
  if (!Array.isArray(fixture.requests) || fixture.requests.length !== CLOSED_INTENTS.length) fail('CONFORMANCE_FIXTURE_REQUESTS_DENIED');
  const actions = fixture.requests.map((request) => validateExternalIntentV2(structuredClone(request)).action);
  if (canonicalJson(actions) !== canonicalJson(CLOSED_INTENTS)) fail('CONFORMANCE_FIXTURE_INTENTS_DENIED');
  exact(fixture.contexts, CLOSED_INTENTS, CLOSED_INTENTS);
  exact(fixture.stubResults, CLOSED_INTENTS, CLOSED_INTENTS);
  return fixture;
}

function disabledReport(reason) {
  return deepFreeze({
    schemaVersion: CLOSED_INTENT_CONFORMANCE_PACK_VERSION,
    mode: 'disabled',
    reason,
    contractVersion: SBA_EXTERNAL_CONTRACT_VERSION,
    executedIntents: 0,
    acceptedEvidence: 0,
    downstreamDispatches: 0,
    evidence: [],
    nonClaims: NON_CLAIMS,
  });
}

function compatibleConsumer(consumer) {
  if (!consumer || typeof consumer !== 'object' || Array.isArray(consumer)) return false;
  const allowed = ['schemaVersion', 'attest', 'dispatch', 'dispatchCount'];
  if (Object.keys(consumer).some((key) => !allowed.includes(key))) return false;
  return consumer.schemaVersion === CLOSED_INTENT_CONSUMER_VERSION
    && typeof consumer.attest === 'function'
    && typeof consumer.dispatch === 'function';
}

function handlersFor(fixture) {
  return Object.fromEntries(CLOSED_INTENTS.map((action) => [action, async () => structuredClone(fixture.stubResults[action])]));
}

export function createDeterministicLocalConsumer(fixture) {
  assertFixture(fixture);
  let dispatches = 0;
  const handlers = handlersFor(fixture);
  return Object.freeze({
    schemaVersion: CLOSED_INTENT_CONSUMER_VERSION,
    attest() {
      return structuredClone(capabilityAttestationV2());
    },
    async dispatch(request) {
      const accepted = validateExternalIntentV2(structuredClone(request));
      dispatches += 1;
      return executeExternalIntentV2(accepted, handlers);
    },
    dispatchCount() {
      return dispatches;
    },
  });
}

export async function runClosedIntentConformancePack({consumer, fixture}) {
  if (consumer === undefined || consumer === null) return disabledReport('CONSUMER_ABSENT');
  if (!compatibleConsumer(consumer)) return disabledReport('CONSUMER_INCOMPATIBLE');
  assertFixture(fixture);

  const attestation = consumer.attest();
  assertCapabilityAttestationForEvidence(attestation);
  const bridge = new ExternalIntentEvidenceBridge();
  const evidence = [];
  const before = typeof consumer.dispatchCount === 'function' ? consumer.dispatchCount() : 0;

  for (const request of fixture.requests) {
    const accepted = validateExternalIntentV2(structuredClone(request));
    const response = await consumer.dispatch(accepted);
    const mapped = bridge.consume({
      request: accepted,
      response,
      attestation,
      context: structuredClone(fixture.contexts[accepted.action]),
    });
    evidence.push({
      action: accepted.action,
      requestId: accepted.requestId,
      resultIntegrityDigest: response.integrity.digest,
      evidenceDigest: mapped.evidenceDigest,
      eventId: mapped.event.eventId,
      receiptId: mapped.receipt.executionId,
      status: mapped.receipt.status,
    });
  }

  const observedDispatches = typeof consumer.dispatchCount === 'function'
    ? consumer.dispatchCount() - before
    : CLOSED_INTENTS.length;
  if (observedDispatches !== CLOSED_INTENTS.length) fail('CONFORMANCE_DISPATCH_COUNT_DENIED');

  const body = {
    schemaVersion: CLOSED_INTENT_CONFORMANCE_PACK_VERSION,
    mode: 'local-stub-conformance',
    contractVersion: SBA_EXTERNAL_CONTRACT_VERSION,
    attestationDigest: attestation.attestation.digest,
    executedIntents: CLOSED_INTENTS.length,
    acceptedEvidence: evidence.length,
    downstreamDispatches: observedDispatches,
    evidence,
    nonClaims: NON_CLAIMS,
  };
  return deepFreeze({...body, reportDigest: sha256Digest(body)});
}

function contextFor(fixture, action) {
  return structuredClone(fixture.contexts[action]);
}

function resealAttestation(attestation) {
  const body = Object.fromEntries(Object.entries(attestation).filter(([key]) => key !== 'attestation'));
  attestation.attestation = {algorithm: 'sha256-canonical-json', digest: sha256Digest(body)};
  return attestation;
}

function requestProbe(request, dispatchCounter) {
  validateExternalIntentV2(structuredClone(request));
  dispatchCounter.count += 1;
  fail('CONFORMANCE_NEGATIVE_REACHED_DISPATCH');
}

function responseProbe({fixture, baseline, attestation, mutate}) {
  const request = fixture.requests[0];
  const input = {
    request,
    response: structuredClone(baseline),
    attestation: structuredClone(attestation),
    context: contextFor(fixture, request.action),
  };
  mutate?.(input);
  return buildExternalIntentEvidence(input);
}

export async function runClosedIntentNegativeMatrix({fixture}) {
  assertFixture(fixture);
  const setupConsumer = createDeterministicLocalConsumer(fixture);
  const attestation = setupConsumer.attest();
  const baseline = await setupConsumer.dispatch(fixture.requests[0]);
  const request = fixture.requests[0];
  const replayInput = {
    request,
    response: structuredClone(baseline),
    attestation: structuredClone(attestation),
    context: contextFor(fixture, request.action),
  };
  const replayBridge = new ExternalIntentEvidenceBridge();
  replayBridge.consume(structuredClone(replayInput));
  const probes = [
    {id: 'extra-tool', run(counter) { requestProbe({...request, action: 'extra-tool'}, counter); }},
    {id: 'trusted-apply', run(counter) { requestProbe({...request, action: 'trusted-apply'}, counter); }},
    {id: 'free-sql', run(counter) { requestProbe({...request, action: 'plan', input: {objective: 'Review safe totals', sql: 'SELECT * FROM secret'}}, counter); }},
    {id: 'arbitrary-url', run(counter) { requestProbe({...request, action: 'plan', input: {objective: 'Review safe totals', url: 'https://untrusted.invalid'}}, counter); }},
    {id: 'credential', run(counter) { requestProbe({...request, action: 'analyze', input: {credential: 'must-not-cross'}}, counter); }},
    {id: 'raw-row', run(counter) { requestProbe({...request, action: 'analyze', input: {rawRows: [{value: 'must-not-cross'}]}}, counter); }},
    {id: 'malformed-response', run() { responseProbe({fixture, baseline, attestation, mutate(input) { delete input.response.integrity; }}); }},
    {id: 'tampered-response', run() { responseProbe({fixture, baseline, attestation, mutate(input) { input.response.result.status = 'TAMPERED'; }}); }},
    {id: 'replayed-response', run() { replayBridge.consume(structuredClone(replayInput)); }},
    {id: 'stale-contract', run() { responseProbe({fixture, baseline, attestation, mutate(input) { input.attestation.contract.version = '1.0.0'; resealAttestation(input.attestation); }}); }},
    {id: 'missing-capability', run() { responseProbe({fixture, baseline, attestation, mutate(input) { input.attestation.capabilities = input.attestation.capabilities.filter((item) => item.action !== 'readback'); resealAttestation(input.attestation); }}); }},
  ];

  const results = [];
  for (const probe of probes) {
    const counter = {count: 0};
    let denialCode = null;
    try {
      probe.run(counter);
    } catch (error) {
      denialCode = error?.code ?? error?.message ?? 'UNKNOWN_DENIAL';
    }
    if (!denialCode || denialCode === 'CONFORMANCE_NEGATIVE_REACHED_DISPATCH') fail('CONFORMANCE_NEGATIVE_NOT_DENIED');
    results.push({
      id: probe.id,
      denied: true,
      denialCode,
      downstreamDispatches: counter.count,
      acceptedEvidence: 0,
    });
  }
  if (results.some((result) => result.downstreamDispatches !== 0 || result.acceptedEvidence !== 0)) fail('CONFORMANCE_NEGATIVE_SIDE_EFFECT');

  const body = {
    schemaVersion: CLOSED_INTENT_CONFORMANCE_PACK_VERSION,
    mode: 'negative-matrix',
    setupDispatchesExcluded: 1,
    setupAcceptedEvidenceExcluded: 1,
    probeCount: results.length,
    downstreamDispatches: 0,
    acceptedEvidence: 0,
    results,
    nonClaims: NON_CLAIMS,
  };
  return deepFreeze({...body, reportDigest: sha256Digest(body)});
}

export const renderClosedIntentConformanceReport = (report) => `${canonicalJson(report)}\n`;
