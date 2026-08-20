import { createHash } from 'node:crypto';

import { canonicalJson } from '../canonical-json.js';

export const EVENT_ENVELOPE_VERSION = 'chimpmaera.bi/event-envelope/v1';
export const VERSION_IDENTITY_VERSION = 'chimpmaera.bi/version-identity/v1';
export const EVENT_CHANNELS = Object.freeze(['durable', 'live']);
export const DATA_CLASSES = Object.freeze(['public', 'internal', 'confidential', 'restricted']);
export const KNOWN_EVENT_TYPES = new Set([
  'transcript.partial', 'transcript.final', 'assistant.delta', 'assistant.final',
  'ui_action.proposed', 'ui_action.applied', 'ui_action.denied',
  'interaction.interrupted', 'interaction.cancelled', 'tool.execution.receipt',
]);

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SENSITIVE_KEY = /(password|passwd|secret|access.?token|refresh.?token|authorization|cookie|ssn|social.?security|email|phone|raw.?row|source.?row|chain.?of.?thought|reasoning)/i;
const SENSITIVE_VALUE = /(-----BEGIN [A-Z ]+PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+\/-]+=*|\bsk-[A-Za-z0-9_-]{12,})/i;
const fail = (code) => { const error = new Error(code); error.code = code; throw error; };

export function sha256Digest(value) {
  return `sha256:${createHash('sha256').update(typeof value === 'string' ? value : canonicalJson(value)).digest('hex')}`;
}

export function assertSafeJson(value, path = '$') {
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return;
  if (typeof value === 'string') {
    if (SENSITIVE_VALUE.test(value)) fail('SENSITIVE_VALUE_DENIED');
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertSafeJson(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('NON_JSON_PAYLOAD_DENIED');
  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) fail('SENSITIVE_FIELD_DENIED');
    if (item === undefined) fail('UNDEFINED_PAYLOAD_DENIED');
    assertSafeJson(item, `${path}.${key}`);
  }
}

export function assertVersionIdentity(identity) {
  if (!identity || identity.schemaVersion !== VERSION_IDENTITY_VERSION) fail('VERSION_IDENTITY_VERSION_UNSUPPORTED');
  if (!ID.test(identity.contract ?? '') || !/^v[1-9][0-9]*$/.test(identity.version ?? '')) fail('VERSION_IDENTITY_INVALID');
  if (!identity.producer || !ID.test(identity.producer.id ?? '') || !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(identity.producer.version ?? '')) fail('PRODUCER_IDENTITY_INVALID');
  if (!DIGEST.test(identity.producer.artifactDigest ?? '')) fail('PRODUCER_DIGEST_INVALID');
  return identity;
}

export function assertEventEnvelope(envelope) {
  if (!envelope || envelope.schemaVersion !== EVENT_ENVELOPE_VERSION) fail('EVENT_ENVELOPE_VERSION_UNSUPPORTED');
  if (!ID.test(envelope.eventId ?? '') || !ID.test(envelope.streamId ?? '') || !ID.test(envelope.correlationId ?? '')) fail('EVENT_IDENTITY_INVALID');
  if (!ID.test(envelope.eventType ?? '')) fail('EVENT_TYPE_INVALID');
  if (envelope.causationId !== null && envelope.causationId !== undefined && !ID.test(envelope.causationId)) fail('EVENT_CAUSATION_INVALID');
  if (!EVENT_CHANNELS.includes(envelope.channel) || !Number.isSafeInteger(envelope.seq) || envelope.seq < 1) fail('EVENT_SEQUENCE_INVALID');
  if (Number.isNaN(Date.parse(envelope.occurredAt ?? ''))) fail('EVENT_TIME_INVALID');
  assertVersionIdentity(envelope.version);
  if (!envelope.sensitivity || !DATA_CLASSES.includes(envelope.sensitivity.dataClass)) fail('EVENT_DATA_CLASS_INVALID');
  const categories = envelope.sensitivity.categories;
  if (!Array.isArray(categories) || categories.length === 0 || categories.some((item) => !['none', 'pii'].includes(item))) fail('EVENT_SENSITIVE_CATEGORY_DENIED');
  if (categories.includes('pii') && envelope.sensitivity.redaction !== 'redacted') fail('EVENT_PII_REDACTION_REQUIRED');
  if (!['none', 'redacted'].includes(envelope.sensitivity.redaction)) fail('EVENT_REDACTION_INVALID');
  if (typeof envelope.ignorable !== 'boolean') fail('EVENT_IGNORABLE_REQUIRED');
  if (!KNOWN_EVENT_TYPES.has(envelope.eventType) && envelope.ignorable !== true) fail('UNKNOWN_REQUIRED_EVENT');
  assertSafeJson(envelope.payload);
  if (!DIGEST.test(envelope.payloadDigest ?? '') || envelope.payloadDigest !== sha256Digest(envelope.payload)) fail('EVENT_PAYLOAD_DIGEST_MISMATCH');
  return envelope;
}

export class InMemoryEvidenceStore {
  #events = [];
  #lastSequence = new Map();
  #eventById = new Map();

  append(envelope) {
    assertEventEnvelope(envelope);
    if (this.#eventById.has(envelope.eventId)) fail('EVENT_ID_REPLAY');
    const sequenceKey = `${envelope.streamId}:${envelope.channel}`;
    const expected = (this.#lastSequence.get(sequenceKey) ?? 0) + 1;
    if (envelope.seq !== expected) fail('EVENT_SEQUENCE_NON_MONOTONIC');
    if (envelope.causationId) {
      const cause = this.#eventById.get(envelope.causationId);
      if (!cause) fail('EVENT_CAUSATION_UNKNOWN');
      if (cause.correlationId !== envelope.correlationId) fail('EVENT_CORRELATION_MISMATCH');
    }
    const frozen = structuredClone(envelope);
    Object.freeze(frozen);
    this.#events.push(frozen);
    this.#eventById.set(frozen.eventId, frozen);
    this.#lastSequence.set(sequenceKey, frozen.seq);
    return frozen;
  }

  durableEvents() { return this.#events.filter((event) => event.channel === 'durable').map(structuredClone); }
  liveEvents() { return this.#events.filter((event) => event.channel === 'live').map(structuredClone); }
}
