const DENIED_TEXT = /(?:\b(?:insert|update|delete|merge|drop|alter|create|truncate|grant|revoke|exec(?:ute)?|dbcc|backup|restore)\b|\braw\s+sql\b|password|credential|api[_ -]?key|ignore\s+(?:all\s+)?previous|system\s+prompt)/i;

export function exactObject(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw coded('CONTROL_REQUEST_INVALID');
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) {
    throw coded('CONTROL_REQUEST_SURFACE_DENIED');
  }
  return value;
}

export function validateActionRequest(value, action) {
  exactObject(value, ['action'], ['action']);
  if (value.action !== action) throw coded('CONTROL_ACTION_DENIED');
  return value;
}

export function validateAgentText(value) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 500) throw coded('AGENT_INPUT_INVALID');
  if (DENIED_TEXT.test(value)) throw coded('AGENT_UNSAFE_INPUT_DENIED');
  return value.trim();
}

export function parseSchemas(value) {
  const schemas = String(value ?? '').split(',').map((entry) => entry.trim()).filter(Boolean);
  if (schemas.length === 0 || schemas.length > 32 || schemas.some((entry) => !/^[A-Za-z_][A-Za-z0-9_$#]{0,127}$/.test(entry))) {
    throw coded('DB_ANALYZE_SCHEMA_SCOPE_INVALID');
  }
  return [...new Set(schemas)].sort();
}

export function coded(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

