export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("Canonical JSON accepts plain JSON objects only");
  }
  const entries = Object.keys(value).sort().map((key) => {
    if (value[key] === undefined) throw new TypeError("Canonical JSON rejects undefined object values");
    return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
  });
  return `{${entries.join(",")}}`;
}
