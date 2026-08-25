export const ENV_VAR_KEY_RE = /^[A-Z_][A-Z0-9_]*$/i;
export const MAX_ENV_VAR_COUNT = 256;
export const MAX_ENV_VAR_BYTES = 1_000_000;

/**
 * Sanitizes caller-provided environment variables at every process boundary.
 * Keep the service gateway and sandbox runner on this single policy.
 *
 * @param {unknown} raw
 * @returns {Record<string, string> | undefined}
 */
export function sanitizeEnvVars(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;

  /** @type {Record<string, string>} */
  const out = {};
  let entryCount = 0;
  let totalBytes = 0;
  for (const [key, value] of Object.entries(raw)) {
    entryCount += 1;
    if (entryCount > MAX_ENV_VAR_COUNT) {
      throw new Error(`env_vars exceeds maximum count of ${MAX_ENV_VAR_COUNT}`);
    }
    if (typeof value !== 'string') continue;
    if (!ENV_VAR_KEY_RE.test(key)) continue;
    const entryBytes = Buffer.byteLength(key) + Buffer.byteLength(value);
    if (totalBytes + entryBytes > MAX_ENV_VAR_BYTES) {
      throw new Error(`env_vars exceeds maximum total size of ${MAX_ENV_VAR_BYTES} bytes`);
    }
    totalBytes += entryBytes;
    out[key] = value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}
