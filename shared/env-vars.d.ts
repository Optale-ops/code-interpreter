export const ENV_VAR_KEY_RE: RegExp;
export const MAX_ENV_VAR_COUNT: 256;
export const MAX_ENV_VAR_BYTES: 1_000_000;
export function sanitizeEnvVars(raw: unknown): Record<string, string> | undefined;
