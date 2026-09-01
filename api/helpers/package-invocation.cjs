const fs = require('node:fs');
const path = require('node:path');

const MANAGERS = new Set(['pip', 'npm', 'bun']);
const VALUE_OPTIONS = new Set([
  '--index-url', '--extra-index-url', '--trusted-host', '--target', '--prefix',
  '--registry', '--cache-dir', '--cafile', '--proxy', '-i', '-t', '-r',
]);
const ARCHIVE_SUFFIX = /(?:\.tar\.gz|\.tgz|\.whl|\.zip)$/i;
const NPM_REGISTRY_SPEC = /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)(?:@[A-Za-z0-9*^~<>=|., -]+)?$/i;
const PIP_REGISTRY_SPEC = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._,-]+\])?(?:\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9*+!._,-]+(?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9*+!._,-]+)*)?$/;

function sanitizeRequestedSpec(manager, value) {
  if (!MANAGERS.has(manager) || typeof value !== 'string') return undefined;
  if (
    value.length < 1 ||
    value.length > 256 ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f\\]/.test(value) ||
    /:\/\//.test(value) ||
    /^[/.]/.test(value) ||
    ARCHIVE_SUFFIX.test(value)
  ) return undefined;
  if (manager === 'pip') {
    if (value.includes('@') || /^(?:git|hg|svn|bzr|file):/i.test(value))
      return undefined;
    return PIP_REGISTRY_SPEC.test(value) ? value : undefined;
  }
  if (/^(?:git|hg|svn|bzr|file|github|gitlab|bitbucket):/i.test(value))
    return undefined;
  return NPM_REGISTRY_SPEC.test(value) ? value : undefined;
}

function invocationRecord(manager, start, end, status, argv) {
  if (!MANAGERS.has(manager)) return undefined;
  if (![start, end, status].every(Number.isFinite) || !Array.isArray(argv))
    return undefined;
  const requestedSpecs = [];
  for (let index = 1; index < argv.length && requestedSpecs.length < 32; index += 1) {
    const value = argv[index];
    if (VALUE_OPTIONS.has(value)) { index += 1; continue; }
    if (typeof value !== 'string' || value.startsWith('-')) continue;
    const sanitized = sanitizeRequestedSpec(manager, value);
    if (sanitized !== undefined) requestedSpecs.push(sanitized);
  }
  if (requestedSpecs.length === 0) return undefined;
  return {
    manager,
    requestedSpecs,
    durationMs: Math.max(0, Math.min(300000, Math.floor(end - start))),
    outcome: status === 0 ? 'success' : 'failed',
  };
}

if (require.main === module) {
  const [manager, rawStart, rawEnd, rawStatus, ...argv] = process.argv.slice(2);
  const record = invocationRecord(
    manager,
    Number(rawStart),
    Number(rawEnd),
    Number(rawStatus),
    argv,
  );
  if (record) {
    const root = '/mnt/data/.optale-packages';
    fs.mkdirSync(root, { recursive: true });
    fs.appendFileSync(
      path.join(root, 'invocations.jsonl'),
      JSON.stringify(record) + '\n',
      { encoding: 'utf8', mode: 0o600 },
    );
  }
}

module.exports = { invocationRecord, sanitizeRequestedSpec };
