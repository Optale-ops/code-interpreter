const fs = require('node:fs');
const path = require('node:path');

const [manager, rawStart, rawEnd, rawStatus, ...argv] = process.argv.slice(2);
if (!['pip', 'npm', 'bun'].includes(manager)) process.exit(0);
const start = Number(rawStart);
const end = Number(rawEnd);
const status = Number(rawStatus);
if (![start, end, status].every(Number.isFinite)) process.exit(0);
const valueOptions = new Set([
  '--index-url', '--extra-index-url', '--trusted-host', '--target', '--prefix',
  '--registry', '--cache-dir', '--cafile', '--proxy', '-i', '-t', '-r',
]);
const requestedSpecs = [];
for (let index = 1; index < argv.length && requestedSpecs.length < 32; index += 1) {
  const value = argv[index];
  if (valueOptions.has(value)) { index += 1; continue; }
  if (value.startsWith('-')) continue;
  if (value.length < 1 || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) continue;
  requestedSpecs.push(value);
}
if (requestedSpecs.length === 0) process.exit(0);
const root = '/mnt/data/.optale-packages';
fs.mkdirSync(root, { recursive: true });
fs.appendFileSync(path.join(root, 'invocations.jsonl'), JSON.stringify({
  manager,
  requestedSpecs,
  durationMs: Math.max(0, Math.min(300000, Math.floor(end - start))),
  outcome: status === 0 ? 'success' : 'failed',
}) + '\n', { encoding: 'utf8', mode: 0o600 });
