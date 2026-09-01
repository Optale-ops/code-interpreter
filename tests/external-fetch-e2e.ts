import crypto from 'node:crypto';

const SERVICE_URL = process.env.SERVICE_URL ?? 'http://api:3112';
const QUERY_MARKER = 'W733_QUERY_MARKER_9f3d82';

type Surface = 'exec' | 'exec/programmatic';

function outputText(payload: unknown): string {
  if (!payload || typeof payload !== 'object') return '';
  const parts: string[] = [];
  if ('stdout' in payload && typeof payload.stdout === 'string')
    parts.push(payload.stdout);
  if ('stderr' in payload && typeof payload.stderr === 'string')
    parts.push(payload.stderr);
  if ('run' in payload && payload.run && typeof payload.run === 'object') {
    if ('stdout' in payload.run && typeof payload.run.stdout === 'string')
      parts.push(payload.run.stdout);
    if ('stderr' in payload.run && typeof payload.run.stderr === 'string')
      parts.push(payload.run.stderr);
  }
  return parts.join('\n');
}

async function execute(
  surface: Surface,
  code: string,
  sentinel: string,
  language = 'python',
): Promise<unknown> {
  const body =
    surface === 'exec'
      ? { code, lang: language, user_id: 'w733-boundary' }
      : {
          code,
          language,
          tools: [
            {
              name: 'unused_boundary_tool',
              description:
                'Not called; keeps the real programmatic route contract valid',
              parameters: { type: 'object', properties: {} },
            },
          ],
          user_id: 'w733-boundary',
        };
  const response = await fetch(`${SERVICE_URL}/v1/${surface}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok)
    throw new Error(`${surface} returned ${response.status}: ${text}`);
  const payload = JSON.parse(text) as unknown;

  const output = outputText(payload);
  if (!output.includes(sentinel)) {
    throw new Error(`${surface} missing ${sentinel}: ${text}`);
  }
  if (text.includes(QUERY_MARKER)) {
    throw new Error(`${surface} response leaked the query marker`);
  }
    return payload;
}

const GATEWAY_URL = 'http://egress-gateway:3190';

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const INTERNAL_TOKEN = requiredEnv('CODEAPI_INTERNAL_SERVICE_TOKEN');
const GRANT_SECRET = requiredEnv('CODEAPI_EGRESS_GRANT_SECRET');

const POLICY_LIMITS = {
    maxRedirects: 3,
    maxResponseBytes: 26_214_400,
    maxAggregateBytesPerGrant: 52_428_800,
    maxFetchesPerGrant: 8,
    connectTimeoutMs: 3_000,
    headersTimeoutMs: 5_000,
    totalTimeoutMs: 15_000,
};
const NETWORK_POLICY = {
    version: 1,
    limits: POLICY_LIMITS,
    hosts: {
        'allowed.test': {
            contentTypes: ['application/pdf'],
            httpsPassthrough: true,
            httpsPassthroughTotalTimeoutMs: 300_000,
            packageTransport: true,
            limits: POLICY_LIMITS,
        },
        'private.test': {
            contentTypes: ['application/pdf'],
            limits: POLICY_LIMITS,
        },
    },
};
function canonicalJson(value: unknown): string {
    if (
        value === null ||
        typeof value === 'string' ||
        typeof value === 'boolean' ||
        typeof value === 'number'
    ) {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
        .sort()
        .map(key => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
        .join(',')}}`;
}
const NETWORK_POLICY_DIGEST = crypto
    .createHash('sha256')
    .update(canonicalJson(NETWORK_POLICY), 'utf8')
    .digest('base64url');

function grantClaims(execId: string, exp: number): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    exec_id: execId,
    tenant_id: 'w733-tenant',
    user_id: 'w733-user',
    session_key: 'w733-tenant:user:w733-user',
    input_files: [],
    read_sessions: [],
    output_session_id: `output-${execId}`,
    max_upload_bytes: 1024,
    max_output_files: 10,
    max_requests: 100,
    iat: now - 10,
    exp,
    principal_source: 'none',
        network_policy: NETWORK_POLICY,
        network_policy_digest: NETWORK_POLICY_DIGEST,
  };
}

function sealGrant(claims: Record<string, unknown>): string {
    const key = crypto
        .createHash('sha256')
        .update(GRANT_SECRET, 'utf8')
        .digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('codeapi-egress-grant:v1', 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(claims), 'utf8'),
    cipher.final(),
  ]);
  return [
    'ceg1',
    iv.toString('base64url'),
    ciphertext.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
  ].join('.');
}

async function externalFetchWithGrant(token?: string): Promise<Response> {
  return fetch(`${GATEWAY_URL}/external-fetch`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token === undefined ? {} : { 'X-CodeAPI-Egress-Grant': token }),
    },
    body: JSON.stringify({ url: 'https://unlisted.test/file.pdf' }),
  });
}

async function verifyGrantDenials(): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const expired = sealGrant({
    ...grantClaims('expired-exec', now - 60),
    typ: 'grant',
    grant_id: 'expired-grant',
  });
  if ((await externalFetchWithGrant(expired)).status !== 401)
    throw new Error('expired grant reached policy');

  const claims = grantClaims('active-exec', now + 300);
    const createResponse = await fetch(
        `${GATEWAY_URL}/internal/egress-grants`,
        {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CodeAPI-Internal-Token': INTERNAL_TOKEN,
    },
    body: JSON.stringify({
      payload: {
        language: 'python',
        version: '3.14.4',
        session_id: 'output-active-exec',
        files: [],
      },
      claims,
    }),
        },
    );
  if (createResponse.status !== 201)
    throw new Error(`grant create failed: ${await createResponse.text()}`);
  const created: unknown = await createResponse.json();
  if (
    !created ||
    typeof created !== 'object' ||
    !('grant_id' in created) ||
    !('egressGrantToken' in created)
  ) {
    throw new Error('grant create response shape invalid');
  }
  if (
    typeof created.grant_id !== 'string' ||
    typeof created.egressGrantToken !== 'string'
  ) {
    throw new Error('grant create response values invalid');
  }

  const crossExecution = sealGrant({
    ...claims,
    v: 1,
    typ: 'grant',
    grant_id: created.grant_id,
    exec_id: 'different-exec',
  });
  if ((await externalFetchWithGrant(crossExecution)).status !== 403)
    throw new Error('cross-exec grant reached policy');

  const revokeResponse = await fetch(
    `${GATEWAY_URL}/internal/egress-grants/${created.grant_id}/revoke`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CodeAPI-Internal-Token': INTERNAL_TOKEN,
      },
      body: JSON.stringify({ reason: 'boundary-test' }),
    },
  );
  if (revokeResponse.status !== 204)
    throw new Error(`grant revoke failed: ${await revokeResponse.text()}`);
  if ((await externalFetchWithGrant(created.egressGrantToken)).status !== 403)
    throw new Error('revoked grant reached policy');
  if ((await externalFetchWithGrant()).status !== 404)
    throw new Error('missing grant was not opaque');
}

async function waitForService(): Promise<void> {
  for (let attempt = 0; attempt < 180; attempt += 1) {
    try {
      const response = await fetch(`${SERVICE_URL}/v1/health`);
      if (response.ok) return;
    } catch {
      /* service not listening yet */
    }
    await Bun.sleep(1_000);
  }
  throw new Error('CodeAPI service did not become ready');
}

function packageSummaries(payload: unknown): Array<Record<string, unknown>> {
    if (!payload || typeof payload !== 'object') return [];
    if ('package_setup' in payload && Array.isArray(payload.package_setup)) {
        return payload.package_setup as Array<Record<string, unknown>>;
    }
    if (!('run' in payload)) return [];
    const run = payload.run;
    if (!run || typeof run !== 'object' || !('package_setup' in run)) return [];
    return Array.isArray(run.package_setup)
        ? (run.package_setup as Array<Record<string, unknown>>)
        : [];
}

function assertPackageSummary(
    payload: unknown,
    manager: 'pip' | 'npm' | 'bun',
    requestedSpec: string,
): void {
    const summaries = packageSummaries(payload);
    const summary = summaries.find(
        item =>
            item.manager === manager && item.requestedSpec === requestedSpec,
    );
    if (!summary)
        throw new Error(
            `missing ${manager} setup summary: ${JSON.stringify(payload)}`,
        );
    if (
        summary.requestedSpec !== requestedSpec ||
        summary.installedVersion !== '1.0.0'
    ) {
        throw new Error(
            `unexpected ${manager} summary: ${JSON.stringify(summary)}`,
        );
    }
    if (
        typeof summary.gatewayRequestCount !== 'number' ||
        summary.gatewayRequestCount < 2 ||
        typeof summary.gatewayResponseBytes !== 'number' ||
        summary.gatewayResponseBytes < 1 ||
        summary.policyDigest !== NETWORK_POLICY_DIGEST ||
        summary.outcome !== 'success'
    ) {
        throw new Error(
            `incomplete ${manager} summary: ${JSON.stringify(summary)}`,
        );
    }
    const serialized = JSON.stringify(summary);
    for (const forbidden of [
        'https://',
        'Authorization',
        'Cookie',
        'stdout',
        'stderr',
        'lockfile',
    ]) {
        if (serialized.includes(forbidden))
            throw new Error(`summary leaked ${forbidden}`);
    }
}

const pipInstall = `
import os, subprocess, sys
subprocess.run([
    sys.executable, '-m', 'pip', 'install', '--no-deps',
    '--index-url', 'https://allowed.test/simple',
    'optale-fixture-py==1.0.0',
    'optale-fixture-source==1.0.0',
], check=True)
check = subprocess.run([
    sys.executable, '-c',
    'import optale_fixture_py as p; assert p.__version__ == "1.0.0"; assert p.MARKER == "OPTALE_PY_FIXTURE_OK"; print(p.MARKER)',
], check=True, capture_output=True, text=True)
assert 'OPTALE_PY_FIXTURE_OK' in check.stdout
source_check = subprocess.run([
    sys.executable, '-c',
    'import optale_fixture_source as p; assert p.__version__ == "1.0.0"; assert p.MARKER == "OPTALE_PIP_SOURCE_FIXTURE_OK"; print(p.MARKER)',
], check=True, capture_output=True, text=True)
assert 'OPTALE_PIP_SOURCE_FIXTURE_OK' in source_check.stdout
assert open('/mnt/data/pip-source-build-marker.txt').read() == 'OPTALE_PIP_SOURCE_BUILD_OK'
assert not os.path.exists('/run/codeapi/package-ca-key.pem')
print('W822_PIP_INSTALL_OK')
`;

const npmInstall = `
npm install optale-fixture-npm@1.0.0 --registry=https://allowed.test
node -e "const p=require('optale-fixture-npm'); if(p.version!=='1.0.0'||p.marker!=='OPTALE_NPM_FIXTURE_OK')process.exit(1)"
test "$(cat /mnt/data/npm-lifecycle-marker.txt)" = OPTALE_NPM_LIFECYCLE_OK
printf '%s\n' W822_NPM_INSTALL_OK
`;

const bunInstall = `
set -e
bun add optale-fixture-npm@1.0.0 --registry=https://allowed.test
cd /mnt/data/.optale-packages/bun
bun -e "const p=require('optale-fixture-npm'); if(p.version!=='1.0.0'||p.marker!=='OPTALE_NPM_FIXTURE_OK')process.exit(1)"
printf '%s\n' W822_BUN_INSTALL_OK
`;

const packageProxyDenies = `
import socket

def raw(request):
    client = socket.create_connection(('127.0.0.1', 3129), timeout=2)
    client.sendall(request)
    response = b''
    while True:
        chunk = client.recv(4096)
        if not chunk: break
        response += chunk
    return response
assert b'403' in raw(b'CONNECT allowed.test:444 HTTP/1.1\\r\\nHost: allowed.test:444\\r\\n\\r\\n')
assert b'403' in raw(b'CONNECT allowed.test:443 HTTP/1.1\\r\\nHost: allowed.test:443\\r\\n\\r\\nopaque-connect-bytes')
print('W822_PACKAGE_PROXY_DENIES_OK')
`;

const successAndRelay = `
import json, os, socket
from sandbox_fetch import sandbox_fetch
result = sandbox_fetch("https://allowed.test/success?secret=${QUERY_MARKER}", "/mnt/data/success.pdf")
assert result["bytes"] == 23
assert result["content_type"] == "application/pdf"
assert result["host"] == "allowed.test"
assert result["redirects"] == 0
assert open("/mnt/data/success.pdf", "rb").read() == b"controlled pdf fixture\\n"
redirected = sandbox_fetch("https://allowed.test/redirect", "/mnt/data/redirect-success.pdf")
assert redirected["redirects"] == 1
assert open("/mnt/data/redirect-success.pdf", "rb").read() == b"controlled pdf fixture\\n"
assert os.stat("/mnt/data/success.pdf").st_mode & 0o777 == 0o600
for host, port in [("allowed.test", 443), ("127.0.0.1", 443), ("169.254.169.254", 80), ("10.0.0.1", 443)]:
    try:
        socket.create_connection((host, port), timeout=1)
        raise AssertionError("direct network unexpectedly succeeded")
    except OSError:
        pass
try:
    socket.getaddrinfo("allowed.test", 443)
    raise AssertionError("direct DNS unexpectedly succeeded")
except OSError:
    pass
try:
    import urllib.request
    urllib.request.urlopen("http://allowed.test/", timeout=1)
    raise AssertionError("ordinary HTTP unexpectedly succeeded")
except Exception:
    pass
def raw(request):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect("/tmp/tcs.sock")
    client.sendall(request)
    response = b""
    while True:
        chunk = client.recv(4096)
        if not chunk: break
        response += chunk
    return response
assert b"404" in raw(b"GET /external-fetch HTTP/1.1\\r\\nHost: local\\r\\nConnection: close\\r\\n\\r\\n")
grant = open("/run/codeapi/egress-grant").read()
body = json.dumps({"url":"https://allowed.test/success","headers":{"Authorization":"bad"}}).encode()
request = b"POST /external-fetch HTTP/1.1\\r\\nHost: local\\r\\nContent-Type: application/json\\r\\nContent-Length: " + str(len(body)).encode() + b"\\r\\nX-CodeAPI-Egress-Grant: " + grant.encode() + b"\\r\\nConnection: close\\r\\n\\r\\n" + body
assert b"400" in raw(request)
# The production gateway runs the bundled artifact under Node because Bun's
# node:http compat layer does not emit HTTP response trailers. Prove the real
# outcome trailer reaches the sandbox on the wire, through the real relay.
ok_body = json.dumps({"url":"https://allowed.test/success"}).encode()
ok_request = b"POST /external-fetch HTTP/1.1\\r\\nHost: local\\r\\nContent-Type: application/json\\r\\nContent-Length: " + str(len(ok_body)).encode() + b"\\r\\nX-CodeAPI-Egress-Grant: " + grant.encode() + b"\\r\\nConnection: close\\r\\n\\r\\n" + ok_body
ok_response = raw(ok_request)
ok_headers = ok_response.split(b"\\r\\n\\r\\n", 1)[0].lower()
assert b"200 ok" in ok_headers, ok_response[:120]
assert b"transfer-encoding: chunked" in ok_headers, ok_response[:200]
assert b"trailer: x-codeapi-egress-outcome" in ok_headers, ok_response[:400]
assert b"x-codeapi-egress-host: allowed.test" in ok_headers, ok_response[:400]
assert ok_response.rstrip().endswith(b"X-CodeAPI-Egress-Outcome: OK"), ok_response[-200:]
assert b"W733_QUERY_MARKER" not in ok_response
print("W733_SUCCESS_RELAY_OK")
`;

const httpsPassthrough = `
node <<'NODE'
const allowed = await fetch('https://allowed.test/passthrough', {
  method: 'POST',
  headers: {
    Authorization: 'Bearer presence-only-test-token',
    'Content-Type': 'application/json',
    'X-Client-Marker': 'kept',
  },
  body: JSON.stringify({ action: 'record_search' }),
});
if (allowed.status !== 201) throw new Error('allowed status ' + allowed.status + ': ' + await allowed.text());
if (allowed.headers.get('x-upstream-marker') !== 'preserved') throw new Error('response header stripped');
if (allowed.headers.get('x-codeapi-egress-outcome') !== null) throw new Error('origin control header escaped');
const allowedBody = await allowed.json();
if (allowedBody.accepted !== true) throw new Error('allowed body changed');
const redirectDenied = await fetch('https://allowed.test/redirect', {
  headers: { Authorization: 'Bearer presence-only-test-token' },
});
const redirectDeniedBody = await redirectDenied.json();
if (redirectDenied.status !== 403 || redirectDeniedBody.error !== 'REDIRECT_REJECTED') {
  throw new Error('unexpected redirect denial ' + redirectDenied.status + ': ' + JSON.stringify(redirectDeniedBody));
}
const denied = await fetch('https://unlisted.test/passthrough');
const deniedBody = await denied.json();
if (denied.status !== 403 || deniedBody.error !== 'HOST_NOT_ALLOWED') {
  throw new Error('unexpected host denial ' + denied.status + ': ' + JSON.stringify(deniedBody));
}
const httpDenied = await fetch('http://allowed.test/passthrough');
const httpDeniedBody = await httpDenied.json();
if (httpDenied.status !== 403 || httpDeniedBody.error !== 'URL_REJECTED') {
  throw new Error('unexpected HTTP denial ' + httpDenied.status + ': ' + JSON.stringify(httpDeniedBody));
}
console.log('W799_HTTPS_PASSTHROUGH_OK');
NODE
`;

const urlDenies = `
import os
from sandbox_fetch import sandbox_fetch
cases = [
  ("https://unlisted.test/file.pdf", "HOST_NOT_ALLOWED"),
  ("http://allowed.test/file.pdf", "URL_REJECTED"),
  ("ftp://allowed.test/file.pdf", "URL_REJECTED"),
  ("ws://allowed.test/file.pdf", "URL_REJECTED"),
  ("https://allowed.test:444/file.pdf", "URL_REJECTED"),
  ("https://user@allowed.test/file.pdf", "URL_REJECTED"),
  ("https://127.0.0.1/file.pdf", "URL_REJECTED"),
  ("https://[::1]/file.pdf", "URL_REJECTED"),
]
for index, (url, expected) in enumerate(cases):
    output = f"/mnt/data/url-{index}.pdf"
    try:
        sandbox_fetch(url, output)
        raise AssertionError("deny unexpectedly succeeded")
    except Exception as error:
        assert str(error) == expected, (str(error), expected)
    assert not os.path.exists(output)
print("W733_URL_DENIES_OK")
`;

const redirectDenies = `
import os
from sandbox_fetch import sandbox_fetch
cases = [
  ("/private-redirect", "REDIRECT_REJECTED"),
  ("/unlisted-redirect", "REDIRECT_REJECTED"),
  ("/four-0", "REDIRECT_REJECTED"),
]
for index, (route, expected) in enumerate(cases):
    output = f"/mnt/data/redirect-{index}.pdf"
    try:
        sandbox_fetch("https://allowed.test" + route, output)
        raise AssertionError("redirect deny unexpectedly succeeded")
    except Exception as error:
        assert str(error) == expected, (str(error), expected)
    assert not os.path.exists(output)
print("W733_REDIRECT_DENIES_OK")
`;

const oversizeDenies = `
import os
from sandbox_fetch import sandbox_fetch
for index, route in enumerate(["/declared-oversize", "/streamed-oversize"]):
    output = f"/mnt/data/oversize-{index}.pdf"
    try:
        sandbox_fetch("https://allowed.test" + route, output)
        raise AssertionError("oversize unexpectedly succeeded")
    except Exception as error:
        assert str(error) == "RESPONSE_TOO_LARGE", str(error)
    assert not os.path.exists(output)
print("W733_OVERSIZE_DENIES_OK")
`;

const responseDenies = `
import os
from sandbox_fetch import sandbox_fetch
cases = [
  ("/html", "CONTENT_TYPE_REJECTED"),
  ("/gzip", "CONTENT_TYPE_REJECTED"),
  ("/disconnect", "FETCH_FAILED"),
]
for index, (route, expected) in enumerate(cases):
    output = f"/mnt/data/response-{index}.pdf"
    try:
        sandbox_fetch("https://allowed.test" + route, output)
        raise AssertionError("response deny unexpectedly succeeded")
    except Exception as error:
        assert str(error) == expected, (str(error), expected)
    assert not os.path.exists(output)
print("W733_RESPONSE_DENIES_OK")
`;

const authorityDenies = `
import os
from sandbox_fetch import sandbox_fetch
cases = [
  ("https://2130706433/file.pdf", "URL_REJECTED"),
  ("https://0x7f000001/file.pdf", "URL_REJECTED"),
  ("https://017700000001/file.pdf", "URL_REJECTED"),
  ("https://allowed.test./file.pdf", "URL_REJECTED"),
  ("https://allowed.test/bad%zz", "URL_REJECTED"),
]
for index, (url, expected) in enumerate(cases):
    output = f"/mnt/data/authority-{index}.pdf"
    try:
        sandbox_fetch(url, output)
        raise AssertionError("authority deny unexpectedly succeeded")
    except Exception as error:
        assert str(error) == expected, (str(error), expected)
    assert not os.path.exists(output)
print("W733_AUTHORITY_DENIES_OK")
`;

const dnsDenies = `
import os
from sandbox_fetch import sandbox_fetch
for index, host in enumerate(["private.test"]):
    output = f"/mnt/data/dns-{index}.pdf"
    try:
        sandbox_fetch("https://" + host + "/success", output)
        raise AssertionError("private DNS unexpectedly succeeded")
    except Exception as error:
        assert str(error) == "ADDRESS_NOT_GLOBAL", (host, str(error))
    assert not os.path.exists(output)
print("W733_DNS_DENIES_OK")
`;

const fetchBudgetDenies = `
import os
from sandbox_fetch import sandbox_fetch
host_denial_output = "/mnt/data/fetch-budget-host-denial.pdf"
try:
    sandbox_fetch("https://unlisted.test/file.pdf", host_denial_output)
    raise AssertionError("unlisted host unexpectedly succeeded")
except Exception as error:
    assert str(error) == "HOST_NOT_ALLOWED", str(error)
assert not os.path.exists(host_denial_output)

for index in range(9):
    output = f"/mnt/data/fetch-budget-{index}.pdf"
    if index < 8:
        sandbox_fetch("https://allowed.test/success", output)
        assert os.path.exists(output)
        os.unlink(output)
        continue
    try:
        sandbox_fetch("https://allowed.test/success", output)
        raise AssertionError("ninth far-side request unexpectedly succeeded")
    except Exception as error:
        assert str(error) == "FETCH_BUDGET_EXCEEDED", (index, str(error))
    assert not os.path.exists(output)
print("W733_HOST_DENIAL_AND_FETCH_BUDGET_OK")
`;

const aggregateBudgetDenies = `
import os
from sandbox_fetch import sandbox_fetch
for index in range(3):
    output = f"/mnt/data/aggregate-{index}.pdf"
    try:
        sandbox_fetch("https://allowed.test/streamed-oversize", output)
        raise AssertionError("oversize unexpectedly succeeded")
    except Exception as error:
        expected = "FETCH_BUDGET_EXCEEDED" if index == 2 else "RESPONSE_TOO_LARGE"
        assert str(error) == expected, (index, str(error), expected)
    assert not os.path.exists(output)
print("W733_AGGREGATE_BUDGET_OK")
`;

const timeoutDenies = `
import os
from sandbox_fetch import sandbox_fetch
for index, route in enumerate(["/slow-headers", "/slow-body"]):
    output = f"/mnt/data/timeout-{index}.pdf"
    try:
        sandbox_fetch("https://allowed.test" + route, output)
        raise AssertionError("timeout unexpectedly succeeded")
    except Exception as error:
        assert str(error) == "FETCH_TIMEOUT", (route, str(error))
    assert not os.path.exists(output)
print("W733_TIMEOUT_DENIES_OK")
`;

const confinementDenies = `
import os
from sandbox_fetch import sandbox_fetch
victim = "/mnt/data/existing.pdf"
symlink = "/mnt/data/symlink.pdf"
open(victim, "wb").write(b"keep")
os.symlink(victim, symlink)
for output in ["relative.pdf", "/tmp/outside.pdf", "/mnt/data", victim, symlink]:
    try:
        sandbox_fetch("https://allowed.test/success", output)
        raise AssertionError("output confinement unexpectedly succeeded")
    except Exception as error:
        assert str(error) == "FETCH_FAILED", (output, str(error))
assert open(victim, "rb").read() == b"keep"
assert os.path.islink(symlink)
print("W733_CONFINEMENT_DENIES_OK")
`;

await waitForService();
if (process.env.E2E_MODE !== 'packages') {
    await verifyGrantDenials();

    for (const surface of ['exec', 'exec/programmatic'] as const) {
        await execute(surface, successAndRelay, 'W733_SUCCESS_RELAY_OK');
        await execute(
            surface,
            httpsPassthrough,
            'W799_HTTPS_PASSTHROUGH_OK',
            'bash',
        );
        await execute(surface, urlDenies, 'W733_URL_DENIES_OK');
        await execute(surface, redirectDenies, 'W733_REDIRECT_DENIES_OK');
        await execute(surface, oversizeDenies, 'W733_OVERSIZE_DENIES_OK');
        await execute(surface, responseDenies, 'W733_RESPONSE_DENIES_OK');
        await execute(surface, authorityDenies, 'W733_AUTHORITY_DENIES_OK');
        await execute(surface, dnsDenies, 'W733_DNS_DENIES_OK');
        await execute(
            surface,
            fetchBudgetDenies,
            'W733_HOST_DENIAL_AND_FETCH_BUDGET_OK',
        );
        await execute(
            surface,
            aggregateBudgetDenies,
            'W733_AGGREGATE_BUDGET_OK',
        );
        await execute(surface, timeoutDenies, 'W733_TIMEOUT_DENIES_OK');
        await execute(surface, confinementDenies, 'W733_CONFINEMENT_DENIES_OK');
    }
}

const pipResult = await execute('exec', pipInstall, 'W822_PIP_INSTALL_OK');
assertPackageSummary(pipResult, 'pip', 'optale-fixture-py==1.0.0');
assertPackageSummary(pipResult, 'pip', 'optale-fixture-source==1.0.0');
const npmResult = await execute(
    'exec',
    npmInstall,
    'W822_NPM_INSTALL_OK',
    'bash',
);
assertPackageSummary(npmResult, 'npm', 'optale-fixture-npm@1.0.0');
const bunResult = await execute(
    'exec',
    bunInstall,
    'W822_BUN_INSTALL_OK',
    'bash',
);
assertPackageSummary(bunResult, 'bun', 'optale-fixture-npm@1.0.0');
await execute('exec', packageProxyDenies, 'W822_PACKAGE_PROXY_DENIES_OK');

const observationsResponse = await fetch(
    'https://allowed.test/package-observations',
);
if (!observationsResponse.ok)
    throw new Error('package observations unavailable');
const observations = (await observationsResponse.json()) as Array<{
    method: string;
    path: string;
    credentialHeaders: boolean;
}>;
const expectedPackagePaths = new Set([
    '/simple/optale-fixture-py/',
    '/simple/optale-fixture-source/',
    '/packages/optale_fixture_py-1.0.0-py3-none-any.whl',
    '/packages/optale-fixture-source-1.0.0.tar.gz',
    '/optale-fixture-npm',
    '/npm/optale-fixture-npm-1.0.0.tgz',
]);
for (const observation of observations) {
    if (!expectedPackagePaths.has(observation.path)) {
        throw new Error(
            `unexpected package request ${JSON.stringify(observation)}`,
        );
    }
    if (
        (observation.method !== 'GET' && observation.method !== 'HEAD') ||
        observation.credentialHeaders
    ) {
        throw new Error(
            `unsafe package request ${JSON.stringify(observation)}`,
        );
    }
}
for (const expected of expectedPackagePaths) {
    if (!observations.some(observation => observation.path === expected)) {
        throw new Error(
            `missing package request ${expected}: ${JSON.stringify(
                observations,
            )}`,
        );
    }
}
console.log('W822_NATIVE_PACKAGE_BOUNDARY_OK');

console.log('W733_DUAL_ROUTE_BOUNDARY_OK');
console.log('W799_HTTPS_PASSTHROUGH_BOUNDARY_OK');
