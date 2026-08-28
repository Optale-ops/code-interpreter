import assert from 'node:assert/strict';
import { promises as dns } from 'node:dns';
import { EventEmitter, once } from 'node:events';
import https from 'node:https';
import type { ClientRequest } from 'node:http';
import type { Socket } from 'node:net';

const SECRET = 'test-egress-gateway-secret-32-bytes';
const HOST = 'console-staging.optale.com';

process.env.CODEAPI_EGRESS_GATEWAY_AUTOSTART = 'false';
process.env.CODEAPI_EGRESS_GRANT_SECRET = SECRET;
process.env.CODEAPI_HARDENED_SANDBOX_MODE = 'false';

class FailingRequest extends EventEmitter {
  end(): void {
    const socket = new EventEmitter();
    queueMicrotask(() => {
      this.emit('socket', socket as Socket);
      queueMicrotask(() => {
        const error = Object.assign(new Error('connect ENETUNREACH'), {
          code: 'ENETUNREACH',
        });
        socket.emit('error', error);
      });
    });
  }

  destroy(error?: Error): this {
    if (error) queueMicrotask(() => this.emit('error', error));
    return this;
  }
}

async function main(): Promise<void> {
  dns.resolveCname = async (): Promise<string[]> => [];
  dns.resolve4 = async (): Promise<string[]> => [];
  dns.resolve6 = async (): Promise<string[]> => ['2606:4700:3032::ac43:80c6'];
  https.request = (() => new FailingRequest() as unknown as ClientRequest) as typeof https.request;

  // The gateway reads process environment during module initialization, so this
  // test intentionally loads it only after the fixture has installed its boundary.
  const [{ app }, { EGRESS_GRANT_HEADER, sealEgressGrant }] = await Promise.all([
    import('./egress-gateway'),
    import('./egress-grant'),
  ]);

  const now = Math.floor(Date.now() / 1000);
  const grant = sealEgressGrant({
    v: 1,
    typ: 'grant',
    grant_id: 'grant_socket_failure',
    exec_id: 'exec_socket_failure',
    tenant_id: 'tenant_test',
    user_id: 'user_test',
    session_key: 'tenant:tenant_test:user:user_test',
    input_files: [],
    read_sessions: [],
    output_session_id: 'session_output',
    max_upload_bytes: 1024,
    max_output_files: 1,
    max_requests: 10,
    iat: now - 10,
    exp: now + 300,
    principal_source: 'test',
    auth_context_hash: 'test',
  }, SECRET);

  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.notEqual(address, null);
  assert.equal(typeof address, 'object');
  if (typeof address !== 'object') throw new Error('gateway did not bind a TCP address');
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    const failed = await fetch(`${baseUrl}/https-passthrough`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        [EGRESS_GRANT_HEADER]: grant,
      },
      body: JSON.stringify({
        url: `https://${HOST}/api/optale/mcp`,
        method: 'POST',
        headers: {},
        bodyBase64: '',
      }),
    });
    assert.equal(failed.status, 502);
    assert.deepEqual(await failed.json(), {
      error: 'FETCH_FAILED',
      message: 'External fetch failed',
    });

    const subsequent = await fetch(`${baseUrl}/live`);
    assert.equal(subsequent.status, 200);
    process.stdout.write('EGRESS_GATEWAY_SOCKET_FAILURE_SURVIVED\n');
  } finally {
    server.close();
    await once(server, 'close');
  }
}

void main();
