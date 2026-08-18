import assert from 'node:assert/strict';
import { Resolver } from 'node:dns/promises';
import dgram from 'node:dgram';
import fs from 'node:fs';
import https from 'node:https';
import { PassThrough, Writable } from 'node:stream';
import type { RemoteInfo } from 'node:dgram';
import { openExternalFetch, pipeExternalFetchBody } from './external-fetch';
import { ExternalFetchError } from './external-fetch-errors';
import { parseExternalFetchPolicy } from './external-fetch-policy';

const HOST = 'allowed.test';
const TEST_ADDRESS = '93.184.216.34';
const certDir = process.env.EXTERNAL_FETCH_TLS_FIXTURE_DIR ?? '';

async function run(command: string[]): Promise<void> {
  const process = Bun.spawn(command, { stdout: 'pipe', stderr: 'pipe' });
  const status = await process.exited;
  if (status !== 0)
    throw new Error(
      `${command[0]} failed: ${await new Response(process.stderr).text()}`,
    );
}

function readDnsQuestion(packet: Buffer): { name: string; end: number } {
  const labels: string[] = [];
  let cursor = 12;
  for (;;) {
    const length = packet[cursor];
    if (length === 0) return { name: labels.join('.'), end: cursor + 1 };
    labels.push(
      packet.subarray(cursor + 1, cursor + 1 + length).toString('ascii'),
    );
    cursor += length + 1;
  }
}

async function startDnsAuthority(): Promise<{
  resolver: Resolver;
  close: () => Promise<void>;
  queries: string[];
}> {
  const queries: string[] = [];
  const socket = dgram.createSocket('udp4');
  socket.on('message', (packet: Buffer, remote: RemoteInfo) => {
    const question = readDnsQuestion(packet);
    const type = packet.readUInt16BE(question.end);
    const questionEnd = question.end + 4;
    queries.push(`${question.name}:${type}`);
    const answerData =
      question.name === HOST && type === 1
        ? Buffer.from(TEST_ADDRESS.split('.').map(part => Number(part)))
        : undefined;
    const header = Buffer.alloc(12);
    packet.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answerData ? 1 : 0, 6);
    const answer = answerData
      ? Buffer.concat([
          Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]),
          answerData,
        ])
      : Buffer.alloc(0);
    socket.send(
      Buffer.concat([header, packet.subarray(12, questionEnd), answer]),
      remote.port,
      remote.address,
    );
  });
  const listening = Promise.withResolvers<void>();
  socket.bind(0, '127.0.0.1', listening.resolve);
  await listening.promise;
  const address = socket.address();
  const resolver = new Resolver();
  resolver.setServers([`127.0.0.1:${address.port}`]);
  return {
    resolver,
    queries,
    close: () => {
      const closed = Promise.withResolvers<void>();
      socket.close(closed.resolve);
      return closed.promise;
    },
  };
}

function policy(timeoutOverrides: Record<string, number> = {}) {
  return parseExternalFetchPolicy({
    version: 1,
    limits: {
      maxRedirects: 3,
      maxResponseBytes: 26_214_400,
      maxAggregateBytesPerGrant: 52_428_800,
      maxFetchesPerGrant: 8,
      connectTimeoutMs: 3_000,
      headersTimeoutMs: 5_000,
      totalTimeoutMs: 15_000,
      ...timeoutOverrides,
    },
    hosts: { [HOST]: { contentTypes: ['application/pdf'] } },
  });
}

async function expectCode(
  operation: () => Promise<unknown>,
  code: ExternalFetchError['code'],
): Promise<void> {
  try {
    await operation();
    throw new Error(`expected ${code}`);
  } catch (error) {
    if (!(error instanceof ExternalFetchError)) throw error;
    assert.equal(error.code, code);
  }
}

async function main(): Promise<void> {
  await run(['ip', 'link', 'set', 'lo', 'up']);
  await run(['ip', 'address', 'add', `${TEST_ADDRESS}/32`, 'dev', 'lo']);
  const dns = await startDnsAuthority();
  const requests: Array<{
    path: string;
    method?: string;
    headers: string[];
  }> = [];
  const server = https.createServer(
    {
      key: fs.readFileSync(`${certDir}/key.pem`),
      cert: fs.readFileSync(`${certDir}/cert.pem`),
    },
    (request, response) => {
      requests.push({
        path: request.url ?? '',
        method: request.method,
        headers: Object.keys(request.headers),
      });
      if (request.url === '/redirect') {
        response.writeHead(302, { Location: '/success' });
        return response.end();
      }
      if (request.url?.startsWith('/four-')) {
        const step = Number(request.url.slice('/four-'.length));
        response.writeHead(302, {
          Location: step === 3 ? '/success' : `/four-${step + 1}`,
        });
        return response.end();
      }
      if (request.url === '/wrong-host') {
        response.writeHead(302, {
          Location: 'https://unlisted.test/success',
        });
        return response.end();
      }
      if (request.url === '/declared-large') {
        response.writeHead(200, {
          'Content-Type': 'application/pdf',
          'Content-Length': '26214401',
        });
        return response.end();
      }
      if (request.url === '/stream-large') {
        response.writeHead(200, { 'Content-Type': 'application/pdf' });
        response.write(Buffer.alloc(26_214_400));
        response.end(Buffer.from([1]));
        return;
      }
      if (request.url === '/gzip') {
        response.writeHead(200, {
          'Content-Type': 'application/pdf',
          'Content-Encoding': 'gzip',
        });
        return response.end('compressed');
      }
      if (request.url === '/slow-headers') {
        setTimeout(() => {
          response.writeHead(200, {
            'Content-Type': 'application/pdf',
          });
          response.end('late');
        }, 200);
        return;
      }
      response.writeHead(200, { 'Content-Type': 'application/pdf' });
      response.end('pdf fixture');
    },
  );
  const serverListening = Promise.withResolvers<void>();
  server.listen(443, TEST_ADDRESS, serverListening.resolve);
  await serverListening.promise;

  try {
    const opened = await openExternalFetch({
      url: `https://${HOST}/success`,
      policy: policy(),
      resolver: dns.resolver,
    });
    const chunks: Buffer[] = [];
    const destination = new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    });
    assert.equal(await pipeExternalFetchBody(opened, destination), 11);
    assert.equal(Buffer.concat(chunks).toString('utf8'), 'pdf fixture');
    assert.equal(opened.redirects, 0);
    assert.equal(opened.contentType, 'application/pdf');
    assert.equal(requests[0]?.method, 'GET');
    assert.deepEqual(requests[0]?.headers.sort(), [
      'accept',
      'accept-encoding',
      'host',
      'user-agent',
    ]);

    const disconnectOpened = await openExternalFetch({
      url: `https://${HOST}/success`,
      policy: policy(),
      resolver: dns.resolver,
    });
    const disconnectedDestination = new PassThrough({ highWaterMark: 1 });
    setTimeout(() => disconnectedDestination.destroy(), 10);
    const disconnectOutcome = await Promise.race([
      pipeExternalFetchBody(disconnectOpened, disconnectedDestination).then(
        () => 'unexpected-success',
        error => error instanceof ExternalFetchError ? error.code : 'unexpected-error',
      ),
      Bun.sleep(250).then(() => 'hung'),
    ]);
    assert.equal(disconnectOutcome, 'FETCH_FAILED');

    const redirected = await openExternalFetch({
      url: `https://${HOST}/redirect`,
      policy: policy(),
      resolver: dns.resolver,
    });
    assert.equal(redirected.redirects, 1);
    await pipeExternalFetchBody(
      redirected,
      new Writable({
        write(_chunk, _encoding, callback) {
          callback();
        },
      }),
    );

    const queryCount = dns.queries.length;
    await expectCode(
      () =>
        openExternalFetch({
          url: `https://${HOST}/wrong-host`,
          policy: policy(),
          resolver: dns.resolver,
        }),
      'REDIRECT_REJECTED',
    );
    assert.equal(
      dns.queries.some(query => query.startsWith('unlisted.test:')),
      false,
    );
    assert.ok(dns.queries.length >= queryCount);

    const successCount = requests.filter(
      request => request.path === '/success',
    ).length;
    await expectCode(
      () =>
        openExternalFetch({
          url: `https://${HOST}/four-0`,
          policy: policy(),
          resolver: dns.resolver,
        }),
      'REDIRECT_REJECTED',
    );
    assert.equal(
      requests.filter(request => request.path === '/success').length,
      successCount,
    );

    await expectCode(
      () =>
        openExternalFetch({
          url: `https://${HOST}/declared-large`,
          policy: policy(),
          resolver: dns.resolver,
        }),
      'RESPONSE_TOO_LARGE',
    );
    await expectCode(async () => {
      const response = await openExternalFetch({
        url: `https://${HOST}/stream-large`,
        policy: policy(),
        resolver: dns.resolver,
      });
      await pipeExternalFetchBody(
        response,
        new Writable({
          write(_chunk, _encoding, callback) {
            callback();
          },
        }),
      );
    }, 'RESPONSE_TOO_LARGE');
    await expectCode(
      () =>
        openExternalFetch({
          url: `https://${HOST}/gzip`,
          policy: policy(),
          resolver: dns.resolver,
        }),
      'CONTENT_TYPE_REJECTED',
    );
    await expectCode(
      () =>
        openExternalFetch({
          url: `https://${HOST}/slow-headers`,
          policy: policy({
            headersTimeoutMs: 50,
            totalTimeoutMs: 100,
          }),
          resolver: dns.resolver,
        }),
      'FETCH_TIMEOUT',
    );

    console.log('EXTERNAL_FETCH_TLS_BOUNDARY_OK');
  } finally {
    const closed = Promise.withResolvers<void>();
    server.close(() => closed.resolve());
    await closed.promise;
    await dns.close();
  }
}

void main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
