import fs from 'node:fs';
import https from 'node:https';

const fixture = Buffer.from('controlled pdf fixture\n');
const packageFixtureRoot = '/fixtures/package-fixtures';
const packageManifest = JSON.parse(
    fs.readFileSync(`${packageFixtureRoot}/manifest.json`, 'utf8'),
) as {
    wheel: { file: string; sha256: string; bytes: number };
    npm: { file: string; sha1: string; integrity: string; bytes: number };
    source: { file: string; sha256: string; bytes: number };
};
const wheel = fs.readFileSync(
    `${packageFixtureRoot}/${packageManifest.wheel.file}`,
);
const npmTarball = fs.readFileSync(
    `${packageFixtureRoot}/${packageManifest.npm.file}`,
);
const sourceTarball = fs.readFileSync(
    `${packageFixtureRoot}/${packageManifest.source.file}`,
);
const packageRequests: Array<{
    method: string;
    path: string;
    credentialHeaders: boolean;
}> = [];
let privateTrapContacts = 0;

const server = https.createServer(
  {
    key: fs.readFileSync('/fixtures/key.pem'),
    cert: fs.readFileSync('/fixtures/cert.pem'),
  },
  async (request, response) => {
        const packagePaths = new Set([
            '/simple/optale-fixture-py/',
            '/simple/optale-fixture-source/',
            `/packages/${packageManifest.wheel.file}`,
            `/packages/${packageManifest.source.file}`,
            '/optale-fixture-npm',
            `/npm/${packageManifest.npm.file}`,
        ]);
        if (request.url === '/package-observations') {
            response.writeHead(200, { 'Content-Type': 'application/json' });
            response.end(JSON.stringify(packageRequests));
            return;
        }
        if (request.url && packagePaths.has(request.url)) {
            const method = request.method ?? '';
            const credentialHeaders = Boolean(
                request.headers.authorization ||
                    request.headers.cookie ||
                    request.headers['proxy-authorization'],
            );
            packageRequests.push({
                method,
                path: request.url,
                credentialHeaders,
            });
            if (
                (method !== 'GET' && method !== 'HEAD') ||
                credentialHeaders ||
                request.headers['accept-encoding'] !== 'identity'
            ) {
                response.writeHead(400, { 'Content-Type': 'text/plain' });
                response.end('package transport invariant failed');
                return;
            }
            let body: Buffer;
            let contentType: string;
            if (request.url === '/simple/optale-fixture-py/') {
                body = Buffer.from(
                    `<!doctype html><a href="/packages/${packageManifest.wheel.file}#sha256=${packageManifest.wheel.sha256}">optale-fixture-py</a>`,
                );
                contentType = 'text/html';
            } else if (request.url === '/simple/optale-fixture-source/') {
                body = Buffer.from(
                    `<!doctype html><a href="/packages/${packageManifest.source.file}#sha256=${packageManifest.source.sha256}">optale-fixture-source</a>`,
                );
                contentType = 'text/html';
            } else if (
                request.url === `/packages/${packageManifest.wheel.file}`
            ) {
                body = wheel;
                contentType = 'application/octet-stream';
            } else if (
                request.url === `/packages/${packageManifest.source.file}`
            ) {
                body = sourceTarball;
                contentType = 'application/gzip';
            } else if (request.url === '/optale-fixture-npm') {
                body = Buffer.from(
                    JSON.stringify({
                        name: 'optale-fixture-npm',
                        'dist-tags': { latest: '1.0.0' },
                        versions: {
                            '1.0.0': {
                                name: 'optale-fixture-npm',
                                version: '1.0.0',
                                main: 'index.js',
                                scripts: {
                                    postinstall:
                                        "node -e \"require('fs').writeFileSync('/mnt/data/npm-lifecycle-marker.txt','OPTALE_NPM_LIFECYCLE_OK')\"",
                                },
                                dist: {
                                    tarball: `https://allowed.test/npm/${packageManifest.npm.file}`,
                                    shasum: packageManifest.npm.sha1,
                                    integrity: packageManifest.npm.integrity,
                                },
                            },
                        },
                    }),
                );
                contentType = 'application/json';
            } else {
                body = npmTarball;
                contentType = 'application/octet-stream';
            }
            response.writeHead(200, {
                'Content-Type': contentType,
                'Content-Length': String(body.length),
            });
            if (method === 'HEAD') response.end();
            else response.end(body);
            return;
        }
    if (request.url === '/passthrough') {
      const chunks: Buffer[] = [];
      for await (const chunk of request)
                chunks.push(
                    Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
                );
      const body = Buffer.concat(chunks).toString('utf8');
      if (
                request.method !== 'POST' ||
                request.headers.authorization !==
                    'Bearer presence-only-test-token' ||
                request.headers['x-client-marker'] !== 'kept' ||
                request.headers['accept-encoding'] !== 'identity' ||
                body !== JSON.stringify({ action: 'record_search' })
      ) {
        response.writeHead(500, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ accepted: false }));
        return;
      }
      response.writeHead(201, {
        'Content-Type': 'application/json',
        'X-Upstream-Marker': 'preserved',
        'X-CodeAPI-Egress-Outcome': 'spoofed-origin-value',
        'X-Request-ID': 'spoofed-origin-value',
      });
      response.end(JSON.stringify({ accepted: true }));
      return;
    }
    if (request.url === '/redirect') {
      response.writeHead(302, { Location: '/success' });
      response.end();
      return;
    }
    if (request.url?.startsWith('/four-')) {
      const step = Number(request.url.slice('/four-'.length));
      response.writeHead(302, {
        Location: step === 3 ? '/success' : `/four-${step + 1}`,
      });
      response.end();
      return;
    }
    if (request.url === '/private-redirect') {
      response.writeHead(302, {
        Location: 'https://127.0.0.1/private-trap',
      });
      response.end();
      return;
    }
    if (request.url === '/unlisted-redirect') {
      response.writeHead(302, {
        Location: 'https://unlisted.test/private-trap',
      });
      response.end();
      return;
    }
    if (request.url === '/declared-oversize') {
      response.writeHead(200, {
        'Content-Type': 'application/pdf',
        'Content-Length': '26214401',
      });
      response.end();
      return;
    }
    if (request.url === '/streamed-oversize') {
      response.writeHead(200, { 'Content-Type': 'application/pdf' });
      response.write(Buffer.alloc(26_214_400));
      response.end(Buffer.from([1]));
      return;
    }
    if (request.url === '/html') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end('<html>denied</html>');
      return;
    }
    if (request.url === '/gzip') {
      response.writeHead(200, {
        'Content-Type': 'application/pdf',
        'Content-Encoding': 'gzip',
      });
            response.end(
                'not compressed because it must be rejected before read',
            );
      return;
    }
    if (request.url === '/disconnect') {
      response.writeHead(200, {
        'Content-Type': 'application/pdf',
        'Content-Length': '100',
      });
      response.write('partial');
      response.destroy();
      return;
    }
    if (request.url === '/slow-headers') {
      setTimeout(() => {
        response.writeHead(200, { 'Content-Type': 'application/pdf' });
        response.end(fixture);
      }, 5_500);
      return;
    }
    if (request.url === '/slow-body') {
      response.writeHead(200, { 'Content-Type': 'application/pdf' });
      response.write('partial');
      setTimeout(() => response.end('late'), 16_000);
      return;
    }
    if (request.url === '/private-trap') {
      privateTrapContacts += 1;
      response.writeHead(500).end();
      return;
    }
    if (request.url === '/trap-count') {
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end(String(privateTrapContacts));
      return;
    }
        if (
            request.url === '/success' ||
            request.url?.startsWith('/success?')
        ) {
      const observed = {
        method: request.method,
        headers: request.headers,
      };
      if (
        observed.method !== 'GET' ||
        observed.headers.accept !== 'application/pdf' ||
        observed.headers['accept-encoding'] !== 'identity' ||
        observed.headers.authorization ||
        observed.headers.cookie ||
        observed.headers.range ||
        observed.headers.referer
      ) {
        response.writeHead(500, { 'Content-Type': 'text/plain' });
        response.end('fixed-header invariant failed');
        return;
      }
      response.writeHead(200, {
        'Content-Type': 'application/pdf',
        'Content-Length': String(fixture.length),
      });
      response.end(fixture);
      return;
    }
    response.writeHead(404, { 'Content-Type': 'text/plain' });
    response.end('not found');
  },
);

server.listen(443, '0.0.0.0', () => {
  console.log('EXTERNAL_FETCH_ORIGIN_READY');
});
