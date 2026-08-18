import fs from 'node:fs';
import https from 'node:https';

const fixture = Buffer.from('controlled pdf fixture\n');
let privateTrapContacts = 0;

const server = https.createServer(
  {
    key: fs.readFileSync('/fixtures/key.pem'),
    cert: fs.readFileSync('/fixtures/cert.pem'),
  },
  (request, response) => {
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
      response.end('not compressed because it must be rejected before read');
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
    if (request.url === '/success' || request.url?.startsWith('/success?')) {
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
