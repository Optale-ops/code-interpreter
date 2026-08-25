'use strict';

const fs = require('node:fs');
const http = require('node:http');
const { Readable, Transform } = require('node:stream');

const SOCKET_PATH = process.env.CODEAPI_EGRESS_SOCKET_PATH || '/tmp/tcs.sock';
const GRANT_FILE = process.env.CODEAPI_EGRESS_GRANT_FILE || '/run/codeapi/egress-grant';
const INSTALLED = Symbol.for('codeapi.httpsPassthroughFetchInstalled');

function fetchThroughEgress(request) {
  return (async () => {
    const body = request.method === 'GET' || request.method === 'HEAD'
      ? Buffer.alloc(0)
      : Buffer.from(await request.arrayBuffer());
    const headers = Object.fromEntries(request.headers.entries());
    headers['accept-encoding'] = 'identity';
    const envelope = Buffer.from(JSON.stringify({
      url: request.url,
      method: request.method,
      headers,
      bodyBase64: body.toString('base64'),
    }));
    const grant = fs.readFileSync(GRANT_FILE, 'utf8').trim();
    if (!grant) throw new TypeError('fetch failed');

    return await new Promise((resolve, reject) => {
      const upstream = http.request({
        socketPath: SOCKET_PATH,
        path: '/https-passthrough',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(envelope.length),
          'X-CodeAPI-Egress-Grant': grant,
          Connection: 'close',
        },
      });
      const fail = error => reject(new TypeError('fetch failed', { cause: error }));
      upstream.once('error', fail);
      upstream.once('response', response => {
        const headers = new Headers();
        for (const [name, value] of Object.entries(response.headers)) {
          if (value === undefined) continue;
          if (Array.isArray(value)) {
            for (const item of value) headers.append(name, item);
          } else {
            headers.append(name, value);
          }
        }
        const status = response.statusCode || 502;
        const noBody = request.method === 'HEAD' || status === 204 || status === 205 || status === 304;
        const expectsOutcome = (response.headers.trailer || '')
          .split(',')
          .some(value => value.trim().toLowerCase() === 'x-codeapi-egress-outcome');
        let bodyStream = response;
        if (!noBody && expectsOutcome) {
          const verifiedBody = new Transform({
            transform(chunk, _encoding, callback) {
              callback(null, chunk);
            },
            flush(callback) {
              const outcome = response.trailers['x-codeapi-egress-outcome'];
              if (outcome === 'OK') callback();
              else callback(new Error('controlled egress transfer failed'));
            },
          });
          response.once('error', error => verifiedBody.destroy(error));
          response.pipe(verifiedBody);
          bodyStream = verifiedBody;
        }
        resolve(new Response(noBody ? null : Readable.toWeb(bodyStream), {
          status,
          statusText: response.statusMessage,
          headers,
        }));
      });
      if (request.signal.aborted) {
        upstream.destroy(request.signal.reason);
        return;
      }
      request.signal.addEventListener('abort', () => upstream.destroy(request.signal.reason), { once: true });
      upstream.end(envelope);
    });
  })();
}

if (!globalThis[INSTALLED]) {
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = function codeapiHttpsPassthroughFetch(input, init) {
    const request = new Request(input, init);
    const protocol = new URL(request.url).protocol;
    if (protocol !== 'http:' && protocol !== 'https:') return nativeFetch(request);
    return fetchThroughEgress(request);
  };
  Object.defineProperty(globalThis, INSTALLED, { value: true });
}
