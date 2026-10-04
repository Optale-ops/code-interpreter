import { afterEach, describe, expect, test } from 'bun:test';
import busboy from 'busboy';
import http from 'http';
import type { AddressInfo } from 'net';
import { Readable } from 'stream';
import { setImmediate as yieldTurn } from 'timers/promises';
import { UploadIncompleteError, createForwardQueue, forwardUploadToFileServer } from './upload-forward';

/** A file server stand-in that reads the PUT body and reports a stored size. */
function fileServer(storedSize: (received: number) => number) {
  const deletes: string[] = [];
  const framing: Array<{ contentLength?: string; transferEncoding?: string }> = [];
  const server = http.createServer((req, res) => {
    if (req.method === 'DELETE') {
      deletes.push(req.url ?? '');
      res.end('{}');
      return;
    }
    framing.push({
      contentLength: req.headers['content-length'],
      transferEncoding: req.headers['transfer-encoding'],
    });
    let received = 0;
    req.on('data', (chunk: Buffer) => (received += chunk.length));
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ filename: 'cli.tgz', fileId: 'f1', size: storedSize(received) }));
    });
  });
  return new Promise<{ url: string; deletes: string[]; framing: typeof framing; close: () => void }>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}/sessions/s1/objects/f1`, deletes, framing, close: () => server.close() });
    });
  });
}

function upload(bytes: number): Readable {
  const body = Buffer.alloc(bytes, 7);
  return Readable.from((function* () {
    for (let offset = 0; offset < body.length; offset += 65536) yield body.subarray(offset, offset + 65536);
  })());
}

let close: (() => void) | undefined;
afterEach(() => close?.());

describe('forwardUploadToFileServer', () => {
  test('returns the stored file when the file server holds every forwarded byte', async () => {
    const server = await fileServer((received) => received);
    close = server.close;
    const result = await forwardUploadToFileServer({
      file: upload(262600),
      url: server.url,
      headers: { 'Content-Type': 'application/gzip', 'X-Original-Filename': 'cli.tgz' },
      maxBytes: 1 << 20,
      signal: new AbortController().signal,
    });
    expect(result).toEqual({ filename: 'cli.tgz', fileId: 'f1' });
    expect(server.deletes).toEqual([]);
    /* The whole file goes out as one fixed-length body, never chunked. */
    expect(server.framing).toEqual([{ contentLength: '262600', transferEncoding: undefined }]);
  });

  test('refuses and deletes a stored object shorter than what was forwarded', async () => {
    const server = await fileServer(() => 225423);
    close = server.close;
    const forwarding = forwardUploadToFileServer({
      file: upload(262600),
      url: server.url,
      headers: { 'Content-Type': 'application/gzip', 'X-Original-Filename': 'cli.tgz' },
      maxBytes: 1 << 20,
      signal: new AbortController().signal,
    });
    await expect(forwarding).rejects.toBeInstanceOf(UploadIncompleteError);
    await forwarding.catch((error: UploadIncompleteError) => {
      expect(error.forwardedBytes).toBe(262600);
      expect(error.storedBytes).toBe(225423);
    });
    expect(server.deletes).toEqual(['/sessions/s1/objects/f1']);
  });

  test('refuses a file server answer that carries no stored size', async () => {
    const server = await fileServer(() => undefined as unknown as number);
    close = server.close;
    await expect(
      forwardUploadToFileServer({
        file: upload(1024),
        url: server.url,
        headers: { 'Content-Type': 'application/gzip', 'X-Original-Filename': 'cli.tgz' },
        maxBytes: 1 << 20,
        signal: new AbortController().signal,
      }),
    ).rejects.toBeInstanceOf(UploadIncompleteError);
  });
});

describe('createForwardQueue', () => {
  test('keeps one file in flight per multipart upload, however many files it carries', async () => {
    /* A file server that answers a few event-loop turns late and records how
     * many PUTs are open at once. */
    let open = 0;
    let maxOpen = 0;
    const fileServerStub = http.createServer((req, res) => {
      open += 1;
      maxOpen = Math.max(maxOpen, open);
      let received = 0;
      req.on('data', (chunk: Buffer) => (received += chunk.length));
      req.on('end', async () => {
        for (let turn = 0; turn < 5; turn++) await yieldTurn();
        open -= 1;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ filename: 'f', fileId: req.url, size: received }));
      });
    });
    /* The api side, wired as router.ts wires /upload/batch. */
    const api = http.createServer((req, res) => {
      const enqueueForward = createForwardQueue();
      const forwards: Promise<unknown>[] = [];
      const bb = busboy({ headers: req.headers });
      let n = 0;
      bb.on('file', (_field, file) => {
        const { port } = fileServerStub.address() as AddressInfo;
        const url = `http://127.0.0.1:${port}/sessions/s/objects/${n++}`;
        forwards.push(enqueueForward(() => forwardUploadToFileServer({
          file,
          url,
          headers: { 'Content-Type': 'application/octet-stream', 'X-Original-Filename': 'f' },
          maxBytes: 1 << 22,
          signal: new AbortController().signal,
        })));
      });
      bb.on('finish', async () => res.end(JSON.stringify((await Promise.allSettled(forwards)).map(r => r.status))));
      req.pipe(bb);
    });
    await new Promise<void>((resolve) => fileServerStub.listen(0, '127.0.0.1', resolve));
    await new Promise<void>((resolve) => api.listen(0, '127.0.0.1', resolve));
    close = () => {
      fileServerStub.close();
      api.close();
    };

    const form = new FormData();
    for (let i = 0; i < 12; i++) form.append('file', new Blob([Buffer.alloc(256 * 1024, i)]), `f${i}`);
    const { port } = api.address() as AddressInfo;
    const statuses = await (await fetch(`http://127.0.0.1:${port}/`, { method: 'POST', body: form })).json();

    expect(statuses).toEqual(Array(12).fill('fulfilled'));
    expect(maxOpen).toBe(1);
  });

  test('runs the forwards after a failed one', async () => {
    const enqueue = createForwardQueue();
    const failed = enqueue(() => Promise.reject(new Error('lost')));
    const next = enqueue(() => Promise.resolve('stored'));
    await expect(failed).rejects.toThrow();
    expect(await next).toBe('stored');
  });
});
