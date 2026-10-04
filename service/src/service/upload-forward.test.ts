import { afterEach, describe, expect, test } from 'bun:test';
import http from 'http';
import type { AddressInfo } from 'net';
import { Readable } from 'stream';
import { UploadIncompleteError, forwardUploadToFileServer } from './upload-forward';

/** A file server stand-in that reads the PUT body and reports a stored size. */
function fileServer(storedSize: (received: number) => number) {
  const deletes: string[] = [];
  const server = http.createServer((req, res) => {
    if (req.method === 'DELETE') {
      deletes.push(req.url ?? '');
      res.end('{}');
      return;
    }
    let received = 0;
    req.on('data', (chunk: Buffer) => (received += chunk.length));
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ filename: 'cli.tgz', fileId: 'f1', size: storedSize(received) }));
    });
  });
  return new Promise<{ url: string; deletes: string[]; close: () => void }>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}/sessions/s1/objects/f1`, deletes, close: () => server.close() });
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
