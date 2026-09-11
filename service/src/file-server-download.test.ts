import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import express from 'express';
import type { AddressInfo } from 'net';
import { Readable } from 'stream';
import { streamObjectToResponse } from './file-server-download';

/**
 * Real-HTTP tests for the object-download streaming seam: Content-Length is
 * declared, and a source failure must surface as an aborted transfer —
 * never a clean short 200 (the defect that defeated downloader retries).
 */

type Scenario = {
  size: number | undefined;
  body: Buffer;
  /** When set, the source destroys itself after this many bytes. */
  failAfterBytes?: number;
};

let scenario: Scenario;

function sourceStream(s: Scenario): Readable {
  if (s.failAfterBytes === undefined) return Readable.from([s.body]);
  let sent = 0;
  const failAfter = s.failAfterBytes;
  return new Readable({
    read() {
      if (sent >= failAfter) {
        process.nextTick(() => this.destroy(new Error('minio stream failure')));
        return;
      }
      const n = Math.min(16_384, failAfter - sent);
      this.push(s.body.subarray(sent, sent + n));
      sent += n;
    },
  });
}

const app = express();
app.get('/object', async (_req, res) => {
  res.setHeader('Content-Disposition', "attachment; filename*=UTF-8''artifact.bin");
  try {
    await streamObjectToResponse(sourceStream(scenario), res, scenario.size);
  } catch {
    /* Mirrors the file-server handler: pipeline already destroyed the
     * socket; nothing more can be written. */
  }
});

let server: ReturnType<typeof app.listen>;
let baseUrl: string;

beforeAll(() => {
  server = app.listen(0);
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => {
  server.close();
});

describe('streamObjectToResponse', () => {
  test('serves the full body with its declared Content-Length and metadata headers', async () => {
    const body = Buffer.alloc(200_000, 0x61);
    scenario = { size: body.length, body };

    const res = await fetch(`${baseUrl}/object`);

    expect(res.status).toBe(200);
    expect(res.headers.get('content-length')).toBe(String(body.length));
    expect(res.headers.get('content-disposition')).toBe("attachment; filename*=UTF-8''artifact.bin");
    const received = Buffer.from(await res.arrayBuffer());
    expect(received.equals(body)).toBe(true);
  });

  test('serves a zero-byte object cleanly', async () => {
    scenario = { size: 0, body: Buffer.alloc(0) };

    const res = await fetch(`${baseUrl}/object`);

    expect(res.status).toBe(200);
    expect(res.headers.get('content-length')).toBe('0');
    expect((await res.arrayBuffer()).byteLength).toBe(0);
  });

  test('a mid-stream source failure aborts the transfer instead of completing a short body', async () => {
    const body = Buffer.alloc(200_000, 0x62);
    scenario = { size: body.length, body, failAfterBytes: 50_000 };

    /* The client must see an incomplete transfer — never a clean 200 with
     * 50_000 of 200_000 bytes. */
    await expect(fetch(`${baseUrl}/object`).then(r => r.arrayBuffer())).rejects.toThrow();
  });

  test('a source failure before the first byte sends no successful response, and the listener survives', async () => {
    const body = Buffer.alloc(200_000, 0x63);
    scenario = { size: body.length, body, failAfterBytes: 0 };

    await expect(fetch(`${baseUrl}/object`).then(r => r.arrayBuffer())).rejects.toThrow();

    /* The listener survives an aborted transfer — the retry's target. */
    const healthy = Buffer.from('ok!!');
    scenario = { size: healthy.length, body: healthy };
    const res = await fetch(`${baseUrl}/object`);
    expect(res.status).toBe(200);
    expect(Buffer.from(await res.arrayBuffer()).equals(healthy)).toBe(true);
  });
});
