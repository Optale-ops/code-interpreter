import { pipeline } from 'stream/promises';
import type { Response } from 'express';
import type { Readable } from 'stream';

/**
 * Object-body streaming with recoverable completion semantics: declares
 * Content-Length up front when known, and on source failure rejects only
 * after pipeline has destroyed the socket — the client sees an aborted
 * transfer, never a clean short 200. Extracted from file-server.ts, whose
 * import-time side effects (Redis connect, server start) block direct tests.
 */
export async function streamObjectToResponse(
  dataStream: Readable,
  res: Response,
  size: number | undefined,
): Promise<void> {
  if (typeof size === 'number') {
    res.setHeader('Content-Length', size);
  }
  await pipeline(dataStream, res);
}
