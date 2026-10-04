import axios from 'axios';
import type { Readable } from 'stream';
import type * as t from '../types';
import { internalServiceHeaders } from '../internal-service-auth';
import logger from '../logger';

/** The file server stored fewer (or more) bytes than the api forwarded. */
export class UploadIncompleteError extends Error {
  constructor(
    readonly forwardedBytes: number,
    readonly storedBytes: number | undefined,
  ) {
    super('Upload incomplete');
    this.name = 'UploadIncompleteError';
  }
}

/**
 * Sends one multipart file to the file server and proves the stored object
 * holds every byte the api read from the upload.
 *
 * The file is staged in memory (busboy already caps it at the plan's file
 * size) and sent as one Buffer with an explicit Content-Length. Streaming the
 * busboy file straight into axios.put lost the tail under Bun: the chunked
 * request was ended cleanly while chunks written under backpressure were
 * dropped, and the file server stored a well-formed but short body.
 *
 * The file server reports the stored object's size. A different size (or
 * none) means bytes were lost on the way, so the object is deleted and the
 * upload fails instead of handing the caller a reference to a truncated file.
 */
export async function forwardUploadToFileServer({
  file,
  url,
  headers,
  maxBytes,
  signal,
}: {
  file: Readable;
  url: string;
  headers: Record<string, string>;
  maxBytes: number;
  signal: AbortSignal;
}): Promise<t.UploadResult> {
  const chunks: Buffer[] = [];
  for await (const chunk of file) chunks.push(chunk as Buffer);
  /* busboy ends a file early at the plan's size limit; the route aborts the
   * signal for that case and reports the limit, so nothing partial is sent. */
  signal.throwIfAborted();
  const body = Buffer.concat(chunks);
  /* Only the joined copy stays alive while the request is in flight. */
  chunks.length = 0;
  const forwardedBytes = body.length;
  const response = await axios.put<t.StoredUploadResult>(url, body, {
    headers: internalServiceHeaders({ ...headers, 'Content-Length': String(forwardedBytes) }),
    maxBodyLength: maxBytes,
    maxContentLength: maxBytes,
    signal,
  });
  const storedBytes = response.data.size;
  if (storedBytes !== forwardedBytes) {
    logger.error('Stored upload is incomplete', {
      fileId: response.data.fileId,
      forwardedBytes,
      storedBytes,
    });
    await axios
      .delete(url, { headers: internalServiceHeaders() })
      .catch((error: unknown) => {
        logger.error('Failed to delete incomplete upload', {
          fileId: response.data.fileId,
          status: axios.isAxiosError(error) ? error.response?.status : undefined,
        });
      });
    throw new UploadIncompleteError(forwardedBytes, storedBytes);
  }
  return { filename: response.data.filename, fileId: response.data.fileId };
}

/**
 * Runs one upload's forwards one at a time, in the order they are queued.
 *
 * A file is read only when its turn comes, and busboy does not reach the next
 * part until the current file stream is drained. So the request body is held
 * back while a file is in flight, and the api holds at most one staged file
 * per upload request, whatever the number of files in it. A failed forward
 * does not stop the ones after it.
 */
export function createForwardQueue(): <T>(forward: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(forward: () => Promise<T>): Promise<T> => {
    const run = tail.then(forward);
    tail = run.catch(() => undefined);
    return run;
  };
}
