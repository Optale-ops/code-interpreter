import axios from 'axios';
import { Transform } from 'stream';
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
 * Streams one multipart file to the file server and proves the stored object
 * holds every byte the api read from the upload. The file server reports the
 * stored object's size; a different size (or none) means bytes were lost on
 * the way, so the object is deleted and the upload fails instead of handing
 * the caller a reference to a truncated file.
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
  let forwardedBytes = 0;
  const counter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      forwardedBytes += chunk.length;
      callback(null, chunk);
    },
  });
  file.once('error', (error) => counter.destroy(error));
  file.pipe(counter);
  const response = await axios.put<t.StoredUploadResult>(url, counter, {
    headers: internalServiceHeaders(headers),
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
