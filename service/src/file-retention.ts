import type { Client } from 'minio';
import { createReadStream } from 'node:fs';
import { mkdtemp, open, rm, type FileHandle } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface RetentionOptions {
  retentionHours: number;
  sessionTtlSeconds: number;
  enabled: boolean;
  workPerTick: number;
  excludedPrefixes: string[];
  tempDirectory?: string;
}

type Count = { prefixes: number; bytes: number };
export type RetentionSummary = {
  dryRun: boolean;
  complete: boolean;
  eligible: Count;
  deleted: Count;
  keptAge: Count;
  keptLive: Count;
  keptExclusion: Count;
};

type Store = Pick<Client, 'listObjectsV2' | 'removeObjects'>;
type Sessions = { exists(key: string): Promise<number> };
const DELETE_PAGE_SIZE = 100;
const IN_MEMORY_OBJECTS = 10_000;

type Candidate = { name: string; size: number };

/** Only exact keys and sizes are spooled, never object bytes. Each sweep owns
 * a private temporary directory; generator finalization removes it. */
class CandidateSpool {
  private buffered: Candidate[] = [];
  private directory?: string;
  private file?: FileHandle;

  constructor(private root: string) {}

  async append(candidate: Candidate): Promise<void> {
    if (!this.directory && this.buffered.length === IN_MEMORY_OBJECTS) {
      this.directory = await mkdtemp(join(this.root, 'codeapi-file-retention-'));
      this.file = await open(join(this.directory, 'candidates.jsonl'), 'wx', 0o600);
      await this.flush();
    }
    this.buffered.push(candidate);
    if (this.file && this.buffered.length === DELETE_PAGE_SIZE) await this.flush();
  }

  private async flush(): Promise<void> {
    if (!this.buffered.length) return;
    await this.file!.appendFile(this.buffered.map(item => JSON.stringify(item) + '\n').join(''));
    this.buffered = [];
  }

  async *pages(): AsyncGenerator<Candidate[]> {
    if (!this.directory) {
      for (let offset = 0; offset < this.buffered.length; offset += DELETE_PAGE_SIZE) {
        yield this.buffered.slice(offset, offset + DELETE_PAGE_SIZE);
      }
      return;
    }
    await this.flush();
    await this.file!.close();
    this.file = undefined;
    let page: Candidate[] = [];
    let remainder = '';
    for await (const chunk of createReadStream(join(this.directory, 'candidates.jsonl'), { encoding: 'utf8' })) {
      const lines = (remainder + chunk).split('\n');
      remainder = lines.pop()!;
      for (const line of lines) {
        page.push(JSON.parse(line) as Candidate);
        if (page.length === DELETE_PAGE_SIZE) {
          yield page;
          page = [];
        }
      }
    }
    if (remainder) throw new Error('Incomplete file retention candidate spool');
    if (page.length) yield page;
  }

  async close(): Promise<void> {
    try {
      await this.file?.close();
    } finally {
      if (this.directory) await rm(this.directory, { recursive: true, force: true });
    }
  }
}

/** One bounded pass resumes across ticks. Listings and deletes use the existing
 * MinIO client, whose listing stream fetches pages lazily. No bucket-wide key
 * array is retained. A process restart simply starts a new, idempotent pass. */
export class FileRetentionSweep {
  private pass?: AsyncGenerator<void>;
  private summary!: RetentionSummary;

  constructor(
    private store: Store,
    private sessions: Sessions,
    private bucket: string,
    private options: RetentionOptions,
    private now: () => number = Date.now,
  ) {
    if (!Number.isFinite(options.retentionHours) || options.retentionHours < 0 ||
        !Number.isFinite(options.sessionTtlSeconds) || options.sessionTtlSeconds <= 0 ||
        !Number.isInteger(options.workPerTick) || options.workPerTick < 1) {
      throw new Error('Invalid file retention configuration');
    }
  }

  async tick(): Promise<RetentionSummary> {
    if (!this.pass) {
      const count = (): Count => ({ prefixes: 0, bytes: 0 });
      this.summary = {
        dryRun: !this.options.enabled, complete: false,
        eligible: count(), deleted: count(), keptAge: count(),
        keptLive: count(), keptExclusion: count(),
      };
      this.pass = this.scan();
    }
    try {
      for (let work = 0; work < this.options.workPerTick; work++) {
        if ((await this.pass.next()).done) {
          this.summary.complete = true;
          this.pass = undefined;
          break;
        }
      }
      return structuredClone(this.summary);
    } catch (error) {
      await this.pass?.return();
      this.pass = undefined;
      throw error;
    }
  }

  async close(): Promise<void> {
    await this.pass?.return();
    this.pass = undefined;
  }

  private async *scan(): AsyncGenerator<void> {
    // The fixed session authorization window is not an idle timer. Add at
    // least 24h, or the configured longer TTL, to the requested idle retention.
    const cutoff = this.now() - (this.options.retentionHours * 3600 +
      Math.max(86400, this.options.sessionTtlSeconds)) * 1000;
    const add = (count: Count, bytes: number): void => {
      count.prefixes++;
      count.bytes += bytes;
    };
    for await (const entry of this.store.listObjectsV2(this.bucket, '', false)) {
      yield;
      const prefix = entry.prefix as string | undefined;
      if (!prefix) {
        add(this.summary.keptExclusion, entry.size ?? 0);
        continue;
      }
      let bytes = 0;
      let newest = 0;
      let objects = 0;
      let excluded = this.options.excludedPrefixes.some(value =>
        prefix.startsWith(value) || value.startsWith(prefix));
      for await (const object of this.store.listObjectsV2(this.bucket, prefix, true)) {
        bytes += object.size;
        objects++;
        newest = Math.max(newest, object.lastModified?.getTime() ?? Infinity);
        // Nested objects are not session files (<sid>/<file-id><extension>).
        excluded ||= object.name.slice(prefix.length).includes('/');
        yield;
      }
      if (excluded) { add(this.summary.keptExclusion, bytes); continue; }
      const sessionId = prefix.slice(0, -1);
      if (await this.sessions.exists(`session:${sessionId}`)) {
        add(this.summary.keptLive, bytes); continue;
      }
      if (newest >= cutoff) { add(this.summary.keptAge, bytes); continue; }

      // Re-read the entire prefix before deleting any key. A newly written
      // object keeps the whole prefix, not just that object.
      let checkedBytes = 0;
      let checkedNewest = 0;
      let checkedObjects = 0;
      for await (const object of this.store.listObjectsV2(this.bucket, prefix, true)) {
        checkedBytes += object.size;
        checkedObjects++;
        checkedNewest = Math.max(checkedNewest, object.lastModified?.getTime() ?? Infinity);
        yield;
      }
      if (await this.sessions.exists(`session:${sessionId}`)) {
        add(this.summary.keptLive, checkedBytes); continue;
      }
      if (checkedNewest >= cutoff || checkedNewest !== newest ||
          checkedBytes !== bytes || checkedObjects !== objects) {
        add(this.summary.keptAge, checkedBytes); continue;
      }
      // Complete the final listing before deleting any page. Spill large
      // prefixes to this process's temp directory instead of exempting them.
      const candidates = new CandidateSpool(this.options.tempDirectory ?? tmpdir());
      try {
        let finalBytes = 0;
        let finalObjects = 0;
        let finalNewest = 0;
        for await (const object of this.store.listObjectsV2(this.bucket, prefix, true)) {
          finalBytes += object.size;
          finalObjects++;
          finalNewest = Math.max(finalNewest, object.lastModified?.getTime() ?? Infinity);
          await candidates.append({ name: object.name, size: object.size });
          yield;
        }
        if (await this.sessions.exists(`session:${sessionId}`)) {
          add(this.summary.keptLive, finalBytes); continue;
        }
        if (finalNewest >= cutoff || finalNewest !== checkedNewest ||
            finalBytes !== checkedBytes || finalObjects !== checkedObjects) {
          add(this.summary.keptAge, finalBytes); continue;
        }
        if (!finalObjects) continue;
        add(this.summary.eligible, finalBytes);
        if (!this.options.enabled) continue;

        let deletedBytes = 0;
        let deletedObjects = 0;
        for await (const page of candidates.pages()) {
          if (await this.sessions.exists(`session:${sessionId}`)) break;
          // This client has no conditional delete. An overwrite after listing
          // can still race deletion; closing that race requires versioned
          // deletes or coordination with every writer.
          const errors = await this.store.removeObjects(this.bucket, page.map(object => object.name));
          if (errors.length) throw new Error(`File retention delete failed: ${JSON.stringify(errors)}`);
          deletedBytes += page.reduce((sum, object) => sum + object.size, 0);
          deletedObjects += page.length;
          yield;
        }
        if (deletedObjects) add(this.summary.deleted, deletedBytes);
      } finally {
        await candidates.close();
      }
    }
  }
}
