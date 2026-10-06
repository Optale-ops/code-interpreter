import type { BucketItem, Client } from 'minio';

export interface RetentionOptions {
  retentionHours: number;
  sessionTtlSeconds: number;
  enabled: boolean;
  workPerTick: number;
  excludedPrefixes: string[];
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
      add(this.summary.eligible, checkedBytes);
      if (!this.options.enabled) continue;

      let page: BucketItem[] = [];
      let deletedBytes = 0;
      let deletedObjects = 0;
      const remove = async (): Promise<void> => {
        // Never issue a prefix deletion. Only exact, old keys from this page.
        // This client has no conditional delete. An overwrite after this
        // listing can still race the delete; fixing that requires versioned
        // deletes or coordination with every writer, not another stat call.
        const errors = await this.store.removeObjects(this.bucket, page.map(object => object.name));
        if (errors.length) throw new Error(`File retention delete failed: ${JSON.stringify(errors)}`);
        deletedBytes += page.reduce((sum, object) => sum + object.size, 0);
        deletedObjects += page.length;
        page = [];
      };
      for await (const object of this.store.listObjectsV2(this.bucket, prefix, true)) {
        if ((object.lastModified?.getTime() ?? Infinity) >= cutoff ||
            await this.sessions.exists(`session:${sessionId}`)) {
          page = [];
          break;
        }
        page.push(object);
        if (page.length === DELETE_PAGE_SIZE) {
          await remove();
        }
        yield;
      }
      if (page.length && !await this.sessions.exists(`session:${sessionId}`)) await remove();
      if (deletedObjects) add(this.summary.deleted, deletedBytes);
    }
  }
}
