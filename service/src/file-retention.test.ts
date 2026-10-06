import { describe, expect, test } from 'bun:test';
import { Readable } from 'node:stream';
import type { Client } from 'minio';
import { FileRetentionSweep, type RetentionSummary } from './file-retention';

const now = Date.parse('2026-10-06T12:00:00Z');
const hour = 3600_000;
type ObjectEntry = { name: string; size: number; lastModified: Date };

function fixture(enabled = true, workPerTick = 1000) {
  const objects = new Map<string, ObjectEntry>();
  const live = new Set<string>();
  const deleted: string[][] = [];
  let visits = 0;
  let listing = 0;
  let onList: ((prefix: string, count: number) => void) | undefined;
  const put = (name: string, age = 73, size = 10): void => {
    objects.set(name, { name, size, lastModified: new Date(now - age * hour) });
  };
  const store = {
    listObjectsV2(_bucket: string, prefix: string, recursive: boolean) {
      onList?.(prefix, ++listing);
      const snapshot = [...objects.values()].filter(object => object.name.startsWith(prefix));
      const entries = recursive ? snapshot : [...new Set(snapshot.map(object => object.name.split('/')[0] + '/'))]
        .sort().map(prefix => ({ prefix }));
      return Readable.from((async function* () {
        for (const entry of entries) { visits++; yield entry; }
      })());
    },
    async removeObjects(_bucket: string, names: string[]) {
      deleted.push([...names]);
      for (const name of names) objects.delete(name);
      return [];
    },
  } as unknown as Pick<Client, 'listObjectsV2' | 'removeObjects'>;
  const sweep = new FileRetentionSweep(store, {
    exists: async key => Number(live.has(key.slice('session:'.length))),
  }, 'files', {
    enabled, retentionHours: 48, sessionTtlSeconds: 86400, workPerTick,
    excludedPrefixes: ['rtsx-checkpoints/', 'runner/', 'custom-build/'],
  }, () => now);
  return { put, objects, live, deleted, sweep, visits: () => visits,
    onList: (callback: typeof onList) => { onList = callback; } };
}

async function finish(sweep: FileRetentionSweep): Promise<RetentionSummary> {
  for (let tick = 0; tick < 10000; tick++) {
    const summary = await sweep.tick();
    if (summary.complete) return summary;
  }
  throw new Error('Sweep did not finish');
}

describe('session file retention', () => {
  test('deletes old idle files in bounded pages and is idempotent', async () => {
    const f = fixture();
    for (let i = 0; i < 205; i++) f.put(`old/${i}.txt`);
    const summary = await finish(f.sweep);
    expect(f.objects.size).toBe(0);
    expect(f.deleted.map(page => page.length)).toEqual([100, 100, 5]);
    expect(summary.deleted).toEqual({ prefixes: 1, bytes: 2050 });
    expect((await finish(f.sweep)).eligible).toEqual({ prefixes: 0, bytes: 0 });
  });

  test('keeps the whole prefix for recent objects, live sessions and cross-session storage', async () => {
    const f = fixture();
    f.put('recent/old.txt');
    f.put('recent/new.txt', 1);
    f.put('boundary/exact.txt', 72);
    f.put('live/a.txt');
    f.live.add('live');
    f.put('rtsx-checkpoints/rt_id/1.tar.gz', 100);
    f.put('runner/runner-build.zip', 100);
    f.put('custom-build/artifact.zip', 100);
    const summary = await finish(f.sweep);
    expect(f.deleted).toEqual([]);
    expect(summary.keptAge).toEqual({ prefixes: 2, bytes: 30 });
    expect(summary.keptLive).toEqual({ prefixes: 1, bytes: 10 });
    expect(summary.keptExclusion).toEqual({ prefixes: 3, bytes: 30 });
  });

  test('dry-run reports candidate prefixes and bytes without deleting', async () => {
    const f = fixture(false);
    f.put('old/a.txt', 73, 20);
    f.put('old/b.txt', 100, 30);
    f.put('recent/a.txt', 5, 7);
    f.put('live/a.txt', 90, 8);
    f.live.add('live');
    f.put('rtsx-checkpoints/rt/1.tar.gz', 100, 9);
    const summary = await finish(f.sweep);
    expect(summary.dryRun).toBe(true);
    expect(summary.eligible).toEqual({ prefixes: 1, bytes: 50 });
    expect(summary.deleted).toEqual({ prefixes: 0, bytes: 0 });
    expect(summary.keptAge).toEqual({ prefixes: 1, bytes: 7 });
    expect(summary.keptLive).toEqual({ prefixes: 1, bytes: 8 });
    expect(summary.keptExclusion).toEqual({ prefixes: 1, bytes: 9 });
    expect(f.deleted).toEqual([]);
    expect(f.objects.size).toBe(5);
  });

  test('rechecks the whole prefix and aborts when a new write arrived', async () => {
    const f = fixture();
    f.put('old/a.txt');
    f.onList((prefix, count) => {
      if (prefix === 'old/' && count === 3) f.put('old/b.txt', 0);
    });
    expect((await finish(f.sweep)).keptAge).toEqual({ prefixes: 1, bytes: 20 });
    expect(f.deleted).toEqual([]);
  });

  test('detects a same-key overwrite during recheck', async () => {
    const f = fixture();
    f.put('old/a.txt');
    f.onList((prefix, count) => {
      if (prefix === 'old/' && count === 3) f.put('old/a.txt', 0);
    });
    await finish(f.sweep);
    expect(f.deleted).toEqual([]);
  });

  test('resumes a large prefix across bounded ticks without starving later prefixes', async () => {
    const f = fixture(true, 2);
    for (let i = 0; i < 20; i++) f.put(`a/${i}.txt`);
    f.put('z/last.txt');
    expect((await f.sweep.tick()).complete).toBe(false);
    expect(f.deleted).toEqual([]);
    await finish(f.sweep);
    expect(f.objects.size).toBe(0);
  });

  test('a newly live mapping during recheck preserves the prefix', async () => {
    const f = fixture();
    f.put('old/a.txt');
    f.onList((_prefix, count) => { if (count === 3) f.live.add('old'); });
    expect((await finish(f.sweep)).keptLive).toEqual({ prefixes: 1, bytes: 10 });
    expect(f.deleted).toEqual([]);
  });

  test('a fresh object in the deletion listing is never sent for deletion', async () => {
    const f = fixture();
    f.put('old/a.txt');
    f.onList((prefix, count) => {
      if (prefix === 'old/' && count === 4) f.put('old/new.txt', 0);
    });
    await finish(f.sweep);
    expect(f.deleted).toEqual([]);
    expect(f.objects.has('old/new.txt')).toBe(true);
    expect(f.objects.has('old/a.txt')).toBe(true);
  });

  test('tolerates another replica removing a prefix after it was listed', async () => {
    const f = fixture(true, 1);
    f.put('old/a.txt');
    // Start one pass, then remove its object before its eventual delete call.
    await f.sweep.tick();
    f.objects.delete('old/a.txt');
    await finish(f.sweep);
    expect(f.objects.size).toBe(0);
  });
});
