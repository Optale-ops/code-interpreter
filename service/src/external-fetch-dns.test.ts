import { afterEach, describe, expect, test } from 'bun:test';
import { Resolver } from 'node:dns/promises';
import dgram from 'node:dgram';
import type { RemoteInfo } from 'node:dgram';
import { resolveExternalFetchAddresses } from './external-fetch';
import { ExternalFetchError } from './external-fetch-errors';

type DnsRecord = { a?: string[]; cname?: string };

function readDnsName(
  packet: Buffer,
  offset: number,
): { name: string; end: number } {
  const labels: string[] = [];
  let cursor = offset;
  for (;;) {
    const length = packet[cursor];
    if (length === 0) return { name: labels.join('.'), end: cursor + 1 };
    labels.push(
      packet.subarray(cursor + 1, cursor + 1 + length).toString('ascii'),
    );
    cursor += length + 1;
  }
}

function encodeDnsName(name: string): Buffer {
  return Buffer.concat([
    ...name
      .split('.')
      .map(label =>
        Buffer.concat([
          Buffer.from([label.length]),
          Buffer.from(label, 'ascii'),
        ]),
      ),
    Buffer.from([0]),
  ]);
}

async function startDnsAuthority(records: Record<string, DnsRecord>): Promise<{
  resolver: Resolver;
  close: () => Promise<void>;
}> {
  const socket = dgram.createSocket('udp4');
  socket.on('message', (packet: Buffer, remote: RemoteInfo) => {
    const question = readDnsName(packet, 12);
    const type = packet.readUInt16BE(question.end);
    const questionEnd = question.end + 4;
    const record = records[question.name];
    let answerType = type;
    let answerData: Buffer[] = [];
    if (type === 1 && record?.a?.length) {
      answerData = record.a.map(address =>
        Buffer.from(address.split('.').map(part => Number(part))),
      );
    } else if (type === 5 && record?.cname) {
      answerData = [encodeDnsName(record.cname)];
      answerType = 5;
    }

    const header = Buffer.alloc(12);
    packet.copy(header, 0, 0, 2);
    header.writeUInt16BE(0x8180, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answerData.length, 6);
    const answers = answerData.map(rdata =>
      Buffer.concat([
        Buffer.from([0xc0, 0x0c]),
        Buffer.from([
          answerType >> 8,
          answerType & 0xff,
          0,
          1,
          0,
          0,
          0,
          1,
          rdata.length >> 8,
          rdata.length & 0xff,
        ]),
        rdata,
      ]),
    );
    socket.send(
      Buffer.concat([header, packet.subarray(12, questionEnd), ...answers]),
      remote.port,
      remote.address,
    );
  });
  const listening = Promise.withResolvers<void>();
  socket.bind(0, '127.0.0.1', listening.resolve);
  await listening.promise;
  const address = socket.address();
  const resolver = new Resolver();
  resolver.setServers([`127.0.0.1:${address.port}`]);
  return {
    resolver,
    close: () => {
      const closed = Promise.withResolvers<void>();
      socket.close(closed.resolve);
      return closed.promise;
    },
  };
}

const authorities: Array<{ close: () => Promise<void> }> = [];
afterEach(async () => {
  await Promise.all(authorities.splice(0).map(authority => authority.close()));
});

function expectCode(
  promise: Promise<unknown>,
  code: ExternalFetchError['code'],
): Promise<void> {
  return promise.then(
    () => {
      throw new Error('expected external fetch error');
    },
    error => {
      expect(error).toBeInstanceOf(ExternalFetchError);
      expect((error as ExternalFetchError).code).toBe(code);
    },
  );
}

describe('real external-fetch DNS authority', () => {
  test('resolves and validates the complete A answer set', async () => {
    const authority = await startDnsAuthority({
      'allowed.test': { a: ['93.184.216.34'] },
    });
    authorities.push(authority);

    await expect(
      resolveExternalFetchAddresses('allowed.test', authority.resolver),
    ).resolves.toEqual([{ address: '93.184.216.34', family: 4 }]);
  });

  test('fails closed when an allowed name rebinds to a private address', async () => {
    const records: Record<string, DnsRecord> = {
      'allowed.test': { a: ['93.184.216.34'] },
    };
    const authority = await startDnsAuthority(records);
    authorities.push(authority);

    await expect(
      resolveExternalFetchAddresses('allowed.test', authority.resolver),
    ).resolves.toHaveLength(1);
    records['allowed.test'] = { a: ['127.0.0.1'] };
    await Bun.sleep(1_100);
    await expectCode(
      resolveExternalFetchAddresses('allowed.test', authority.resolver),
      'ADDRESS_NOT_GLOBAL',
    );
  });

  test('rejects a real mixed global and private A answer set', async () => {
    const authority = await startDnsAuthority({
      'mixed.test': { a: ['93.184.216.34', '127.0.0.1'] },
    });
    authorities.push(authority);

    await expectCode(
      resolveExternalFetchAddresses('mixed.test', authority.resolver),
      'ADDRESS_NOT_GLOBAL',
    );
  });

  test('follows a bounded CNAME chain without changing URL authority', async () => {
    const authority = await startDnsAuthority({
      'allowed.test': { cname: 'edge.test' },
      'edge.test': { a: ['93.184.216.34'] },
    });
    authorities.push(authority);

    await expect(
      resolveExternalFetchAddresses('allowed.test', authority.resolver),
    ).resolves.toEqual([{ address: '93.184.216.34', family: 4 }]);
  });

  test('rejects a CNAME chain deeper than eight hops', async () => {
    const records: Record<string, DnsRecord> = {};
    for (let index = 0; index < 9; index += 1) {
      records[`hop-${index}.test`] = { cname: `hop-${index + 1}.test` };
    }
    records['hop-9.test'] = { a: ['93.184.216.34'] };
    const authority = await startDnsAuthority(records);
    authorities.push(authority);

    await expectCode(
      resolveExternalFetchAddresses('hop-0.test', authority.resolver),
      'FETCH_FAILED',
    );
  });
});
