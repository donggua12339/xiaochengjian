import { EventEmitter } from 'events';
import { Readable } from 'stream';
import { BangcleAdapter } from './bangcle.adapter';
import * as yauzl from 'yauzl';

jest.mock('yauzl');

type Zip = EventEmitter & {
  readEntry: () => void;
  openReadStream: (e: unknown, cb: (err: Error | null, s?: Readable) => void) => void;
  close: () => void;
};

function makeZip(
  entries: { fileName: string }[],
  opts: { readError?: boolean; zipError?: boolean } = {},
): Zip {
  const zip = new EventEmitter() as Zip;
  let idx = 0;
  zip.close = () => {};
  zip.readEntry = () => {
    if (opts.zipError) {
      process.nextTick(() => zip.emit('error', new Error('zip stream boom')));
      return;
    }
    if (idx < entries.length) {
      const e = entries[idx++];
      process.nextTick(() => zip.emit('entry', e));
    } else {
      process.nextTick(() => zip.emit('end'));
    }
  };
  zip.openReadStream = (_e: unknown, cb: (err: Error | null, s?: Readable) => void) => {
    if (opts.readError) {
      process.nextTick(() => cb(new Error('read stream boom')));
      return;
    }
    const s = new Readable();
    s.push('so-content');
    s.push(null);
    process.nextTick(() => cb(null, s));
  };
  return zip;
}

describe('BangcleAdapter.extractFileFromZip(yauzl mocked)', () => {
  let adapter: BangcleAdapter;

  beforeEach(() => {
    jest.clearAllMocks();
    adapter = new BangcleAdapter();
  });

  const call = (buf: Buffer, entry: string) =>
    (
      adapter as unknown as { extractFileFromZip: (b: Buffer, e: string) => Promise<Buffer | null> }
    ).extractFileFromZip(buf, entry);

  it('找到 entry 应返回内容', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'lib/x.so' }, { fileName: 'other.txt' }])),
    );
    await expect(call(Buffer.from('apk'), 'lib/x.so')).resolves.toEqual(Buffer.from('so-content'));
  });

  it('openReadStream 失败应 reject', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'lib/x.so' }], { readError: true })),
    );
    await expect(call(Buffer.from('apk'), 'lib/x.so')).rejects.toThrow('read stream boom');
  });

  it('yauzl.fromBuffer 打开失败应 reject', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: Error) => void) => cb(new Error('fromBuffer boom')),
    );
    await expect(call(Buffer.from('apk'), 'lib/x.so')).rejects.toThrow('fromBuffer boom');
  });

  it('zipfile 流错误应 reject', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'lib/x.so' }], { zipError: true })),
    );
    await expect(call(Buffer.from('apk'), 'lib/x.so')).rejects.toThrow();
  });

  it('entry 不存在应 reject entry not found', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'other.txt' }])),
    );
    await expect(call(Buffer.from('apk'), 'lib/not-exist.so')).rejects.toThrow('entry not found');
  });
});
