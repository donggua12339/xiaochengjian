import { EventEmitter } from 'events';
import { Readable } from 'stream';
import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { WatermarkService } from './watermark.service';
import { CryptoService } from '../crypto/crypto.service';
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
      process.nextTick(() => zip.emit('error', new Error('zip boom')));
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
    s.push('watermark-content');
    s.push(null);
    process.nextTick(() => cb(null, s));
  };
  return zip;
}

describe('WatermarkService.extractWatermarkFileFromZip(yauzl mocked)', () => {
  let service: WatermarkService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const moduleRef = await Test.createTestingModule({
      providers: [
        WatermarkService,
        { provide: CryptoService, useValue: { aesEncrypt: jest.fn(), aesDecrypt: jest.fn() } },
        { provide: ConfigService, useValue: { get: () => 'a'.repeat(64) } },
      ],
    }).compile();
    service = moduleRef.get(WatermarkService);
  });

  const call = (buf: Buffer) =>
    (
      service as unknown as { extractWatermarkFileFromZip: (b: Buffer) => Promise<string | null> }
    ).extractWatermarkFileFromZip(buf);

  it('找到水印 entry 应返回内容', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'META-INF/xcj-watermark.enc.txt' }, { fileName: 'other' }])),
    );
    await expect(call(Buffer.from('apk'))).resolves.toBe('watermark-content');
  });

  it('openReadStream 失败应 reject', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'META-INF/xcj-watermark.enc.txt' }], { readError: true })),
    );
    await expect(call(Buffer.from('apk'))).rejects.toThrow('read stream boom');
  });

  it('zipfile 流错误应 reject APK_PARSE_FAILED', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'META-INF/xcj-watermark.enc.txt' }], { zipError: true })),
    );
    await expect(call(Buffer.from('apk'))).rejects.toThrow('APK_PARSE_FAILED');
  });

  it('yauzl.fromBuffer 打开失败应 reject APK_PARSE_FAILED', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: Error) => void) => cb(new Error('open boom')),
    );
    await expect(call(Buffer.from('apk'))).rejects.toThrow('APK_PARSE_FAILED');
  });

  it('无水印 entry 应返回 null', async () => {
    (yauzl.fromBuffer as unknown as jest.Mock).mockImplementation(
      (_b: Buffer, _o: unknown, cb: (e: null, z: Zip) => void) =>
        cb(null, makeZip([{ fileName: 'classes.dex' }])),
    );
    await expect(call(Buffer.from('apk'))).resolves.toBeNull();
  });
});
