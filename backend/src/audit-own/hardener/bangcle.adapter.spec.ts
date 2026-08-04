import AdmZip from 'adm-zip';
import { BangcleAdapter } from './bangcle.adapter';

/**
 * BangcleAdapter 单元测试(ADR 0078 锁 C:仅完整性报告)
 *
 * 覆盖:
 *  - 生成报告:so 文件列表 + SHA-256 + 签名状态 + scanVersion
 *  - 无梆梆 so 时 soFiles 为空数组
 *  - applicationClassName 缺失时 entryClass=null
 *  - 报告不含反编译源码(锁 C)
 */
describe('BangcleAdapter', () => {
  let adapter: BangcleAdapter;

  beforeEach(() => {
    adapter = new BangcleAdapter();
  });

  it('应生成含梆梆 so 文件的完整性报告', async () => {
    // yauzl 从 apkBuffer 读真实 .so 内容算 hash;测试用假 buffer 解不开,
    // spy extractFileFromZip 返回确定内容,隔离 zip 读取、只验报告组装 + 哈希逻辑
    const soContent = Buffer.from('fake-so-binary-content');
    const extractSpy = jest
      .spyOn(
        adapter as unknown as { extractFileFromZip: (b: Buffer, e: string) => Promise<Buffer> },
        'extractFileFromZip',
      )
      .mockResolvedValue(soContent);
    const expectedSha = require('crypto').createHash('sha256').update(soContent).digest('hex');

    const report = await adapter.generateReport({
      apkEntries: [
        'lib/arm64-v8a/libSecShell.so',
        'lib/arm64-v8a/libDexHelper.so',
        'classes.dex',
        'AndroidManifest.xml',
      ],
      apkBuffer: Buffer.from('fake-apk-content'),
      applicationClassName: 'com.bangcle.test.MainApplication',
      signatures: { v1: true, v2: true, v3: false },
    });

    expect(report.hardener).toBe('bangcle');
    expect(report.soFiles).toHaveLength(2);
    expect(report.soFiles[0].name).toBe('libSecShell.so');
    expect(report.soFiles[0].sha256).toBe(expectedSha);
    expect(report.soFiles[0].size).toBe(soContent.length);
    expect(report.soFiles[0].loadPath).toBe('lib/arm64-v8a/');
    expect(report.entryClass).toBe('com.bangcle.test.MainApplication');
    expect(report.signatures).toEqual({ v1: true, v2: true, v3: false });
    expect(report.scanVersion).toBe('1.0.0');
    expect(report.scanTime).toBeTruthy();

    extractSpy.mockRestore();
  });

  it('无梆梆 so 时 soFiles 应为空数组', async () => {
    const report = await adapter.generateReport({
      apkEntries: ['classes.dex', 'AndroidManifest.xml'],
      apkBuffer: Buffer.from('apk'),
      signatures: { v1: true, v2: true, v3: true },
    });
    expect(report.soFiles).toEqual([]);
    expect(report.entryClass).toBeNull();
  });

  it('applicationClassName 缺失时 entryClass=null', async () => {
    const report = await adapter.generateReport({
      apkEntries: ['lib/arm64-v8a/libSecShell.so'],
      apkBuffer: Buffer.from('apk'),
      signatures: { v1: true, v2: true, v3: true },
    });
    expect(report.entryClass).toBeNull();
  });

  it('报告不应含反编译源码(锁 C:仅完整性数据)', async () => {
    const report = await adapter.generateReport({
      apkEntries: ['lib/arm64-v8a/libSecShell.so'],
      apkBuffer: Buffer.from('apk'),
      signatures: { v1: true, v2: true, v3: true },
    });
    // 报告字段限定:hardener/soFiles/entryClass/signatures/suspiciousCalls/scanVersion/scanTime
    const allowedKeys = [
      'hardener',
      'soFiles',
      'entryClass',
      'signatures',
      'suspiciousCalls',
      'scanVersion',
      'scanTime',
    ].sort();
    expect(Object.keys(report).sort()).toEqual(allowedKeys);
    // soFiles 字段限定
    expect(Object.keys(report.soFiles[0] ?? {}).sort()).toEqual(
      ['name', 'sha256', 'size', 'loadPath'].sort(),
    );
  });

  it('suspiciousCalls 应为数组(MVP 返回空)', async () => {
    const report = await adapter.generateReport({
      apkEntries: [],
      apkBuffer: Buffer.from('apk'),
      signatures: { v1: true, v2: true, v3: true },
    });
    expect(Array.isArray(report.suspiciousCalls)).toBe(true);
  });

  describe('真实 zip(不 mock extractFileFromZip)', () => {
    function buildZip(soContent: string, manifestAscii: string): Buffer {
      const zip = new AdmZip();
      zip.addFile('lib/arm64-v8a/libSecShell.so', Buffer.from(soContent));
      zip.addFile('AndroidManifest.xml', Buffer.from(manifestAscii, 'latin1'));
      return zip.toBuffer();
    }

    it('extractFileFromZip 应从真实 zip 提取 so 并算真实 hash', async () => {
      const apkBuffer = buildZip('real-so-bytes', 'manifest');
      const report = await adapter.generateReport({
        apkEntries: ['lib/arm64-v8a/libSecShell.so', 'AndroidManifest.xml'],
        apkBuffer,
        signatures: { v1: true, v2: true, v3: true },
      });
      expect(report.soFiles).toHaveLength(1);
      expect(report.soFiles[0].sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(report.soFiles[0].sha256).not.toBe('unknown');
      expect(report.soFiles[0].size).toBe(Buffer.from('real-so-bytes').length);
    });

    it('scanSuspiciousManifest 应检出高风险权限', async () => {
      const apkBuffer = buildZip(
        'so',
        'package com.x  android.permission.CAMERA  android.permission.READ_SMS',
      );
      const report = await adapter.generateReport({
        apkEntries: ['AndroidManifest.xml'],
        apkBuffer,
        signatures: { v1: true, v2: true, v3: true },
      });
      const symbols = report.suspiciousCalls.map((s) => s.symbol);
      expect(symbols).toContain('android.permission.CAMERA');
      expect(symbols).toContain('android.permission.READ_SMS');
    });

    it('无高风险权限时 suspiciousCalls 为空', async () => {
      const apkBuffer = buildZip('so', 'package com.x  android.permission.INTERNET');
      const report = await adapter.generateReport({
        apkEntries: ['AndroidManifest.xml'],
        apkBuffer,
        signatures: { v1: true, v2: true, v3: true },
      });
      expect(report.suspiciousCalls).toEqual([]);
    });
  });
});
