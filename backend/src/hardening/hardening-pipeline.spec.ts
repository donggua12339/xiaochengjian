import { Test } from '@nestjs/testing';
import { HardeningService } from './hardening.service';
import { ApkAnalyzerService } from './apk-analyzer.service';
import { SoInjector } from '../packer/so-injector';
import { PreflightService } from './preflight.service';
import { RedisService } from '../redis/redis.service';
import { execFile } from 'child_process';
import * as fs from 'fs/promises';
import * as fsSync from 'fs';

jest.mock('child_process');
jest.mock('fs/promises');
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  statSync: jest.fn(),
  existsSync: jest.fn(),
}));

const mockExecFile = execFile as unknown as jest.Mock;
const statSyncMock = fsSync.statSync as unknown as jest.Mock;
const existsSyncMock = fsSync.existsSync as unknown as jest.Mock;

describe('HardeningService 加固管线', () => {
  let service: HardeningService;
  let redis: { get: jest.Mock; set: jest.Mock };
  let preflight: { runAll: jest.Mock };
  let soInjector: { pickRandomSoName: jest.Mock };

  const analysis = {
    packageName: 'com.test.app',
    apkSize: 10 * 1024 * 1024,
    dexFiles: ['classes.dex'],
    nativeAbis: ['arm64-v8a', 'armeabi-v7a'],
    originalApplicationName: null,
    isMultidex: false,
    alreadyHardened: false,
    detectedHardener: null,
    minSdkVersion: 21,
    targetSdkVersion: 33,
    recommendedConfig: {} as never,
    unavailableFeatures: [],
  };

  const params = {
    apkPath: '/tmp/in.apk',
    keystorePath: '/tmp/ks.jks',
    keystorePassword: 'kspass',
    keyAlias: 'key0',
    keyPassword: 'keypass',
    config: { productLine: 'xuanjia' as const, preset: 'standard' as const },
    analysis: analysis as never,
    developerId: 'dev-1',
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    redis = { get: jest.fn().mockResolvedValue(null), set: jest.fn().mockResolvedValue(undefined) };
    preflight = { runAll: jest.fn().mockResolvedValue(undefined) };
    soInjector = { pickRandomSoName: jest.fn().mockReturnValue('librand_abc.so') };

    // execFile 默认成功(execWithStderr 基于 promisify(execFile))
    mockExecFile.mockImplementation(
      (_cmd: string, _args: string[], _opts: unknown, cb: unknown) => {
        (cb as (e: null, stdout: string, stderr: string) => void)(null, '', '');
        return undefined;
      },
    );
    // statSync 让 findSdkDex/findSdkSo 找到产物
    statSyncMock.mockReturnValue({ size: 100 });
    // existsSync 让 findApksigner 找到 apksigner
    existsSyncMock.mockReturnValue(true);
    // fs/promises 默认成功
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.copyFile as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    (fs.rename as jest.Mock).mockResolvedValue(undefined);
    (fs.rm as jest.Mock).mockResolvedValue(undefined);
    (fs.unlink as jest.Mock).mockResolvedValue(undefined);
    // readFile:带 encoding 返回 manifest 文本,否则返回 buffer
    (fs.readFile as jest.Mock).mockImplementation((_p: string, enc?: string) =>
      Promise.resolve(
        enc ? '<manifest><application></application></manifest>' : Buffer.from('bin'),
      ),
    );

    const module = await Test.createTestingModule({
      providers: [
        HardeningService,
        { provide: ApkAnalyzerService, useValue: { analyze: jest.fn() } },
        { provide: SoInjector, useValue: soInjector },
        { provide: PreflightService, useValue: preflight },
        { provide: RedisService, useValue: redis },
      ],
    }).compile();

    service = module.get(HardeningService);
  });

  const flush = async () => {
    for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
  };

  it('全流程成功:status=completed, progress=100, 设 outputPath', async () => {
    const task = await service.harden(params);
    expect(task.status).toBe('hardening');
    await flush();
    expect(task.status).toBe('completed');
    expect(task.progress).toBe(100);
    expect(task.step).toBe('done');
    expect(task.outputPath).toBeTruthy();
    expect(task.detail).toContain('已启用');
    // 预检被调用
    expect(preflight.runAll).toHaveBeenCalled();
    // apktool / zipalign / apksigner 都执行过
    const cmds = mockExecFile.mock.calls.map((c) => c[0]);
    expect(cmds).toContain('apktool');
    expect(cmds).toContain('zipalign');
  });

  it('注入 DEX + SO(arm64/armv7)+ Manifest meta-data/provider/permission', async () => {
    const task = await service.harden(params);
    await flush();
    expect(task.status).toBe('completed');
    // so 随机名被 pickRandomSoName 生成
    expect(soInjector.pickRandomSoName).toHaveBeenCalled();
    // manifest 被写入(含 provider)
    const writeCalls = (fs.writeFile as jest.Mock).mock.calls;
    const manifestWrite = writeCalls.find((c) => String(c[0]).includes('AndroidManifest.xml'));
    expect(manifestWrite).toBeTruthy();
    expect(String(manifestWrite[1])).toContain('DefenderInitProvider');
    expect(String(manifestWrite[1])).toContain('xcj.defender.lib');
    expect(String(manifestWrite[1])).toContain('android.permission.INTERNET');
  });

  it('apktool 失败:status=failed, 记录 error, 清理 workDir', async () => {
    mockExecFile.mockImplementation((cmd: string, _args: string[], _opts: unknown, cb: unknown) => {
      if (cmd === 'apktool') {
        (cb as (e: Error) => void)(Object.assign(new Error('apktool crashed'), { stderr: 'oom' }));
      } else {
        (cb as (e: null, stdout: string, stderr: string) => void)(null, '', '');
      }
      return undefined;
    });
    const task = await service.harden(params);
    await flush();
    expect(task.status).toBe('failed');
    expect(task.step).toBe('error');
    expect(task.error).toBeTruthy();
    // 失败时清理 workDir
    expect(fs.rm).toHaveBeenCalled();
  });

  it('preflight 失败:status=failed', async () => {
    preflight.runAll.mockRejectedValue(new Error('keystore bad'));
    const task = await service.harden(params);
    await flush();
    expect(task.status).toBe('failed');
    expect(task.error).toContain('keystore bad');
  });

  it('apksigner 执行失败应 failed(RESIGN_FAILED)', async () => {
    mockExecFile.mockImplementation((cmd: string, _args: string[], _opts: unknown, cb: unknown) => {
      if (cmd === 'apksigner') {
        (cb as (e: Error) => void)(new Error('sign error'));
      } else {
        (cb as (e: null, stdout: string, stderr: string) => void)(null, '', '');
      }
      return undefined;
    });
    const task = await service.harden(params);
    await flush();
    expect(task.status).toBe('failed');
    expect(task.error).toBeTruthy();
  });

  it('SDK 产物缺失应跳过 DEX/SO 注入但仍完成', async () => {
    statSyncMock.mockImplementation(() => {
      throw new Error('ENOENT');
    });
    const task = await service.harden(params);
    await flush();
    expect(task.status).toBe('completed');
    // 未注入 so(没调 pickRandomSoName)
    expect(soInjector.pickRandomSoName).not.toHaveBeenCalled();
  });

  it('apksigner 路径探测失败应回退到裸命令名', async () => {
    existsSyncMock.mockReturnValue(false);
    const task = await service.harden(params);
    await flush();
    expect(task.status).toBe('completed');
    const cmds = mockExecFile.mock.calls.map((c) => c[0]);
    expect(cmds).toContain('apksigner');
  });
});
