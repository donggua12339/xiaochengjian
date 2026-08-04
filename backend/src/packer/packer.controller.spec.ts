import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException } from '@nestjs/common';
import { PackerController } from './packer.controller';
import { PackerService } from './packer.service';
import { PackerLogService } from './packer-log.service';
import * as fs from 'fs/promises';

jest.mock('fs/promises');

describe('PackerController', () => {
  let controller: PackerController;
  let packerService: { pack: jest.Mock };
  let packerLogService: { listByDeveloper: jest.Mock };
  const configMap: Record<string, string | undefined> = {};

  const req = { headers: { 'user-agent': 'UA' }, ip: '1.2.3.4' } as never;
  const apkFile = { buffer: Buffer.from('apk'), originalname: 'a.apk' } as Express.Multer.File;
  const ksFile = { buffer: Buffer.from('ks') } as Express.Multer.File;
  const dexFile = { buffer: Buffer.from('dex') } as Express.Multer.File;
  const cred = { keystorePassword: 'p', keyAlias: 'a', keyPassword: 'p' };

  beforeEach(async () => {
    packerService = {
      pack: jest.fn().mockResolvedValue({
        taskId: 'packer-1',
        packedApk: Buffer.from('packed'),
        packedApkHash: 'ph',
        injectedDexHash: 'dh',
        injectedDefenderDexHash: null,
        injectedSoHash: null,
        defenderSoName: null,
        keystoreFingerprint: 'kfp',
      }),
    };
    packerLogService = { listByDeveloper: jest.fn().mockResolvedValue([]) };
    (fs.access as jest.Mock).mockResolvedValue(undefined);
    (fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('defender-dex'));

    const module = await Test.createTestingModule({
      controllers: [PackerController],
      providers: [
        { provide: PackerService, useValue: packerService },
        { provide: PackerLogService, useValue: packerLogService },
        { provide: ConfigService, useValue: { get: jest.fn((k: string) => configMap[k]) } },
      ],
    }).compile();
    controller = module.get(PackerController);
  });

  describe('pack - 输入校验', () => {
    it('缺 APK 文件应抛 APK_FILE_REQUIRED', async () => {
      await expect(
        controller.pack('dev-1', req, cred, ksFile, dexFile, undefined as never),
      ).rejects.toThrow(BadRequestException);
    });

    it('缺 keystore 应抛 KEYSTORE_FILE_REQUIRED', async () => {
      await expect(
        controller.pack('dev-1', req, cred, undefined as never, dexFile, apkFile),
      ).rejects.toThrow('KEYSTORE_FILE_REQUIRED');
    });

    it('缺 xcjAuthSdkDex 应抛 XCJ_AUTH_SDK_DEX_REQUIRED', async () => {
      await expect(
        controller.pack('dev-1', req, cred, ksFile, undefined as never, apkFile),
      ).rejects.toThrow('XCJ_AUTH_SDK_DEX_REQUIRED');
    });

    it('缺凭证应抛 KEYSTORE_CREDENTIALS_REQUIRED', async () => {
      await expect(
        controller.pack(
          'dev-1',
          req,
          { keystorePassword: '', keyAlias: '', keyPassword: '' },
          ksFile,
          dexFile,
          apkFile,
        ),
      ).rejects.toThrow('KEYSTORE_CREDENTIALS_REQUIRED');
    });

    it('sdkConfig 非法 JSON 应抛 INVALID_SDK_CONFIG_JSON', async () => {
      await expect(
        controller.pack('dev-1', req, { ...cred, sdkConfig: '{bad' }, ksFile, dexFile, apkFile),
      ).rejects.toThrow('INVALID_SDK_CONFIG_JSON');
    });
  });

  describe('pack - defender 校验', () => {
    it('defender 启用但缺 defenderConfig 应抛 DEFENDER_CONFIG_REQUIRED', async () => {
      await expect(
        controller.pack(
          'dev-1',
          req,
          { ...cred, defenderEnabled: 'true' },
          ksFile,
          dexFile,
          apkFile,
        ),
      ).rejects.toThrow('DEFENDER_CONFIG_REQUIRED');
    });

    it('defenderConfig 非法 JSON 应抛 INVALID_DEFENDER_CONFIG_JSON', async () => {
      await expect(
        controller.pack(
          'dev-1',
          req,
          { ...cred, defenderEnabled: 'true', defenderConfig: '{bad' },
          ksFile,
          dexFile,
          apkFile,
        ),
      ).rejects.toThrow('INVALID_DEFENDER_CONFIG_JSON');
    });

    it('defender 启用但 AAR 未配置应抛 DEFENDER_AAR_NOT_CONFIGURED', async () => {
      configMap.defenderAarPath = undefined;
      await expect(
        controller.pack(
          'dev-1',
          req,
          { ...cred, defenderEnabled: 'true', defenderConfig: '{}' },
          ksFile,
          dexFile,
          apkFile,
        ),
      ).rejects.toThrow('DEFENDER_AAR_NOT_CONFIGURED');
    });

    it('defender 启用但 AAR 文件不存在应抛 DEFENDER_AAR_NOT_FOUND', async () => {
      configMap.defenderAarPath = '/tmp/d.aar';
      (fs.access as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await expect(
        controller.pack(
          'dev-1',
          req,
          { ...cred, defenderEnabled: 'true', defenderConfig: '{}' },
          ksFile,
          dexFile,
          apkFile,
        ),
      ).rejects.toThrow('DEFENDER_AAR_NOT_FOUND');
      (fs.access as jest.Mock).mockResolvedValue(undefined);
    });
  });

  describe('pack - 成功路径', () => {
    it('无 defender 应返回封装结果 + base64', async () => {
      const r = await controller.pack(
        'dev-1',
        req,
        { ...cred, sdkConfig: '{}' },
        ksFile,
        dexFile,
        apkFile,
      );
      expect(packerService.pack).toHaveBeenCalled();
      expect(r.taskId).toBe('packer-1');
      expect(r.packedApkBase64).toBe(Buffer.from('packed').toString('base64'));
      expect(r.packedApkSize).toBe(6);
    });

    it('defender 全启用应读取 aar/dex 并透传', async () => {
      configMap.defenderAarPath = '/tmp/d.aar';
      configMap.defenderDexPath = '/tmp/d.dex';
      const r = await controller.pack(
        'dev-1',
        req,
        { ...cred, defenderEnabled: 'true', defenderConfig: '{"appId":"a"}' },
        ksFile,
        dexFile,
        apkFile,
      );
      expect(packerService.pack).toHaveBeenCalledWith(
        expect.objectContaining({ defenderEnabled: true, defenderAarPath: '/tmp/d.aar' }),
      );
      expect(r).toBeDefined();
      configMap.defenderAarPath = undefined;
      configMap.defenderDexPath = undefined;
    });

    it('defender dex 读取失败应跳过(warn)不阻断', async () => {
      configMap.defenderAarPath = '/tmp/d.aar';
      configMap.defenderDexPath = '/tmp/missing.dex';
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await controller.pack(
        'dev-1',
        req,
        { ...cred, defenderEnabled: 'true', defenderConfig: '{}' },
        ksFile,
        dexFile,
        apkFile,
      );
      expect(packerService.pack).toHaveBeenCalledWith(
        expect.objectContaining({ defenderDex: undefined }),
      );
      (fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('defender-dex'));
      configMap.defenderAarPath = undefined;
      configMap.defenderDexPath = undefined;
    });
  });

  describe('listLogs', () => {
    it('默认 limit=50 offset=0', async () => {
      await controller.listLogs('dev-1');
      expect(packerLogService.listByDeveloper).toHaveBeenCalledWith('dev-1', {
        limit: 50,
        offset: 0,
      });
    });

    it('非法 limit 应抛 INVALID_LIMIT', async () => {
      await expect(controller.listLogs('dev-1', 'abc')).rejects.toThrow('INVALID_LIMIT');
      await expect(controller.listLogs('dev-1', '0')).rejects.toThrow('INVALID_LIMIT');
      await expect(controller.listLogs('dev-1', '201')).rejects.toThrow('INVALID_LIMIT');
    });

    it('非法 offset 应抛 INVALID_OFFSET', async () => {
      await expect(controller.listLogs('dev-1', '10', '-1')).rejects.toThrow('INVALID_OFFSET');
      await expect(controller.listLogs('dev-1', '10', 'abc')).rejects.toThrow('INVALID_OFFSET');
    });

    it('合法 limit+offset 应透传', async () => {
      await controller.listLogs('dev-1', '20', '5');
      expect(packerLogService.listByDeveloper).toHaveBeenCalledWith('dev-1', {
        limit: 20,
        offset: 5,
      });
    });
  });
});
