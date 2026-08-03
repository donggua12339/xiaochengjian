import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException } from '@nestjs/common';
import { HardeningController } from './hardening.controller';
import { HardeningService } from './hardening.service';
import { FileStorageService } from './file-storage.service';
import { ChunkStorageService } from './chunk-storage.service';
import * as fs from 'fs/promises';

jest.mock('fs/promises');

describe('默认签名', () => {
  let controller: HardeningController;
  let configGet: jest.Mock;
  let hardenMock: jest.Mock;
  let fileStorageGet: jest.Mock;

  const defaultKsConfig = {
    enabled: true,
    path: '/tmp/default-ks.jks',
    password: 'kspass',
    alias: 'myalias',
    keyPassword: 'keypass',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    configGet = jest.fn();
    hardenMock = jest.fn().mockResolvedValue({ id: 'task-1', status: 'queued', message: 'ok' });
    fileStorageGet = jest.fn().mockResolvedValue({ path: '/tmp/test.apk', fileName: 'test.apk' });

    const module = await Test.createTestingModule({
      controllers: [HardeningController],
      providers: [
        {
          provide: HardeningService,
          useValue: {
            harden: hardenMock,
            startAnalysis: jest.fn(),
            getTask: jest.fn(),
            getUserTasks: jest.fn(),
            cancelTask: jest.fn(),
          },
        },
        {
          provide: FileStorageService,
          useValue: { get: fileStorageGet, save: jest.fn() },
        },
        {
          provide: ChunkStorageService,
          useValue: { createUpload: jest.fn(), receiveChunk: jest.fn(), mergeChunks: jest.fn() },
        },
        {
          provide: ConfigService,
          useValue: { get: configGet },
        },
      ],
    }).compile();

    controller = module.get(HardeningController);
  });

  const baseBody = {
    fileId: 'file-1',
    config: JSON.stringify({ productLine: 'xuanjia' }),
    analysisJson: JSON.stringify({ packageName: 'com.test' }),
    ownershipConfirmed: 'true',
  };

  // ===== POST /harden 默认签名分支 =====

  describe('harden useDefaultSign', () => {
    it('useDefaultSign=true + 默认签名已启用 → 用配置中的 keystore', async () => {
      configGet.mockImplementation((key: string) => {
        if (key === 'defaultKeystore') return defaultKsConfig;
        return undefined;
      });
      (fs.stat as jest.Mock).mockResolvedValue({ size: 2048 });
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);

      const result = await controller.harden(
        undefined, // 无 keystore 文件
        'dev-1',
        { ...baseBody, useDefaultSign: 'true' } as never,
      );

      expect(result).toEqual({ taskId: 'task-1', status: 'queued', message: 'ok' });
      expect(hardenMock).toHaveBeenCalledWith(
        expect.objectContaining({
          keystorePath: defaultKsConfig.path,
          keystorePassword: defaultKsConfig.password,
          keyAlias: defaultKsConfig.alias,
          keyPassword: defaultKsConfig.keyPassword,
        }),
      );
    });

    it('useDefaultSign=true + 默认签名未启用 → 400', async () => {
      configGet.mockImplementation((key: string) => {
        if (key === 'defaultKeystore') return { ...defaultKsConfig, enabled: false };
        return undefined;
      });

      await expect(
        controller.harden(undefined, 'dev-1', { ...baseBody, useDefaultSign: 'true' } as never),
      ).rejects.toThrow(BadRequestException);
    });

    it('useDefaultSign=true + keystore 文件不存在 → 400', async () => {
      configGet.mockImplementation((key: string) => {
        if (key === 'defaultKeystore') return defaultKsConfig;
        return undefined;
      });
      (fs.stat as jest.Mock).mockRejectedValue(new Error('ENOENT'));

      await expect(
        controller.harden(undefined, 'dev-1', { ...baseBody, useDefaultSign: 'true' } as never),
      ).rejects.toThrow('Keystore 文件不存在');
    });

    it('无 useDefaultSign + 无 keystore 文件 → 400(现有行为)', async () => {
      await expect(
        controller.harden(undefined, 'dev-1', {
          ...baseBody,
          keystorePassword: 'pass',
          keyAlias: 'alias',
          keyPassword: 'keypass',
        } as never),
      ).rejects.toThrow('请上传 Keystore 文件');
    });

    it('useDefaultSign=true + 同时上传了 keystore 文件 → 400', async () => {
      configGet.mockImplementation((key: string) => {
        if (key === 'defaultKeystore') return defaultKsConfig;
        return undefined;
      });

      const fakeFile = { buffer: Buffer.from('fake'), originalname: 'ks.jks', size: 4 } as never;

      await expect(
        controller.harden(fakeFile, 'dev-1', { ...baseBody, useDefaultSign: 'true' } as never),
      ).rejects.toThrow('不能同时');
    });

    it('useDefaultSign=true + 缺 ownershipConfirmed → 400', async () => {
      configGet.mockImplementation((key: string) => {
        if (key === 'defaultKeystore') return defaultKsConfig;
        return undefined;
      });

      await expect(
        controller.harden(undefined, 'dev-1', {
          ...baseBody,
          ownershipConfirmed: 'false',
          useDefaultSign: 'true',
        } as never),
      ).rejects.toThrow('所有权');
    });
  });

  // ===== GET /default-sign-status =====

  describe('defaultSignStatus', () => {
    it('默认签名已启用 → 返回 enabled + alias', () => {
      configGet.mockImplementation((key: string) => {
        if (key === 'defaultKeystore') return defaultKsConfig;
        return undefined;
      });

      const result = controller.defaultSignStatus();
      expect(result).toEqual({ enabled: true, alias: 'myalias' });
    });

    it('默认签名未启用 → 返回 enabled=false', () => {
      configGet.mockImplementation((key: string) => {
        if (key === 'defaultKeystore') return { enabled: false };
        return undefined;
      });

      const result = controller.defaultSignStatus();
      expect(result).toEqual({ enabled: false });
    });

    it('配置不存在 → 返回 enabled=false', () => {
      configGet.mockReturnValue(undefined);

      const result = controller.defaultSignStatus();
      expect(result).toEqual({ enabled: false });
    });
  });
});
