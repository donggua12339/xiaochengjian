import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { HardeningController } from './hardening.controller';
import { HardeningService } from './hardening.service';
import { FileStorageService } from './file-storage.service';
import { ChunkStorageService } from './chunk-storage.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import * as fs from 'fs/promises';

jest.mock('fs/promises');

describe('HardeningController(非上传端点)', () => {
  let controller: HardeningController;
  let hardeningService: Record<string, jest.Mock>;
  let fileStorage: { get: jest.Mock; save: jest.Mock };
  let chunkStorage: Record<string, jest.Mock>;
  let configGet: jest.Mock;

  beforeEach(async () => {
    hardeningService = {
      harden: jest.fn().mockResolvedValue({ id: 'task-1', status: 'queued', message: 'ok' }),
      startAnalysis: jest.fn(),
      getTask: jest.fn(),
      getUserTasks: jest.fn().mockResolvedValue([]),
      cancelTask: jest.fn().mockResolvedValue(undefined),
    };
    fileStorage = {
      get: jest.fn().mockResolvedValue({ path: '/tmp/a.apk', fileName: 'a.apk' }),
      save: jest.fn(),
    };
    chunkStorage = {
      createUpload: jest.fn().mockResolvedValue({ uploadId: 'u-1' }),
      receiveChunk: jest.fn().mockResolvedValue({ received: 1 }),
      mergeChunks: jest.fn().mockResolvedValue({ fileId: 'f-1' }),
    };
    configGet = jest.fn();
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    (fs.unlink as jest.Mock).mockResolvedValue(undefined);
    (fs.stat as jest.Mock).mockResolvedValue({ size: 100 });
    (fs.access as jest.Mock).mockResolvedValue(undefined);
    (fs.readFile as jest.Mock).mockResolvedValue(Buffer.from('apk-bytes'));

    const module = await Test.createTestingModule({
      controllers: [HardeningController],
      providers: [
        { provide: HardeningService, useValue: hardeningService },
        { provide: FileStorageService, useValue: fileStorage },
        { provide: ChunkStorageService, useValue: chunkStorage },
        { provide: ConfigService, useValue: { get: configGet } },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = module.get(HardeningController);
  });

  const baseBody = {
    fileId: 'f-1',
    config: JSON.stringify({ productLine: 'xuanjia' }),
    analysisJson: JSON.stringify({ packageName: 'com.test' }),
    ownershipConfirmed: 'true',
  };
  const ksFile = { buffer: Buffer.from('ks'), originalname: 'k.jks' } as Express.Multer.File;

  describe('harden - 上传签名分支', () => {
    it('缺 fileId 应抛错', async () => {
      await expect(controller.harden(ksFile, 'dev-1', { ...baseBody, fileId: '' })).rejects.toThrow(
        BadRequestException,
      );
    });

    it('缺 config 应抛错', async () => {
      await expect(controller.harden(ksFile, 'dev-1', { ...baseBody, config: '' })).rejects.toThrow(
        BadRequestException,
      );
    });

    it('未确认所有权应抛错', async () => {
      await expect(
        controller.harden(ksFile, 'dev-1', { ...baseBody, ownershipConfirmed: 'false' }),
      ).rejects.toThrow('所有权');
    });

    it('上传签名缺密码应抛错', async () => {
      await expect(
        controller.harden(ksFile, 'dev-1', { ...baseBody, keyAlias: '' }),
      ).rejects.toThrow('Keystore 密码和别名');
    });

    it('上传签名缺文件应抛错', async () => {
      await expect(
        controller.harden(undefined, 'dev-1', {
          ...baseBody,
          keystorePassword: 'p',
          keyAlias: 'a',
          keyPassword: 'p',
        }),
      ).rejects.toThrow('请上传 Keystore 文件');
    });

    it('上传签名成功应委托 hardeningService.harden', async () => {
      const r = await controller.harden(ksFile, 'dev-1', {
        ...baseBody,
        keystorePassword: 'p',
        keyAlias: 'a',
        keyPassword: 'p',
      });
      expect(hardeningService.harden).toHaveBeenCalled();
      expect(r.taskId).toBe('task-1');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('harden 失败应清理临时 keystore 并抛错', async () => {
      hardeningService.harden.mockRejectedValue(new Error('harden boom'));
      await expect(
        controller.harden(ksFile, 'dev-1', {
          ...baseBody,
          keystorePassword: 'p',
          keyAlias: 'a',
          keyPassword: 'p',
        }),
      ).rejects.toThrow('harden boom');
      expect(fs.unlink).toHaveBeenCalled();
    });
  });

  describe('harden - 默认签名分支', () => {
    it('同时上传文件应抛错', async () => {
      configGet.mockReturnValue({
        enabled: true,
        path: '/tmp/ks',
        password: 'p',
        alias: 'a',
        keyPassword: 'p',
      });
      await expect(
        controller.harden(ksFile, 'dev-1', { ...baseBody, useDefaultSign: 'true' }),
      ).rejects.toThrow('不能同时上传');
    });

    it('默认签名成功应使用配置路径', async () => {
      configGet.mockReturnValue({
        enabled: true,
        path: '/tmp/ks',
        password: 'p',
        alias: 'a',
        keyPassword: 'p',
      });
      const r = await controller.harden(undefined, 'dev-1', {
        ...baseBody,
        useDefaultSign: 'true',
      });
      expect(hardeningService.harden).toHaveBeenCalledWith(
        expect.objectContaining({ keystorePath: '/tmp/ks' }),
      );
      expect(r.taskId).toBe('task-1');
    });

    it('默认签名文件不存在应抛错', async () => {
      configGet.mockReturnValue({
        enabled: true,
        path: '/tmp/missing',
        password: 'p',
        alias: 'a',
        keyPassword: 'p',
      });
      (fs.stat as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await expect(
        controller.harden(undefined, 'dev-1', { ...baseBody, useDefaultSign: 'true' }),
      ).rejects.toThrow('默认 Keystore 文件不存在');
    });
  });

  describe('status', () => {
    it('任务存在应返回', async () => {
      hardeningService.getTask.mockResolvedValue({
        id: 't-1',
        developerId: 'dev-1',
        status: 'completed',
      });
      const r = await controller.status('t-1', 'dev-1');
      expect(r.id).toBe('t-1');
    });

    it('任务不存在应抛 NotFoundException', async () => {
      hardeningService.getTask.mockResolvedValue(null);
      await expect(controller.status('nope', 'dev-1')).rejects.toThrow(NotFoundException);
    });

    it('非本人任务应抛 NotFoundException', async () => {
      hardeningService.getTask.mockResolvedValue({ id: 't-1', developerId: 'other' });
      await expect(controller.status('t-1', 'dev-1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('tasks', () => {
    it('应返回用户任务列表', async () => {
      hardeningService.getUserTasks.mockResolvedValue([
        {
          id: 't-1',
          status: 'completed',
          progress: 100,
          message: 'm',
          step: 'done',
          detail: '',
          createdAt: 'c',
          updatedAt: 'u',
        },
      ]);
      const r = await controller.tasks('dev-1');
      expect(r.tasks).toHaveLength(1);
      expect(hardeningService.getUserTasks).toHaveBeenCalledWith('dev-1');
    });
  });

  describe('cancelTask', () => {
    it('任务不存在应抛错', async () => {
      hardeningService.getTask.mockResolvedValue(null);
      await expect(controller.cancelTask('nope', 'dev-1')).rejects.toThrow(NotFoundException);
    });

    it('非本人任务应抛错', async () => {
      hardeningService.getTask.mockResolvedValue({ id: 't-1', developerId: 'other' });
      await expect(controller.cancelTask('t-1', 'dev-1')).rejects.toThrow(NotFoundException);
    });

    it('已完成任务应抛 BadRequest', async () => {
      hardeningService.getTask.mockResolvedValue({
        id: 't-1',
        developerId: 'dev-1',
        status: 'completed',
      });
      await expect(controller.cancelTask('t-1', 'dev-1')).rejects.toThrow(BadRequestException);
    });

    it('进行中任务应可取消', async () => {
      hardeningService.getTask.mockResolvedValue({
        id: 't-1',
        developerId: 'dev-1',
        status: 'hardening',
      });
      const r = await controller.cancelTask('t-1', 'dev-1');
      expect(r.cancelled).toBe(true);
      expect(hardeningService.cancelTask).toHaveBeenCalledWith('t-1');
    });
  });

  describe('download', () => {
    const res = () =>
      ({ setHeader: jest.fn(), send: jest.fn() }) as unknown as import('express').Response;

    it('任务不存在应抛错', async () => {
      hardeningService.getTask.mockResolvedValue(null);
      await expect(controller.download('nope', 'dev-1', res())).rejects.toThrow(NotFoundException);
    });

    it('未完成应抛 BadRequest', async () => {
      hardeningService.getTask.mockResolvedValue({
        id: 't-1',
        developerId: 'dev-1',
        status: 'hardening',
      });
      await expect(controller.download('t-1', 'dev-1', res())).rejects.toThrow(BadRequestException);
    });

    it('完成但文件不存在应抛 NotFound', async () => {
      hardeningService.getTask.mockResolvedValue({
        id: 't-1',
        developerId: 'dev-1',
        status: 'completed',
        outputPath: '/tmp/o.apk',
      });
      (fs.access as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await expect(controller.download('t-1', 'dev-1', res())).rejects.toThrow(NotFoundException);
    });

    it('完成应返回文件', async () => {
      hardeningService.getTask.mockResolvedValue({
        id: 't-1',
        developerId: 'dev-1',
        status: 'completed',
        outputPath: '/tmp/o.apk',
      });
      const r = res();
      await controller.download('t-1', 'dev-1', r);
      expect(r.setHeader).toHaveBeenCalled();
      expect(r.send).toHaveBeenCalled();
    });
  });

  describe('分片上传端点', () => {
    it('uploadInit 缺参应抛错', async () => {
      await expect(
        controller.uploadInit({ fileName: '', fileSize: 0, totalChunks: 0 }, 'dev-1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('uploadInit 成功应委托', async () => {
      await controller.uploadInit({ fileName: 'a.apk', fileSize: 100, totalChunks: 1 }, 'dev-1');
      expect(chunkStorage.createUpload).toHaveBeenCalled();
    });

    it('uploadChunk 缺 uploadId 应抛错', async () => {
      await expect(
        controller.uploadChunk(ksFile, 'dev-1', { uploadId: '', chunkIndex: '0' }),
      ).rejects.toThrow(BadRequestException);
    });

    it('uploadChunk 缺文件应抛错', async () => {
      await expect(
        controller.uploadChunk(undefined, 'dev-1', { uploadId: 'u-1', chunkIndex: '0' }),
      ).rejects.toThrow('请上传分片');
    });

    it('uploadChunk chunkIndex 非数字应抛错', async () => {
      await expect(
        controller.uploadChunk(ksFile, 'dev-1', { uploadId: 'u-1', chunkIndex: 'abc' }),
      ).rejects.toThrow('chunkIndex');
    });

    it('uploadChunk 成功应委托', async () => {
      await controller.uploadChunk(ksFile, 'dev-1', { uploadId: 'u-1', chunkIndex: '2' });
      expect(chunkStorage.receiveChunk).toHaveBeenCalledWith('u-1', 'dev-1', 2, expect.any(Buffer));
    });

    it('uploadComplete 缺 uploadId 应抛错', async () => {
      await expect(controller.uploadComplete({ uploadId: '' }, 'dev-1')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('uploadComplete 成功应委托', async () => {
      await controller.uploadComplete({ uploadId: 'u-1' }, 'dev-1');
      expect(chunkStorage.mergeChunks).toHaveBeenCalledWith('u-1', 'dev-1');
    });
  });

  describe('upload - diskStorage(file.path)分支', () => {
    const diskFile = () =>
      ({
        buffer: Buffer.alloc(0), // diskStorage 模式 buffer 为空
        originalname: 'disk.apk',
        size: 2048,
        mimetype: 'application/octet-stream',
        path: '/tmp/disk.apk',
      }) as Express.Multer.File;

    it('file.path 有效 magic 应返回 fileId', async () => {
      const fd = {
        read: jest.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x50;
          buf[1] = 0x4b;
          buf[2] = 0x03;
          buf[3] = 0x04;
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined),
      };
      (fs.open as jest.Mock).mockResolvedValue(fd);
      const r = await controller.upload(diskFile(), 'dev-1');
      expect(r.fileId).toBeTruthy();
      expect(fs.open).toHaveBeenCalled();
    });

    it('file.path 无效 magic 应抛错并删除文件', async () => {
      const fd = {
        read: jest.fn().mockImplementation((buf: Buffer) => {
          buf[0] = 0x00;
          buf[1] = 0x00;
          buf[2] = 0x00;
          buf[3] = 0x00;
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined),
      };
      (fs.open as jest.Mock).mockResolvedValue(fd);
      await expect(controller.upload(diskFile(), 'dev-1')).rejects.toThrow(BadRequestException);
      expect(fs.unlink).toHaveBeenCalled();
    });

    it('file.path 读取失败应视为无效 magic', async () => {
      (fs.open as jest.Mock).mockRejectedValue(new Error('open fail'));
      await expect(controller.upload(diskFile(), 'dev-1')).rejects.toThrow(BadRequestException);
    });
  });
});
