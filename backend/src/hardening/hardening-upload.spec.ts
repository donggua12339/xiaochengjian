import { Test } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { HardeningController } from './hardening.controller';
import { HardeningService } from './hardening.service';
import { FileStorageService } from './file-storage.service';
import { ChunkStorageService } from './chunk-storage.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

describe('HardeningController.upload', () => {
  let controller: HardeningController;
  let fileStorage: { save: jest.Mock; get: jest.Mock; delete: jest.Mock };
  let chunkStorage: { createUpload: jest.Mock; receiveChunk: jest.Mock; mergeChunks: jest.Mock };
  let hardeningService: { startAnalysis: jest.Mock; harden: jest.Mock; getTask: jest.Mock; getUserTasks: jest.Mock };

  beforeEach(async () => {
    fileStorage = { save: jest.fn(), get: jest.fn(), delete: jest.fn() };
    chunkStorage = { createUpload: jest.fn(), receiveChunk: jest.fn(), mergeChunks: jest.fn() };
    hardeningService = {
      startAnalysis: jest.fn(),
      harden: jest.fn(),
      getTask: jest.fn(),
      getUserTasks: jest.fn(),
    };
    const module = await Test.createTestingModule({
      controllers: [HardeningController],
      providers: [
        { provide: HardeningService, useValue: hardeningService },
        { provide: FileStorageService, useValue: fileStorage },
        { provide: ChunkStorageService, useValue: chunkStorage },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = module.get(HardeningController);
  });

  describe('upload', () => {
    const mockFile = (buffer: Buffer, name: string, size: number) =>
      ({ buffer, originalname: name, size, mimetype: 'application/octet-stream', path: `/tmp/${name}` } as Express.Multer.File);

    it('should return fileId for valid APK', async () => {
      // APK magic bytes: PK\x03\x04
      const buf = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(100)]);
      const file = mockFile(buf, 'test.apk', buf.length);

      const result = await controller.upload(file, 'dev1');
      expect(result).toHaveProperty('fileId');
      expect(result.fileName).toBe('test.apk');
      expect(result.fileSize).toBe(buf.length);
      expect(fileStorage.save).toHaveBeenCalledWith(
        result.fileId,
        'dev1',
        expect.stringContaining('test.apk'),
        'test.apk',
        buf.length,
      );
    });

    it('should reject non-APK file (wrong magic bytes)', async () => {
      const buf = Buffer.from('not an apk file at all');
      const file = mockFile(buf, 'readme.txt', buf.length);

      await expect(controller.upload(file, 'dev1')).rejects.toThrow(BadRequestException);
    });

    it('should reject null file', async () => {
      await expect(
        controller.upload(null as unknown as Express.Multer.File, 'dev1'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('analyze (refactored: accepts fileId)', () => {
    it('should return taskId for valid fileId', async () => {
      fileStorage.get.mockResolvedValue({
        path: '/tmp/f1.apk',
        devId: 'dev1',
        fileName: 'test.apk',
        fileSize: 1024,
        uploadedAt: '2026-01-01T00:00:00Z',
      });
      hardeningService.startAnalysis.mockResolvedValue({ id: 'task-1' });

      const result = await controller.analyze({ fileId: 'f1' }, 'dev1');
      expect(result.taskId).toBe('task-1');
      expect(hardeningService.startAnalysis).toHaveBeenCalledWith('/tmp/f1.apk', 'dev1', 'test.apk');
    });

    it('should reject invalid fileId', async () => {
      fileStorage.get.mockRejectedValue(new NotFoundException('not found'));
      await expect(controller.analyze({ fileId: 'nope' }, 'dev1')).rejects.toThrow(NotFoundException);
    });
  });
});
