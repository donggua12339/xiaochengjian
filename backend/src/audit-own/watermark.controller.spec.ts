import { Test } from '@nestjs/testing';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { WatermarkController } from './watermark.controller';
import { WatermarkService } from './watermark.service';

/**
 * WatermarkController 单元测试(ADR 0030 §c)
 *
 * 覆盖:
 *  - generate: 正常 / watermarkId 缺失(用 developerId 兜底)
 *  - trace: 非 ADMIN 拒绝 / 缺 file 拒绝 / 正常调用
 */
describe('WatermarkController', () => {
  let controller: WatermarkController;
  let watermarkService: jest.Mocked<WatermarkService>;

  beforeEach(async () => {
    watermarkService = {
      generateEncryptedWatermark: jest.fn().mockResolvedValue({
        watermarkBase64: 'base64-data',
        version: '0.2.0',
        algorithm: 'AES-256-GCM',
      }),
      extractAndDecryptFromApk: jest.fn().mockResolvedValue({
        found: true,
        watermark: {
          version: '0.2.0',
          watermarkId: 'dev-1',
          timestamp: 1700000000000,
          nonce: 'abc123',
        },
      }),
    } as unknown as jest.Mocked<WatermarkService>;

    const moduleRef = await Test.createTestingModule({
      controllers: [WatermarkController],
      providers: [{ provide: WatermarkService, useValue: watermarkService }],
    }).compile();
    controller = moduleRef.get(WatermarkController);
  });

  describe('generate', () => {
    it('正常应调 service 并返回结果', async () => {
      const result = await controller.generate('dev-1', {
        watermarkId: 'dev-1',
        version: '0.2.0',
      });
      expect(watermarkService.generateEncryptedWatermark).toHaveBeenCalledWith(
        'dev-1',
        '0.2.0',
      );
      expect(result.watermarkBase64).toBe('base64-data');
    });

    it('watermarkId 空时用 developerId 兜底', async () => {
      await controller.generate('dev-fallback', {
        watermarkId: '',
        version: '0.2.0',
      });
      expect(watermarkService.generateEncryptedWatermark).toHaveBeenCalledWith(
        'dev-fallback',
        '0.2.0',
      );
    });

    it('version 缺失时用默认 0.2.0', async () => {
      await controller.generate('dev-1', { watermarkId: 'dev-1' });
      expect(watermarkService.generateEncryptedWatermark).toHaveBeenCalledWith(
        'dev-1',
        '0.2.0',
      );
    });
  });

  describe('trace', () => {
    it('非 ADMIN 应抛 ForbiddenException', async () => {
      const req = { user: { sub: 'dev-1', role: 'DEVELOPER' } } as any;
      await expect(
        controller.trace(req, { buffer: Buffer.from('apk') } as any),
      ).rejects.toThrow(ForbiddenException);
    });

    it('缺 file 应抛 BadRequestException', async () => {
      const req = { user: { sub: 'admin-1', role: 'ADMIN' } } as any;
      await expect(controller.trace(req, undefined as any)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('ADMIN + 有 file 应调 service.extractAndDecryptFromApk', async () => {
      const req = { user: { sub: 'admin-1', role: 'ADMIN' } } as any;
      const file = { buffer: Buffer.from('apk') } as any;
      const result = await controller.trace(req, file);
      expect(watermarkService.extractAndDecryptFromApk).toHaveBeenCalledWith(file.buffer);
      expect(result.found).toBe(true);
      expect(result.watermark?.watermarkId).toBe('dev-1');
    });

    it('service 返回 found=false 时正确转发', async () => {
      watermarkService.extractAndDecryptFromApk.mockResolvedValueOnce({ found: false });
      const req = { user: { sub: 'admin-1', role: 'ADMIN' } } as any;
      const file = { buffer: Buffer.from('apk') } as any;
      const result = await controller.trace(req, file);
      expect(result.found).toBe(false);
      expect(result.watermark).toBeUndefined();
    });
  });
});
