import { Test } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { FileStorageService } from './file-storage.service';
import { RedisService } from '../redis/redis.service';
import * as fs from 'fs/promises';

jest.mock('fs/promises');

describe('FileStorageService', () => {
  let service: FileStorageService;
  let redis: { set: jest.Mock; get: jest.Mock; del: jest.Mock };

  beforeEach(async () => {
    redis = { set: jest.fn(), get: jest.fn(), del: jest.fn() };
    const module = await Test.createTestingModule({
      providers: [
        FileStorageService,
        { provide: RedisService, useValue: redis },
      ],
    }).compile();
    service = module.get(FileStorageService);
  });

  describe('save', () => {
    it('should store file metadata in Redis with TTL', async () => {
      await service.save('f1', 'dev1', '/tmp/f1.apk', 'test.apk', 1024);
      expect(redis.set).toHaveBeenCalledWith(
        'hardening:file:f1',
        expect.stringContaining('"devId":"dev1"'),
        1800,
      );
    });
  });

  describe('get', () => {
    it('should return file meta when fileId exists and devId matches', async () => {
      const meta = JSON.stringify({
        path: '/tmp/f1.apk',
        devId: 'dev1',
        fileName: 'test.apk',
        fileSize: 1024,
        uploadedAt: '2026-01-01T00:00:00Z',
      });
      redis.get.mockResolvedValue(meta);

      const result = await service.get('f1', 'dev1');
      expect(result.path).toBe('/tmp/f1.apk');
      expect(result.devId).toBe('dev1');
    });

    it('should throw NotFoundException when fileId does not exist', async () => {
      redis.get.mockResolvedValue(null);
      await expect(service.get('nope', 'dev1')).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when devId does not match', async () => {
      const meta = JSON.stringify({
        path: '/tmp/f1.apk',
        devId: 'other-dev',
        fileName: 'test.apk',
        fileSize: 1024,
        uploadedAt: '2026-01-01T00:00:00Z',
      });
      redis.get.mockResolvedValue(meta);
      await expect(service.get('f1', 'dev1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('delete', () => {
    it('should delete Redis key and disk file', async () => {
      const meta = JSON.stringify({
        path: '/tmp/f1.apk',
        devId: 'dev1',
        fileName: 'test.apk',
        fileSize: 1024,
        uploadedAt: '2026-01-01T00:00:00Z',
      });
      redis.get.mockResolvedValue(meta);
      (fs.unlink as jest.Mock).mockResolvedValue(undefined);

      await service.delete('f1');
      expect(fs.unlink).toHaveBeenCalledWith('/tmp/f1.apk');
      expect(redis.del).toHaveBeenCalledWith('hardening:file:f1');
    });

    it('should not throw when disk file already deleted', async () => {
      const meta = JSON.stringify({
        path: '/tmp/gone.apk',
        devId: 'dev1',
        fileName: 'test.apk',
        fileSize: 1024,
        uploadedAt: '2026-01-01T00:00:00Z',
      });
      redis.get.mockResolvedValue(meta);
      const enoent = Object.assign(new Error('not found'), { code: 'ENOENT' });
      (fs.unlink as jest.Mock).mockRejectedValue(enoent);

      await expect(service.delete('f1')).resolves.toBeUndefined();
      expect(redis.del).toHaveBeenCalledWith('hardening:file:f1');
    });
  });
});
