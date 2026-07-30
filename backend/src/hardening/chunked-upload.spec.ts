import { Test } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ChunkStorageService, CHUNK_SIZE, MAX_FILE_SIZE } from './chunk-storage.service';
import { FileStorageService } from './file-storage.service';
import { RedisService } from '../redis/redis.service';
import * as fs from 'fs/promises';

jest.mock('fs/promises');

describe('ChunkStorageService', () => {
  let service: ChunkStorageService;
  let redis: { set: jest.Mock; get: jest.Mock; del: jest.Mock };
  let fileStorage: { save: jest.Mock; get: jest.Mock; delete: jest.Mock };

  beforeEach(async () => {
    jest.clearAllMocks();
    redis = { set: jest.fn(), get: jest.fn(), del: jest.fn() };
    fileStorage = { save: jest.fn(), get: jest.fn(), delete: jest.fn() };
    const module = await Test.createTestingModule({
      providers: [
        ChunkStorageService,
        { provide: RedisService, useValue: redis },
        { provide: FileStorageService, useValue: fileStorage },
      ],
    }).compile();
    service = module.get(ChunkStorageService);
  });

  describe('createUpload', () => {
    it('should create upload session and return uploadId', async () => {
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);

      const result = await service.createUpload('dev1', 'test.apk', 50 * 1024 * 1024, 10);
      expect(result).toHaveProperty('uploadId');
      expect(result.chunkSize).toBe(CHUNK_SIZE);
      expect(redis.set).toHaveBeenCalledWith(
        expect.stringContaining('hardening:upload:'),
        expect.stringContaining('"devId":"dev1"'),
        3600,
      );
    });

    it('should reject file > 1GB', async () => {
      await expect(
        service.createUpload('dev1', 'huge.apk', MAX_FILE_SIZE + 1, 200),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid totalChunks', async () => {
      await expect(
        service.createUpload('dev1', 'test.apk', 1024, 0),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.createUpload('dev1', 'test.apk', 1024, 201),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('receiveChunk', () => {
    const validMeta = JSON.stringify({
      devId: 'dev1',
      fileName: 'test.apk',
      fileSize: 10 * 1024 * 1024,
      totalChunks: 2,
      receivedChunks: [],
      createdAt: '2026-01-01T00:00:00Z',
    });

    beforeEach(() => {
      redis.get.mockResolvedValue(validMeta);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
    });

    it('should write chunk and update Redis', async () => {
      const result = await service.receiveChunk('u1', 'dev1', 0, Buffer.from('data'));
      expect(result.received).toBe(true);
      expect(result.chunkIndex).toBe(0);
      expect(fs.writeFile).toHaveBeenCalled();
      expect(redis.set).toHaveBeenCalled();
    });

    it('should be idempotent for duplicate chunkIndex', async () => {
      redis.get.mockResolvedValue(
        JSON.stringify({
          devId: 'dev1',
          fileName: 'test.apk',
          fileSize: 10 * 1024 * 1024,
          totalChunks: 2,
          receivedChunks: [0],
          createdAt: '2026-01-01T00:00:00Z',
        }),
      );

      const result = await service.receiveChunk('u1', 'dev1', 0, Buffer.from('data'));
      expect(result.received).toBe(true);
      expect(fs.writeFile).not.toHaveBeenCalled(); // 幂等,不重复写
    });

    it('should reject invalid uploadId', async () => {
      redis.get.mockResolvedValue(null);
      await expect(
        service.receiveChunk('nope', 'dev1', 0, Buffer.from('data')),
      ).rejects.toThrow(NotFoundException);
    });

    it('should reject other dev uploadId', async () => {
      redis.get.mockResolvedValue(
        JSON.stringify({
          devId: 'other-dev',
          fileName: 'test.apk',
          fileSize: 1024,
          totalChunks: 1,
          receivedChunks: [],
          createdAt: '2026-01-01T00:00:00Z',
        }),
      );
      await expect(
        service.receiveChunk('u1', 'dev1', 0, Buffer.from('data')),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('isComplete', () => {
    it('should return true when all chunks received', async () => {
      redis.get.mockResolvedValue(
        JSON.stringify({
          devId: 'dev1',
          fileName: 'test.apk',
          fileSize: 10 * 1024 * 1024,
          totalChunks: 2,
          receivedChunks: [0, 1],
          createdAt: '2026-01-01T00:00:00Z',
        }),
      );
      expect(await service.isComplete('u1', 'dev1')).toBe(true);
    });

    it('should return false when chunks missing', async () => {
      redis.get.mockResolvedValue(
        JSON.stringify({
          devId: 'dev1',
          fileName: 'test.apk',
          fileSize: 10 * 1024 * 1024,
          totalChunks: 2,
          receivedChunks: [0],
          createdAt: '2026-01-01T00:00:00Z',
        }),
      );
      expect(await service.isComplete('u1', 'dev1')).toBe(false);
    });
  });

  describe('mergeChunks', () => {
    it('should reject when not all chunks received', async () => {
      redis.get.mockResolvedValue(
        JSON.stringify({
          devId: 'dev1',
          fileName: 'test.apk',
          fileSize: 10 * 1024 * 1024,
          totalChunks: 2,
          receivedChunks: [0],
          createdAt: '2026-01-01T00:00:00Z',
        }),
      );
      await expect(service.mergeChunks('u1', 'dev1')).rejects.toThrow(BadRequestException);
    });
  });

  describe('cleanup', () => {
    it('should delete chunks dir and Redis key', async () => {
      (fs.rm as jest.Mock).mockResolvedValue(undefined);
      await service.cleanup('u1');
      expect(fs.rm).toHaveBeenCalled();
      expect(redis.del).toHaveBeenCalledWith(expect.stringContaining('hardening:upload:u1'));
    });
  });
});
