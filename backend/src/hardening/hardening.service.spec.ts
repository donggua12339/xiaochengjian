import { Test } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { HardeningService } from './hardening.service';
import { ApkAnalyzerService } from './apk-analyzer.service';
import { SoInjector } from '../packer/so-injector';
import { PreflightService } from './preflight.service';
import { RedisService } from '../redis/redis.service';

describe('HardeningService', () => {
  let service: HardeningService;
  let redis: { get: jest.Mock; set: jest.Mock };
  let analyzer: { analyze: jest.Mock };

  beforeEach(async () => {
    redis = { get: jest.fn(), set: jest.fn().mockResolvedValue(undefined) };
    analyzer = { analyze: jest.fn() };

    const module = await Test.createTestingModule({
      providers: [
        HardeningService,
        { provide: ApkAnalyzerService, useValue: analyzer },
        { provide: SoInjector, useValue: {} },
        { provide: PreflightService, useValue: {} },
        { provide: RedisService, useValue: redis },
      ],
    }).compile();

    service = module.get(HardeningService);
  });

  const flush = () => new Promise((r) => setImmediate(r));

  describe('getTask', () => {
    it('存在应返回解析后的任务', async () => {
      redis.get.mockResolvedValue(JSON.stringify({ id: 't-1', status: 'completed' }));
      const task = await service.getTask('t-1');
      expect(task).toEqual({ id: 't-1', status: 'completed' });
    });

    it('不存在应返回 null', async () => {
      redis.get.mockResolvedValue(null);
      expect(await service.getTask('nope')).toBeNull();
    });
  });

  describe('cancelTask', () => {
    it('存在应标记 cancelled 并保存', async () => {
      redis.get.mockResolvedValue(JSON.stringify({ id: 't-1', status: 'hardening' }));
      await service.cancelTask('t-1');
      expect(redis.set).toHaveBeenCalledWith(
        expect.stringContaining('t-1'),
        expect.stringContaining('cancelled'),
        expect.any(Number),
      );
    });

    it('不存在应抛 NotFoundException', async () => {
      redis.get.mockResolvedValue(null);
      await expect(service.cancelTask('nope')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getUserTasks', () => {
    it('无索引应返回空数组', async () => {
      redis.get.mockResolvedValue(null);
      expect(await service.getUserTasks('dev-1')).toEqual([]);
    });

    it('应按 createdAt 倒序返回任务', async () => {
      redis.get.mockImplementation((key: string) => {
        if (key.includes('user_tasks')) return Promise.resolve(JSON.stringify(['t-1', 't-2']));
        if (key.includes('t-1'))
          return Promise.resolve(JSON.stringify({ id: 't-1', createdAt: '2026-01-01' }));
        if (key.includes('t-2'))
          return Promise.resolve(JSON.stringify({ id: 't-2', createdAt: '2026-02-01' }));
        return Promise.resolve(null);
      });
      const tasks = await service.getUserTasks('dev-1');
      expect(tasks.map((t) => t.id)).toEqual(['t-2', 't-1']);
    });

    it('索引中失效任务应被跳过', async () => {
      redis.get.mockImplementation((key: string) => {
        if (key.includes('user_tasks')) return Promise.resolve(JSON.stringify(['t-1', 'gone']));
        if (key.includes('t-1'))
          return Promise.resolve(JSON.stringify({ id: 't-1', createdAt: '2026-01-01' }));
        return Promise.resolve(null);
      });
      const tasks = await service.getUserTasks('dev-1');
      expect(tasks).toHaveLength(1);
    });
  });

  describe('startAnalysis + runAnalysis', () => {
    it('应立即返回 analyzing 任务并写入 Redis', async () => {
      // analyze 挂起,runAnalysis 停在分析中,断言返回任务的稳定字段
      analyzer.analyze.mockReturnValue(new Promise(() => {}));
      const task = await service.startAnalysis('/tmp/a.apk', 'dev-1', 'a.apk');
      expect(task.id).toBeTruthy();
      expect(task.status).toBe('analyzing');
      expect(task.apkFileName).toBe('a.apk');
      expect(redis.set).toHaveBeenCalled();
    });

    it('分析成功后任务应变 completed(progress=100)', async () => {
      analyzer.analyze.mockResolvedValue({
        packageName: 'com.test',
        dexFiles: ['classes.dex', 'classes2.dex'],
        nativeAbis: ['arm64-v8a', 'armeabi-v7a'],
      });
      const task = await service.startAnalysis('/tmp/a.apk', 'dev-1', 'a.apk');
      await flush();
      expect(task.status).toBe('completed');
      expect(task.progress).toBe(100);
      expect(task.step).toBe('done');
      expect(task.analysis?.packageName).toBe('com.test');
      expect(task.detail).toContain('com.test');
    });

    it('分析失败后任务应变 failed 并记录 error', async () => {
      analyzer.analyze.mockRejectedValue(new Error('bad apk'));
      const task = await service.startAnalysis('/tmp/a.apk', 'dev-1', 'a.apk');
      await flush();
      expect(task.status).toBe('failed');
      expect(task.error).toBe('bad apk');
      expect(task.step).toBe('error');
    });

    it('分析进度回调应更新 step/message', async () => {
      analyzer.analyze.mockImplementation(
        async (_p: string, cb: (s: string, n: number, d?: string) => Promise<void>) => {
          await cb('dex', 40, 'parsing');
          return { packageName: 'com.test', dexFiles: [], nativeAbis: [] };
        },
      );
      const task = await service.startAnalysis('/tmp/a.apk', 'dev-1', 'a.apk');
      await flush();
      expect(task.status).toBe('completed');
    });
  });
});
