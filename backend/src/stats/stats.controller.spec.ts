import { Test } from '@nestjs/testing';
import { StatsController } from './stats.controller';
import { StatsService } from './stats.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

/**
 * StatsController 单元测试
 *
 * 覆盖 4 个端点:
 *  - GET /apps/:appId/stats/overview
 *  - GET /apps/:appId/stats/validations
 *  - GET /apps/:appId/stats/activations
 *  - GET /developer/stats/overview
 */
describe('StatsController', () => {
  let controller: StatsController;
  let statsService: {
    appOverview: jest.Mock;
    validationTrend: jest.Mock;
    activationTrend: jest.Mock;
    developerOverview: jest.Mock;
  };

  beforeEach(async () => {
    statsService = {
      appOverview: jest.fn().mockResolvedValue({
        cards: { total: 10, byStatus: { UNUSED: 5, ACTIVE: 5 }, activated: 5 },
        devices: { total: 3, active30d: 2 },
        validations: { today: 20, todaySuccess: 18, todayFailRate: 10 },
      }),
      validationTrend: jest.fn().mockResolvedValue([
        { date: '2026-07-18', total: 20, success: 18, fail: 2 },
      ]),
      activationTrend: jest.fn().mockResolvedValue([{ date: '2026-07-18', count: 5 }]),
      developerOverview: jest.fn().mockResolvedValue({
        totals: { apps: 2, cards: 10, devices: 3, templates: 1 },
        recent7d: { validations: 100, activations: 10 },
        topApps: [],
      }),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [StatsController],
      providers: [{ provide: StatsService, useValue: statsService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = moduleRef.get(StatsController);
  });

  it('appOverview 应转调 service.appOverview', async () => {
    const result = await controller.appOverview('dev-1', 'app-1');
    expect(statsService.appOverview).toHaveBeenCalledWith('dev-1', 'app-1');
    expect(result.cards.total).toBe(10);
  });

  it('validationTrend 应转调 service.validationTrend(默认 7 天)', async () => {
    const result = await controller.validationTrend('dev-1', 'app-1', {} as any);
    expect(statsService.validationTrend).toHaveBeenCalledWith('dev-1', 'app-1', 7);
    expect(result).toHaveLength(1);
  });

  it('validationTrend 支持自定义天数', async () => {
    await controller.validationTrend('dev-1', 'app-1', { days: 30 } as any);
    expect(statsService.validationTrend).toHaveBeenCalledWith('dev-1', 'app-1', 30);
  });

  it('activationTrend 应转调 service.activationTrend(默认 7 天)', async () => {
    const result = await controller.activationTrend('dev-1', 'app-1', {} as any);
    expect(statsService.activationTrend).toHaveBeenCalledWith('dev-1', 'app-1', 7);
    expect(result).toHaveLength(1);
  });

  it('activationTrend 支持自定义天数', async () => {
    await controller.activationTrend('dev-1', 'app-1', { days: 14 } as any);
    expect(statsService.activationTrend).toHaveBeenCalledWith('dev-1', 'app-1', 14);
  });

  it('developerOverview 应转调 service.developerOverview', async () => {
    const result = await controller.developerOverview('dev-1');
    expect(statsService.developerOverview).toHaveBeenCalledWith('dev-1');
    expect(result.totals.apps).toBe(2);
  });
});
