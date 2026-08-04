import { HardenController } from './harden.controller';
import { HardenService } from './harden.service';

describe('HardenController', () => {
  let controller: HardenController;
  let hardenService: Record<string, jest.Mock>;

  beforeEach(() => {
    hardenService = {
      getConfig: jest.fn().mockResolvedValue({ strength: 'standard' }),
      upsertConfig: jest.fn().mockResolvedValue({}),
      submitReport: jest.fn().mockResolvedValue({ id: 'r-1' }),
      getReports: jest.fn().mockResolvedValue([]),
    };
    controller = new HardenController(hardenService as unknown as HardenService);
  });

  it('getConfig 应委托 service', async () => {
    await controller.getConfig('dev-1', 'app-1');
    expect(hardenService.getConfig).toHaveBeenCalledWith('dev-1', 'app-1');
  });

  it('upsertConfig 应委托 service 并传 dto', async () => {
    const dto = { strength: 'aggressive' };
    await controller.upsertConfig('dev-1', 'app-1', dto);
    expect(hardenService.upsertConfig).toHaveBeenCalledWith('dev-1', 'app-1', dto);
  });

  it('submitReport 应委托 service 并传 body', async () => {
    const body = { overallScore: 90, grade: 'A', dimensions: {}, raw: {} };
    await controller.submitReport('dev-1', 'app-1', body);
    expect(hardenService.submitReport).toHaveBeenCalledWith('dev-1', 'app-1', body);
  });

  it('getReports 无 limit 应默认 10', async () => {
    await controller.getReports('dev-1', 'app-1');
    expect(hardenService.getReports).toHaveBeenCalledWith('dev-1', 'app-1', 10);
  });

  it('getReports 有 limit 应 parseInt', async () => {
    await controller.getReports('dev-1', 'app-1', '25');
    expect(hardenService.getReports).toHaveBeenCalledWith('dev-1', 'app-1', 25);
  });
});
