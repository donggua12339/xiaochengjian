import { Test } from '@nestjs/testing';
import { DeviceController } from './device.controller';
import { DeviceService } from './device.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

/**
 * DeviceController 单元测试
 *
 * 覆盖 3 个端点:
 *  - GET /apps/:appId/devices(分页列表)
 *  - GET /apps/:appId/devices/:deviceId(详情)
 *  - POST /apps/:appId/devices/:deviceId/unbind(解绑)
 */
describe('DeviceController', () => {
  let controller: DeviceController;
  let deviceService: {
    list: jest.Mock;
    getById: jest.Mock;
    unbindAll: jest.Mock;
  };

  beforeEach(async () => {
    deviceService = {
      list: jest.fn().mockResolvedValue({
        items: [{ id: 'dev-1', machineId: 'm1', lastSeenAt: new Date() }],
        total: 1,
        page: 1,
        pageSize: 20,
        totalPages: 1,
      }),
      getById: jest.fn().mockResolvedValue({
        id: 'dev-1',
        machineId: 'm1',
        bindings: [],
      }),
      unbindAll: jest.fn().mockResolvedValue({ success: true, unboundCount: 3 }),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [DeviceController],
      providers: [{ provide: DeviceService, useValue: deviceService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = moduleRef.get(DeviceController);
  });

  it('list 应转调 service.list(默认分页)', async () => {
    const result = await controller.list('dev-1', 'app-1', {} as any);
    expect(deviceService.list).toHaveBeenCalledWith('dev-1', 'app-1', {
      page: 1,
      pageSize: 20,
    });
    expect(result.total).toBe(1);
  });

  it('list 支持自定义分页', async () => {
    await controller.list('dev-1', 'app-1', { page: 2, pageSize: 50 } as any);
    expect(deviceService.list).toHaveBeenCalledWith('dev-1', 'app-1', {
      page: 2,
      pageSize: 50,
    });
  });

  it('getById 应转调 service.getById', async () => {
    const result = await controller.getById('dev-1', 'app-1', 'dev-1');
    expect(deviceService.getById).toHaveBeenCalledWith('dev-1', 'app-1', 'dev-1');
    expect(result.id).toBe('dev-1');
  });

  it('unbindAll 应转调 service.unbindAll', async () => {
    const result = await controller.unbindAll('dev-1', 'app-1', 'dev-1');
    expect(deviceService.unbindAll).toHaveBeenCalledWith('dev-1', 'app-1', 'dev-1');
    expect(result.success).toBe(true);
    expect(result.unboundCount).toBe(3);
  });
});
