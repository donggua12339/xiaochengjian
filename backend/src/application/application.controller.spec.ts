import { Test } from '@nestjs/testing';
import { ApplicationController } from './application.controller';
import { ApplicationService } from './application.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuditInterceptor } from '../audit/audit.interceptor';

/**
 * ApplicationController 单元测试
 *
 * 覆盖 6 个端点:
 *  - POST /apps
 *  - GET /apps
 *  - GET /apps/:id
 *  - PATCH /apps/:id
 *  - DELETE /apps/:id
 *  - POST /apps/:id/rotate-secret
 */
describe('ApplicationController', () => {
  let controller: ApplicationController;
  let appService: {
    create: jest.Mock;
    list: jest.Mock;
    getById: jest.Mock;
    update: jest.Mock;
    delete: jest.Mock;
    rotateSecret: jest.Mock;
  };

  beforeEach(async () => {
    appService = {
      create: jest.fn().mockResolvedValue({
        id: 'app-1',
        name: '测试',
        appSecret: 'secret',
        appSecretPrefix: 'secr',
      }),
      list: jest.fn().mockResolvedValue([{ id: 'app-1', name: '测试' }]),
      getById: jest.fn().mockResolvedValue({ id: 'app-1', name: '测试' }),
      update: jest.fn().mockResolvedValue({ id: 'app-1', name: '新名' }),
      delete: jest.fn().mockResolvedValue(undefined),
      rotateSecret: jest.fn().mockResolvedValue({ appSecret: 'new', appSecretPrefix: 'new' }),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [ApplicationController],
      providers: [{ provide: ApplicationService, useValue: appService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideInterceptor(AuditInterceptor)
      .useValue({ intercept: (_ctx: any, next: any) => next.handle() })
      .compile();
    controller = moduleRef.get(ApplicationController);
  });

  it('create 应转调 service.create', async () => {
    const dto = { name: '测试', packageName: 'com.xcj.test' };
    const result = await controller.create('dev-1', dto);
    expect(appService.create).toHaveBeenCalledWith('dev-1', dto);
    expect(result.id).toBe('app-1');
  });

  it('list 应转调 service.list', async () => {
    const result = await controller.list('dev-1');
    expect(appService.list).toHaveBeenCalledWith('dev-1');
    expect(result).toHaveLength(1);
  });

  it('getById 应转调 service.getById', async () => {
    const result = await controller.getById('dev-1', 'app-1');
    expect(appService.getById).toHaveBeenCalledWith('dev-1', 'app-1');
    expect(result.id).toBe('app-1');
  });

  it('update 应转调 service.update', async () => {
    const dto = { name: '新名' };
    const result = await controller.update('dev-1', 'app-1', dto);
    expect(appService.update).toHaveBeenCalledWith('dev-1', 'app-1', dto);
    expect(result.name).toBe('新名');
  });

  it('delete 应转调 service.delete + 返回 success', async () => {
    const result = await controller.delete('dev-1', 'app-1');
    expect(appService.delete).toHaveBeenCalledWith('dev-1', 'app-1');
    expect(result).toEqual({ success: true });
  });

  it('rotateSecret 应转调 service.rotateSecret', async () => {
    const result = await controller.rotateSecret('dev-1', 'app-1');
    expect(appService.rotateSecret).toHaveBeenCalledWith('dev-1', 'app-1');
    expect(result.appSecret).toBe('new');
  });
});
