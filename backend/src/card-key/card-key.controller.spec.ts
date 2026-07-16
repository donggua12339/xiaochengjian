import { Test } from '@nestjs/testing';
import { CardKeyController } from './card-key.controller';
import { CardKeyService } from './card-key.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuditInterceptor } from '../audit/audit.interceptor';
import { CardKeyType, BindingStrategy } from '@prisma/client';

/**
 * CardKeyController 单元测试
 *
 * 覆盖 8 个端点的路由分发:
 *  - POST apps/:appId/cards/generate
 *  - GET apps/:appId/cards
 *  - GET apps/:appId/cards/:cardId
 *  - POST apps/:appId/cards/:cardId/disable
 *  - POST apps/:appId/cards/:cardId/enable
 *  - POST apps/:appId/cards/:cardId/unbind
 *  - POST apps/:appId/cards/templates
 *  - GET apps/:appId/cards/templates/list
 *  - DELETE apps/:appId/cards/templates/:templateId
 */
describe('CardKeyController', () => {
  let controller: CardKeyController;
  let cardKeyService: {
    generate: jest.Mock;
    list: jest.Mock;
    getById: jest.Mock;
    disable: jest.Mock;
    enable: jest.Mock;
    unbindDevice: jest.Mock;
    createTemplate: jest.Mock;
    listTemplates: jest.Mock;
    deleteTemplate: jest.Mock;
  };

  beforeEach(async () => {
    cardKeyService = {
      generate: jest.fn().mockResolvedValue({
        batchId: 'b1',
        cardKeys: ['XXXX-XXXX-XXXX-XXXX'],
        count: 1,
      }),
      list: jest.fn().mockResolvedValue({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 }),
      getById: jest.fn().mockResolvedValue({ id: 'c1', boundDevicesCount: 0 }),
      disable: jest.fn().mockResolvedValue({ id: 'c1', status: 'DISABLED' }),
      enable: jest.fn().mockResolvedValue({ id: 'c1', status: 'ACTIVE' }),
      unbindDevice: jest.fn().mockResolvedValue({ success: true }),
      createTemplate: jest.fn().mockResolvedValue({ id: 't1' }),
      listTemplates: jest.fn().mockResolvedValue([]),
      deleteTemplate: jest.fn().mockResolvedValue({ success: true }),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [CardKeyController],
      providers: [{ provide: CardKeyService, useValue: cardKeyService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideInterceptor(AuditInterceptor)
      .useValue({ intercept: (_ctx: any, next: any) => next.handle() })
      .compile();
    controller = moduleRef.get(CardKeyController);
  });

  describe('generate', () => {
    it('应转调 service.generate 并返回结果', async () => {
      const dto = {
        type: CardKeyType.MONTH,
        bindingStrategy: BindingStrategy.FIRST_BIND,
        maxDevices: 1,
        count: 1,
      };
      const result = await controller.generate('dev-1', 'app-1', dto);
      expect(cardKeyService.generate).toHaveBeenCalledWith('dev-1', 'app-1', dto);
      expect(result).toEqual({
        batchId: 'b1',
        cardKeys: ['XXXX-XXXX-XXXX-XXXX'],
        count: 1,
      });
    });
  });

  describe('list', () => {
    it('应转调 service.list,page/pageSize 默认 1/20', async () => {
      await controller.list(
        'dev-1',
        'app-1',
        { page: undefined, pageSize: undefined },
        undefined,
        undefined,
        undefined,
      );
      expect(cardKeyService.list).toHaveBeenCalledWith('dev-1', 'app-1', {
        page: 1,
        pageSize: 20,
        type: undefined,
        status: undefined,
        batchId: undefined,
      });
    });

    it('应透传 type/status/batchId 筛选', async () => {
      await controller.list(
        'dev-1',
        'app-1',
        { page: 2, pageSize: 50 },
        CardKeyType.MONTH,
        'ACTIVE',
        'batch-1',
      );
      expect(cardKeyService.list).toHaveBeenCalledWith('dev-1', 'app-1', {
        page: 2,
        pageSize: 50,
        type: CardKeyType.MONTH,
        status: 'ACTIVE',
        batchId: 'batch-1',
      });
    });
  });

  describe('getById', () => {
    it('应转调 service.getById', async () => {
      const result = await controller.getById('dev-1', 'app-1', 'c1');
      expect(cardKeyService.getById).toHaveBeenCalledWith('dev-1', 'app-1', 'c1');
      expect(result).toEqual({ id: 'c1', boundDevicesCount: 0 });
    });
  });

  describe('disable', () => {
    it('应转调 service.disable', async () => {
      await controller.disable('dev-1', 'app-1', 'c1');
      expect(cardKeyService.disable).toHaveBeenCalledWith('dev-1', 'app-1', 'c1');
    });
  });

  describe('enable', () => {
    it('应转调 service.enable', async () => {
      await controller.enable('dev-1', 'app-1', 'c1');
      expect(cardKeyService.enable).toHaveBeenCalledWith('dev-1', 'app-1', 'c1');
    });
  });

  describe('unbind', () => {
    it('应转调 service.unbindDevice,从 body 取 deviceId', async () => {
      await controller.unbind('dev-1', 'app-1', 'c1', { deviceId: 'd1' });
      expect(cardKeyService.unbindDevice).toHaveBeenCalledWith('dev-1', 'app-1', 'c1', 'd1');
    });
  });

  describe('createTemplate', () => {
    it('应转调 service.createTemplate', async () => {
      const dto = {
        name: '模板',
        type: CardKeyType.MONTH,
        bindingStrategy: BindingStrategy.FIRST_BIND,
      };
      await controller.createTemplate('dev-1', 'app-1', dto);
      expect(cardKeyService.createTemplate).toHaveBeenCalledWith('dev-1', 'app-1', dto);
    });
  });

  describe('listTemplates', () => {
    it('应转调 service.listTemplates', async () => {
      await controller.listTemplates('dev-1', 'app-1');
      expect(cardKeyService.listTemplates).toHaveBeenCalledWith('dev-1', 'app-1');
    });
  });

  describe('deleteTemplate', () => {
    it('应转调 service.deleteTemplate', async () => {
      await controller.deleteTemplate('dev-1', 'app-1', 't1');
      expect(cardKeyService.deleteTemplate).toHaveBeenCalledWith('dev-1', 'app-1', 't1');
    });
  });
});
