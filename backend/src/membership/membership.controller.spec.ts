import { Test } from '@nestjs/testing';
import { MembershipController } from './membership.controller';
import { MembershipService } from './membership.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuditInterceptor } from '../audit/audit.interceptor';

/**
 * MembershipController 单元测试
 *
 * 覆盖 4 个端点:
 *  - POST /developer/membership/redeem(开发者兑换)
 *  - POST /admin/membership-codes/generate(管理员生成)
 *  - GET /admin/membership-codes(管理员列表)
 *  - POST /admin/membership-codes/:id/disable(管理员禁用)
 */
describe('MembershipController', () => {
  let controller: MembershipController;
  let membershipService: {
    generate: jest.Mock;
    redeem: jest.Mock;
    list: jest.Mock;
    disable: jest.Mock;
  };

  beforeEach(async () => {
    membershipService = {
      generate: jest.fn().mockResolvedValue({
        batchId: 'batch-1',
        codes: ['CODE1', 'CODE2'],
        count: 2,
      }),
      redeem: jest.fn().mockResolvedValue({
        level: 'VIP',
        durationDays: 30,
        newVipLevel: 'VIP',
        newVipExpiresAt: new Date('2026-08-18'),
      }),
      list: jest.fn().mockResolvedValue({
        items: [{ id: 'code-1', codePrefix: 'CODE', status: 'UNUSED' }],
        total: 1,
        page: 1,
        pageSize: 20,
        totalPages: 1,
      }),
      disable: jest.fn().mockResolvedValue({ id: 'code-1', status: 'DISABLED' }),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [MembershipController],
      providers: [{ provide: MembershipService, useValue: membershipService }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideInterceptor(AuditInterceptor)
      .useValue({ intercept: (_ctx: any, next: any) => next.handle() })
      .compile();
    controller = moduleRef.get(MembershipController);
  });

  it('redeem 应转调 service.redeem', async () => {
    const dto = { code: 'TESTCODE1234' };
    const result = await controller.redeem('dev-1', dto);
    expect(membershipService.redeem).toHaveBeenCalledWith('dev-1', dto);
    expect(result.level).toBe('VIP');
  });

  it('generate 应转调 service.generate', async () => {
    const dto = { level: 'VIP', durationDays: 30, count: 2, remark: '测试' };
    const result = await controller.generate('admin-1', dto);
    expect(membershipService.generate).toHaveBeenCalledWith('admin-1', dto);
    expect(result.count).toBe(2);
    expect(result.codes).toHaveLength(2);
  });

  it('list 应转调 service.list(默认分页)', async () => {
    const result = await controller.list({} as any, undefined, undefined);
    expect(membershipService.list).toHaveBeenCalledWith({
      page: 1,
      pageSize: 20,
      status: undefined,
      batchId: undefined,
    });
    expect(result.total).toBe(1);
  });

  it('list 支持自定义分页 + 筛选', async () => {
    await controller.list(
      { page: 2, pageSize: 50 } as any,
      'UNUSED',
      'batch-1',
    );
    expect(membershipService.list).toHaveBeenCalledWith({
      page: 2,
      pageSize: 50,
      status: 'UNUSED',
      batchId: 'batch-1',
    });
  });

  it('disable 应转调 service.disable', async () => {
    const result = await controller.disable('code-1');
    expect(membershipService.disable).toHaveBeenCalledWith('code-1');
    expect(result.status).toBe('DISABLED');
  });
});
