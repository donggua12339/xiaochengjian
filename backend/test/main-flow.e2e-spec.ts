import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { appConfig, validate } from '../src/config/configuration';
import { PrismaService } from '../src/prisma/prisma.service';
import { AllExceptionsFilter } from '../src/common/filters/all-exceptions.filter';

/**
 * 主流程 e2e 测试
 * 详见 ADR 0038 (测试策略) - 集成测试关键路径 100%
 *
 * 覆盖:注册 -> 登录 -> 创建应用 -> 生成卡密 -> 列出 -> 禁用 -> 删除 -> 登出
 *
 * 注意:需要 PG + Redis 运行,用真实数据库(测试后清理)
 */
describe('主流程 (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const testEmail = `e2e-${Date.now()}-${Math.floor(Math.random() * 10000)}@xcj.dev`;
  let accessToken: string;
  let refreshToken: string;
  let appId: string;
  let cardId: string;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.JWT_ACCESS_SECRET = 'test-access-secret-at-least-32-chars-long';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-at-least-32-chars-long';

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [appConfig],
          validate,
        }),
        AppModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    app.setGlobalPrefix('v1', {
      exclude: [{ path: 'health', method: 0 }],
    });
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    // 清理测试数据(PrismaService 直接操作,RLS 只在事务内 set_config 才生效)
    if (testEmail) {
      const dev = await prisma.developer.findUnique({
        where: { email: testEmail },
        select: { id: true },
      });
      if (dev) {
        // 级联删除会清理 session/application/card_key/device/audit_log
        await prisma.developer.delete({ where: { id: dev.id } });
      }
    }
    await app.close();
  });

  it('1. 注册新开发者', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/auth/register')
      .send({ email: testEmail, password: 'Password123' })
      .expect(201);
    expect(res.body).toHaveProperty('developerId');
    expect(res.body.email).toBe(testEmail);
  });

  it('2. 重复注册应 409', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/auth/register')
      .send({ email: testEmail, password: 'Password123' })
      .expect(409);
    expect(res.body.code).toBe('CONFLICT');
    expect(res.body.message).toBe('EMAIL_ALREADY_REGISTERED');
  });

  it('3. 登录(未启用 2FA,直接返回 token)', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: testEmail, password: 'Password123' })
      .expect(201);
    expect(res.body.requiresTotp).toBe(false);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
    accessToken = res.body.accessToken;
    refreshToken = res.body.refreshToken;
  });

  it('4. 登录密码错误应 401', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/auth/login')
      .send({ email: testEmail, password: 'WrongPassword' })
      .expect(401);
    expect(res.body.code).toBe('UNAUTHORIZED');
    expect(res.body.message).toBe('INVALID_CREDENTIALS');
  });

  it('5. 无 token 访问受保护接口应 401', async () => {
    await request(app.getHttpServer()).get('/v1/apps').expect(401);
  });

  it('6. 创建应用(返回明文 appSecret)', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/apps')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'E2E Test App', packageName: `com.xcj.e2e.t${Date.now()}` })
      .expect(201);
    expect(res.body.id).toBeTruthy();
    expect(res.body.appSecret).toBeTruthy();
    expect(res.body.appSecret.length).toBe(32);
    expect(res.body.appSecretPrefix).toBeTruthy();
    appId = res.body.id;
  });

  it('7. 列出应用(应只有 1 个)', async () => {
    const res = await request(app.getHttpServer())
      .get('/v1/apps')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBe(1);
    expect(res.body[0].id).toBe(appId);
  });

  it('8. 生成 10 张月卡', async () => {
    const res = await request(app.getHttpServer())
      .post(`/v1/apps/${appId}/cards/generate`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        type: 'MONTH',
        bindingStrategy: 'FIRST_BIND',
        maxDevices: 1,
        count: 10,
      })
      .expect(201);
    expect(res.body.batchId).toBeTruthy();
    expect(res.body.cardKeys).toHaveLength(10);
    expect(res.body.count).toBe(10);
    // 卡密格式应为 4x4
    for (const key of res.body.cardKeys) {
      expect(key).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    }
  });

  it('9. 列出卡密(应有 10 张)', async () => {
    const res = await request(app.getHttpServer())
      .get(`/v1/apps/${appId}/cards`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
    expect(res.body.total).toBe(10);
    expect(res.body.items).toHaveLength(10);
    cardId = res.body.items[0].id;
  });

  it('10. 禁用第一张卡密', async () => {
    const res = await request(app.getHttpServer())
      .post(`/v1/apps/${appId}/cards/${cardId}/disable`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(201);
    expect(res.body.status).toBe('DISABLED');
  });

  it('11. 启用同一张卡密', async () => {
    const res = await request(app.getHttpServer())
      .post(`/v1/apps/${appId}/cards/${cardId}/enable`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(201);
    expect(res.body.status).toBe('ACTIVE');
  });

  it('12. 更新应用(限流配置)', async () => {
    const res = await request(app.getHttpServer())
      .patch(`/v1/apps/${appId}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ rateLimitIpPerMinute: 200, offlineCacheDays: 14 })
      .expect(200);
    expect(res.body.rateLimitIpPerMinute).toBe(200);
    expect(res.body.offlineCacheDays).toBe(14);
  });

  it('13. refresh token 刷新', async () => {
    const res = await request(app.getHttpServer())
      .post('/v1/auth/refresh')
      .send({ refreshToken })
      .expect(201);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.refreshToken).toBeTruthy();
    // 旧 refresh 应已失效(rotation)
    refreshToken = res.body.refreshToken;
    accessToken = res.body.accessToken;
  });

  it('14. 登出', async () => {
    await request(app.getHttpServer())
      .post('/v1/auth/logout')
      .send({ refreshToken })
      .expect(201);
  });

  it('15. 登出后用旧 refresh 应 401', async () => {
    await request(app.getHttpServer())
      .post('/v1/auth/refresh')
      .send({ refreshToken })
      .expect(401);
  });

  it('16. 删除应用(级联清理)', async () => {
    await request(app.getHttpServer())
      .delete(`/v1/apps/${appId}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
  });
});
