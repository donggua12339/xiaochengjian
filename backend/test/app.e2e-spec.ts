import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { appConfig, validate } from '../src/config/configuration';
import { AllExceptionsFilter } from '../src/common/filters/all-exceptions.filter';

describe('HealthController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.DATABASE_URL =
      process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? '';
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
  });

  afterAll(async () => {
    await app.close();
  });

  it('/health (GET) should return 200 and status field', async () => {
    const res = await request(app.getHttpServer()).get('/health').expect(200);
    expect(res.body).toHaveProperty('status');
    expect(res.body).toHaveProperty('timestamp');
    // DB 可能未连接(测试环境),status 可能是 degraded
    expect(['ok', 'degraded']).toContain(res.body.status);
  });

  it('/v1/nonexistent (GET) should return 404 with standard error shape', async () => {
    const res = await request(app.getHttpServer()).get('/v1/nonexistent').expect(404);
    expect(res.body).toHaveProperty('code');
    expect(res.body).toHaveProperty('message');
    expect(res.body).toHaveProperty('requestId');
    expect(res.body).toHaveProperty('timestamp');
  });
});
