import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { DesensitizeInterceptor } from './common/interceptors/desensitize.interceptor';
import type { AppConfig } from './config/configuration';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });

  const configService = app.get(ConfigService<AppConfig, true>);
  const port = configService.get('port', { infer: true }) ?? 3000;
  const corsOrigins = configService.get('corsOrigins', { infer: true }) ?? [
    'http://localhost:5173',
  ];
  const nodeEnv = configService.get('nodeEnv', { infer: true });

  // 安全头
  app.use(helmet());

  // Cookie
  app.use(cookieParser());

  // CORS
  app.enableCors({
    origin: corsOrigins,
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
  });

  // 全局管道:DTO 校验
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  // 全局过滤器:统一异常响应
  app.useGlobalFilters(new AllExceptionsFilter());

  // 全局拦截器:响应脱敏(卡密/密码/密钥)
  app.useGlobalInterceptors(new DesensitizeInterceptor());

  // API 前缀
  app.setGlobalPrefix('v1', {
    exclude: [
      { path: 'health', method: 0 },
      { path: 'metrics', method: 0 },
    ],
  });

  // Swagger(仅非生产)
  if (nodeEnv !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('小城笺 API')
      .setDescription('开源 + SaaS 双模式 Android 卡密验证系统')
      .setVersion('0.1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document);
  }

  await app.listen(port);
  Logger.log(`小城笺后端运行于 http://localhost:${port}`, 'Bootstrap');
  Logger.log(`环境: ${nodeEnv}`, 'Bootstrap');
  if (nodeEnv !== 'production') {
    Logger.log(`Swagger 文档: http://localhost:${port}/docs`, 'Bootstrap');
  }
}

bootstrap().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('启动失败:', err);
  process.exit(1);
});
