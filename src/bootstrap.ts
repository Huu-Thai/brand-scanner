import {
  type INestApplication,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import {
  API_KEY_HEADER,
  API_PREFIX,
  SWAGGER_PATH,
} from './common/constants/api.constants.js';
import type { AppConfig } from './config/configuration.js';

/** Applies the HTTP pipeline. Shared by main.ts and the e2e tests so both run the same app. */
export function configureApp(app: INestApplication): void {
  const config = app.get(ConfigService<AppConfig, true>);

  app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));
  app.use(helmet({ contentSecurityPolicy: false }));
  app.setGlobalPrefix(API_PREFIX);
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: undefined });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: false },
    }),
  );
  app.enableShutdownHooks();

  if (config.get('swagger', { infer: true }).enabled) {
    const document = SwaggerModule.createDocument(
      app,
      new DocumentBuilder()
        .setTitle('Fuzzer Scanner API')
        .setDescription(
          'Typosquatting / look-alike domain discovery: trigger scans, manage scanned domains, review and score them.',
        )
        .setVersion(process.env.npm_package_version ?? '0.1.0')
        .addApiKey(
          { type: 'apiKey', name: API_KEY_HEADER, in: 'header' },
          'api-key',
        )
        .addSecurityRequirements('api-key')
        .build(),
    );
    SwaggerModule.setup(SWAGGER_PATH, app, document, {
      jsonDocumentUrl: `${SWAGGER_PATH}-json`,
      swaggerOptions: {
        persistAuthorization: true,
        tagsSorter: 'alpha',
        operationsSorter: 'method',
      },
    });
  }
}
