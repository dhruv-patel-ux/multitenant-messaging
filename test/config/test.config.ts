import { ConfigModule } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';

export const createTestConfig = () => ({
  NODE_ENV: 'test',
  PORT: 3001,
  DB_HOST: 'localhost',
  DB_PORT: 5432,
  DB_USERNAME: 'postgres',
  DB_PASSWORD: 'postgres',
  DB_DATABASE: 'test_db',
  JWT_SECRET: 'test-jwt-secret-key-for-testing-only',
  JWT_EXPIRES_IN: 3600,
  JWT_REFRESH_EXPIRES_IN: 604800,
  WAHA_BASE_URL: 'http://localhost:3001',
  WAHA_API_KEY: 'test-api-key',
  WAHA_TIMEOUT: 30000,
  BCRYPT_ROUNDS: 10,
  RATE_LIMIT_MAX: 100,
  RATE_LIMIT_WINDOW: 60000,
  CORS_ORIGIN: 'http://localhost:3000',
  LOG_LEVEL: 'debug',
  LOG_FORMAT: 'json',
  TEST_TIMEOUT: 30000,
});

export const getTestModule = async (): Promise<TestingModule> => {
  return Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        load: [createTestConfig],
      }),
    ],
  }).compile();
};
