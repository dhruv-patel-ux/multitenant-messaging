import { IsString, IsNumber, IsOptional, IsEnum } from 'class-validator';
import { Transform } from 'class-transformer';

export enum Environment {
  Development = 'development',
  Production = 'production',
  Test = 'test',
}

export class EnvironmentVariables {
  @IsEnum(Environment)
  NODE_ENV: Environment = Environment.Development;

  @Transform(({ value }) => parseInt(value))
  @IsNumber()
  PORT: number = 3000;

  @IsString()
  API_PREFIX: string = 'api/v1';

  // Database Configuration
  @IsString()
  DB_HOST: string;

  @Transform(({ value }) => parseInt(value))
  @IsNumber()
  DB_PORT: number;

  @IsString()
  DB_USERNAME: string;

  @IsString()
  DB_PASSWORD: string;

  @IsString()
  DB_DATABASE: string;

  // JWT Configuration
  @IsString()
  JWT_SECRET: string;

  @IsString()
  JWT_EXPIRES_IN: string = '24h';

  @IsString()
  JWT_REFRESH_SECRET: string;

  @IsString()
  JWT_REFRESH_EXPIRES_IN: string = '7d';

  // WAHA Configuration
  @IsString()
  WAHA_BASE_URL: string;

  @IsString()
  WAHA_API_KEY: string;

  // Redis Configuration
  @IsString()
  REDIS_HOST: string = 'localhost';

  @Transform(({ value }) => parseInt(value))
  @IsNumber()
  REDIS_PORT: number = 6379;

  @IsOptional()
  @IsString()
  REDIS_PASSWORD?: string;

  // Webhook Configuration
  @IsString()
  WEBHOOK_SECRET: string;

  @IsOptional()
  @IsString()
  WAHA_WEBHOOK_SECRET?: string;

  // Rate Limiting
  @Transform(({ value }) => parseInt(value))
  @IsNumber()
  RATE_LIMIT_TTL: number = 60;

  @Transform(({ value }) => parseInt(value))
  @IsNumber()
  RATE_LIMIT_LIMIT: number = 100;

  // File Upload Configuration
  @Transform(({ value }) => parseInt(value))
  @IsNumber()
  MAX_FILE_SIZE: number = 10485760;

  @IsString()
  ALLOWED_FILE_TYPES: string = 'image/jpeg,image/png,image/gif,application/pdf,text/plain';

  // Logging
  @IsString()
  LOG_LEVEL: string = 'debug';

  @IsString()
  LOG_FILE: string = 'logs/app.log';
}
