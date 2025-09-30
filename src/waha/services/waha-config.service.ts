import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from '../../config/env.validation';

export interface WahaConfig {
  baseUrl: string;
  apiKey: string;
  timeout: number;
  retryAttempts: number;
  connectionPool: {
    max: number;
    min: number;
    acquireTimeoutMillis: number;
    idleTimeoutMillis: number;
  };
  webhook: {
    secret: string;
    timeout: number;
    retryAttempts: number;
  };
}

@Injectable()
export class WahaConfigService {
  private readonly logger = new Logger(WahaConfigService.name);
  private readonly config: WahaConfig;

  constructor(private configService: ConfigService<EnvironmentVariables>) {
    this.config = this.loadConfig();
    this.logger.log('WAHA configuration loaded');
  }

  private loadConfig(): WahaConfig {
    return {
      baseUrl: this.configService.get('WAHA_BASE_URL' as keyof EnvironmentVariables) || 'http://localhost:3000',
      apiKey: this.configService.get('WAHA_API_KEY' as keyof EnvironmentVariables) || '',
      timeout: this.configService.get('WAHA_TIMEOUT' as keyof EnvironmentVariables) || 30000,
      retryAttempts: this.configService.get('WAHA_RETRY_ATTEMPTS' as keyof EnvironmentVariables) || 3,
      connectionPool: {
        max: this.configService.get('WAHA_POOL_MAX' as keyof EnvironmentVariables) || 20,
        min: this.configService.get('WAHA_POOL_MIN' as keyof EnvironmentVariables) || 5,
        acquireTimeoutMillis: this.configService.get('WAHA_POOL_ACQUIRE_TIMEOUT' as keyof EnvironmentVariables) || 30000,
        idleTimeoutMillis: this.configService.get('WAHA_POOL_IDLE_TIMEOUT' as keyof EnvironmentVariables) || 30000,
      },
      webhook: {
        secret: this.configService.get('WAHA_WEBHOOK_SECRET' as keyof EnvironmentVariables) || '',
        timeout: this.configService.get('WAHA_WEBHOOK_TIMEOUT' as keyof EnvironmentVariables) || 10000,
        retryAttempts: this.configService.get('WAHA_WEBHOOK_RETRY_ATTEMPTS' as keyof EnvironmentVariables) || 3,
      },
    };
  }

  getConfig(): WahaConfig {
    return this.config;
  }

  getBaseUrl(): string {
    return this.config.baseUrl;
  }

  getApiKey(): string {
    return this.config.apiKey;
  }

  getTimeout(): number {
    return this.config.timeout;
  }

  getRetryAttempts(): number {
    return this.config.retryAttempts;
  }

  getConnectionPool() {
    return this.config.connectionPool;
  }

  getWebhookConfig() {
    return this.config.webhook;
  }

  isConfigured(): boolean {
    return !!(this.config.baseUrl && this.config.apiKey);
  }

  validateConfig(): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!this.config.baseUrl) {
      errors.push('WAHA_BASE_URL is required');
    }

    if (!this.config.apiKey) {
      errors.push('WAHA_API_KEY is required');
    }

    if (this.config.timeout < 1000) {
      errors.push('WAHA_TIMEOUT must be at least 1000ms');
    }

    if (this.config.retryAttempts < 1) {
      errors.push('WAHA_RETRY_ATTEMPTS must be at least 1');
    }

    if (this.config.connectionPool.max < this.config.connectionPool.min) {
      errors.push('WAHA_POOL_MAX must be greater than or equal to WAHA_POOL_MIN');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}
