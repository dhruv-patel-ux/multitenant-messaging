import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom, retry, catchError, timeout } from 'rxjs';
import { AxiosResponse } from 'axios';
import { EnvironmentVariables } from '../../config/env.validation';
import {
  SessionConfig,
  SessionInfo,
  SessionStatus,
  MessageResponse,
  SendMessageDto,
  WahaHealthResponse,
} from '../dto/waha.dto';

export interface WahaApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

@Injectable()
export class WahaClientService {
  private readonly logger = new Logger(WahaClientService.name);
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly retryAttempts: number;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService<EnvironmentVariables>,
  ) {
    this.baseUrl = this.configService.get('WAHA_BASE_URL' as keyof EnvironmentVariables) || 'http://localhost:3000';
    this.apiKey = this.configService.get('WAHA_API_KEY' as keyof EnvironmentVariables) || '';
    this.timeout = this.configService.get('WAHA_TIMEOUT' as keyof EnvironmentVariables) || 30000;
    this.retryAttempts = this.configService.get('WAHA_RETRY_ATTEMPTS' as keyof EnvironmentVariables) || 3;

    this.logger.log(`WAHA Client initialized with base URL: ${this.baseUrl}`);
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    return headers;
  }

  private async makeRequest<T>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    endpoint: string,
    data?: any,
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = this.getHeaders();

    this.logger.debug(`Making ${method} request to ${url}`);

    try {
      const response = await firstValueFrom(
        this.httpService.request({
          method,
          url,
          headers,
          data,
          timeout: this.timeout,
        }).pipe(
          retry(this.retryAttempts),
          timeout(this.timeout),
          catchError((error) => {
            this.logger.error(`WAHA API request failed: ${error.message}`, error.stack);
            throw new HttpException(
              `WAHA service unavailable: ${error.message}`,
              HttpStatus.SERVICE_UNAVAILABLE,
            );
          }),
        ),
      );

      return response.data;
    } catch (error) {
      this.logger.error(`WAHA API request failed: ${error.message}`, error.stack);
      throw new HttpException(
        `WAHA service error: ${error.message}`,
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
  }

  // Core WAHA API methods
  async createSession(sessionName: string, config: SessionConfig): Promise<SessionInfo> {
    this.logger.log(`Creating WAHA session: ${sessionName}`);

    const payload = {
      name: sessionName,
      config: {
        engine: config.engine,
        webhook: config.webhookUrl ? {
          url: config.webhookUrl,
          events: config.webhookEvents || ['message', 'session.status'],
        } : undefined,
        timeout: config.timeout,
        ...config.config,
      },
    };

    const response = await this.makeRequest<WahaApiResponse<SessionInfo>>(
      'POST',
      '/api/sessions',
      payload,
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to create session: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    this.logger.log(`WAHA session created successfully: ${sessionName}`);
    if (!response.data) {
      throw new HttpException('Failed to create session: empty response payload', HttpStatus.BAD_REQUEST);
    }
    return response.data;
  }

  async startSession(sessionName: string): Promise<void> {
    this.logger.log(`Starting WAHA session: ${sessionName}`);

    const response = await this.makeRequest<WahaApiResponse>(
      'POST',
      `/api/sessions/${sessionName}/start`,
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to start session: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    this.logger.log(`WAHA session started successfully: ${sessionName}`);
  }

  async stopSession(sessionName: string): Promise<void> {
    this.logger.log(`Stopping WAHA session: ${sessionName}`);

    const response = await this.makeRequest<WahaApiResponse>(
      'POST',
      `/api/sessions/${sessionName}/stop`,
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to stop session: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    this.logger.log(`WAHA session stopped successfully: ${sessionName}`);
  }

  async getSessionStatus(sessionName: string): Promise<SessionStatus> {
    this.logger.debug(`Getting status for WAHA session: ${sessionName}`);

    const response = await this.makeRequest<WahaApiResponse<SessionStatus>>(
      'GET',
      `/api/sessions/${sessionName}/status`,
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to get session status: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!response.data) {
      throw new HttpException('Failed to get session status: empty response payload', HttpStatus.BAD_REQUEST);
    }
    return response.data;
  }

  async listSessions(): Promise<SessionInfo[]> {
    this.logger.debug('Listing WAHA sessions');

    const response = await this.makeRequest<WahaApiResponse<SessionInfo[]>>(
      'GET',
      '/api/sessions',
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to list sessions: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    return response.data || [];
  }

  async getSessionQR(sessionName: string): Promise<string> {
    this.logger.debug(`Getting QR code for WAHA session: ${sessionName}`);

    const response = await this.makeRequest<WahaApiResponse<{ qr: string }>>(
      'GET',
      `/api/sessions/${sessionName}/qr`,
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to get QR code: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!response.data?.qr) {
      throw new HttpException('Failed to get QR code: empty response payload', HttpStatus.BAD_REQUEST);
    }
    return response.data.qr;
  }

  async sendTextMessage(sessionName: string, to: string, text: string): Promise<MessageResponse> {
    this.logger.log(`Sending text message via WAHA session: ${sessionName} to ${to}`);

    const payload = {
      to,
      text,
    };

    const response = await this.makeRequest<WahaApiResponse<MessageResponse>>(
      'POST',
      `/api/sessions/${sessionName}/send/text`,
      payload,
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to send message: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    this.logger.log(`Message sent successfully via session: ${sessionName}`);
    if (!response.data) {
      throw new HttpException('Failed to send message: empty response payload', HttpStatus.BAD_REQUEST);
    }
    return response.data;
  }

  async getSessionScreen(sessionName: string): Promise<Buffer> {
    this.logger.debug(`Getting screen for WAHA session: ${sessionName}`);

    const response = await firstValueFrom(
      this.httpService.get(`/api/sessions/${sessionName}/screen`, {
        headers: this.getHeaders(),
        responseType: 'arraybuffer',
        timeout: this.timeout,
      }).pipe(
        retry(this.retryAttempts),
        timeout(this.timeout),
        catchError((error) => {
          this.logger.error(`Failed to get session screen: ${error.message}`, error.stack);
          throw new HttpException(
            `Failed to get session screen: ${error.message}`,
            HttpStatus.BAD_REQUEST,
          );
        }),
      ),
    );

    return Buffer.from(response.data);
  }

  // Health and monitoring
  async checkHealth(): Promise<boolean> {
    try {
      this.logger.debug('Checking WAHA service health');

      const response = await this.makeRequest<WahaApiResponse<WahaHealthResponse>>(
        'GET',
        '/api/health',
      );

      return response.success && response.data?.healthy === true;
    } catch (error) {
      this.logger.error(`WAHA health check failed: ${error.message}`, error.stack);
      return false;
    }
  }

  async getVersion(): Promise<string> {
    try {
      this.logger.debug('Getting WAHA service version');

      const response = await this.makeRequest<WahaApiResponse<WahaHealthResponse>>(
        'GET',
        '/api/health',
      );

      return response.data?.version || 'unknown';
    } catch (error) {
      this.logger.error(`Failed to get WAHA version: ${error.message}`, error.stack);
      return 'unknown';
    }
  }

  async getHealthInfo(): Promise<WahaHealthResponse> {
    this.logger.debug('Getting WAHA health information');

    const response = await this.makeRequest<WahaApiResponse<WahaHealthResponse>>(
      'GET',
      '/api/health',
    );

    if (!response.success) {
      throw new HttpException(
        `Failed to get health info: ${response.error || response.message}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!response.data) {
      throw new HttpException('Failed to get health info: empty response payload', HttpStatus.BAD_REQUEST);
    }
    return response.data;
  }
}
