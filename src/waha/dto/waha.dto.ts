import { IsString, IsEnum, IsOptional, IsBoolean, IsObject, IsUrl, MinLength, MaxLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { WahaEngine, WahaSessionStatus } from '../entities/waha-session.entity';

export class SessionConfig {
  @ApiProperty({
    description: 'WAHA engine type',
    enum: WahaEngine,
    example: WahaEngine.WEBJS,
  })
  @IsEnum(WahaEngine)
  engine: WahaEngine;

  @ApiPropertyOptional({
    description: 'Webhook URL for session events',
    example: 'https://api.example.com/webhooks/waha',
  })
  @IsOptional()
  @IsUrl()
  webhookUrl?: string;

  @ApiPropertyOptional({
    description: 'Webhook events to subscribe to',
    example: ['message', 'session.status'],
  })
  @IsOptional()
  @IsString({ each: true })
  webhookEvents?: string[];

  @ApiPropertyOptional({
    description: 'Session timeout in seconds',
    example: 3600,
  })
  @IsOptional()
  timeout?: number;

  @ApiPropertyOptional({
    description: 'Additional session configuration',
    example: { proxy: 'http://proxy:8080' },
  })
  @IsOptional()
  @IsObject()
  config?: Record<string, any>;
}

export class CreateSessionDto {
  @ApiProperty({
    description: 'Session name (unique per tenant)',
    example: 'main-session',
    minLength: 3,
    maxLength: 50,
  })
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  sessionName: string;

  @ApiProperty({
    description: 'WAHA engine type',
    enum: WahaEngine,
    example: WahaEngine.WEBJS,
  })
  @IsEnum(WahaEngine)
  engine: WahaEngine;

  @ApiPropertyOptional({
    description: 'Webhook URL for session events',
    example: 'https://api.example.com/webhooks/waha',
  })
  @IsOptional()
  @IsUrl()
  webhookUrl?: string;

  @ApiPropertyOptional({
    description: 'Webhook events to subscribe to',
    example: ['message', 'session.status'],
  })
  @IsOptional()
  @IsString({ each: true })
  webhookEvents?: string[];

  @ApiPropertyOptional({
    description: 'Additional session configuration',
    example: { proxy: 'http://proxy:8080' },
  })
  @IsOptional()
  @IsObject()
  config?: Record<string, any>;
}

export class SessionInfo {
  @ApiProperty({
    description: 'Session name',
    example: 'main-session',
  })
  name: string;

  @ApiProperty({
    description: 'Session status',
    enum: WahaSessionStatus,
    example: WahaSessionStatus.WORKING,
  })
  status: WahaSessionStatus;

  @ApiProperty({
    description: 'Session engine',
    enum: WahaEngine,
    example: WahaEngine.WEBJS,
  })
  engine: WahaEngine;

  @ApiPropertyOptional({
    description: 'Session metadata',
    example: { profileName: 'My WhatsApp' },
  })
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Session creation date',
    example: '2024-01-15T10:30:00Z',
  })
  createdAt: Date;
}

export class SessionStatus {
  @ApiProperty({
    description: 'Session name',
    example: 'main-session',
  })
  name: string;

  @ApiProperty({
    description: 'Session status',
    enum: WahaSessionStatus,
    example: WahaSessionStatus.WORKING,
  })
  status: WahaSessionStatus;

  @ApiPropertyOptional({
    description: 'Session metadata',
    example: { profileName: 'My WhatsApp', phoneNumber: '+1234567890' },
  })
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Last status update',
    example: '2024-01-15T10:30:00Z',
  })
  lastUpdate: Date;
}

export class MessageResponse {
  @ApiProperty({
    description: 'Message ID from WAHA',
    example: 'waha_msg_123456',
  })
  messageId: string;

  @ApiProperty({
    description: 'Message status',
    example: 'sent',
  })
  status: string;

  @ApiProperty({
    description: 'Recipient phone number',
    example: '+1234567890',
  })
  to: string;

  @ApiProperty({
    description: 'Message content',
    example: 'Hello, this is a test message',
  })
  text: string;

  @ApiProperty({
    description: 'Message timestamp',
    example: '2024-01-15T10:30:00Z',
  })
  timestamp: Date;
}

export class SendMessageDto {
  @ApiProperty({
    description: 'Recipient phone number (with country code)',
    example: '+1234567890',
  })
  @IsString()
  to: string;

  @ApiProperty({
    description: 'Message text content',
    example: 'Hello, this is a test message',
  })
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  text: string;

  @ApiPropertyOptional({
    description: 'Message metadata',
    example: { priority: 'high' },
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}

export class WahaHealthResponse {
  @ApiProperty({
    description: 'WAHA service health status',
    example: true,
  })
  healthy: boolean;

  @ApiProperty({
    description: 'WAHA service version',
    example: '1.0.0',
  })
  version: string;

  @ApiProperty({
    description: 'WAHA service uptime',
    example: '2d 5h 30m',
  })
  uptime: string;

  @ApiProperty({
    description: 'Active sessions count',
    example: 5,
  })
  activeSessions: number;

  @ApiProperty({
    description: 'Health check timestamp',
    example: '2024-01-15T10:30:00Z',
  })
  timestamp: Date;
}

export class SessionResponseDto {
  @ApiProperty({
    description: 'Session ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
  })
  id: string;

  @ApiProperty({
    description: 'External session ID from WAHA',
    example: 'waha-session-123',
  })
  externalSessionId: string;

  @ApiProperty({
    description: 'Session status',
    enum: WahaSessionStatus,
    example: WahaSessionStatus.WORKING,
  })
  status: WahaSessionStatus;

  @ApiProperty({
    description: 'Session engine',
    enum: WahaEngine,
    example: WahaEngine.WEBJS,
  })
  engine: WahaEngine;

  @ApiPropertyOptional({
    description: 'Session metadata',
    example: { profileName: 'My WhatsApp', phoneNumber: '+1234567890' },
  })
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Tenant ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
  })
  tenantId: string;

  @ApiProperty({
    description: 'Session creation date',
    example: '2024-01-15T10:30:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Session last update date',
    example: '2024-01-15T10:30:00Z',
  })
  updatedAt: Date;
}
