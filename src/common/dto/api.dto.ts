import { IsString, IsEnum, IsOptional, IsArray, IsDateString, IsNumber, MinLength, MaxLength, IsPhoneNumber, IsUUID, IsEmail, IsBoolean, IsObject } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { MessageStatus, MessageDirection } from '../../messages/entities/message.entity';

// Base response DTO
export class BaseResponseDto {
  @ApiProperty({
    description: 'Indicates if the request was successful',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: 'Response data',
  })
  data?: any;

  @ApiProperty({
    description: 'Response message',
    example: 'Operation completed successfully',
  })
  message?: string;
}

// Error response DTOs
export class ErrorResponseDto {
  @ApiProperty({
    description: 'Indicates if the request was successful',
    example: false,
  })
  success: boolean;

  @ApiProperty({
    description: 'HTTP status code',
    example: 400,
  })
  statusCode: number;

  @ApiProperty({
    description: 'Error message',
    example: 'Validation failed',
  })
  message: string;

  @ApiProperty({
    description: 'Error type',
    example: 'Bad Request',
  })
  error: string;

  @ApiProperty({
    description: 'Timestamp of the error',
    example: '2024-01-15T10:30:00Z',
  })
  timestamp: string;

  @ApiProperty({
    description: 'Request path',
    example: '/api/v1/messages/send',
  })
  path: string;
}

export class ValidationErrorDto {
  @ApiProperty({
    description: 'Indicates if the request was successful',
    example: false,
  })
  success: boolean;

  @ApiProperty({
    description: 'HTTP status code',
    example: 400,
  })
  statusCode: number;

  @ApiProperty({
    description: 'Validation error messages',
    type: [String],
    example: ['email must be a valid email address', 'password must be at least 8 characters'],
  })
  message: string[];

  @ApiProperty({
    description: 'Error type',
    example: 'Bad Request',
  })
  error: string;

  @ApiProperty({
    description: 'Timestamp of the error',
    example: '2024-01-15T10:30:00Z',
  })
  timestamp: string;
}

export class RateLimitErrorDto {
  @ApiProperty({
    description: 'Indicates if the request was successful',
    example: false,
  })
  success: boolean;

  @ApiProperty({
    description: 'HTTP status code',
    example: 429,
  })
  statusCode: number;

  @ApiProperty({
    description: 'Rate limit error message',
    example: 'Too many requests. Please try again later.',
  })
  message: string;

  @ApiProperty({
    description: 'Error type',
    example: 'Too Many Requests',
  })
  error: string;

  @ApiProperty({
    description: 'Seconds to wait before retrying',
    example: 60,
  })
  retryAfter: number;

  @ApiProperty({
    description: 'Timestamp of the error',
    example: '2024-01-15T10:30:00Z',
  })
  timestamp: string;
}

// Authentication DTOs
export class LoginDto {
  @ApiProperty({
    description: 'User email address',
    example: 'admin@company.com',
    format: 'email',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'SecurePass123!',
    minLength: 8,
    maxLength: 128,
  })
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  password: string;
}

export class AuthResponseDto {
  @ApiProperty({
    description: 'JWT access token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken: string;

  @ApiProperty({
    description: 'JWT refresh token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  refreshToken: string;

  @ApiProperty({
    description: 'Token expiration time in seconds',
    example: 3600,
  })
  expiresIn: number;

  @ApiProperty({
    description: 'User information',
    type: 'object',
    example: {
      id: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
      email: 'admin@company.com',
      role: 'TENANT_ADMIN',
      tenantId: 'tenant-123',
    },
  })
  user: {
    id: string;
    email: string;
    role: string;
    tenantId: string;
  };
}

export class RefreshTokenDto {
  @ApiProperty({
    description: 'JWT refresh token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString()
  refreshToken: string;
}

// Message DTOs
export class SendMessageDto {
  @ApiProperty({
    description: 'WAHA session ID to send message through',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    format: 'uuid',
  })
  @IsUUID()
  sessionId: string;

  @ApiProperty({
    description: 'Recipient phone number with country code',
    example: '+1234567890',
    pattern: '^\\+[1-9]\\d{1,14}$',
  })
  @IsString()
  @IsPhoneNumber(undefined, { message: 'Invalid phone number format' })
  to: string;

  @ApiProperty({
    description: 'Message content',
    example: 'Hello from the messaging API!',
    minLength: 1,
    maxLength: 4096,
  })
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  body: string;

  @ApiPropertyOptional({
    description: 'Message priority',
    enum: ['high', 'normal', 'low'],
    example: 'normal',
    default: 'normal',
  })
  @IsOptional()
  @IsEnum(['high', 'normal', 'low'])
  priority?: 'high' | 'normal' | 'low' = 'normal';

  @ApiPropertyOptional({
    description: 'Message metadata',
    example: { campaignId: 'campaign-123', tags: ['marketing'] },
    type: 'object',
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}

export class BulkMessageDto {
  @ApiProperty({
    description: 'WAHA session ID to send messages through',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    format: 'uuid',
  })
  @IsUUID()
  sessionId: string;

  @ApiProperty({
    description: 'List of recipient phone numbers',
    example: ['+1234567890', '+0987654321'],
    type: [String],
    minItems: 1,
    maxItems: 1000,
  })
  @IsArray()
  @IsString({ each: true })
  @IsPhoneNumber(undefined, { each: true, message: 'Invalid phone number format' })
  recipients: string[];

  @ApiProperty({
    description: 'Message content for all recipients',
    example: 'Bulk notification message',
    minLength: 1,
    maxLength: 4096,
  })
  @IsString()
  @MinLength(1)
  @MaxLength(4096)
  body: string;

  @ApiPropertyOptional({
    description: 'Batch size for processing',
    example: 10,
    minimum: 1,
    maximum: 50,
    default: 10,
  })
  @IsOptional()
  @IsNumber()
  batchSize?: number = 10;

  @ApiPropertyOptional({
    description: 'Message priority',
    enum: ['high', 'normal', 'low'],
    example: 'normal',
    default: 'normal',
  })
  @IsOptional()
  @IsEnum(['high', 'normal', 'low'])
  priority?: 'high' | 'normal' | 'low' = 'normal';

  @ApiPropertyOptional({
    description: 'Message metadata',
    example: { campaignId: 'campaign-123', tags: ['marketing'] },
    type: 'object',
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}

export class MessageFiltersDto {
  @ApiPropertyOptional({
    description: 'Filter by session ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    format: 'uuid',
  })
  @IsOptional()
  @IsUUID()
  sessionId?: string;

  @ApiPropertyOptional({
    description: 'Filter by message direction',
    enum: MessageDirection,
    example: MessageDirection.OUTBOUND,
  })
  @IsOptional()
  @IsEnum(MessageDirection)
  direction?: MessageDirection;

  @ApiPropertyOptional({
    description: 'Filter by message status',
    enum: MessageStatus,
    example: MessageStatus.SENT,
  })
  @IsOptional()
  @IsEnum(MessageStatus)
  status?: MessageStatus;

  @ApiPropertyOptional({
    description: 'Filter from date (ISO string)',
    example: '2024-01-01T00:00:00Z',
    format: 'date-time',
  })
  @IsOptional()
  @IsDateString()
  fromDate?: string;

  @ApiPropertyOptional({
    description: 'Filter to date (ISO string)',
    example: '2024-01-31T23:59:59Z',
    format: 'date-time',
  })
  @IsOptional()
  @IsDateString()
  toDate?: string;

  @ApiPropertyOptional({
    description: 'Search in phone numbers or message content',
    example: 'john',
    minLength: 1,
    maxLength: 100,
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  search?: string;

  @ApiPropertyOptional({
    description: 'Page number (1-based)',
    example: 1,
    minimum: 1,
    default: 1,
  })
  @IsOptional()
  @IsNumber()
  page?: number = 1;

  @ApiPropertyOptional({
    description: 'Number of items per page',
    example: 20,
    minimum: 1,
    maximum: 100,
    default: 20,
  })
  @IsOptional()
  @IsNumber()
  limit?: number = 20;
}

export class DateRangeDto {
  @ApiProperty({
    description: 'Start date (ISO string)',
    example: '2024-01-01T00:00:00Z',
    format: 'date-time',
  })
  @IsDateString()
  fromDate: string;

  @ApiProperty({
    description: 'End date (ISO string)',
    example: '2024-01-31T23:59:59Z',
    format: 'date-time',
  })
  @IsDateString()
  toDate: string;
}

export class MessageStatsDto {
  @ApiProperty({
    description: 'Total messages in the period',
    example: 1250,
  })
  totalMessages: number;

  @ApiProperty({
    description: 'Outbound messages sent',
    example: 1000,
  })
  outboundMessages: number;

  @ApiProperty({
    description: 'Inbound messages received',
    example: 250,
  })
  inboundMessages: number;

  @ApiProperty({
    description: 'Messages by status',
    example: {
      queued: 50,
      sent: 900,
      delivered: 800,
      failed: 100,
    },
    type: 'object',
  })
  messagesByStatus: Record<MessageStatus, number>;

  @ApiProperty({
    description: 'Messages by day',
    example: [
      { date: '2024-01-01', count: 100 },
      { date: '2024-01-02', count: 150 },
    ],
    type: 'array',
    items: {
      type: 'object',
      properties: {
        date: { type: 'string', format: 'date' },
        count: { type: 'number' },
      },
    },
  })
  messagesByDay: Array<{ date: string; count: number }>;

  @ApiProperty({
    description: 'Average messages per day',
    example: 40.3,
  })
  averagePerDay: number;

  @ApiProperty({
    description: 'Success rate percentage',
    example: 88.5,
  })
  successRate: number;

  @ApiProperty({
    description: 'Date range for statistics',
    example: {
      fromDate: '2024-01-01T00:00:00Z',
      toDate: '2024-01-31T23:59:59Z',
    },
    type: 'object',
  })
  dateRange: {
    fromDate: string;
    toDate: string;
  };
}

export class BulkMessageResponseDto {
  @ApiProperty({
    description: 'Total messages queued',
    example: 100,
  })
  totalQueued: number;

  @ApiProperty({
    description: 'Successfully queued messages',
    example: 95,
  })
  successCount: number;

  @ApiProperty({
    description: 'Failed to queue messages',
    example: 5,
  })
  failureCount: number;

  @ApiProperty({
    description: 'Batch processing information',
    example: {
      totalBatches: 10,
      batchSize: 10,
      estimatedProcessingTime: '5 minutes',
    },
    type: 'object',
  })
  batchInfo: {
    totalBatches: number;
    batchSize: number;
    estimatedProcessingTime: string;
  };

  @ApiProperty({
    description: 'Failed phone numbers',
    example: ['+invalid1', '+invalid2'],
    type: [String],
  })
  failedRecipients: string[];

  @ApiProperty({
    description: 'Bulk message ID for tracking',
    example: 'bulk-msg-123456',
  })
  bulkMessageId: string;
}

export class MessageResponseDto {
  @ApiProperty({
    description: 'Message ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    format: 'uuid',
  })
  id: string;

  @ApiProperty({
    description: 'Session ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    format: 'uuid',
  })
  sessionId: string;

  @ApiProperty({
    description: 'Message direction',
    enum: MessageDirection,
    example: MessageDirection.OUTBOUND,
  })
  direction: MessageDirection;

  @ApiProperty({
    description: 'Recipient phone number',
    example: '+1234567890',
  })
  toMsisdn: string;

  @ApiProperty({
    description: 'Sender phone number',
    example: '+0987654321',
  })
  fromMsisdn: string;

  @ApiProperty({
    description: 'Message content',
    example: 'Hello, this is a test message',
  })
  body: string;

  @ApiProperty({
    description: 'Message status',
    enum: MessageStatus,
    example: MessageStatus.SENT,
  })
  status: MessageStatus;

  @ApiPropertyOptional({
    description: 'WAHA message ID',
    example: 'waha_msg_123456',
  })
  wahaMessageId?: string;

  @ApiPropertyOptional({
    description: 'Message priority',
    example: 'normal',
  })
  priority?: string;

  @ApiPropertyOptional({
    description: 'Message metadata',
    example: { campaignId: 'campaign-123' },
    type: 'object',
  })
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Message creation date',
    example: '2024-01-15T10:30:00Z',
    format: 'date-time',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Message last update date',
    example: '2024-01-15T10:30:00Z',
    format: 'date-time',
  })
  updatedAt: Date;
}

export class PaginatedResponseDto<T> {
  @ApiProperty({
    description: 'Response data',
    type: 'array',
  })
  data: T[];

  @ApiProperty({
    description: 'Pagination information',
    type: 'object',
    example: {
      page: 1,
      limit: 20,
      total: 100,
      totalPages: 5,
      hasNext: true,
      hasPrev: false,
    },
  })
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

// Webhook DTOs
export class WahaWebhookPayload {
  @ApiProperty({
    description: 'WAHA event type',
    example: 'message.text',
    enum: [
      'message.any',
      'message.text',
      'message.image',
      'message.document',
      'message.status',
      'session.status',
      'session.qr',
      'session.failed',
      'api.error',
    ],
  })
  event: string;

  @ApiProperty({
    description: 'WAHA session name',
    example: 'main-session',
  })
  session: string;

  @ApiProperty({
    description: 'Event payload',
    type: 'object',
    example: {
      id: 'waha_msg_123456',
      from: '+1234567890',
      to: '+0987654321',
      body: 'Hello, this is a test message',
      timestamp: 1642248600000,
      type: 'text',
    },
  })
  payload: {
    id?: string;
    from?: string;
    to?: string;
    body?: string;
    timestamp?: number;
    status?: string;
    type?: string;
    metadata?: any;
  };
}

export class WebhookResponseDto {
  @ApiProperty({
    description: 'Indicates if webhook was processed successfully',
    example: true,
  })
  success: boolean;

  @ApiProperty({
    description: 'Response message',
    example: 'Webhook processed successfully',
  })
  message: string;
}

export class HealthResponseDto {
  @ApiProperty({
    description: 'Service status',
    example: 'healthy',
  })
  status: string;

  @ApiProperty({
    description: 'Service timestamp',
    example: '2024-01-15T10:30:00Z',
    format: 'date-time',
  })
  timestamp: string;

  @ApiProperty({
    description: 'Service name',
    example: 'messaging-api',
  })
  service: string;
}
