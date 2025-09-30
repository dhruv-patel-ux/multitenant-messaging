import { IsString, IsEnum, IsOptional, IsArray, IsDateString, IsNumber, MinLength, MaxLength, IsPhoneNumber, IsUUID } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { MessageStatus, MessageDirection } from '../entities/message.entity';

export class SendMessageDto {
  @ApiProperty({
    description: 'WAHA session ID to send message through',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
  })
  @IsUUID()
  sessionId: string;

  @ApiProperty({
    description: 'Recipient phone number with country code',
    example: '+1234567890',
  })
  @IsString()
  @IsPhoneNumber(undefined, { message: 'Invalid phone number format' })
  to: string;

  @ApiProperty({
    description: 'Message content',
    example: 'Hello, this is a test message',
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
  })
  @IsOptional()
  @IsEnum(['high', 'normal', 'low'])
  priority?: 'high' | 'normal' | 'low' = 'normal';

  @ApiPropertyOptional({
    description: 'Message metadata',
    example: { campaignId: 'campaign-123', tags: ['marketing'] },
  })
  @IsOptional()
  metadata?: Record<string, any>;
}

export class BulkMessageDto {
  @ApiProperty({
    description: 'WAHA session ID to send messages through',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
  })
  @IsUUID()
  sessionId: string;

  @ApiProperty({
    description: 'List of recipient phone numbers',
    example: ['+1234567890', '+0987654321'],
    type: [String],
  })
  @IsArray()
  @IsString({ each: true })
  @IsPhoneNumber(undefined, { each: true, message: 'Invalid phone number format' })
  recipients: string[];

  @ApiProperty({
    description: 'Message content for all recipients',
    example: 'Hello, this is a bulk message',
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
  })
  @IsOptional()
  @IsNumber()
  batchSize?: number = 10;

  @ApiPropertyOptional({
    description: 'Message priority',
    enum: ['high', 'normal', 'low'],
    example: 'normal',
  })
  @IsOptional()
  @IsEnum(['high', 'normal', 'low'])
  priority?: 'high' | 'normal' | 'low' = 'normal';

  @ApiPropertyOptional({
    description: 'Message metadata',
    example: { campaignId: 'campaign-123', tags: ['marketing'] },
  })
  @IsOptional()
  metadata?: Record<string, any>;
}

export class MessageFiltersDto {
  @ApiPropertyOptional({
    description: 'Filter by session ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
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
  })
  @IsOptional()
  @IsDateString()
  fromDate?: string;

  @ApiPropertyOptional({
    description: 'Filter to date (ISO string)',
    example: '2024-01-31T23:59:59Z',
  })
  @IsOptional()
  @IsDateString()
  toDate?: string;

  @ApiPropertyOptional({
    description: 'Search in phone numbers or message content',
    example: 'john',
  })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional({
    description: 'Page number (1-based)',
    example: 1,
    minimum: 1,
  })
  @IsOptional()
  @IsNumber()
  page?: number = 1;

  @ApiPropertyOptional({
    description: 'Number of items per page',
    example: 20,
    minimum: 1,
    maximum: 100,
  })
  @IsOptional()
  @IsNumber()
  limit?: number = 20;
}

export class DateRangeDto {
  @ApiProperty({
    description: 'Start date (ISO string)',
    example: '2024-01-01T00:00:00Z',
  })
  @IsDateString()
  fromDate: string;

  @ApiProperty({
    description: 'End date (ISO string)',
    example: '2024-01-31T23:59:59Z',
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
  })
  messagesByStatus: Record<MessageStatus, number>;

  @ApiProperty({
    description: 'Messages by day',
    example: [
      { date: '2024-01-01', count: 100 },
      { date: '2024-01-02', count: 150 },
    ],
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
  })
  batchInfo: {
    totalBatches: number;
    batchSize: number;
    estimatedProcessingTime: string;
  };

  @ApiProperty({
    description: 'Failed phone numbers',
    example: ['+invalid1', '+invalid2'],
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
  })
  id: string;

  @ApiProperty({
    description: 'Session ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
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

  @ApiProperty({
    description: 'WAHA message ID',
    example: 'waha_msg_123456',
  })
  wahaMessageId?: string;

  @ApiProperty({
    description: 'Message priority',
    example: 'normal',
  })
  priority?: string;

  @ApiProperty({
    description: 'Message metadata',
    example: { campaignId: 'campaign-123' },
  })
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Message creation date',
    example: '2024-01-15T10:30:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Message last update date',
    example: '2024-01-15T10:30:00Z',
  })
  updatedAt: Date;
}

export class WahaInboundPayload {
  @ApiProperty({
    description: 'WAHA event type',
    example: 'message.text',
  })
  event: string;

  @ApiProperty({
    description: 'WAHA session name',
    example: 'main-session',
  })
  session: string;

  @ApiProperty({
    description: 'Message payload',
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
    id: string;
    from: string;
    to: string;
    body: string;
    timestamp: number;
    type: string;
    metadata?: any;
  };
}
