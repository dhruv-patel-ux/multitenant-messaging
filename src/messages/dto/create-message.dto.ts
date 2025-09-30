import { IsString, IsEnum, IsOptional, IsNotEmpty, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { MessageDirection, MessageStatus } from '../entities/message.entity';

export class CreateMessageDto {
  @ApiProperty({
    description: 'Message direction',
    enum: MessageDirection,
    example: MessageDirection.OUTBOUND,
  })
  @IsEnum(MessageDirection)
  @IsNotEmpty()
  direction: MessageDirection;

  @ApiProperty({
    description: 'Recipient phone number',
    example: '+1234567890',
  })
  @IsString()
  @IsNotEmpty()
  toMsisdn: string;

  @ApiProperty({
    description: 'Sender phone number',
    example: '+1234567890',
  })
  @IsString()
  @IsNotEmpty()
  fromMsisdn: string;

  @ApiProperty({
    description: 'Message body content',
    example: 'Hello, this is a test message',
  })
  @IsString()
  @IsNotEmpty()
  body: string;

  @ApiProperty({
    description: 'WAHA Session ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsUUID()
  @IsNotEmpty()
  sessionId: string;

  @ApiProperty({
    description: 'Message type',
    example: 'text',
    required: false,
  })
  @IsString()
  @IsOptional()
  messageType?: string;

  @ApiProperty({
    description: 'Media URL for media messages',
    example: 'https://example.com/image.jpg',
    required: false,
  })
  @IsString()
  @IsOptional()
  mediaUrl?: string;

  @ApiProperty({
    description: 'Message metadata',
    example: { replyTo: 'msg_123', forwarded: true },
    required: false,
  })
  @IsOptional()
  metadata?: Record<string, any>;
}

export class UpdateMessageDto {
  @ApiProperty({
    description: 'Message status',
    enum: MessageStatus,
    example: MessageStatus.DELIVERED,
    required: false,
  })
  @IsEnum(MessageStatus)
  @IsOptional()
  status?: MessageStatus;

  @ApiProperty({
    description: 'WAHA message ID',
    example: 'msg_123456789',
    required: false,
  })
  @IsString()
  @IsOptional()
  wahaMessageId?: string;

  @ApiProperty({
    description: 'Raw payload from WAHA',
    example: { id: 'msg_123', timestamp: 1642248000 },
    required: false,
  })
  @IsOptional()
  rawPayload?: Record<string, any>;

  @ApiProperty({
    description: 'Error message if message failed',
    example: 'Invalid phone number',
    required: false,
  })
  @IsString()
  @IsOptional()
  errorMessage?: string;

  @ApiProperty({
    description: 'Delivery timestamp',
    example: '2024-01-15T10:30:00Z',
    required: false,
  })
  @IsOptional()
  deliveredAt?: Date;
}