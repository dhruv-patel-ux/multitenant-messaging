import { Entity, Column, ManyToOne, JoinColumn, Index } from 'typeorm';
import { IsString, IsEnum, IsNotEmpty, IsOptional, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { BaseEntity } from '../../common/entities/base.entity';
import { Tenant } from '../../tenants/entities/tenant.entity';
import { WahaSession } from '../../waha/entities/waha-session.entity';

export enum MessageDirection {
  INBOUND = 'inbound',
  OUTBOUND = 'outbound',
}

export enum MessageStatus {
  QUEUED = 'queued',
  SENT = 'sent',
  DELIVERED = 'delivered',
  FAILED = 'failed',
}

@Entity('messages')
@Index(['tenantId'])
@Index(['sessionId'])
@Index(['toMsisdn'])
@Index(['fromMsisdn'])
@Index(['status'])
@Index(['createdAt'])
@Index(['wahaMessageId'], { unique: true, where: 'wahaMessageId IS NOT NULL' })
export class Message extends BaseEntity {
  @ApiProperty({
    description: 'Message direction',
    enum: MessageDirection,
    example: MessageDirection.OUTBOUND,
  })
  @Column({
    type: 'enum',
    enum: MessageDirection,
  })
  @IsEnum(MessageDirection)
  direction: MessageDirection;

  @ApiProperty({
    description: 'Recipient phone number',
    example: '+1234567890',
  })
  @Column({ type: 'varchar', length: 20 })
  @IsString()
  @IsNotEmpty()
  toMsisdn: string;

  @ApiProperty({
    description: 'Sender phone number',
    example: '+1234567890',
  })
  @Column({ type: 'varchar', length: 20 })
  @IsString()
  @IsNotEmpty()
  fromMsisdn: string;

  @ApiProperty({
    description: 'Message body content',
    example: 'Hello, this is a test message',
  })
  @Column({ type: 'text' })
  @IsString()
  @IsNotEmpty()
  body: string;

  @ApiProperty({
    description: 'Message status',
    enum: MessageStatus,
    example: MessageStatus.DELIVERED,
  })
  @Column({
    type: 'enum',
    enum: MessageStatus,
    default: MessageStatus.QUEUED,
  })
  @IsEnum(MessageStatus)
  status: MessageStatus;

  @ApiProperty({
    description: 'WAHA message ID',
    example: 'msg_123456789',
    required: false,
  })
  @Column({ type: 'varchar', length: 255, nullable: true })
  @IsString()
  @IsOptional()
  wahaMessageId?: string;

  @ApiProperty({
    description: 'Raw payload from WAHA',
    example: { id: 'msg_123', timestamp: 1642248000 },
    required: false,
  })
  @Column({ type: 'jsonb', nullable: true })
  @IsOptional()
  rawPayload?: Record<string, any>;

  @ApiProperty({
    description: 'Message type',
    example: 'text',
    required: false,
  })
  @Column({ type: 'varchar', length: 50, nullable: true })
  @IsString()
  @IsOptional()
  messageType?: string;

  @ApiProperty({
    description: 'Media URL for media messages',
    example: 'https://example.com/image.jpg',
    required: false,
  })
  @Column({ type: 'varchar', length: 500, nullable: true })
  @IsString()
  @IsOptional()
  mediaUrl?: string;

  @ApiProperty({
    description: 'Message metadata',
    example: { replyTo: 'msg_123', forwarded: true },
    required: false,
  })
  @Column({ type: 'jsonb', nullable: true })
  @IsOptional()
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Error message if message failed',
    example: 'Invalid phone number',
    required: false,
  })
  @Column({ type: 'text', nullable: true })
  @IsString()
  @IsOptional()
  errorMessage?: string;

  @ApiProperty({
    description: 'Delivery timestamp',
    example: '2024-01-15T10:30:00Z',
    required: false,
  })
  @Column({ type: 'timestamp', nullable: true })
  deliveredAt?: Date;

  // Foreign keys
  @ApiProperty({
    description: 'Tenant ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @Column({ type: 'uuid' })
  @IsUUID()
  @IsNotEmpty()
  tenantId: string;

  @ApiProperty({
    description: 'WAHA Session ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @Column({ type: 'uuid' })
  @IsUUID()
  @IsNotEmpty()
  sessionId: string;

  // Relationships
  @ManyToOne(() => Tenant, (tenant) => tenant.messages, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'tenantId' })
  tenant: Tenant;

  @ManyToOne(() => WahaSession, (session) => session.messages, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sessionId' })
  session: WahaSession;
}