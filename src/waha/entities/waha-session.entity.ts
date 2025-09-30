import { Entity, Column, ManyToOne, OneToMany, JoinColumn, Index } from 'typeorm';
import { IsString, IsEnum, IsNotEmpty, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { BaseEntity } from '../../common/entities/base.entity';
import { Tenant } from '../../tenants/entities/tenant.entity';
import { Message } from '../../messages/entities/message.entity';

export enum WahaSessionStatus {
  STARTING = 'starting',
  SCAN_QR = 'scan_qr',
  WORKING = 'working',
  FAILED = 'failed',
  STOPPED = 'stopped',
}

export enum WahaEngine {
  WEBJS = 'WEBJS',
  NOWEB = 'NOWEB',
}

@Entity('waha_sessions')
@Index(['externalSessionId'], { unique: true })
@Index(['tenantId'])
@Index(['status'])
export class WahaSession extends BaseEntity {
  @ApiProperty({
    description: 'External session ID from WAHA',
    example: 'session_123456789',
  })
  @Column({ type: 'varchar', length: 255 })
  @IsString()
  @IsNotEmpty()
  externalSessionId: string;

  @ApiProperty({
    description: 'Session status',
    enum: WahaSessionStatus,
    example: WahaSessionStatus.WORKING,
  })
  @Column({
    type: 'enum',
    enum: WahaSessionStatus,
    default: WahaSessionStatus.STARTING,
  })
  @IsEnum(WahaSessionStatus)
  status: WahaSessionStatus;

  @ApiProperty({
    description: 'WAHA engine type',
    enum: WahaEngine,
    example: WahaEngine.WEBJS,
  })
  @Column({
    type: 'enum',
    enum: WahaEngine,
    default: WahaEngine.WEBJS,
  })
  @IsEnum(WahaEngine)
  engine: WahaEngine;

  @ApiProperty({
    description: 'Session metadata including QR code and profile info',
    example: { qrCode: 'data:image/png;base64...', profileName: 'John Doe' },
    required: false,
  })
  @Column({ type: 'jsonb', nullable: true })
  @IsOptional()
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Session configuration',
    example: { webhookUrl: 'https://api.example.com/webhooks', timeout: 30000 },
    required: false,
  })
  @Column({ type: 'jsonb', nullable: true })
  @IsOptional()
  config?: Record<string, any>;

  @ApiProperty({
    description: 'Last activity timestamp',
    example: '2024-01-15T10:30:00Z',
    required: false,
  })
  @Column({ type: 'timestamp', nullable: true })
  lastActivityAt?: Date;

  @ApiProperty({
    description: 'Error message if session failed',
    example: 'Connection timeout',
    required: false,
  })
  @Column({ type: 'text', nullable: true })
  @IsString()
  @IsOptional()
  errorMessage?: string;

  // Foreign key
  @ApiProperty({
    description: 'Tenant ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @Column({ type: 'uuid' })
  @IsString()
  @IsNotEmpty()
  tenantId: string;

  // Relationships
  @ManyToOne(() => Tenant, (tenant) => tenant.wahaSessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'tenantId' })
  tenant: Tenant;

  @OneToMany(() => Message, (message) => message.session, { cascade: true })
  messages: Message[];
}