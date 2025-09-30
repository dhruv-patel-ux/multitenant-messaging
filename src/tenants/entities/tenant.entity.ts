import { Entity, Column, OneToMany, Index } from 'typeorm';
import { IsString, IsEnum, IsNotEmpty, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { BaseEntity } from '../../common/entities/base.entity';
import { User } from '../../users/entities/user.entity';
import { WahaSession } from '../../waha/entities/waha-session.entity';
import { Message } from '../../messages/entities/message.entity';

export enum TenantStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
}

@Entity('tenants')
@Index(['name'], { unique: true })
export class Tenant extends BaseEntity {
  @ApiProperty({
    description: 'Tenant name',
    example: 'Acme Corporation',
    minLength: 2,
    maxLength: 100,
  })
  @Column({ type: 'varchar', length: 100 })
  @IsString()
  @IsNotEmpty()
  @Length(2, 100)
  name: string;

  @ApiProperty({
    description: 'Tenant status',
    enum: TenantStatus,
    example: TenantStatus.ACTIVE,
  })
  @Column({
    type: 'enum',
    enum: TenantStatus,
    default: TenantStatus.ACTIVE,
  })
  @IsEnum(TenantStatus)
  status: TenantStatus;

  @ApiProperty({
    description: 'Tenant description',
    example: 'A leading technology company',
    required: false,
  })
  @Column({ type: 'text', nullable: true })
  @IsString()
  description?: string;

  @ApiProperty({
    description: 'Tenant settings as JSON',
    example: { maxUsers: 100, features: ['messaging', 'analytics'] },
    required: false,
  })
  @Column({ type: 'jsonb', nullable: true })
  settings?: Record<string, any>;

  // Relationships
  @OneToMany(() => User, (user) => user.tenant, { cascade: true })
  users: User[];

  @OneToMany(() => WahaSession, (session) => session.tenant, { cascade: true })
  wahaSessions: WahaSession[];

  @OneToMany(() => Message, (message) => message.tenant, { cascade: true })
  messages: Message[];
}