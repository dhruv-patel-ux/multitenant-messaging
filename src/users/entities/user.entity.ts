import { Entity, Column, ManyToOne, OneToMany, JoinColumn, Index } from 'typeorm';
import { IsString, IsEnum, IsEmail, IsBoolean, IsNotEmpty, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { BaseEntity } from '../../common/entities/base.entity';
import { Tenant } from '../../tenants/entities/tenant.entity';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';

export enum UserRole {
  TENANT_ADMIN = 'TENANT_ADMIN',
  MANAGER = 'MANAGER',
  AGENT = 'AGENT',
  AUDITOR = 'AUDITOR',
}

@Entity('users')
@Index(['email', 'tenantId'], { unique: true })
@Index(['tenantId'])
export class User extends BaseEntity {
  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@acme.com',
  })
  @Column({ type: 'varchar', length: 255 })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'Hashed password',
    example: '$2b$10$...',
  })
  @Column({ type: 'varchar', length: 255 })
  @IsString()
  @IsNotEmpty()
  passwordHash: string;

  @ApiProperty({
    description: 'User first name',
    example: 'John',
    minLength: 1,
    maxLength: 50,
  })
  @Column({ type: 'varchar', length: 50 })
  @IsString()
  @IsNotEmpty()
  @Length(1, 50)
  firstName: string;

  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    minLength: 1,
    maxLength: 50,
  })
  @Column({ type: 'varchar', length: 50 })
  @IsString()
  @IsNotEmpty()
  @Length(1, 50)
  lastName: string;

  @ApiProperty({
    description: 'User role within the tenant',
    enum: UserRole,
    example: UserRole.AGENT,
  })
  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.AGENT,
  })
  @IsEnum(UserRole)
  role: UserRole;

  @ApiProperty({
    description: 'Whether the user is active',
    example: true,
  })
  @Column({ type: 'boolean', default: true })
  @IsBoolean()
  isActive: boolean;

  @ApiProperty({
    description: 'Last login timestamp',
    example: '2024-01-15T10:30:00Z',
    required: false,
  })
  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt?: Date;

  @ApiProperty({
    description: 'User preferences as JSON',
    example: { theme: 'dark', notifications: true },
    required: false,
  })
  @Column({ type: 'jsonb', nullable: true })
  preferences?: Record<string, any>;

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
  @ManyToOne(() => Tenant, (tenant) => tenant.users, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'tenantId' })
  tenant: Tenant;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user, { cascade: true })
  refreshTokens: RefreshToken[];
}