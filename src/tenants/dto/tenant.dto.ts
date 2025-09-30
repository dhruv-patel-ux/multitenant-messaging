import { IsString, IsEmail, IsOptional, IsEnum, IsBoolean, MinLength, MaxLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { TenantStatus } from '../entities/tenant.entity';
import { UserRole } from '../../common/enums/roles.enum';

export class CreateTenantDto {
  @ApiProperty({
    description: 'Name of the tenant',
    example: 'Acme Corporation',
    minLength: 2,
    maxLength: 255,
  })
  @IsString()
  @MinLength(2)
  @MaxLength(255)
  name: string;

  @ApiProperty({
    description: 'Admin user email for the tenant',
    example: 'admin@acme.com',
  })
  @IsEmail()
  adminEmail: string;

  @ApiProperty({
    description: 'Admin user password',
    example: 'SecurePassword123!',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  adminPassword: string;

  @ApiProperty({
    description: 'Admin user first name',
    example: 'John',
  })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  adminFirstName: string;

  @ApiProperty({
    description: 'Admin user last name',
    example: 'Doe',
  })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  adminLastName: string;

  @ApiPropertyOptional({
    description: 'Initial tenant settings',
    example: { timezone: 'UTC', language: 'en' },
  })
  @IsOptional()
  settings?: Record<string, any>;
}

export class UpdateTenantDto {
  @ApiPropertyOptional({
    description: 'Name of the tenant',
    example: 'Acme Corporation Updated',
  })
  @IsOptional()
  @IsString()
  @MinLength(2)
  @MaxLength(255)
  name?: string;

  @ApiPropertyOptional({
    description: 'Tenant status',
    enum: TenantStatus,
    example: TenantStatus.ACTIVE,
  })
  @IsOptional()
  @IsEnum(TenantStatus)
  status?: TenantStatus;

  @ApiPropertyOptional({
    description: 'Tenant settings',
    example: { timezone: 'UTC', language: 'en', features: ['messaging', 'analytics'] },
  })
  @IsOptional()
  settings?: Record<string, any>;
}

export class TenantStatsDto {
  @ApiProperty({
    description: 'Total number of users in the tenant',
    example: 25,
  })
  totalUsers: number;

  @ApiProperty({
    description: 'Number of active users',
    example: 23,
  })
  activeUsers: number;

  @ApiProperty({
    description: 'Number of inactive users',
    example: 2,
  })
  inactiveUsers: number;

  @ApiProperty({
    description: 'Total number of WAHA sessions',
    example: 5,
  })
  totalSessions: number;

  @ApiProperty({
    description: 'Number of active sessions',
    example: 3,
  })
  activeSessions: number;

  @ApiProperty({
    description: 'Total number of messages sent',
    example: 1250,
  })
  totalMessages: number;

  @ApiProperty({
    description: 'Messages sent in the last 24 hours',
    example: 45,
  })
  messagesLast24h: number;

  @ApiProperty({
    description: 'Messages sent in the last 7 days',
    example: 320,
  })
  messagesLast7d: number;

  @ApiProperty({
    description: 'Messages sent in the last 30 days',
    example: 1250,
  })
  messagesLast30d: number;

  @ApiProperty({
    description: 'Tenant creation date',
    example: '2024-01-15T10:30:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Last activity date',
    example: '2024-01-20T15:45:00Z',
  })
  lastActivity: Date;
}

export class TenantResponseDto {
  @ApiProperty({
    description: 'Tenant ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
  })
  id: string;

  @ApiProperty({
    description: 'Tenant name',
    example: 'Acme Corporation',
  })
  name: string;

  @ApiProperty({
    description: 'Tenant status',
    enum: TenantStatus,
    example: TenantStatus.ACTIVE,
  })
  status: TenantStatus;

  @ApiProperty({
    description: 'Tenant settings',
    example: { timezone: 'UTC', language: 'en' },
  })
  settings: Record<string, any>;

  @ApiProperty({
    description: 'Tenant creation date',
    example: '2024-01-15T10:30:00Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Tenant last update date',
    example: '2024-01-20T15:45:00Z',
  })
  updatedAt: Date;

  @ApiPropertyOptional({
    description: 'Tenant statistics (only for current tenant)',
    type: TenantStatsDto,
  })
  stats?: TenantStatsDto;
}

export class PaginationDto {
  @ApiPropertyOptional({
    description: 'Page number (1-based)',
    example: 1,
    minimum: 1,
  })
  @IsOptional()
  page?: number = 1;

  @ApiPropertyOptional({
    description: 'Number of items per page',
    example: 10,
    minimum: 1,
    maximum: 100,
  })
  @IsOptional()
  limit?: number = 10;

  @ApiPropertyOptional({
    description: 'Search term for filtering',
    example: 'acme',
  })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional({
    description: 'Sort field',
    example: 'createdAt',
  })
  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @ApiPropertyOptional({
    description: 'Sort order',
    example: 'DESC',
    enum: ['ASC', 'DESC'],
  })
  @IsOptional()
  @IsString()
  sortOrder?: 'ASC' | 'DESC' = 'DESC';
}

export class PaginatedResponse<T> {
  @ApiProperty({
    description: 'Array of items',
    type: 'array',
  })
  data: T[];

  @ApiProperty({
    description: 'Pagination metadata',
    example: {
      page: 1,
      limit: 10,
      total: 25,
      totalPages: 3,
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

export class DeactivateTenantDto {
  @ApiProperty({
    description: 'Reason for deactivation',
    example: 'Tenant requested account closure',
  })
  @IsString()
  @MinLength(10)
  @MaxLength(500)
  reason: string;

  @ApiPropertyOptional({
    description: 'Additional notes',
    example: 'All data will be retained for 30 days',
  })
  @IsOptional()
  @IsString()
  @MaxLength(1000)
  notes?: string;
}
