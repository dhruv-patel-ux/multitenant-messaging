import { IsString, IsEnum, IsOptional, Length, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { TenantStatus } from '../entities/tenant.entity';

export class CreateTenantDto {
  @ApiProperty({
    description: 'Tenant name',
    example: 'Acme Corporation',
    minLength: 2,
    maxLength: 100,
  })
  @IsString()
  @IsNotEmpty()
  @Length(2, 100)
  name: string;

  @ApiProperty({
    description: 'Tenant status',
    enum: TenantStatus,
    example: TenantStatus.ACTIVE,
    required: false,
  })
  @IsEnum(TenantStatus)
  @IsOptional()
  status?: TenantStatus;

  @ApiProperty({
    description: 'Tenant description',
    example: 'A leading technology company',
    required: false,
  })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({
    description: 'Tenant settings as JSON',
    example: { maxUsers: 100, features: ['messaging', 'analytics'] },
    required: false,
  })
  @IsOptional()
  settings?: Record<string, any>;
}

export class UpdateTenantDto {
  @ApiProperty({
    description: 'Tenant name',
    example: 'Acme Corporation',
    minLength: 2,
    maxLength: 100,
    required: false,
  })
  @IsString()
  @IsOptional()
  @Length(2, 100)
  name?: string;

  @ApiProperty({
    description: 'Tenant status',
    enum: TenantStatus,
    example: TenantStatus.ACTIVE,
    required: false,
  })
  @IsEnum(TenantStatus)
  @IsOptional()
  status?: TenantStatus;

  @ApiProperty({
    description: 'Tenant description',
    example: 'A leading technology company',
    required: false,
  })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({
    description: 'Tenant settings as JSON',
    example: { maxUsers: 100, features: ['messaging', 'analytics'] },
    required: false,
  })
  @IsOptional()
  settings?: Record<string, any>;
}