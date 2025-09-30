import { IsString, IsEnum, IsEmail, IsBoolean, IsOptional, Length, IsNotEmpty, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from '../entities/user.entity';

export class CreateUserDto {
  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@acme.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'User password',
    example: 'SecurePassword123!',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty()
  @Length(8, 100)
  password: string;

  @ApiProperty({
    description: 'User first name',
    example: 'John',
    minLength: 1,
    maxLength: 50,
  })
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
  @IsString()
  @IsNotEmpty()
  @Length(1, 50)
  lastName: string;

  @ApiProperty({
    description: 'User role within the tenant',
    enum: UserRole,
    example: UserRole.AGENT,
    required: false,
  })
  @IsEnum(UserRole)
  @IsOptional()
  role?: UserRole;

  @ApiProperty({
    description: 'Whether the user is active',
    example: true,
    required: false,
  })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;

  @ApiProperty({
    description: 'User preferences as JSON',
    example: { theme: 'dark', notifications: true },
    required: false,
  })
  @IsOptional()
  preferences?: Record<string, any>;
}

export class UpdateUserDto {
  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@acme.com',
    required: false,
  })
  @IsEmail()
  @IsOptional()
  email?: string;

  @ApiProperty({
    description: 'User password',
    example: 'SecurePassword123!',
    minLength: 8,
    required: false,
  })
  @IsString()
  @IsOptional()
  @Length(8, 100)
  password?: string;

  @ApiProperty({
    description: 'User first name',
    example: 'John',
    minLength: 1,
    maxLength: 50,
    required: false,
  })
  @IsString()
  @IsOptional()
  @Length(1, 50)
  firstName?: string;

  @ApiProperty({
    description: 'User last name',
    example: 'Doe',
    minLength: 1,
    maxLength: 50,
    required: false,
  })
  @IsString()
  @IsOptional()
  @Length(1, 50)
  lastName?: string;

  @ApiProperty({
    description: 'User role within the tenant',
    enum: UserRole,
    example: UserRole.AGENT,
    required: false,
  })
  @IsEnum(UserRole)
  @IsOptional()
  role?: UserRole;

  @ApiProperty({
    description: 'Whether the user is active',
    example: true,
    required: false,
  })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;

  @ApiProperty({
    description: 'User preferences as JSON',
    example: { theme: 'dark', notifications: true },
    required: false,
  })
  @IsOptional()
  preferences?: Record<string, any>;
}