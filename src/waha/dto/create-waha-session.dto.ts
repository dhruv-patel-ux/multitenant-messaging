import { IsString, IsEnum, IsOptional, IsNotEmpty, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { WahaSessionStatus, WahaEngine } from '../entities/waha-session.entity';

export class CreateWahaSessionDto {
  @ApiProperty({
    description: 'External session ID from WAHA',
    example: 'session_123456789',
  })
  @IsString()
  @IsNotEmpty()
  externalSessionId: string;

  @ApiProperty({
    description: 'WAHA engine type',
    enum: WahaEngine,
    example: WahaEngine.WEBJS,
    required: false,
  })
  @IsEnum(WahaEngine)
  @IsOptional()
  engine?: WahaEngine;

  @ApiProperty({
    description: 'Session configuration',
    example: { webhookUrl: 'https://api.example.com/webhooks', timeout: 30000 },
    required: false,
  })
  @IsOptional()
  config?: Record<string, any>;
}

export class UpdateWahaSessionDto {
  @ApiProperty({
    description: 'Session status',
    enum: WahaSessionStatus,
    example: WahaSessionStatus.WORKING,
    required: false,
  })
  @IsEnum(WahaSessionStatus)
  @IsOptional()
  status?: WahaSessionStatus;

  @ApiProperty({
    description: 'Session metadata including QR code and profile info',
    example: { qrCode: 'data:image/png;base64...', profileName: 'John Doe' },
    required: false,
  })
  @IsOptional()
  metadata?: Record<string, any>;

  @ApiProperty({
    description: 'Session configuration',
    example: { webhookUrl: 'https://api.example.com/webhooks', timeout: 30000 },
    required: false,
  })
  @IsOptional()
  config?: Record<string, any>;

  @ApiProperty({
    description: 'Error message if session failed',
    example: 'Connection timeout',
    required: false,
  })
  @IsString()
  @IsOptional()
  errorMessage?: string;
}
