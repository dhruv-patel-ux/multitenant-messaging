import { Entity, Column, Index } from 'typeorm';
import { IsString, IsNotEmpty, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { BaseEntity } from '../../common/entities/base.entity';

@Entity('login_attempts')
@Index(['email', 'ipAddress'])
@Index(['email'])
@Index(['ipAddress'])
@Index(['createdAt'])
export class LoginAttempt extends BaseEntity {
  @ApiProperty({
    description: 'Email address used in login attempt',
    example: 'user@example.com',
  })
  @Column({ type: 'varchar', length: 255 })
  @IsString()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'IP address of the client',
    example: '192.168.1.100',
  })
  @Column({ type: 'varchar', length: 45 })
  @IsString()
  @IsNotEmpty()
  ipAddress: string;

  @ApiProperty({
    description: 'Whether the login attempt was successful',
    example: false,
  })
  @Column({ type: 'boolean', default: false })
  @IsBoolean()
  isSuccessful: boolean;

  @ApiProperty({
    description: 'User agent from the request',
    example: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    required: false,
  })
  @Column({ type: 'text', nullable: true })
  @IsString()
  userAgent?: string;

  @ApiProperty({
    description: 'Failure reason if login failed',
    example: 'Invalid password',
    required: false,
  })
  @Column({ type: 'varchar', length: 255, nullable: true })
  @IsString()
  failureReason?: string;
}
