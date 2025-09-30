import { Entity, Column, ManyToOne, JoinColumn, Index } from 'typeorm';
import { IsString, IsNotEmpty, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { BaseEntity } from '../../common/entities/base.entity';
import { User } from '../../users/entities/user.entity';

@Entity('refresh_tokens')
@Index(['token'], { unique: true })
@Index(['userId'])
@Index(['expiresAt'])
export class RefreshToken extends BaseEntity {
  @ApiProperty({
    description: 'Refresh token value',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @Column({ type: 'text' })
  @IsString()
  @IsNotEmpty()
  token: string;

  @ApiProperty({
    description: 'Token expiration timestamp',
    example: '2024-01-22T10:30:00Z',
  })
  @Column({ type: 'timestamp' })
  @IsNotEmpty()
  expiresAt: Date;

  @ApiProperty({
    description: 'User agent from the request',
    example: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    required: false,
  })
  @Column({ type: 'text', nullable: true })
  @IsString()
  userAgent?: string;

  @ApiProperty({
    description: 'IP address of the client',
    example: '192.168.1.100',
    required: false,
  })
  @Column({ type: 'varchar', length: 45, nullable: true })
  @IsString()
  ipAddress?: string;

  @ApiProperty({
    description: 'Whether the token is revoked',
    example: false,
  })
  @Column({ type: 'boolean', default: false })
  isRevoked: boolean;

  @ApiProperty({
    description: 'Token revocation timestamp',
    example: '2024-01-15T10:30:00Z',
    required: false,
  })
  @Column({ type: 'timestamp', nullable: true })
  revokedAt?: Date;

  // Foreign key
  @ApiProperty({
    description: 'User ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @Column({ type: 'uuid' })
  @IsUUID()
  @IsNotEmpty()
  userId: string;

  // Relationships
  @ManyToOne(() => User, (user) => user.refreshTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;
}
