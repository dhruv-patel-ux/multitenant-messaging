import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { User } from '../users/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { LoginAttempt } from './entities/login-attempt.entity';
import { LoginDto, RefreshTokenDto } from './dto/auth.dto';
import { AuthResponseDto, UserResponseDto } from './dto/auth-response.dto';
import { RateLimitService } from './services/rate-limit.service';
import { EnvironmentVariables } from '../config/env.validation';

@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS = 12;
  private readonly ACCESS_TOKEN_EXPIRY = '15m';
  private readonly REFRESH_TOKEN_EXPIRY_DAYS = 7;

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(LoginAttempt)
    private loginAttemptRepository: Repository<LoginAttempt>,
    private jwtService: JwtService,
    private configService: ConfigService<EnvironmentVariables>,
    private rateLimitService: RateLimitService,
  ) {}

  async login(loginDto: LoginDto, ipAddress: string, userAgent?: string): Promise<AuthResponseDto> {
    const { email, password } = loginDto;

    // Check rate limiting
    await this.rateLimitService.checkRateLimit(email, ipAddress);

    // Validate user credentials
    const user = await this.validateUser(email, password);
    if (!user) {
      await this.rateLimitService.recordLoginAttempt(
        email,
        ipAddress,
        false,
        userAgent,
        'Invalid credentials',
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if account is locked
    const isLocked = await this.rateLimitService.isAccountLocked(email);
    if (isLocked) {
      await this.rateLimitService.recordLoginAttempt(
        email,
        ipAddress,
        false,
        userAgent,
        'Account locked due to too many failed attempts',
      );
      throw new UnauthorizedException('Account temporarily locked due to too many failed attempts');
    }

    // Update last login
    await this.updateLastLogin(user.id);

    // Record successful login attempt
    await this.rateLimitService.recordLoginAttempt(email, ipAddress, true, userAgent);

    // Generate tokens
    const tokens = await this.generateTokens(user);

    // Save refresh token
    await this.saveRefreshToken(tokens.refreshToken, user.id, userAgent, ipAddress);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: 15 * 60, // 15 minutes in seconds
      tokenType: 'Bearer',
      user: this.mapUserToResponse(user),
    };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<AuthResponseDto> {
    const { refreshToken } = refreshTokenDto;

    // Find refresh token in database
    const storedToken = await this.refreshTokenRepository.findOne({
      where: { token: refreshToken, isRevoked: false },
      relations: ['user', 'user.tenant'],
    });

    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check if token is expired
    if (storedToken.expiresAt < new Date()) {
      await this.revokeRefreshToken(storedToken.id);
      throw new UnauthorizedException('Refresh token expired');
    }

    // Check if user is still active
    if (!storedToken.user.isActive || storedToken.user.tenant.status !== 'active') {
      throw new UnauthorizedException('User or tenant is inactive');
    }

    // Generate new tokens
    const tokens = await this.generateTokens(storedToken.user);

    // Revoke old refresh token
    await this.revokeRefreshToken(storedToken.id);

    // Save new refresh token
    await this.saveRefreshToken(tokens.refreshToken, storedToken.user.id);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: 15 * 60, // 15 minutes in seconds
      tokenType: 'Bearer',
      user: this.mapUserToResponse(storedToken.user),
    };
  }

  async logout(userId: string, refreshToken?: string): Promise<void> {
    if (refreshToken) {
      // Revoke specific refresh token
      const token = await this.refreshTokenRepository.findOne({
        where: { token: refreshToken, userId },
      });
      if (token) {
        await this.revokeRefreshToken(token.id);
      }
    } else {
      // Revoke all refresh tokens for user
      await this.refreshTokenRepository.update(
        { userId, isRevoked: false },
        { isRevoked: true, revokedAt: new Date() },
      );
    }
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userRepository.findOne({
      where: { email, isActive: true },
      relations: ['tenant'],
    });

    if (!user) {
      return null;
    }

    // Check if tenant is active
    if (user.tenant.status !== 'active') {
      return null;
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return null;
    }

    return user;
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }

  async generateTokens(user: User): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = {
      sub: user.id,
      email: user.email,
      tenantId: user.tenantId,
      role: user.role,
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.ACCESS_TOKEN_EXPIRY,
    });

    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: `${this.REFRESH_TOKEN_EXPIRY_DAYS}d`,
    });

    return { accessToken, refreshToken };
  }

  private async saveRefreshToken(
    token: string,
    userId: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<void> {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_EXPIRY_DAYS);

    const refreshToken = this.refreshTokenRepository.create({
      token,
      userId,
      expiresAt,
      userAgent,
      ipAddress,
    });

    await this.refreshTokenRepository.save(refreshToken);
  }

  private async revokeRefreshToken(tokenId: string): Promise<void> {
    await this.refreshTokenRepository.update(tokenId, {
      isRevoked: true,
      revokedAt: new Date(),
    });
  }

  private async updateLastLogin(userId: string): Promise<void> {
    await this.userRepository.update(userId, {
      lastLoginAt: new Date(),
    });
  }

  private mapUserToResponse(user: User): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      preferences: user.preferences,
      tenantId: user.tenantId,
      tenantName: user.tenant.name,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  async getUserProfile(userId: string): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['tenant'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Get active sessions count
    const activeSessions = await this.refreshTokenRepository.count({
      where: { userId, isRevoked: false, expiresAt: MoreThan(new Date()) },
    });

    // Get last login attempt for IP and user agent
    const lastLoginAttempt = await this.loginAttemptRepository.findOne({
      where: { email: user.email, isSuccessful: true },
      order: { createdAt: 'DESC' },
    });

    return {
      user: this.mapUserToResponse(user),
      activeSessions,
      lastLoginIp: lastLoginAttempt?.ipAddress,
      lastLoginUserAgent: lastLoginAttempt?.userAgent,
    };
  }
}
