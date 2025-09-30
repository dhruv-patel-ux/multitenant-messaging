import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { LoginAttempt } from '../entities/login-attempt.entity';

@Injectable()
export class RateLimitService {
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION_MINUTES = 15;
  private readonly RATE_LIMIT_WINDOW_MINUTES = 15;

  constructor(
    @InjectRepository(LoginAttempt)
    private loginAttemptRepository: Repository<LoginAttempt>,
  ) {}

  async checkRateLimit(email: string, ipAddress: string): Promise<void> {
    const now = new Date();
    const windowStart = new Date(now.getTime() - this.RATE_LIMIT_WINDOW_MINUTES * 60 * 1000);

    // Check failed attempts in the last 15 minutes
    const recentAttempts = await this.loginAttemptRepository.count({
      where: [
        { email, createdAt: MoreThan(windowStart), isSuccessful: false },
        { ipAddress, createdAt: MoreThan(windowStart), isSuccessful: false },
      ],
    });

    if (recentAttempts >= this.MAX_LOGIN_ATTEMPTS) {
      throw new HttpException(
        `Too many login attempts. Please try again in ${this.LOCKOUT_DURATION_MINUTES} minutes.`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  async recordLoginAttempt(
    email: string,
    ipAddress: string,
    isSuccessful: boolean,
    userAgent?: string,
    failureReason?: string,
  ): Promise<void> {
    const loginAttempt = this.loginAttemptRepository.create({
      email,
      ipAddress,
      isSuccessful,
      userAgent,
      failureReason,
    });

    await this.loginAttemptRepository.save(loginAttempt);
  }

  async isAccountLocked(email: string): Promise<boolean> {
    const now = new Date();
    const lockoutStart = new Date(now.getTime() - this.LOCKOUT_DURATION_MINUTES * 60 * 1000);

    const recentFailedAttempts = await this.loginAttemptRepository.count({
      where: {
        email,
        createdAt: MoreThan(lockoutStart),
        isSuccessful: false,
      },
    });

    return recentFailedAttempts >= this.MAX_LOGIN_ATTEMPTS;
  }

  async getRemainingAttempts(email: string, ipAddress: string): Promise<number> {
    const now = new Date();
    const windowStart = new Date(now.getTime() - this.RATE_LIMIT_WINDOW_MINUTES * 60 * 1000);

    const recentAttempts = await this.loginAttemptRepository.count({
      where: [
        { email, createdAt: MoreThan(windowStart), isSuccessful: false },
        { ipAddress, createdAt: MoreThan(windowStart), isSuccessful: false },
      ],
    });

    return Math.max(0, this.MAX_LOGIN_ATTEMPTS - recentAttempts);
  }
}
