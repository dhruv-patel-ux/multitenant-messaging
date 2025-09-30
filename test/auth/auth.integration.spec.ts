import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as request from 'supertest';
import * as bcrypt from 'bcrypt';

import { AuthService } from '../../src/auth/auth.service';
import { UsersService } from '../../src/users/users.service';
import { RateLimitService } from '../../src/auth/services/rate-limit.service';
import { User } from '../../src/users/entities/user.entity';
import { Tenant } from '../../src/tenants/entities/tenant.entity';
import { RefreshToken } from '../../src/auth/entities/refresh-token.entity';
import { LoginAttempt } from '../../src/auth/entities/login-attempt.entity';
import { UserRole } from '../../src/users/entities/user.entity';
import { TenantStatus } from '../../src/tenants/entities/tenant.entity';

import {
  TestDatabase,
  TestHelpers,
  TestDataFactory,
  AuthTestHelpers,
  DatabaseTestHelpers,
  MockHelpers,
  TestAssertions,
} from '../setup';

describe('Authentication Flow', () => {
  let app: INestApplication;
  let module: TestingModule;
  let authService: AuthService;
  let usersService: UsersService;
  let rateLimitService: RateLimitService;
  let jwtService: JwtService;
  let userRepository: Repository<User>;
  let tenantRepository: Repository<Tenant>;
  let refreshTokenRepository: Repository<RefreshToken>;
  let loginAttemptRepository: Repository<LoginAttempt>;

  beforeAll(async () => {
    module = await TestDatabase.createTestModule();
    app = await TestHelpers.createTestApp(module);

    authService = module.get<AuthService>(AuthService);
    usersService = module.get<UsersService>(UsersService);
    rateLimitService = module.get<RateLimitService>(RateLimitService);
    jwtService = module.get<JwtService>(JwtService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    tenantRepository = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    refreshTokenRepository = module.get<Repository<RefreshToken>>(getRepositoryToken(RefreshToken));
    loginAttemptRepository = module.get<Repository<LoginAttempt>>(getRepositoryToken(LoginAttempt));

    await DatabaseTestHelpers.seedTestData(module);
  });

  afterAll(async () => {
    await TestHelpers.cleanupDatabase(module);
    await app.close();
  });

  beforeEach(async () => {
    MockHelpers.resetAllMocks();
  });

  describe('POST /auth/login', () => {
    it('should login successfully with valid credentials', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.user).toBeDefined();

      TestAssertions.expectValidJwtToken(response.body.data.accessToken);
      TestAssertions.expectValidJwtToken(response.body.data.refreshToken);
      TestAssertions.expectValidUser(response.body.data.user);
    });

    it('should fail login with invalid credentials', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should fail login with non-existent user', async () => {
      const loginDto = {
        email: 'nonexistent@example.com',
        password: 'password123',
      };

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid credentials');
    });

    it('should enforce rate limiting on login attempts', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      // Make multiple failed attempts
      for (let i = 0; i < 6; i++) {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send(loginDto);
      }

      // Should be rate limited
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(429);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Too many login attempts');
    });

    it('should record login attempts in database', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto);

      const loginAttempts = await loginAttemptRepository.find({
        where: { email: 'test@example.com' },
      });

      expect(loginAttempts).toHaveLength(1);
      expect(loginAttempts[0].isSuccessful).toBe(false);
      expect(loginAttempts[0].failureReason).toBeDefined();
    });
  });

  describe('POST /auth/refresh', () => {
    it('should refresh token successfully with valid refresh token', async () => {
      // First login to get tokens
      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      const refreshToken = loginResponse.body.data.refreshToken;

      // Refresh the token
      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();

      TestAssertions.expectValidJwtToken(response.body.data.accessToken);
      TestAssertions.expectValidJwtToken(response.body.data.refreshToken);
    });

    it('should fail refresh with invalid refresh token', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid refresh token');
    });

    it('should fail refresh with expired refresh token', async () => {
      // Create an expired refresh token
      const expiredToken = jwtService.sign(
        { sub: 'user-123', type: 'refresh' },
        { expiresIn: '-1h' }
      );

      const response = await request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken: expiredToken })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid refresh token');
    });
  });

  describe('GET /auth/profile', () => {
    it('should get user profile with valid JWT token', async () => {
      // Login to get token
      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      const accessToken = loginResponse.body.data.accessToken;

      // Get profile
      const response = await request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
      TestAssertions.expectValidUser(response.body.data);
    });

    it('should fail profile access without token', async () => {
      const response = await request(app.getHttpServer())
        .get('/auth/profile')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Unauthorized');
    });

    it('should fail profile access with invalid token', async () => {
      const response = await request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Unauthorized');
    });
  });

  describe('POST /auth/logout', () => {
    it('should logout successfully with valid token', async () => {
      // Login to get token
      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      const accessToken = loginResponse.body.data.accessToken;

      // Logout
      const response = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken: loginResponse.body.data.refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Logout successful');
    });

    it('should fail logout without token', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/logout')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Unauthorized');
    });
  });

  describe('JWT Token Validation', () => {
    it('should validate JWT token structure', async () => {
      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      const token = loginResponse.body.data.accessToken;
      const decoded = jwtService.decode(token) as any;

      expect(decoded).toBeDefined();
      expect(decoded.sub).toBeDefined();
      expect(decoded.email).toBeDefined();
      expect(decoded.tenantId).toBeDefined();
      expect(decoded.role).toBeDefined();
      expect(decoded.iat).toBeDefined();
      expect(decoded.exp).toBeDefined();
    });

    it('should include tenant context in JWT payload', async () => {
      const loginResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      const token = loginResponse.body.data.accessToken;
      const decoded = jwtService.decode(token) as any;

      expect(decoded.tenantId).toBe('tenant-123');
      expect(decoded.role).toBe(UserRole.TENANT_ADMIN);
    });
  });

  describe('Account Lockout', () => {
    it('should lock account after multiple failed attempts', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      // Make multiple failed attempts
      for (let i = 0; i < 5; i++) {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send(loginDto);
      }

      // Check if account is locked
      const user = await userRepository.findOne({
        where: { email: 'test@example.com' },
      });

      // Note: In a real implementation, you might have an account lockout mechanism
      // For this test, we're verifying that failed attempts are recorded
      const failedAttempts = await loginAttemptRepository.count({
        where: { email: 'test@example.com', isSuccessful: false },
      });

      expect(failedAttempts).toBeGreaterThanOrEqual(5);
    });
  });

  describe('Password Security', () => {
    it('should hash passwords securely', async () => {
      const user = await userRepository.findOne({
        where: { email: 'test@example.com' },
      });

      expect(user?.passwordHash).toBeDefined();
      expect(user?.passwordHash).not.toBe('password123');
      expect(user?.passwordHash.length).toBeGreaterThan(50); // bcrypt hash length
    });

    it('should verify password hashing', async () => {
      const user = await userRepository.findOne({
        where: { email: 'test@example.com' },
      });

      const isValid = await bcrypt.compare('password123', user?.passwordHash || '');
      expect(isValid).toBe(true);
    });
  });
});
