import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

// Import entities
import { User } from '../src/users/entities/user.entity';
import { Tenant } from '../src/tenants/entities/tenant.entity';
import { WahaSession, WahaSessionStatus } from '../src/waha/entities/waha-session.entity';
import { Message } from '../src/messages/entities/message.entity';
import { RefreshToken } from '../src/auth/entities/refresh-token.entity';
import { LoginAttempt } from '../src/auth/entities/login-attempt.entity';

// Import services
import { AuthService } from '../src/auth/auth.service';
import { UsersService } from '../src/users/users.service';
import { TenantsService } from '../src/tenants/tenants.service';
import { WahaService } from '../src/waha/waha.service';
import { MessagesService } from '../src/messages/messages.service';
import { WebhooksService } from '../src/webhooks/webhooks.service';
import { SecurityAuditService } from '../src/common/services/security-audit.service';
import { RateLimitService } from '../src/auth/services/rate-limit.service';

// Test utilities
export class TestDatabase {
  static async createTestModule(): Promise<TestingModule> {
    return Test.createTestingModule({
      imports: [
        TypeOrmModule.forFeature([
          User,
          Tenant,
          WahaSession,
          Message,
          RefreshToken,
          LoginAttempt,
        ]),
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          entities: [User, Tenant, WahaSession, Message, RefreshToken, LoginAttempt],
          synchronize: true,
          logging: false,
        }),
        TypeOrmModule.forFeature([
          User,
          Tenant,
          WahaSession,
          Message,
          RefreshToken,
          LoginAttempt,
        ]),
      ],
        providers: [
      AuthService,
      UsersService,
      TenantsService,
      WahaService,
      MessagesService,
      WebhooksService,
      SecurityAuditService,
      JwtService,
      RateLimitService,
    ],
    }).compile();
  }
}

export class TestHelpers {
  static async createTestApp(module: TestingModule): Promise<INestApplication> {
    const app = module.createNestApplication();
    await app.init();
    return app;
  }

  static async cleanupDatabase(module: TestingModule): Promise<void> {
    const userRepo = module.get<Repository<User>>(getRepositoryToken(User));
    const tenantRepo = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    const sessionRepo = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));
    const messageRepo = module.get<Repository<Message>>(getRepositoryToken(Message));
    const refreshTokenRepo = module.get<Repository<RefreshToken>>(getRepositoryToken(RefreshToken));
    const loginAttemptRepo = module.get<Repository<LoginAttempt>>(getRepositoryToken(LoginAttempt));

    await messageRepo.clear();
    await sessionRepo.clear();
    await refreshTokenRepo.clear();
    await loginAttemptRepo.clear();
    await userRepo.clear();
    await tenantRepo.clear();
  }
}

// Mock external services
export const mockWahaService = {
  createSession: jest.fn(),
  startSession: jest.fn(),
  stopSession: jest.fn(),
  getSessionStatus: jest.fn(),
  listSessions: jest.fn(),
  getSessionQR: jest.fn(),
  sendMessage: jest.fn(),
  getSessionScreen: jest.fn(),
  checkHealth: jest.fn(),
  getVersion: jest.fn(),
  syncSessionStatus: jest.fn(),
};

export const mockSecurityAuditService = {
  logSecurityEvent: jest.fn(),
};

// Test data factories
export class TestDataFactory {
  static createTenant(overrides: Partial<Tenant> = {}): Partial<Tenant> {
    return {
      id: 'tenant-123',
      name: 'Test Tenant',
      status: 'active' as any, // TODO: Fix this with TenantStatus enum if available
      settings: {},
      ...overrides,
    };
  }

  static createUser(overrides: Partial<User> = {}): Partial<User> {
    return {
      id: 'user-123',
      email: 'test@example.com',
      passwordHash: 'hashed-password',
      role: 'TENANT_ADMIN' as any, // TODO: Fix this with UserRole enum if available
      isActive: true,
      tenantId: 'tenant-123',
      ...overrides,
    };
  }

  static createWahaSession(overrides: Partial<WahaSession> = {}): Partial<WahaSession> {
    return {
      id: 'session-123',
      externalSessionId: 'waha-session-123',
      status: WahaSessionStatus.WORKING,
      engine: 'WEBJS',
      metadata: {},
      tenantId: 'tenant-123',
      ...overrides,
    };
  }

  static createMessage(overrides: Partial<Message> = {}): Partial<Message> {
    return {
      id: 'message-123',
      tenantId: 'tenant-123',
      sessionId: 'session-123',
      direction: 'outbound',
      toMsisdn: '+1234567890',
      fromMsisdn: '+0987654321',
      body: 'Test message',
      status: 'sent',
      wahaMessageId: 'waha-msg-123',
      rawPayload: {},
      ...overrides,
    };
  }

  static createRefreshToken(overrides: Partial<RefreshToken> = {}): Partial<RefreshToken> {
    return {
      id: 'token-123',
      token: 'refresh-token-123',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      userAgent: 'test-agent',
      ipAddress: '127.0.0.1',
      isRevoked: false,
      userId: 'user-123',
      ...overrides,
    };
  }
}

// Authentication helpers
export class AuthTestHelpers {
  static generateJwtToken(payload: any, jwtService: JwtService): string {
    return jwtService.sign(payload, { expiresIn: '1h' });
  }

  static createAuthHeaders(token: string): Record<string, string> {
    return {
      Authorization: `Bearer ${token}`,
    };
  }

  static createUserPayload(overrides: any = {}): any {
    return {
      sub: 'user-123',
      email: 'test@example.com',
      tenantId: 'tenant-123',
      role: 'TENANT_ADMIN',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...overrides,
    };
  }
}

// Database test helpers
export class DatabaseTestHelpers {
  static async seedTestData(module: TestingModule): Promise<void> {
    const tenantRepo = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    const userRepo = module.get<Repository<User>>(getRepositoryToken(User));
    const sessionRepo = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));

    // Create test tenant
    const tenant = tenantRepo.create(TestDataFactory.createTenant());
    await tenantRepo.save(tenant);

    // Create test user
    const user = userRepo.create(TestDataFactory.createUser());
    await userRepo.save(user);

    // Create test session
    const session = sessionRepo.create(TestDataFactory.createWahaSession());
    await sessionRepo.save(session);
  }

  static async clearTestData(module: TestingModule): Promise<void> {
    await TestHelpers.cleanupDatabase(module);
  }
}

// Mock helpers
export class MockHelpers {
  static mockWahaServiceResponse(method: string, response: any): void {
    (mockWahaService as any)[method].mockResolvedValue(response);
  }

  static mockWahaServiceError(method: string, error: Error): void {
    (mockWahaService as any)[method].mockRejectedValue(error);
  }

  static resetAllMocks(): void {
    jest.clearAllMocks();
    Object.values(mockWahaService).forEach(mock => {
      if (jest.isMockFunction(mock)) {
        mock.mockClear();
      }
    });
    Object.values(mockSecurityAuditService).forEach(mock => {
      if (jest.isMockFunction(mock)) {
        mock.mockClear();
      }
    });
  }
}

// Test assertions
export class TestAssertions {
  static expectValidJwtToken(token: string): void {
    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);
  }

  static expectValidMessage(message: any): void {
    expect(message).toBeDefined();
    expect(message.id).toBeDefined();
    expect(message.tenantId).toBeDefined();
    expect(message.direction).toBeDefined();
    expect(message.status).toBeDefined();
    expect(message.createdAt).toBeDefined();
  }

  static expectValidTenant(tenant: any): void {
    expect(tenant).toBeDefined();
    expect(tenant.id).toBeDefined();
    expect(tenant.name).toBeDefined();
    expect(tenant.status).toBeDefined();
  }

  static expectValidUser(user: any): void {
    expect(user).toBeDefined();
    expect(user.id).toBeDefined();
    expect(user.email).toBeDefined();
    expect(user.role).toBeDefined();
    expect(user.tenantId).toBeDefined();
  }
}

// Global test setup
beforeAll(async () => {
  // Global setup
});

afterAll(async () => {
  // Global cleanup
});

beforeEach(() => {
  MockHelpers.resetAllMocks();
});

afterEach(() => {
  MockHelpers.resetAllMocks();
});
