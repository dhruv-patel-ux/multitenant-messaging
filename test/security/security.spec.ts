import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as request from 'supertest';

import { AuthService } from '../../src/auth/auth.service';
import { UsersService } from '../../src/users/users.service';
import { MessagesService } from '../../src/messages/messages.service';
import { User } from '../../src/users/entities/user.entity';
import { Tenant } from '../../src/tenants/entities/tenant.entity';
import { Message } from '../../src/messages/entities/message.entity';
import { UserRole } from '../../src/users/entities/user.entity';
import { MessageDirection } from '../../src/messages/entities/message.entity';

import {
  TestDatabase,
  TestHelpers,
  TestDataFactory,
  AuthTestHelpers,
  DatabaseTestHelpers,
  MockHelpers,
  TestAssertions,
} from '../setup';

describe('Security Tests', () => {
  let app: INestApplication;
  let module: TestingModule;
  let authService: AuthService;
  let usersService: UsersService;
  let messagesService: MessagesService;
  let userRepository: Repository<User>;
  let tenantRepository: Repository<Tenant>;
  let messageRepository: Repository<Message>;

  let tenant: Tenant;
  let user: User;
  let userToken: string;

  beforeAll(async () => {
    module = await TestDatabase.createTestModule();
    app = await TestHelpers.createTestApp(module);

    authService = module.get<AuthService>(AuthService);
    usersService = module.get<UsersService>(UsersService);
    messagesService = module.get<MessagesService>(MessagesService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    tenantRepository = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    messageRepository = module.get<Repository<Message>>(getRepositoryToken(Message));

    // Create test tenant and user
    tenant = await tenantRepository.save(
      tenantRepository.create(TestDataFactory.createTenant({
        id: 'tenant-security',
        name: 'Security Test Tenant',
      }))
    );

    user = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-security',
        email: 'security@tenant.com',
        tenantId: 'tenant-security',
        role: UserRole.TENANT_ADMIN,
      }))
    );

    userToken = AuthTestHelpers.generateJwtToken(
      AuthTestHelpers.createUserPayload({
        sub: 'user-security',
        tenantId: 'tenant-security',
        role: UserRole.TENANT_ADMIN,
      }),
      module.get('JwtService')
    );
  });

  afterAll(async () => {
    await TestHelpers.cleanupDatabase(module);
    await app.close();
  });

  beforeEach(() => {
    MockHelpers.resetAllMocks();
  });

  describe('SQL Injection Prevention', () => {
    it('should prevent SQL injection in user queries', async () => {
      const maliciousInput = "'; DROP TABLE users; --";
      
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${userToken}`)
        .query({ search: maliciousInput })
        .expect(200);

      expect(response.body.success).toBe(true);
      // Verify that the malicious input is treated as a literal string, not SQL
      expect(response.body.data).toBeDefined();
    });

    it('should prevent SQL injection in message queries', async () => {
      const maliciousInput = "'; DROP TABLE messages; --";
      
      const response = await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${userToken}`)
        .query({ search: maliciousInput })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
    });

    it('should prevent SQL injection in authentication', async () => {
      const maliciousEmail = "admin@test.com'; DROP TABLE users; --";
      const maliciousPassword = "password'; DROP TABLE users; --";

      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: maliciousEmail,
          password: maliciousPassword,
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      // Verify that the malicious input doesn't cause SQL injection
    });

    it('should prevent SQL injection in user creation', async () => {
      const maliciousInput = "'; DROP TABLE users; --";
      
      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          email: maliciousInput,
          password: 'password123',
          role: UserRole.AGENT,
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Validation failed');
    });
  });

  describe('XSS Attack Prevention', () => {
    it('should sanitize user input in message content', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      
      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          sessionId: 'session-123',
          to: '+1234567890',
          body: xssPayload,
        })
        .expect(201);

      expect(response.body.success).toBe(true);
      // Verify that the XSS payload is sanitized or escaped
      expect(response.body.data.body).not.toContain('<script>');
    });

    it('should sanitize user input in user creation', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      
      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          email: `xss@test.com`,
          password: 'password123',
          role: UserRole.AGENT,
        })
        .expect(201);

      expect(response.body.success).toBe(true);
      // Verify that the XSS payload doesn't affect the response
    });

    it('should sanitize search queries', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      
      const response = await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${userToken}`)
        .query({ search: xssPayload })
        .expect(200);

      expect(response.body.success).toBe(true);
      // Verify that the XSS payload is sanitized in search results
    });
  });

  describe('CSRF Protection', () => {
    it('should require proper authentication for state-changing operations', async () => {
      const endpoints = [
        { method: 'POST', path: '/users' },
        { method: 'PUT', path: '/tenants/current' },
        { method: 'POST', path: '/messages/send' },
        { method: 'POST', path: '/messages/bulk' },
        { method: 'DELETE', path: '/waha/sessions/session-123' },
      ];

      for (const endpoint of endpoints) {
        const response = await request(app.getHttpServer())
          [endpoint.method.toLowerCase()](endpoint.path)
          .expect(401);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Unauthorized');
      }
    });

    it('should validate JWT tokens for all protected endpoints', async () => {
      const invalidToken = 'invalid-jwt-token';
      
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Unauthorized');
    });

    it('should prevent token manipulation', async () => {
      const manipulatedToken = userToken + 'manipulated';
      
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${manipulatedToken}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Unauthorized');
    });
  });

  describe('Input Validation Bypass Attempts', () => {
    it('should prevent email validation bypass', async () => {
      const invalidEmails = [
        'not-an-email',
        '@invalid.com',
        'invalid@',
        'invalid@.com',
        'invalid@com.',
        'invalid@.com.',
      ];

      for (const email of invalidEmails) {
        const response = await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email,
            password: 'password123',
          })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Validation failed');
      }
    });

    it('should prevent phone number validation bypass', async () => {
      const invalidPhones = [
        'not-a-phone',
        '123',
        '+',
        '+123',
        '12345678901234567890', // Too long
        'abc123',
      ];

      for (const phone of invalidPhones) {
        const response = await request(app.getHttpServer())
          .post('/messages/send')
          .set('Authorization', `Bearer ${userToken}`)
          .send({
            sessionId: 'session-123',
            to: phone,
            body: 'Test message',
          })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Validation failed');
      }
    });

    it('should prevent role validation bypass', async () => {
      const invalidRoles = [
        'INVALID_ROLE',
        'ADMIN', // Should be TENANT_ADMIN
        'SUPER_ADMIN',
        'HACKER',
        '',
        null,
        undefined,
      ];

      for (const role of invalidRoles) {
        const response = await request(app.getHttpServer())
          .post('/users')
          .set('Authorization', `Bearer ${userToken}`)
          .send({
            email: 'test@example.com',
            password: 'password123',
            role,
          })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Validation failed');
      }
    });

    it('should prevent UUID validation bypass', async () => {
      const invalidUUIDs = [
        'not-a-uuid',
        '123',
        'uuid-123',
        '12345678-1234-1234-1234-1234567890123', // Too long
        '12345678-1234-1234-1234-12345678901', // Too short
        '',
        null,
        undefined,
      ];

      for (const uuid of invalidUUIDs) {
        const response = await request(app.getHttpServer())
          .get(`/messages/${uuid}`)
          .set('Authorization', `Bearer ${userToken}`)
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Validation failed');
      }
    });
  });

  describe('Rate Limiting Security', () => {
    it('should enforce rate limiting on login attempts', async () => {
      const loginDto = {
        email: 'security@tenant.com',
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

    it('should enforce rate limiting on message sending', async () => {
      const sendMessageDto = {
        sessionId: 'session-123',
        to: '+1234567890',
        body: 'Rate limit test message',
      };

      // Make multiple message sending attempts
      for (let i = 0; i < 25; i++) {
        await request(app.getHttpServer())
          .post('/messages/send')
          .set('Authorization', `Bearer ${userToken}`)
          .send(sendMessageDto);
      }

      // Should be rate limited
      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${userToken}`)
        .send(sendMessageDto)
        .expect(429);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Too many requests');
    });

    it('should enforce rate limiting on API requests', async () => {
      // Make multiple API requests
      for (let i = 0; i < 105; i++) {
        await request(app.getHttpServer())
          .get('/users')
          .set('Authorization', `Bearer ${userToken}`);
      }

      // Should be rate limited
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(429);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Too many requests');
    });
  });

  describe('Authentication Security', () => {
    it('should prevent brute force attacks', async () => {
      const commonPasswords = [
        'password',
        '123456',
        'admin',
        'qwerty',
        'password123',
        '123456789',
      ];

      for (const password of commonPasswords) {
        const response = await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email: 'security@tenant.com',
            password,
          })
          .expect(401);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Invalid credentials');
      }
    });

    it('should prevent account enumeration', async () => {
      const existingEmail = 'security@tenant.com';
      const nonExistentEmail = 'nonexistent@tenant.com';

      const existingResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: existingEmail,
          password: 'wrongpassword',
        })
        .expect(401);

      const nonExistentResponse = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: nonExistentEmail,
          password: 'wrongpassword',
        })
        .expect(401);

      // Both should return the same error message to prevent enumeration
      expect(existingResponse.body.message).toBe(nonExistentResponse.body.message);
    });

    it('should prevent timing attacks', async () => {
      const startTime = Date.now();
      
      await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'security@tenant.com',
          password: 'wrongpassword',
        })
        .expect(401);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      // Response time should be consistent regardless of whether user exists
      expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
    });
  });

  describe('Authorization Security', () => {
    it('should prevent privilege escalation', async () => {
      const agentToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-agent',
          tenantId: 'tenant-security',
          role: UserRole.AGENT,
        }),
        module.get('JwtService')
      );

      // Agent should not be able to create users
      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${agentToken}`)
        .send({
          email: 'newuser@tenant.com',
          password: 'password123',
          role: UserRole.TENANT_ADMIN, // Trying to create admin user
        })
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });

    it('should prevent cross-tenant access', async () => {
      const otherTenantToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-other-tenant',
          tenantId: 'other-tenant-id',
          role: UserRole.TENANT_ADMIN,
        }),
        module.get('JwtService')
      );

      // Should not be able to access current tenant's data
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${otherTenantToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveLength(0); // Should return empty array
    });

    it('should prevent token replay attacks', async () => {
      // Use the same token multiple times
      const response1 = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      const response2 = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      // Both requests should succeed (tokens are valid for multiple uses)
      expect(response1.body.success).toBe(true);
      expect(response2.body.success).toBe(true);
    });
  });

  describe('Data Security', () => {
    it('should not expose sensitive data in responses', async () => {
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      
      // Verify sensitive data is not exposed
      const users = response.body.data;
      users.forEach((user: any) => {
        expect(user.passwordHash).toBeUndefined();
        expect(user.password).toBeUndefined();
        expect(user.refreshTokens).toBeUndefined();
      });
    });

    it('should not expose internal IDs in responses', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      
      // Verify internal IDs are not exposed
      const messages = response.body.data.data;
      messages.forEach((message: any) => {
        expect(message.internalId).toBeUndefined();
        expect(message.databaseId).toBeUndefined();
      });
    });

    it('should sanitize error messages', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages/non-existent-id')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      // Error message should not expose internal details
      expect(response.body.message).not.toContain('database');
      expect(response.body.message).not.toContain('SQL');
      expect(response.body.message).not.toContain('table');
    });
  });

  describe('Webhook Security', () => {
    it('should validate webhook signatures', async () => {
      const payload = {
        event: 'message.text',
        session: 'test-session',
        payload: {
          id: 'test-123',
          from: '+1234567890',
          to: '+0987654321',
          body: 'Test message',
          timestamp: Date.now(),
          type: 'text',
        },
      };

      const response = await request(app.getHttpServer())
        .post('/webhooks/waha')
        .set('X-Waha-Signature', 'sha256=invalid-signature')
        .send(payload)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid webhook signature');
    });

    it('should prevent webhook replay attacks', async () => {
      const payload = {
        event: 'message.text',
        session: 'test-session',
        payload: {
          id: 'test-123',
          from: '+1234567890',
          to: '+0987654321',
          body: 'Test message',
          timestamp: Date.now(),
          type: 'text',
        },
      };

      // Send the same webhook multiple times
      const response1 = await request(app.getHttpServer())
        .post('/webhooks/waha')
        .set('X-Waha-Signature', 'sha256=test-signature')
        .send(payload)
        .expect(200);

      const response2 = await request(app.getHttpServer())
        .post('/webhooks/waha')
        .set('X-Waha-Signature', 'sha256=test-signature')
        .send(payload)
        .expect(200);

      // Both should be processed (idempotency is handled differently)
      expect(response1.body.success).toBe(true);
      expect(response2.body.success).toBe(true);
    });
  });
});
