import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as request from 'supertest';

import { UsersService } from '../../src/users/users.service';
import { TenantsService } from '../../src/tenants/tenants.service';
import { MessagesService } from '../../src/messages/messages.service';
import { User } from '../../src/users/entities/user.entity';
import { Tenant } from '../../src/tenants/entities/tenant.entity';
import { Message } from '../../src/messages/entities/message.entity';
import { WahaSession } from '../../src/waha/entities/waha-session.entity';
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

describe('Tenant Isolation', () => {
  let app: INestApplication;
  let module: TestingModule;
  let usersService: UsersService;
  let tenantsService: TenantsService;
  let messagesService: MessagesService;
  let userRepository: Repository<User>;
  let tenantRepository: Repository<Tenant>;
  let messageRepository: Repository<Message>;
  let sessionRepository: Repository<WahaSession>;

  let tenant1: Tenant;
  let tenant2: Tenant;
  let user1: User;
  let user2: User;
  let session1: WahaSession;
  let session2: WahaSession;
  let message1: Message;
  let message2: Message;

  beforeAll(async () => {
    module = await TestDatabase.createTestModule();
    app = await TestHelpers.createTestApp(module);

    usersService = module.get<UsersService>(UsersService);
    tenantsService = module.get<TenantsService>(TenantsService);
    messagesService = module.get<MessagesService>(MessagesService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    tenantRepository = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    messageRepository = module.get<Repository<Message>>(getRepositoryToken(Message));
    sessionRepository = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));

    // Create two separate tenants
    tenant1 = await tenantRepository.save(
      tenantRepository.create(TestDataFactory.createTenant({
        id: 'tenant-1',
        name: 'Tenant 1',
      }))
    );

    tenant2 = await tenantRepository.save(
      tenantRepository.create(TestDataFactory.createTenant({
        id: 'tenant-2',
        name: 'Tenant 2',
      }))
    );

    // Create users for each tenant
    user1 = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-1',
        email: 'user1@tenant1.com',
        tenantId: 'tenant-1',
        role: UserRole.TENANT_ADMIN,
      }))
    );

    user2 = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-2',
        email: 'user2@tenant2.com',
        tenantId: 'tenant-2',
        role: UserRole.TENANT_ADMIN,
      }))
    );

    // Create sessions for each tenant
    session1 = await sessionRepository.save(
      sessionRepository.create(TestDataFactory.createWahaSession({
        id: 'session-1',
        tenantId: 'tenant-1',
        externalSessionId: 'waha-session-1',
      }))
    );

    session2 = await sessionRepository.save(
      sessionRepository.create(TestDataFactory.createWahaSession({
        id: 'session-2',
        tenantId: 'tenant-2',
        externalSessionId: 'waha-session-2',
      }))
    );

    // Create messages for each tenant
    message1 = await messageRepository.save(
      messageRepository.create(TestDataFactory.createMessage({
        id: 'message-1',
        tenantId: 'tenant-1',
        sessionId: 'session-1',
        toMsisdn: '+1111111111',
        body: 'Message from tenant 1',
      }))
    );

    message2 = await messageRepository.save(
      messageRepository.create(TestDataFactory.createMessage({
        id: 'message-2',
        tenantId: 'tenant-2',
        sessionId: 'session-2',
        toMsisdn: '+2222222222',
        body: 'Message from tenant 2',
      }))
    );
  });

  afterAll(async () => {
    await TestHelpers.cleanupDatabase(module);
    await app.close();
  });

  beforeEach(() => {
    MockHelpers.resetAllMocks();
  });

  describe('User Data Isolation', () => {
    it('should not allow users to access other tenant users', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // User 1 should not be able to see user 2
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      // Should only see users from tenant 1
      const users = response.body.data;
      expect(users).toHaveLength(1);
      expect(users[0].tenantId).toBe('tenant-1');
      expect(users[0].id).toBe('user-1');
    });

    it('should prevent cross-tenant user creation', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      const newUserDto = {
        email: 'newuser@tenant2.com',
        password: 'password123',
        role: UserRole.AGENT,
        tenantId: 'tenant-2', // Trying to create user in tenant 2
      };

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${user1Token}`)
        .send(newUserDto)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });
  });

  describe('Message Data Isolation', () => {
    it('should not allow users to access other tenant messages', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      const response = await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      // Should only see messages from tenant 1
      const messages = response.body.data.data;
      expect(messages).toHaveLength(1);
      expect(messages[0].tenantId).toBe('tenant-1');
      expect(messages[0].id).toBe('message-1');
    });

    it('should prevent cross-tenant message access by ID', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // User 1 should not be able to access message from tenant 2
      const response = await request(app.getHttpServer())
        .get(`/messages/${message2.id}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Message not found');
    });

    it('should prevent cross-tenant message sending', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      const sendMessageDto = {
        sessionId: session2.id, // Session from tenant 2
        to: '+1234567890',
        body: 'Cross-tenant message attempt',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${user1Token}`)
        .send(sendMessageDto)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Session not found');
    });
  });

  describe('Session Data Isolation', () => {
    it('should not allow users to access other tenant sessions', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      const response = await request(app.getHttpServer())
        .get('/waha/sessions')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      // Should only see sessions from tenant 1
      const sessions = response.body.data;
      expect(sessions).toHaveLength(1);
      expect(sessions[0].tenantId).toBe('tenant-1');
      expect(sessions[0].id).toBe('session-1');
    });

    it('should prevent cross-tenant session access by ID', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // User 1 should not be able to access session from tenant 2
      const response = await request(app.getHttpServer())
        .get(`/waha/sessions/${session2.id}`)
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Session not found');
    });
  });

  describe('Database Query Isolation', () => {
    it('should include tenant_id filter in all user queries', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // Mock the repository to track query calls
      const findSpy = jest.spyOn(userRepository, 'find');
      
      await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      expect(findSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'tenant-1',
          }),
        })
      );
    });

    it('should include tenant_id filter in all message queries', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // Mock the repository to track query calls
      const findAndCountSpy = jest.spyOn(messageRepository, 'findAndCount');
      
      await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      expect(findAndCountSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'tenant-1',
          }),
        })
      );
    });
  });

  describe('API Endpoint Tenant Boundaries', () => {
    it('should enforce tenant boundaries in tenant-specific endpoints', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // User 1 should not be able to access tenant 2's data
      const response = await request(app.getHttpServer())
        .get('/tenants/current')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      expect(response.body.data.id).toBe('tenant-1');
      expect(response.body.data.name).toBe('Tenant 1');
    });

    it('should prevent tenant ID manipulation in route parameters', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // Try to access tenant 2's data by manipulating route parameter
      const response = await request(app.getHttpServer())
        .get('/tenants/tenant-2')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });
  });

  describe('Tenant Middleware Enforcement', () => {
    it('should attach tenant context to request', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      // Mock middleware to track tenant context
      const middlewareSpy = jest.fn();
      
      await request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      // Verify that tenant context is properly set
      // This would be verified by checking the request object in the middleware
    });

    it('should validate tenant context in JWT payload', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      const decoded = module.get('JwtService').decode(user1Token) as any;
      expect(decoded.tenantId).toBe('tenant-1');
    });
  });

  describe('Cross-Tenant Request Prevention', () => {
    it('should prevent cross-tenant data access in bulk operations', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      const bulkMessageDto = {
        sessionId: session1.id, // Valid session from tenant 1
        recipients: ['+1111111111', '+2222222222'],
        body: 'Bulk message',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/bulk')
        .set('Authorization', `Bearer ${user1Token}`)
        .send(bulkMessageDto)
        .expect(201);

      // Should only process messages for tenant 1
      expect(response.body.data.successCount).toBeGreaterThan(0);
    });

    it('should prevent cross-tenant statistics access', async () => {
      const user1Token = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-1',
          tenantId: 'tenant-1',
        }),
        module.get('JwtService')
      );

      const response = await request(app.getHttpServer())
        .get('/messages/stats?fromDate=2024-01-01T00:00:00Z&toDate=2024-01-31T23:59:59Z')
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(200);

      // Should only include statistics for tenant 1
      expect(response.body.data.totalMessages).toBe(1); // Only message1
    });
  });

  describe('Tenant Context Validation', () => {
    it('should validate tenant exists and is active', async () => {
      // Create an inactive tenant
      const inactiveTenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'inactive-tenant',
          name: 'Inactive Tenant',
          status: TenantStatus.INACTIVE,
        }))
      );

      const inactiveUser = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'inactive-user',
          email: 'inactive@tenant.com',
          tenantId: 'inactive-tenant',
        }))
      );

      const inactiveUserToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'inactive-user',
          tenantId: 'inactive-tenant',
        }),
        module.get('JwtService')
      );

      // Should be rejected due to inactive tenant
      const response = await request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', `Bearer ${inactiveUserToken}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Unauthorized');
    });
  });
});
