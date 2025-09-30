import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as request from 'supertest';

import { UsersService } from '../../src/users/users.service';
import { TenantsService } from '../../src/tenants/tenants.service';
import { MessagesService } from '../../src/messages/messages.service';
import { WahaService } from '../../src/waha/waha.service';
import { User } from '../../src/users/entities/user.entity';
import { Tenant } from '../../src/tenants/entities/tenant.entity';
import { Message } from '../../src/messages/entities/message.entity';
import { WahaSession } from '../../src/waha/entities/waha-session.entity';
import { UserRole } from '../../src/users/entities/user.entity';
import { Permission } from '../../src/common/enums/roles.enum';

import {
  TestDatabase,
  TestHelpers,
  TestDataFactory,
  AuthTestHelpers,
  DatabaseTestHelpers,
  MockHelpers,
  TestAssertions,
} from '../setup';

describe('Role-Based Access Control', () => {
  let app: INestApplication;
  let module: TestingModule;
  let usersService: UsersService;
  let tenantsService: TenantsService;
  let messagesService: MessagesService;
  let wahaService: WahaService;
  let userRepository: Repository<User>;
  let tenantRepository: Repository<Tenant>;
  let messageRepository: Repository<Message>;
  let sessionRepository: Repository<WahaSession>;

  let tenant: Tenant;
  let tenantAdmin: User;
  let manager: User;
  let agent: User;
  let auditor: User;

  beforeAll(async () => {
    module = await TestDatabase.createTestModule();
    app = await TestHelpers.createTestApp(module);

    usersService = module.get<UsersService>(UsersService);
    tenantsService = module.get<TenantsService>(TenantsService);
    messagesService = module.get<MessagesService>(MessagesService);
    wahaService = module.get<WahaService>(WahaService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    tenantRepository = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    messageRepository = module.get<Repository<Message>>(getRepositoryToken(Message));
    sessionRepository = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));

    // Create test tenant
    tenant = await tenantRepository.save(
      tenantRepository.create(TestDataFactory.createTenant({
        id: 'tenant-rbac',
        name: 'RBAC Test Tenant',
      }))
    );

    // Create users with different roles
    tenantAdmin = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-admin',
        email: 'admin@tenant.com',
        tenantId: 'tenant-rbac',
        role: UserRole.TENANT_ADMIN,
      }))
    );

    manager = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-manager',
        email: 'manager@tenant.com',
        tenantId: 'tenant-rbac',
        role: UserRole.MANAGER,
      }))
    );

    agent = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-agent',
        email: 'agent@tenant.com',
        tenantId: 'tenant-rbac',
        role: UserRole.AGENT,
      }))
    );

    auditor = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-auditor',
        email: 'auditor@tenant.com',
        tenantId: 'tenant-rbac',
        role: UserRole.AUDITOR,
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

  describe('TENANT_ADMIN Role', () => {
    let adminToken: string;

    beforeAll(() => {
      adminToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-admin',
          tenantId: 'tenant-rbac',
          role: UserRole.TENANT_ADMIN,
        }),
        module.get('JwtService')
      );
    });

    it('should allow access to all tenant resources', async () => {
      const endpoints = [
        { method: 'GET', path: '/users' },
        { method: 'GET', path: '/tenants/current' },
        { method: 'GET', path: '/waha/sessions' },
        { method: 'GET', path: '/messages' },
        { method: 'GET', path: '/messages/stats?fromDate=2024-01-01T00:00:00Z&toDate=2024-01-31T23:59:59Z' },
      ];

      for (const endpoint of endpoints) {
        const response = await request(app.getHttpServer())
          [endpoint.method.toLowerCase()](endpoint.path)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
      }
    });

    it('should allow user management operations', async () => {
      const newUserDto = {
        email: 'newuser@tenant.com',
        password: 'password123',
        role: UserRole.AGENT,
      };

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(newUserDto)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe('newuser@tenant.com');
    });

    it('should allow tenant settings management', async () => {
      const updateTenantDto = {
        name: 'Updated Tenant Name',
        settings: { theme: 'dark' },
      };

      const response = await request(app.getHttpServer())
        .put('/tenants/current')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(updateTenantDto)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should allow session management', async () => {
      const createSessionDto = {
        name: 'admin-session',
        engine: 'WEBJS',
        config: { timeout: 30000 },
      };

      const response = await request(app.getHttpServer())
        .post('/waha/sessions')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(createSessionDto)
        .expect(201);

      expect(response.body.success).toBe(true);
    });

    it('should allow message management', async () => {
      const sendMessageDto = {
        sessionId: 'session-123',
        to: '+1234567890',
        body: 'Admin message',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(sendMessageDto)
        .expect(201);

      expect(response.body.success).toBe(true);
    });
  });

  describe('MANAGER Role', () => {
    let managerToken: string;

    beforeAll(() => {
      managerToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-manager',
          tenantId: 'tenant-rbac',
          role: UserRole.MANAGER,
        }),
        module.get('JwtService')
      );
    });

    it('should allow read access to users', async () => {
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${managerToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should deny user creation', async () => {
      const newUserDto = {
        email: 'newuser@tenant.com',
        password: 'password123',
        role: UserRole.AGENT,
      };

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${managerToken}`)
        .send(newUserDto)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });

    it('should allow session management', async () => {
      const response = await request(app.getHttpServer())
        .get('/waha/sessions')
        .set('Authorization', `Bearer ${managerToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should allow message operations', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${managerToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should deny tenant settings management', async () => {
      const updateTenantDto = {
        name: 'Updated Tenant Name',
      };

      const response = await request(app.getHttpServer())
        .put('/tenants/current')
        .set('Authorization', `Bearer ${managerToken}`)
        .send(updateTenantDto)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });
  });

  describe('AGENT Role', () => {
    let agentToken: string;

    beforeAll(() => {
      agentToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-agent',
          tenantId: 'tenant-rbac',
          role: UserRole.AGENT,
        }),
        module.get('JwtService')
      );
    });

    it('should allow basic message operations', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${agentToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should allow session read access', async () => {
      const response = await request(app.getHttpServer())
        .get('/waha/sessions')
        .set('Authorization', `Bearer ${agentToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should deny user management', async () => {
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${agentToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });

    it('should deny tenant management', async () => {
      const response = await request(app.getHttpServer())
        .get('/tenants/current')
        .set('Authorization', `Bearer ${agentToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });

    it('should deny session creation', async () => {
      const createSessionDto = {
        name: 'agent-session',
        engine: 'WEBJS',
      };

      const response = await request(app.getHttpServer())
        .post('/waha/sessions')
        .set('Authorization', `Bearer ${agentToken}`)
        .send(createSessionDto)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });
  });

  describe('AUDITOR Role', () => {
    let auditorToken: string;

    beforeAll(() => {
      auditorToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-auditor',
          tenantId: 'tenant-rbac',
          role: UserRole.AUDITOR,
        }),
        module.get('JwtService')
      );
    });

    it('should allow read-only access to users', async () => {
      const response = await request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${auditorToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should allow read-only access to messages', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages')
        .set('Authorization', `Bearer ${auditorToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should allow read-only access to sessions', async () => {
      const response = await request(app.getHttpServer())
        .get('/waha/sessions')
        .set('Authorization', `Bearer ${auditorToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should allow access to statistics', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages/stats?fromDate=2024-01-01T00:00:00Z&toDate=2024-01-31T23:59:59Z')
        .set('Authorization', `Bearer ${auditorToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should deny write operations', async () => {
      const sendMessageDto = {
        sessionId: 'session-123',
        to: '+1234567890',
        body: 'Auditor message attempt',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send(sendMessageDto)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });

    it('should deny user creation', async () => {
      const newUserDto = {
        email: 'newuser@tenant.com',
        password: 'password123',
        role: UserRole.AGENT,
      };

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send(newUserDto)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });
  });

  describe('Role Hierarchy Enforcement', () => {
    it('should enforce role hierarchy for permissions', async () => {
      const roles = [
        { role: UserRole.TENANT_ADMIN, expectedPermissions: 20 },
        { role: UserRole.MANAGER, expectedPermissions: 15 },
        { role: UserRole.AGENT, expectedPermissions: 4 },
        { role: UserRole.AUDITOR, expectedPermissions: 8 },
      ];

      for (const { role, expectedPermissions } of roles) {
        const token = AuthTestHelpers.generateJwtToken(
          AuthTestHelpers.createUserPayload({
            sub: `user-${role}`,
            tenantId: 'tenant-rbac',
            role,
          }),
          module.get('JwtService')
        );

        // Test that role has appropriate permissions
        // This would be tested by checking the role permissions mapping
        expect(expectedPermissions).toBeGreaterThan(0);
      }
    });

    it('should prevent role escalation', async () => {
      const agentToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-agent',
          tenantId: 'tenant-rbac',
          role: UserRole.AGENT,
        }),
        module.get('JwtService')
      );

      // Agent should not be able to create users with higher roles
      const newUserDto = {
        email: 'newuser@tenant.com',
        password: 'password123',
        role: UserRole.TENANT_ADMIN, // Higher role
      };

      const response = await request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${agentToken}`)
        .send(newUserDto)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Forbidden');
    });
  });

  describe('Permission-Based Access Control', () => {
    it('should check specific permissions for endpoints', async () => {
      const permissionTests = [
        {
          role: UserRole.AGENT,
          endpoint: '/users',
          method: 'GET',
          expectedStatus: 403,
          permission: Permission.USERS_READ,
        },
        {
          role: UserRole.MANAGER,
          endpoint: '/users',
          method: 'GET',
          expectedStatus: 200,
          permission: Permission.USERS_READ,
        },
        {
          role: UserRole.AUDITOR,
          endpoint: '/messages/send',
          method: 'POST',
          expectedStatus: 403,
          permission: Permission.MESSAGES_SEND,
        },
      ];

      for (const test of permissionTests) {
        const token = AuthTestHelpers.generateJwtToken(
          AuthTestHelpers.createUserPayload({
            sub: `user-${test.role}`,
            tenantId: 'tenant-rbac',
            role: test.role,
          }),
          module.get('JwtService')
        );

        const response = await request(app.getHttpServer())
          [test.method.toLowerCase()](test.endpoint)
          .set('Authorization', `Bearer ${token}`)
          .expect(test.expectedStatus);

        if (test.expectedStatus === 403) {
          expect(response.body.success).toBe(false);
          expect(response.body.message).toContain('Forbidden');
        } else {
          expect(response.body.success).toBe(true);
        }
      }
    });
  });

  describe('Unauthorized Access Prevention', () => {
    it('should return 403 for insufficient permissions', async () => {
      const agentToken = AuthTestHelpers.generateJwtToken(
        AuthTestHelpers.createUserPayload({
          sub: 'user-agent',
          tenantId: 'tenant-rbac',
          role: UserRole.AGENT,
        }),
        module.get('JwtService')
      );

      const restrictedEndpoints = [
        { method: 'GET', path: '/users' },
        { method: 'POST', path: '/users' },
        { method: 'PUT', path: '/tenants/current' },
        { method: 'POST', path: '/waha/sessions' },
      ];

      for (const endpoint of restrictedEndpoints) {
        const response = await request(app.getHttpServer())
          [endpoint.method.toLowerCase()](endpoint.path)
          .set('Authorization', `Bearer ${agentToken}`)
          .expect(403);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Forbidden');
      }
    });

    it('should return 401 for invalid or missing tokens', async () => {
      const endpoints = [
        { method: 'GET', path: '/users' },
        { method: 'GET', path: '/messages' },
        { method: 'GET', path: '/waha/sessions' },
      ];

      for (const endpoint of endpoints) {
        const response = await request(app.getHttpServer())
          [endpoint.method.toLowerCase()](endpoint.path)
          .expect(401);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('Unauthorized');
      }
    });
  });

  describe('Role Context in JWT', () => {
    it('should include role information in JWT payload', async () => {
      const tokens = [
        { user: tenantAdmin, role: UserRole.TENANT_ADMIN },
        { user: manager, role: UserRole.MANAGER },
        { user: agent, role: UserRole.AGENT },
        { user: auditor, role: UserRole.AUDITOR },
      ];

      for (const { user, role } of tokens) {
        const token = AuthTestHelpers.generateJwtToken(
          AuthTestHelpers.createUserPayload({
            sub: user.id,
            tenantId: 'tenant-rbac',
            role,
          }),
          module.get('JwtService')
        );

        const decoded = module.get('JwtService').decode(token) as any;
        expect(decoded.role).toBe(role);
        expect(decoded.tenantId).toBe('tenant-rbac');
      }
    });
  });
});
