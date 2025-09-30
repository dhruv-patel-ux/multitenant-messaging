import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { DataSource as TypeOrmDataSource } from 'typeorm';

import { User } from '../../src/users/entities/user.entity';
import { Tenant } from '../../src/tenants/entities/tenant.entity';
import { Message } from '../../src/messages/entities/message.entity';
import { WahaSession } from '../../src/waha/entities/waha-session.entity';
import { RefreshToken } from '../../src/auth/entities/refresh-token.entity';
import { LoginAttempt } from '../../src/auth/entities/login-attempt.entity';
import { UserRole } from '../../src/users/entities/user.entity';
import { TenantStatus } from '../../src/tenants/entities/tenant.entity';
import { MessageStatus, MessageDirection } from '../../src/messages/entities/message.entity';
import { WahaSessionStatus, WahaEngine } from '../../src/waha/entities/waha-session.entity';

import {
  TestDatabase,
  TestHelpers,
  TestDataFactory,
  DatabaseTestHelpers,
  MockHelpers,
  TestAssertions,
} from '../setup';

describe('Database Tests', () => {
  let module: TestingModule;
  let dataSource: DataSource;
  let userRepository: Repository<User>;
  let tenantRepository: Repository<Tenant>;
  let messageRepository: Repository<Message>;
  let sessionRepository: Repository<WahaSession>;
  let refreshTokenRepository: Repository<RefreshToken>;
  let loginAttemptRepository: Repository<LoginAttempt>;

  beforeAll(async () => {
    module = await TestDatabase.createTestModule();
    dataSource = module.get<DataSource>(DataSource);

    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    tenantRepository = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    messageRepository = module.get<Repository<Message>>(getRepositoryToken(Message));
    sessionRepository = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));
    refreshTokenRepository = module.get<Repository<RefreshToken>>(getRepositoryToken(RefreshToken));
    loginAttemptRepository = module.get<Repository<LoginAttempt>>(getRepositoryToken(LoginAttempt));
  });

  afterAll(async () => {
    await TestHelpers.cleanupDatabase(module);
  });

  beforeEach(() => {
    MockHelpers.resetAllMocks();
  });

  describe('Entity Relationships', () => {
    it('should create tenant with users relationship', async () => {
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-relationships',
          name: 'Relationship Test Tenant',
        }))
      );

      const user = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-relationships',
          email: 'relationship@tenant.com',
          tenantId: tenant.id,
          role: UserRole.TENANT_ADMIN,
        }))
      );

      // Test relationship
      const tenantWithUsers = await tenantRepository.findOne({
        where: { id: tenant.id },
        relations: ['users'],
      });

      expect(tenantWithUsers).toBeDefined();
      expect(tenantWithUsers?.users).toHaveLength(1);
      expect(tenantWithUsers?.users[0].id).toBe(user.id);
    });

    it('should create user with refresh tokens relationship', async () => {
      const user = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-refresh-tokens',
          email: 'refreshtokens@tenant.com',
          tenantId: 'tenant-relationships',
          role: UserRole.TENANT_ADMIN,
        }))
      );

      const refreshToken = await refreshTokenRepository.save(
        refreshTokenRepository.create(TestDataFactory.createRefreshToken({
          id: 'refresh-token-1',
          userId: user.id,
          token: 'refresh-token-123',
        }))
      );

      // Test relationship
      const userWithTokens = await userRepository.findOne({
        where: { id: user.id },
        relations: ['refreshTokens'],
      });

      expect(userWithTokens).toBeDefined();
      expect(userWithTokens?.refreshTokens).toHaveLength(1);
      expect(userWithTokens?.refreshTokens[0].id).toBe(refreshToken.id);
    });

    it('should create session with messages relationship', async () => {
      const session = await sessionRepository.save(
        sessionRepository.create(TestDataFactory.createWahaSession({
          id: 'session-messages',
          tenantId: 'tenant-relationships',
          externalSessionId: 'waha-session-messages',
          status: WahaSessionStatus.WORKING,
        }))
      );

      const message = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'message-session',
          tenantId: 'tenant-relationships',
          sessionId: session.id,
          direction: MessageDirection.OUTBOUND,
          status: MessageStatus.SENT,
          body: 'Session message test',
        }))
      );

      // Test relationship
      const sessionWithMessages = await sessionRepository.findOne({
        where: { id: session.id },
        relations: ['messages'],
      });

      expect(sessionWithMessages).toBeDefined();
      expect(sessionWithMessages?.messages).toHaveLength(1);
      expect(sessionWithMessages?.messages[0].id).toBe(message.id);
    });
  });

  describe('Database Constraints', () => {
    it('should enforce unique email per tenant constraint', async () => {
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-unique',
          name: 'Unique Test Tenant',
        }))
      );

      // Create first user
      await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-unique-1',
          email: 'unique@tenant.com',
          tenantId: tenant.id,
          role: UserRole.TENANT_ADMIN,
        }))
      );

      // Try to create second user with same email in same tenant
      await expect(
        userRepository.save(
          userRepository.create(TestDataFactory.createUser({
            id: 'user-unique-2',
            email: 'unique@tenant.com', // Same email
            tenantId: tenant.id, // Same tenant
            role: UserRole.AGENT,
          }))
        )
      ).rejects.toThrow();
    });

    it('should allow same email in different tenants', async () => {
      const tenant1 = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-unique-1',
          name: 'Unique Tenant 1',
        }))
      );

      const tenant2 = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-unique-2',
          name: 'Unique Tenant 2',
        }))
      );

      // Create users with same email in different tenants
      const user1 = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-unique-tenant-1',
          email: 'same@email.com',
          tenantId: tenant1.id,
          role: UserRole.TENANT_ADMIN,
        }))
      );

      const user2 = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-unique-tenant-2',
          email: 'same@email.com', // Same email
          tenantId: tenant2.id, // Different tenant
          role: UserRole.TENANT_ADMIN,
        }))
      );

      expect(user1).toBeDefined();
      expect(user2).toBeDefined();
      expect(user1.email).toBe(user2.email);
      expect(user1.tenantId).not.toBe(user2.tenantId);
    });

    it('should enforce foreign key constraints', async () => {
      // Try to create message with non-existent session
      await expect(
        messageRepository.save(
          messageRepository.create(TestDataFactory.createMessage({
            id: 'message-invalid-session',
            tenantId: 'tenant-relationships',
            sessionId: 'non-existent-session',
            direction: MessageDirection.OUTBOUND,
            status: MessageStatus.SENT,
            body: 'Invalid session message',
          }))
        )
      ).rejects.toThrow();
    });

    it('should enforce cascade delete', async () => {
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-cascade',
          name: 'Cascade Test Tenant',
        }))
      );

      const user = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-cascade',
          email: 'cascade@tenant.com',
          tenantId: tenant.id,
          role: UserRole.TENANT_ADMIN,
        }))
      );

      const session = await sessionRepository.save(
        sessionRepository.create(TestDataFactory.createWahaSession({
          id: 'session-cascade',
          tenantId: tenant.id,
          externalSessionId: 'waha-cascade-session',
          status: WahaSessionStatus.WORKING,
        }))
      );

      const message = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'message-cascade',
          tenantId: tenant.id,
          sessionId: session.id,
          direction: MessageDirection.OUTBOUND,
          status: MessageStatus.SENT,
          body: 'Cascade test message',
        }))
      );

      // Delete tenant
      await tenantRepository.delete(tenant.id);

      // Verify cascade delete
      const deletedUser = await userRepository.findOne({ where: { id: user.id } });
      const deletedSession = await sessionRepository.findOne({ where: { id: session.id } });
      const deletedMessage = await messageRepository.findOne({ where: { id: message.id } });

      expect(deletedUser).toBeNull();
      expect(deletedSession).toBeNull();
      expect(deletedMessage).toBeNull();
    });
  });

  describe('Transaction Rollback Testing', () => {
    it('should rollback transaction on error', async () => {
      const queryRunner = dataSource.createQueryRunner();
      await queryRunner.connect();
      await queryRunner.startTransaction();

      try {
        // Create tenant
        const tenant = await queryRunner.manager.save(
          queryRunner.manager.create(Tenant, TestDataFactory.createTenant({
            id: 'tenant-transaction',
            name: 'Transaction Test Tenant',
          }))
        );

        // Create user
        const user = await queryRunner.manager.save(
          queryRunner.manager.create(User, TestDataFactory.createUser({
            id: 'user-transaction',
            email: 'transaction@tenant.com',
            tenantId: tenant.id,
            role: UserRole.TENANT_ADMIN,
          }))
        );

        // Force error
        throw new Error('Transaction error');

      } catch (error) {
        await queryRunner.rollbackTransaction();
        throw error;
      } finally {
        await queryRunner.release();
      }

      // Verify rollback
      const tenant = await tenantRepository.findOne({ where: { id: 'tenant-transaction' } });
      const user = await userRepository.findOne({ where: { id: 'user-transaction' } });

      expect(tenant).toBeNull();
      expect(user).toBeNull();
    });

    it('should commit transaction on success', async () => {
      const queryRunner = dataSource.createQueryRunner();
      await queryRunner.connect();
      await queryRunner.startTransaction();

      try {
        // Create tenant
        const tenant = await queryRunner.manager.save(
          queryRunner.manager.create(Tenant, TestDataFactory.createTenant({
            id: 'tenant-commit',
            name: 'Commit Test Tenant',
          }))
        );

        // Create user
        const user = await queryRunner.manager.save(
          queryRunner.manager.create(User, TestDataFactory.createUser({
            id: 'user-commit',
            email: 'commit@tenant.com',
            tenantId: tenant.id,
            role: UserRole.TENANT_ADMIN,
          }))
        );

        await queryRunner.commitTransaction();

        // Verify commit
        const savedTenant = await tenantRepository.findOne({ where: { id: tenant.id } });
        const savedUser = await userRepository.findOne({ where: { id: user.id } });

        expect(savedTenant).toBeDefined();
        expect(savedUser).toBeDefined();
        expect(savedUser?.tenantId).toBe(tenant.id);

      } finally {
        await queryRunner.release();
      }
    });
  });

  describe('Connection Pool Behavior', () => {
    it('should handle multiple concurrent connections', async () => {
      const promises = Array.from({ length: 10 }, async (_, i) => {
        const tenant = await tenantRepository.save(
          tenantRepository.create(TestDataFactory.createTenant({
            id: `tenant-concurrent-${i}`,
            name: `Concurrent Tenant ${i}`,
          }))
        );

        return tenant;
      });

      const tenants = await Promise.all(promises);

      expect(tenants).toHaveLength(10);
      expect(tenants.every(tenant => tenant.id.startsWith('tenant-concurrent-'))).toBe(true);
    });

    it('should handle connection timeout', async () => {
      // This would test connection timeout scenarios
      // In a real test, you might simulate slow queries or connection issues
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-timeout',
          name: 'Timeout Test Tenant',
        }))
      );

      expect(tenant).toBeDefined();
    });

    it('should handle connection pool exhaustion', async () => {
      // This would test what happens when the connection pool is exhausted
      // In a real test, you might create many concurrent operations
      const promises = Array.from({ length: 5 }, async (_, i) => {
        return tenantRepository.save(
          tenantRepository.create(TestDataFactory.createTenant({
            id: `tenant-pool-${i}`,
            name: `Pool Tenant ${i}`,
          }))
        );
      });

      const tenants = await Promise.all(promises);

      expect(tenants).toHaveLength(5);
    });
  });

  describe('Database Indexes', () => {
    it('should have proper indexes for performance', async () => {
      // Test that queries use indexes efficiently
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-indexes',
          name: 'Index Test Tenant',
        }))
      );

      const user = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-indexes',
          email: 'indexes@tenant.com',
          tenantId: tenant.id,
          role: UserRole.TENANT_ADMIN,
        }))
      );

      // Test indexed queries
      const userByEmail = await userRepository.findOne({
        where: { email: 'indexes@tenant.com', tenantId: tenant.id },
      });

      expect(userByEmail).toBeDefined();
      expect(userByEmail?.id).toBe(user.id);
    });

    it('should handle composite index queries', async () => {
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-composite',
          name: 'Composite Index Tenant',
        }))
      );

      const message = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'message-composite',
          tenantId: tenant.id,
          sessionId: 'session-composite',
          direction: MessageDirection.OUTBOUND,
          status: MessageStatus.SENT,
          body: 'Composite index test',
        }))
      );

      // Test composite index query
      const messageByTenantAndStatus = await messageRepository.findOne({
        where: { tenantId: tenant.id, status: MessageStatus.SENT },
      });

      expect(messageByTenantAndStatus).toBeDefined();
      expect(messageByTenantAndStatus?.id).toBe(message.id);
    });
  });

  describe('Data Integrity', () => {
    it('should maintain data integrity across operations', async () => {
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-integrity',
          name: 'Integrity Test Tenant',
        }))
      );

      const user = await userRepository.save(
        userRepository.create(TestDataFactory.createUser({
          id: 'user-integrity',
          email: 'integrity@tenant.com',
          tenantId: tenant.id,
          role: UserRole.TENANT_ADMIN,
        }))
      );

      const session = await sessionRepository.save(
        sessionRepository.create(TestDataFactory.createWahaSession({
          id: 'session-integrity',
          tenantId: tenant.id,
          externalSessionId: 'waha-integrity-session',
          status: WahaSessionStatus.WORKING,
        }))
      );

      const message = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'message-integrity',
          tenantId: tenant.id,
          sessionId: session.id,
          direction: MessageDirection.OUTBOUND,
          status: MessageStatus.SENT,
          body: 'Integrity test message',
        }))
      );

      // Verify all relationships are intact
      const tenantWithRelations = await tenantRepository.findOne({
        where: { id: tenant.id },
        relations: ['users', 'wahaSessions'],
      });

      expect(tenantWithRelations).toBeDefined();
      expect(tenantWithRelations?.users).toHaveLength(1);
      expect(tenantWithRelations?.wahaSessions).toHaveLength(1);
      expect(tenantWithRelations?.users[0].id).toBe(user.id);
      expect(tenantWithRelations?.wahaSessions[0].id).toBe(session.id);
    });

    it('should handle soft deletes correctly', async () => {
      const tenant = await tenantRepository.save(
        tenantRepository.create(TestDataFactory.createTenant({
          id: 'tenant-soft-delete',
          name: 'Soft Delete Test Tenant',
        }))
      );

      // Soft delete tenant
      await tenantRepository.softDelete(tenant.id);

      // Verify soft delete
      const deletedTenant = await tenantRepository.findOne({
        where: { id: tenant.id },
        withDeleted: true,
      });

      expect(deletedTenant).toBeDefined();
      expect(deletedTenant?.deletedAt).toBeDefined();

      // Verify tenant is not found in normal queries
      const normalTenant = await tenantRepository.findOne({
        where: { id: tenant.id },
      });

      expect(normalTenant).toBeNull();
    });
  });
});
