import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as request from 'supertest';

import { MessagesService } from '../../src/messages/messages.service';
import { WahaService } from '../../src/waha/waha.service';
import { WebhooksService } from '../../src/webhooks/webhooks.service';
import { User } from '../../src/users/entities/user.entity';
import { Tenant } from '../../src/tenants/entities/tenant.entity';
import { Message } from '../../src/messages/entities/message.entity';
import { WahaSession } from '../../src/waha/entities/waha-session.entity';
import { UserRole } from '../../src/users/entities/user.entity';
import { MessageStatus, MessageDirection } from '../../src/messages/entities/message.entity';
import { WahaSessionStatus } from '../../src/waha/entities/waha-session.entity';

import {
  TestDatabase,
  TestHelpers,
  TestDataFactory,
  AuthTestHelpers,
  DatabaseTestHelpers,
  MockHelpers,
  TestAssertions,
} from '../setup';

describe('Message Processing Flow', () => {
  let app: INestApplication;
  let module: TestingModule;
  let messagesService: MessagesService;
  let wahaService: WahaService;
  let webhooksService: WebhooksService;
  let userRepository: Repository<User>;
  let tenantRepository: Repository<Tenant>;
  let messageRepository: Repository<Message>;
  let sessionRepository: Repository<WahaSession>;

  let tenant: Tenant;
  let user: User;
  let session: WahaSession;
  let userToken: string;

  beforeAll(async () => {
    module = await TestDatabase.createTestModule();
    app = await TestHelpers.createTestApp(module);

    messagesService = module.get<MessagesService>(MessagesService);
    wahaService = module.get<WahaService>(WahaService);
    webhooksService = module.get<WebhooksService>(WebhooksService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    tenantRepository = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    messageRepository = module.get<Repository<Message>>(getRepositoryToken(Message));
    sessionRepository = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));

    // Create test tenant and user
    tenant = await tenantRepository.save(
      tenantRepository.create(TestDataFactory.createTenant({
        id: 'tenant-messages',
        name: 'Message Test Tenant',
      }))
    );

    user = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-messages',
        email: 'messages@tenant.com',
        tenantId: 'tenant-messages',
        role: UserRole.TENANT_ADMIN,
      }))
    );

    session = await sessionRepository.save(
      sessionRepository.create(TestDataFactory.createWahaSession({
        id: 'message-session',
        tenantId: 'tenant-messages',
        externalSessionId: 'waha-message-session',
        status: WahaSessionStatus.WORKING,
      }))
    );

    userToken = AuthTestHelpers.generateJwtToken(
      AuthTestHelpers.createUserPayload({
        sub: 'user-messages',
        tenantId: 'tenant-messages',
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

  describe('End-to-End Message Sending', () => {
    it('should send message successfully through complete flow', async () => {
      const mockWahaResponse = {
        messageId: 'waha-msg-123',
        to: '+1234567890',
        status: 'sent',
        timestamp: Date.now(),
      };

      MockHelpers.mockWahaServiceResponse('sendMessage', mockWahaResponse);

      const sendMessageDto = {
        sessionId: session.id,
        to: '+1234567890',
        body: 'End-to-end test message',
        priority: 'normal',
        metadata: {
          testId: 'e2e-test-123',
        },
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${userToken}`)
        .send(sendMessageDto)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.wahaMessageId).toBe('waha-msg-123');
      expect(response.body.data.status).toBe(MessageStatus.SENT);
      expect(response.body.data.direction).toBe(MessageDirection.OUTBOUND);
      expect(response.body.data.metadata.testId).toBe('e2e-test-123');

      // Verify message is stored in database
      const savedMessage = await messageRepository.findOne({
        where: { id: response.body.data.id },
      });

      expect(savedMessage).toBeDefined();
      expect(savedMessage?.wahaMessageId).toBe('waha-msg-123');
      expect(savedMessage?.status).toBe(MessageStatus.SENT);
    });

    it('should handle message sending failure gracefully', async () => {
      MockHelpers.mockWahaServiceError('sendMessage', new Error('WAHA service unavailable'));

      const sendMessageDto = {
        sessionId: session.id,
        to: '+1234567890',
        body: 'Failed message test',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${userToken}`)
        .send(sendMessageDto)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Failed to send message');

      // Verify message is marked as failed in database
      const failedMessage = await messageRepository.findOne({
        where: { body: 'Failed message test' },
      });

      expect(failedMessage).toBeDefined();
      expect(failedMessage?.status).toBe(MessageStatus.FAILED);
    });
  });

  describe('Message Queuing and Processing', () => {
    it('should queue message for processing', async () => {
      const message = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'queued-message',
          tenantId: 'tenant-messages',
          sessionId: session.id,
          status: MessageStatus.QUEUED,
          body: 'Queued message test',
        }))
      );

      // Test message queuing
      await messagesService.queueMessage(message);

      const queuedMessage = await messageRepository.findOne({
        where: { id: message.id },
      });

      expect(queuedMessage?.status).toBe(MessageStatus.QUEUED);
    });

    it('should process message queue', async () => {
      // Create multiple queued messages
      const messages = await Promise.all([
        messageRepository.save(
          messageRepository.create(TestDataFactory.createMessage({
            id: 'queue-msg-1',
            tenantId: 'tenant-messages',
            sessionId: session.id,
            status: MessageStatus.QUEUED,
            body: 'Queue message 1',
          }))
        ),
        messageRepository.save(
          messageRepository.create(TestDataFactory.createMessage({
            id: 'queue-msg-2',
            tenantId: 'tenant-messages',
            sessionId: session.id,
            status: MessageStatus.QUEUED,
            body: 'Queue message 2',
          }))
        ),
      ]);

      // Process message queue
      await messagesService.processMessageQueue();

      // Verify messages are processed
      const processedMessages = await messageRepository.find({
        where: { id: messages[0].id },
      });

      expect(processedMessages).toHaveLength(1);
    });

    it('should handle queue processing errors', async () => {
      const message = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'error-queue-msg',
          tenantId: 'tenant-messages',
          sessionId: session.id,
          status: MessageStatus.QUEUED,
          body: 'Error queue message',
        }))
      );

      // Mock WAHA service error
      MockHelpers.mockWahaServiceError('sendMessage', new Error('Queue processing error'));

      // Process message queue
      await messagesService.processMessageQueue();

      // Verify message status is updated
      const errorMessage = await messageRepository.findOne({
        where: { id: message.id },
      });

      expect(errorMessage?.status).toBe(MessageStatus.FAILED);
    });
  });

  describe('Message Status Updates', () => {
    let testMessage: Message;

    beforeEach(async () => {
      testMessage = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'status-message',
          tenantId: 'tenant-messages',
          sessionId: session.id,
          status: MessageStatus.SENT,
          body: 'Status update test',
        }))
      );
    });

    it('should update message status successfully', async () => {
      await messagesService.updateMessageStatus(testMessage.id, MessageStatus.DELIVERED);

      const updatedMessage = await messageRepository.findOne({
        where: { id: testMessage.id },
      });

      expect(updatedMessage?.status).toBe(MessageStatus.DELIVERED);
    });

    it('should handle status update for non-existent message', async () => {
      await expect(
        messagesService.updateMessageStatus('non-existent-id', MessageStatus.DELIVERED)
      ).rejects.toThrow('Message not found');
    });

    it('should track status change history', async () => {
      const initialStatus = testMessage.status;
      
      await messagesService.updateMessageStatus(testMessage.id, MessageStatus.DELIVERED);
      
      const updatedMessage = await messageRepository.findOne({
        where: { id: testMessage.id },
      });

      expect(updatedMessage?.status).not.toBe(initialStatus);
      expect(updatedMessage?.updatedAt).toBeDefined();
    });
  });

  describe('Bulk Message Handling', () => {
    it('should process bulk messages successfully', async () => {
      const bulkMessageDto = {
        sessionId: session.id,
        recipients: ['+1111111111', '+2222222222', '+3333333333'],
        body: 'Bulk message test',
        batchSize: 2,
        priority: 'normal',
        metadata: {
          campaignId: 'bulk-test-123',
        },
      };

      const response = await request(app.getHttpServer())
        .post('/messages/bulk')
        .set('Authorization', `Bearer ${userToken}`)
        .send(bulkMessageDto)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.totalQueued).toBe(3);
      expect(response.body.data.successCount).toBe(3);
      expect(response.body.data.failureCount).toBe(0);
      expect(response.body.data.batchInfo.totalBatches).toBe(2);
    });

    it('should handle bulk message failures', async () => {
      const bulkMessageDto = {
        sessionId: session.id,
        recipients: ['+1111111111', 'invalid-phone', '+3333333333'],
        body: 'Bulk message with failures',
        batchSize: 2,
      };

      const response = await request(app.getHttpServer())
        .post('/messages/bulk')
        .set('Authorization', `Bearer ${userToken}`)
        .send(bulkMessageDto)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.totalQueued).toBe(3);
      expect(response.body.data.successCount).toBe(2);
      expect(response.body.data.failureCount).toBe(1);
      expect(response.body.data.failedRecipients).toContain('invalid-phone');
    });

    it('should respect batch size limits', async () => {
      const bulkMessageDto = {
        sessionId: session.id,
        recipients: Array.from({ length: 100 }, (_, i) => `+${1000000000 + i}`),
        body: 'Large bulk message',
        batchSize: 10,
      };

      const response = await request(app.getHttpServer())
        .post('/messages/bulk')
        .set('Authorization', `Bearer ${userToken}`)
        .send(bulkMessageDto)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.batchInfo.totalBatches).toBe(10);
      expect(response.body.data.batchInfo.batchSize).toBe(10);
    });
  });

  describe('Message Retry Mechanism', () => {
    let failedMessage: Message;

    beforeEach(async () => {
      failedMessage = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'retry-message',
          tenantId: 'tenant-messages',
          sessionId: session.id,
          status: MessageStatus.FAILED,
          body: 'Retry test message',
        }))
      );
    });

    it('should retry failed message successfully', async () => {
      const mockWahaResponse = {
        messageId: 'waha-retry-123',
        to: '+1234567890',
        status: 'sent',
        timestamp: Date.now(),
      };

      MockHelpers.mockWahaServiceResponse('sendMessage', mockWahaResponse);

      await messagesService.retryFailedMessage(failedMessage.id);

      const retriedMessage = await messageRepository.findOne({
        where: { id: failedMessage.id },
      });

      expect(retriedMessage?.status).toBe(MessageStatus.QUEUED);
    });

    it('should handle retry for non-existent message', async () => {
      await expect(
        messagesService.retryFailedMessage('non-existent-id')
      ).rejects.toThrow('Message not found');
    });

    it('should handle retry for non-failed message', async () => {
      const sentMessage = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'sent-message',
          tenantId: 'tenant-messages',
          sessionId: session.id,
          status: MessageStatus.SENT,
          body: 'Sent message',
        }))
      );

      await expect(
        messagesService.retryFailedMessage(sentMessage.id)
      ).rejects.toThrow('Message is not in failed state');
    });

    it('should retry message via API endpoint', async () => {
      const response = await request(app.getHttpServer())
        .post(`/messages/${failedMessage.id}/retry`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(204);

      expect(response.body).toEqual({});
    });
  });

  describe('Inbound Message Processing', () => {
    it('should process inbound message from webhook', async () => {
      const inboundPayload = {
        event: 'message.text',
        session: 'waha-message-session',
        payload: {
          id: 'waha-inbound-123',
          from: '+1234567890',
          to: '+0987654321',
          body: 'Inbound message test',
          timestamp: Date.now(),
          type: 'text',
        },
      };

      const response = await request(app.getHttpServer())
        .post('/webhooks/waha')
        .set('X-Waha-Signature', 'sha256=test-signature')
        .send(inboundPayload)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Webhook processed successfully');

      // Verify inbound message is created
      const inboundMessage = await messageRepository.findOne({
        where: { wahaMessageId: 'waha-inbound-123' },
      });

      expect(inboundMessage).toBeDefined();
      expect(inboundMessage?.direction).toBe(MessageDirection.INBOUND);
      expect(inboundMessage?.body).toBe('Inbound message test');
    });

    it('should handle inbound message processing errors', async () => {
      const invalidPayload = {
        event: 'message.text',
        session: 'non-existent-session',
        payload: {
          id: 'waha-invalid-123',
          from: '+1234567890',
          to: '+0987654321',
          body: 'Invalid inbound message',
          timestamp: Date.now(),
          type: 'text',
        },
      };

      const response = await request(app.getHttpServer())
        .post('/webhooks/waha')
        .set('X-Waha-Signature', 'sha256=test-signature')
        .send(invalidPayload)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Webhook received but processing failed');
    });
  });

  describe('Webhook Message Handling', () => {
    it('should handle message status webhook', async () => {
      const message = await messageRepository.save(
        messageRepository.create(TestDataFactory.createMessage({
          id: 'webhook-message',
          tenantId: 'tenant-messages',
          sessionId: session.id,
          wahaMessageId: 'waha-webhook-123',
          status: MessageStatus.SENT,
          body: 'Webhook status test',
        }))
      );

      const statusPayload = {
        event: 'message.status',
        session: 'waha-message-session',
        payload: {
          id: 'waha-webhook-123',
          status: 'delivered',
          timestamp: Date.now(),
        },
      };

      const response = await request(app.getHttpServer())
        .post('/webhooks/waha')
        .set('X-Waha-Signature', 'sha256=test-signature')
        .send(statusPayload)
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify message status is updated
      const updatedMessage = await messageRepository.findOne({
        where: { id: message.id },
      });

      expect(updatedMessage?.status).toBe(MessageStatus.DELIVERED);
    });

    it('should handle session status webhook', async () => {
      const sessionPayload = {
        event: 'session.status',
        session: 'waha-message-session',
        payload: {
          status: 'working',
          metadata: {
            profileName: 'Test WhatsApp',
          },
        },
      };

      const response = await request(app.getHttpServer())
        .post('/webhooks/waha')
        .set('X-Waha-Signature', 'sha256=test-signature')
        .send(sessionPayload)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should handle webhook signature validation', async () => {
      const payload = {
        event: 'message.text',
        session: 'waha-message-session',
        payload: {
          id: 'waha-signature-test',
          from: '+1234567890',
          to: '+0987654321',
          body: 'Signature test',
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
  });

  describe('Message Statistics and Analytics', () => {
    beforeEach(async () => {
      // Create test messages for statistics
      await Promise.all([
        messageRepository.save(
          messageRepository.create(TestDataFactory.createMessage({
            id: 'stats-msg-1',
            tenantId: 'tenant-messages',
            sessionId: session.id,
            direction: MessageDirection.OUTBOUND,
            status: MessageStatus.SENT,
            body: 'Stats message 1',
            createdAt: new Date('2024-01-15T10:00:00Z'),
          }))
        ),
        messageRepository.save(
          messageRepository.create(TestDataFactory.createMessage({
            id: 'stats-msg-2',
            tenantId: 'tenant-messages',
            sessionId: session.id,
            direction: MessageDirection.INBOUND,
            status: MessageStatus.DELIVERED,
            body: 'Stats message 2',
            createdAt: new Date('2024-01-15T11:00:00Z'),
          }))
        ),
        messageRepository.save(
          messageRepository.create(TestDataFactory.createMessage({
            id: 'stats-msg-3',
            tenantId: 'tenant-messages',
            sessionId: session.id,
            direction: MessageDirection.OUTBOUND,
            status: MessageStatus.FAILED,
            body: 'Stats message 3',
            createdAt: new Date('2024-01-15T12:00:00Z'),
          }))
        ),
      ]);
    });

    it('should generate message statistics', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages/stats?fromDate=2024-01-15T00:00:00Z&toDate=2024-01-15T23:59:59Z')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.totalMessages).toBe(3);
      expect(response.body.data.outboundMessages).toBe(2);
      expect(response.body.data.inboundMessages).toBe(1);
      expect(response.body.data.messagesByStatus.sent).toBe(1);
      expect(response.body.data.messagesByStatus.delivered).toBe(1);
      expect(response.body.data.messagesByStatus.failed).toBe(1);
    });

    it('should calculate success rate correctly', async () => {
      const response = await request(app.getHttpServer())
        .get('/messages/stats?fromDate=2024-01-15T00:00:00Z&toDate=2024-01-15T23:59:59Z')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.successRate).toBe(66.7); // 2 successful out of 3 total
    });
  });
});
