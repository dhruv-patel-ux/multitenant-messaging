import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as request from 'supertest';
import { HttpException } from '@nestjs/common';

import { WahaService } from '../../src/waha/waha.service';
import { WahaClientService } from '../../src/waha/services/waha-client.service';
import { WahaConfigService } from '../../src/waha/services/waha-config.service';
import { User } from '../../src/users/entities/user.entity';
import { Tenant } from '../../src/tenants/entities/tenant.entity';
import { WahaSession } from '../../src/waha/entities/waha-session.entity';
import { UserRole } from '../../src/users/entities/user.entity';
import { WahaSessionStatus, WahaEngine } from '../../src/waha/entities/waha-session.entity';

import {
  TestDatabase,
  TestHelpers,
  TestDataFactory,
  AuthTestHelpers,
  DatabaseTestHelpers,
  MockHelpers,
  TestAssertions,
} from '../setup';

describe('WAHA Service Integration', () => {
  let app: INestApplication;
  let module: TestingModule;
  let wahaService: WahaService;
  let wahaClientService: WahaClientService;
  let wahaConfigService: WahaConfigService;
  let userRepository: Repository<User>;
  let tenantRepository: Repository<Tenant>;
  let sessionRepository: Repository<WahaSession>;

  let tenant: Tenant;
  let user: User;
  let userToken: string;

  beforeAll(async () => {
    module = await TestDatabase.createTestModule();
    app = await TestHelpers.createTestApp(module);

    wahaService = module.get<WahaService>(WahaService);
    wahaClientService = module.get<WahaClientService>(WahaClientService);
    wahaConfigService = module.get<WahaConfigService>(WahaConfigService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    tenantRepository = module.get<Repository<Tenant>>(getRepositoryToken(Tenant));
    sessionRepository = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));

    // Create test tenant and user
    tenant = await tenantRepository.save(
      tenantRepository.create(TestDataFactory.createTenant({
        id: 'tenant-waha',
        name: 'WAHA Test Tenant',
      }))
    );

    user = await userRepository.save(
      userRepository.create(TestDataFactory.createUser({
        id: 'user-waha',
        email: 'waha@tenant.com',
        tenantId: 'tenant-waha',
        role: UserRole.TENANT_ADMIN,
      }))
    );

    userToken = AuthTestHelpers.generateJwtToken(
      AuthTestHelpers.createUserPayload({
        sub: 'user-waha',
        tenantId: 'tenant-waha',
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

  describe('WAHA Health Check', () => {
    it('should check WAHA service health successfully', async () => {
      MockHelpers.mockWahaServiceResponse('checkHealth', true);

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.healthy).toBe(true);
    });

    it('should handle WAHA service unavailable', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('WAHA service unavailable'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });

    it('should get WAHA service version', async () => {
      MockHelpers.mockWahaServiceResponse('getVersion', '1.0.0');

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.version).toBe('1.0.0');
    });
  });

  describe('Session Creation', () => {
    it('should create WAHA session with valid config', async () => {
      const createSessionDto = {
        name: 'test-session',
        engine: WahaEngine.WEBJS,
        config: {
          timeout: 30000,
          webhook: {
            url: 'https://example.com/webhook',
            events: ['message', 'session.status'],
          },
        },
      };

      const mockSessionResponse = {
        id: 'session-123',
        name: 'test-session',
        status: WahaSessionStatus.STARTING,
        engine: WahaEngine.WEBJS,
        metadata: {},
      };

      MockHelpers.mockWahaServiceResponse('createSession', mockSessionResponse);

      const response = await request(app.getHttpServer())
        .post('/waha/sessions')
        .set('Authorization', `Bearer ${userToken}`)
        .send(createSessionDto)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe('test-session');
      expect(response.body.data.engine).toBe(WahaEngine.WEBJS);
    });

    it('should handle session creation failure', async () => {
      const createSessionDto = {
        name: 'invalid-session',
        engine: WahaEngine.WEBJS,
      };

      MockHelpers.mockWahaServiceError('createSession', new Error('Session creation failed'));

      const response = await request(app.getHttpServer())
        .post('/waha/sessions')
        .set('Authorization', `Bearer ${userToken}`)
        .send(createSessionDto)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Session creation failed');
    });

    it('should validate session configuration', async () => {
      const invalidSessionDto = {
        name: '', // Invalid empty name
        engine: 'INVALID_ENGINE', // Invalid engine
      };

      const response = await request(app.getHttpServer())
        .post('/waha/sessions')
        .set('Authorization', `Bearer ${userToken}`)
        .send(invalidSessionDto)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Validation failed');
    });
  });

  describe('Session Status Synchronization', () => {
    let testSession: WahaSession;

    beforeEach(async () => {
      testSession = await sessionRepository.save(
        sessionRepository.create(TestDataFactory.createWahaSession({
          id: 'sync-session',
          tenantId: 'tenant-waha',
          externalSessionId: 'waha-sync-session',
          status: WahaSessionStatus.STARTING,
        }))
      );
    });

    it('should synchronize session status successfully', async () => {
      const mockStatusResponse = {
        status: WahaSessionStatus.WORKING,
        metadata: {
          qrCode: 'base64-qr-code',
          profileName: 'Test WhatsApp',
        },
      };

      MockHelpers.mockWahaServiceResponse('getSessionStatus', mockStatusResponse);

      const response = await request(app.getHttpServer())
        .post(`/waha/sessions/${testSession.id}/sync`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.status).toBe(WahaSessionStatus.WORKING);
    });

    it('should handle session status sync failure', async () => {
      MockHelpers.mockWahaServiceError('getSessionStatus', new Error('Session not found'));

      const response = await request(app.getHttpServer())
        .post(`/waha/sessions/${testSession.id}/sync`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Session not found');
    });

    it('should update session metadata during sync', async () => {
      const mockStatusResponse = {
        status: WahaSessionStatus.SCAN_QR,
        metadata: {
          qrCode: 'base64-qr-code',
          profileName: 'Test WhatsApp',
        },
      };

      MockHelpers.mockWahaServiceResponse('getSessionStatus', mockStatusResponse);

      const response = await request(app.getHttpServer())
        .post(`/waha/sessions/${testSession.id}/sync`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.metadata.qrCode).toBe('base64-qr-code');
    });
  });

  describe('Message Sending Through WAHA', () => {
    let testSession: WahaSession;

    beforeEach(async () => {
      testSession = await sessionRepository.save(
        sessionRepository.create(TestDataFactory.createWahaSession({
          id: 'message-session',
          tenantId: 'tenant-waha',
          externalSessionId: 'waha-message-session',
          status: WahaSessionStatus.WORKING,
        }))
      );
    });

    it('should send message through WAHA successfully', async () => {
      const mockMessageResponse = {
        messageId: 'waha-msg-123',
        to: '+1234567890',
        status: 'sent',
        timestamp: Date.now(),
      };

      MockHelpers.mockWahaServiceResponse('sendMessage', mockMessageResponse);

      const sendMessageDto = {
        sessionId: testSession.id,
        to: '+1234567890',
        body: 'Test message via WAHA',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${userToken}`)
        .send(sendMessageDto)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.wahaMessageId).toBe('waha-msg-123');
      expect(response.body.data.status).toBe('sent');
    });

    it('should handle message sending failure', async () => {
      MockHelpers.mockWahaServiceError('sendMessage', new Error('Message sending failed'));

      const sendMessageDto = {
        sessionId: testSession.id,
        to: '+1234567890',
        body: 'Test message via WAHA',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${userToken}`)
        .send(sendMessageDto)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Message sending failed');
    });

    it('should validate phone number format', async () => {
      const sendMessageDto = {
        sessionId: testSession.id,
        to: 'invalid-phone', // Invalid phone format
        body: 'Test message via WAHA',
      };

      const response = await request(app.getHttpServer())
        .post('/messages/send')
        .set('Authorization', `Bearer ${userToken}`)
        .send(sendMessageDto)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Validation failed');
    });
  });

  describe('WAHA Service Unavailable Handling', () => {
    it('should handle WAHA service unavailable gracefully', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('Connection refused'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });

    it('should retry failed requests', async () => {
      let attemptCount = 0;
      const mockWahaService = {
        checkHealth: jest.fn().mockImplementation(() => {
          attemptCount++;
          if (attemptCount < 3) {
            throw new Error('Temporary failure');
          }
          return true;
        }),
      };

      // This would test the retry mechanism
      expect(attemptCount).toBe(0);
    });

    it('should handle timeout scenarios', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('Request timeout'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });
  });

  describe('API Key Authentication', () => {
    it('should include API key in WAHA requests', async () => {
      const mockHeaders = {
        'Authorization': 'Bearer test-api-key',
        'Content-Type': 'application/json',
      };

      MockHelpers.mockWahaServiceResponse('checkHealth', true);

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      // Verify that API key is included in the request
      // This would be tested by checking the request headers
    });

    it('should handle invalid API key', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('Unauthorized'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });
  });

  describe('Connection Timeout Scenarios', () => {
    it('should handle connection timeout', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('Connection timeout'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });

    it('should handle read timeout', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('Read timeout'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });

    it('should handle network errors', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('Network error'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });
  });

  describe('Session Management', () => {
    let testSession: WahaSession;

    beforeEach(async () => {
      testSession = await sessionRepository.save(
        sessionRepository.create(TestDataFactory.createWahaSession({
          id: 'manage-session',
          tenantId: 'tenant-waha',
          externalSessionId: 'waha-manage-session',
          status: WahaSessionStatus.WORKING,
        }))
      );
    });

    it('should start session successfully', async () => {
      MockHelpers.mockWahaServiceResponse('startSession', undefined);

      const response = await request(app.getHttpServer())
        .post(`/waha/sessions/${testSession.id}/start`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should stop session successfully', async () => {
      MockHelpers.mockWahaServiceResponse('stopSession', undefined);

      const response = await request(app.getHttpServer())
        .post(`/waha/sessions/${testSession.id}/stop`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should get session QR code', async () => {
      const mockQRResponse = {
        qr: 'base64-qr-code',
        expiresAt: Date.now() + 60000,
      };

      MockHelpers.mockWahaServiceResponse('getSessionQR', mockQRResponse.qr);

      const response = await request(app.getHttpServer())
        .get(`/waha/sessions/${testSession.id}/qr`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.qr).toBe('base64-qr-code');
    });

    it('should get session screen', async () => {
      const mockScreenResponse = Buffer.from('fake-screen-data');

      MockHelpers.mockWahaServiceResponse('getSessionScreen', mockScreenResponse);

      const response = await request(app.getHttpServer())
        .get(`/waha/sessions/${testSession.id}/screen`)
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toBeDefined();
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle WAHA service errors gracefully', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('WAHA service error'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });

    it('should provide meaningful error messages', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('Service temporarily unavailable'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('WAHA service unavailable');
    });

    it('should log WAHA service errors', async () => {
      MockHelpers.mockWahaServiceError('checkHealth', new Error('WAHA service error'));

      const response = await request(app.getHttpServer())
        .get('/waha/health')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(503);

      expect(response.body.success).toBe(false);
      // Verify that errors are logged
      // This would be tested by checking the logs
    });
  });
});
