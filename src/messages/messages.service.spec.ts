import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { MessagesService } from '../messages.service';
import { MessagesController } from '../messages.controller';
import { WebhooksService } from '../webhooks.service';
import { WebhooksController } from '../webhooks.controller';
import { Message } from '../entities/message.entity';
import { WahaSession } from '../../waha/entities/waha-session.entity';
import { WahaService } from '../../waha/waha.service';
import { SecurityAuditService } from '../../common/services/security-audit.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { SendMessageDto, BulkMessageDto, MessageFiltersDto } from '../dto/message.dto';

describe('Messaging System', () => {
  let messagesService: MessagesService;
  let messagesController: MessagesController;
  let messageRepository: Repository<Message>;
  let sessionRepository: Repository<WahaSession>;
  let wahaService: WahaService;
  let securityAuditService: SecurityAuditService;

  const mockMessageRepository = {
    create: jest.fn(),
    save: jest.fn(),
    findOne: jest.fn(),
    findAndCount: jest.fn(),
    count: jest.fn(),
  };

  const mockSessionRepository = {
    findOne: jest.fn(),
  };

  const mockWahaService = {
    sendMessage: jest.fn(),
    syncSessionStatus: jest.fn(),
  };

  const mockSecurityAuditService = {
    logSecurityEvent: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        MessagesService,
        {
          provide: getRepositoryToken(Message),
          useValue: mockMessageRepository,
        },
        {
          provide: getRepositoryToken(WahaSession),
          useValue: mockSessionRepository,
        },
        {
          provide: WahaService,
          useValue: mockWahaService,
        },
        {
          provide: SecurityAuditService,
          useValue: mockSecurityAuditService,
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('test-value'),
          },
        },
      ],
      controllers: [MessagesController],
    }).compile();

    messagesService = module.get<MessagesService>(MessagesService);
    messagesController = module.get<MessagesController>(MessagesController);
    messageRepository = module.get<Repository<Message>>(getRepositoryToken(Message));
    sessionRepository = module.get<Repository<WahaSession>>(getRepositoryToken(WahaSession));
    wahaService = module.get<WahaService>(WahaService);
    securityAuditService = module.get<SecurityAuditService>(SecurityAuditService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('MessagesService', () => {
    describe('sendMessage', () => {
      it('should send a message successfully', async () => {
        const tenantId = 'tenant-123';
        const sendMessageDto: SendMessageDto = {
          sessionId: 'session-123',
          to: '+1234567890',
          body: 'Test message',
          priority: 'normal',
        };

        const mockSession = {
          id: 'session-123',
          tenantId: 'tenant-123',
          status: 'working',
        };

        const mockMessage = {
          id: 'message-123',
          tenantId: 'tenant-123',
          sessionId: 'session-123',
          direction: 'outbound',
          toMsisdn: '+1234567890',
          fromMsisdn: '',
          body: 'Test message',
          status: 'queued',
          priority: 'normal',
          metadata: {},
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const mockWahaResponse = {
          messageId: 'waha-msg-123',
          to: '+0987654321',
        };

        sessionRepository.findOne.mockResolvedValue(mockSession);
        messageRepository.create.mockReturnValue(mockMessage);
        messageRepository.save.mockResolvedValue(mockMessage);
        wahaService.sendMessage.mockResolvedValue(mockWahaResponse);

        const result = await messagesService.sendMessage(tenantId, sendMessageDto);

        expect(sessionRepository.findOne).toHaveBeenCalledWith({
          where: { id: 'session-123', tenantId: 'tenant-123' },
        });
        expect(messageRepository.create).toHaveBeenCalled();
        expect(messageRepository.save).toHaveBeenCalledTimes(2); // Once for initial save, once for update
        expect(wahaService.sendMessage).toHaveBeenCalledWith('session-123', tenantId, {
          to: '+1234567890',
          text: 'Test message',
          metadata: {},
        });
        expect(result).toEqual(mockMessage);
      });

      it('should throw NotFoundException when session not found', async () => {
        const tenantId = 'tenant-123';
        const sendMessageDto: SendMessageDto = {
          sessionId: 'session-123',
          to: '+1234567890',
          body: 'Test message',
        };

        sessionRepository.findOne.mockResolvedValue(null);

        await expect(messagesService.sendMessage(tenantId, sendMessageDto)).rejects.toThrow(
          'Session not found or does not belong to tenant',
        );
      });

      it('should throw BadRequestException when session not in working state', async () => {
        const tenantId = 'tenant-123';
        const sendMessageDto: SendMessageDto = {
          sessionId: 'session-123',
          to: '+1234567890',
          body: 'Test message',
        };

        const mockSession = {
          id: 'session-123',
          tenantId: 'tenant-123',
          status: 'stopped',
        };

        sessionRepository.findOne.mockResolvedValue(mockSession);

        await expect(messagesService.sendMessage(tenantId, sendMessageDto)).rejects.toThrow(
          'Session is not in working state',
        );
      });
    });

    describe('sendBulkMessages', () => {
      it('should send bulk messages successfully', async () => {
        const tenantId = 'tenant-123';
        const bulkMessageDto: BulkMessageDto = {
          sessionId: 'session-123',
          recipients: ['+1234567890', '+0987654321'],
          body: 'Bulk test message',
          batchSize: 10,
        };

        const mockSession = {
          id: 'session-123',
          tenantId: 'tenant-123',
          status: 'working',
        };

        sessionRepository.findOne.mockResolvedValue(mockSession);
        messageRepository.create.mockReturnValue({});
        messageRepository.save.mockResolvedValue({});

        const result = await messagesService.sendBulkMessages(tenantId, bulkMessageDto);

        expect(result.totalQueued).toBe(2);
        expect(result.successCount).toBe(2);
        expect(result.failureCount).toBe(0);
        expect(result.bulkMessageId).toBeDefined();
      });
    });

    describe('getMessages', () => {
      it('should get messages with filters', async () => {
        const tenantId = 'tenant-123';
        const filters: MessageFiltersDto = {
          sessionId: 'session-123',
          direction: 'outbound',
          page: 1,
          limit: 20,
        };

        const mockMessages = [
          {
            id: 'message-1',
            tenantId: 'tenant-123',
            sessionId: 'session-123',
            direction: 'outbound',
            toMsisdn: '+1234567890',
            fromMsisdn: '+0987654321',
            body: 'Test message 1',
            status: 'sent',
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ];

        messageRepository.findAndCount.mockResolvedValue([mockMessages, 1]);

        const result = await messagesService.getMessages(tenantId, filters);

        expect(result.data).toHaveLength(1);
        expect(result.pagination.total).toBe(1);
        expect(result.pagination.page).toBe(1);
        expect(result.pagination.limit).toBe(20);
      });
    });

    describe('getMessageById', () => {
      it('should get a specific message', async () => {
        const messageId = 'message-123';
        const tenantId = 'tenant-123';

        const mockMessage = {
          id: 'message-123',
          tenantId: 'tenant-123',
          sessionId: 'session-123',
          direction: 'outbound',
          toMsisdn: '+1234567890',
          fromMsisdn: '+0987654321',
          body: 'Test message',
          status: 'sent',
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        messageRepository.findOne.mockResolvedValue(mockMessage);

        const result = await messagesService.getMessageById(messageId, tenantId);

        expect(result.id).toBe('message-123');
        expect(result.tenantId).toBe('tenant-123');
      });

      it('should throw NotFoundException when message not found', async () => {
        const messageId = 'message-123';
        const tenantId = 'tenant-123';

        messageRepository.findOne.mockResolvedValue(null);

        await expect(messagesService.getMessageById(messageId, tenantId)).rejects.toThrow(
          'Message not found',
        );
      });
    });

    describe('getMessageStats', () => {
      it('should get message statistics', async () => {
        const tenantId = 'tenant-123';
        const dateRange = {
          fromDate: '2024-01-01T00:00:00Z',
          toDate: '2024-01-31T23:59:59Z',
        };

        messageRepository.count.mockResolvedValue(100);

        const result = await messagesService.getMessageStats(tenantId, dateRange);

        expect(result.totalMessages).toBe(100);
        expect(result.dateRange).toEqual(dateRange);
      });
    });
  });

  describe('MessagesController', () => {
    describe('sendMessage', () => {
      it('should send a message via controller', async () => {
        const sendMessageDto: SendMessageDto = {
          sessionId: 'session-123',
          to: '+1234567890',
          body: 'Test message',
        };

        const mockMessage = {
          id: 'message-123',
          sessionId: 'session-123',
          direction: 'outbound',
          toMsisdn: '+1234567890',
          fromMsisdn: '+0987654321',
          body: 'Test message',
          status: 'sent',
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        jest.spyOn(messagesService, 'sendMessage').mockResolvedValue(mockMessage);

        const result = await messagesController.sendMessage(
          sendMessageDto,
          'tenant-123',
          { id: 'user-123', role: 'agent' },
        );

        expect(result.id).toBe('message-123');
        expect(result.sessionId).toBe('session-123');
        expect(result.direction).toBe('outbound');
      });
    });
  });
});

describe('Webhook Handler System', () => {
  let webhooksService: WebhooksService;
  let webhooksController: WebhooksController;
  let messageRepository: Repository<Message>;
  let messagesService: MessagesService;
  let wahaService: WahaService;
  let securityAuditService: SecurityAuditService;
  let configService: ConfigService;

  const mockMessageRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
  };

  const mockMessagesService = {
    processInboundMessage: jest.fn(),
    updateMessageStatus: jest.fn(),
  };

  const mockWahaService = {
    syncSessionStatus: jest.fn(),
  };

  const mockSecurityAuditService = {
    logSecurityEvent: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn().mockReturnValue('test-webhook-secret'),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WebhooksService,
        {
          provide: getRepositoryToken(Message),
          useValue: mockMessageRepository,
        },
        {
          provide: MessagesService,
          useValue: mockMessagesService,
        },
        {
          provide: WahaService,
          useValue: mockWahaService,
        },
        {
          provide: SecurityAuditService,
          useValue: mockSecurityAuditService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
      controllers: [WebhooksController],
    }).compile();

    webhooksService = module.get<WebhooksService>(WebhooksService);
    webhooksController = module.get<WebhooksController>(WebhooksController);
    messageRepository = module.get<Repository<Message>>(getRepositoryToken(Message));
    messagesService = module.get<MessagesService>(MessagesService);
    wahaService = module.get<WahaService>(WahaService);
    securityAuditService = module.get<SecurityAuditService>(SecurityAuditService);
    configService = module.get<ConfigService>(ConfigService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('WebhooksService', () => {
    describe('processWahaWebhook', () => {
      it('should process WAHA webhook successfully', async () => {
        const payload = {
          event: 'message.text',
          session: 'main-session',
          payload: {
            id: 'waha-msg-123',
            from: '+1234567890',
            to: '+0987654321',
            body: 'Hello, this is a test message',
            timestamp: 1642248600000,
            type: 'text',
          },
        };

        const signature = 'sha256=valid-signature';

        jest.spyOn(webhooksService, 'validateWebhookSignature').mockReturnValue(true);
        jest.spyOn(webhooksService, 'isDuplicateWebhook').mockResolvedValue(false);
        jest.spyOn(webhooksService, 'processInboundMessage').mockResolvedValue();
        jest.spyOn(webhooksService, 'markWebhookProcessed').mockResolvedValue();

        await webhooksService.processWahaWebhook(payload, signature);

        expect(webhooksService.validateWebhookSignature).toHaveBeenCalledWith(
          JSON.stringify(payload),
          signature,
        );
        expect(webhooksService.isDuplicateWebhook).toHaveBeenCalled();
        expect(webhooksService.processInboundMessage).toHaveBeenCalledWith(payload);
        expect(webhooksService.markWebhookProcessed).toHaveBeenCalled();
      });

      it('should throw UnauthorizedException for invalid signature', async () => {
        const payload = {
          event: 'message.text',
          session: 'main-session',
          payload: {
            id: 'waha-msg-123',
            from: '+1234567890',
            to: '+0987654321',
            body: 'Hello, this is a test message',
            timestamp: 1642248600000,
            type: 'text',
          },
        };

        const signature = 'sha256=invalid-signature';

        jest.spyOn(webhooksService, 'validateWebhookSignature').mockReturnValue(false);

        await expect(webhooksService.processWahaWebhook(payload, signature)).rejects.toThrow(
          'Invalid webhook signature',
        );
      });
    });

    describe('processInboundMessage', () => {
      it('should process inbound message successfully', async () => {
        const payload = {
          event: 'message.text',
          session: 'main-session',
          payload: {
            id: 'waha-msg-123',
            from: '+1234567890',
            to: '+0987654321',
            body: 'Hello, this is a test message',
            timestamp: 1642248600000,
            type: 'text',
          },
        };

        jest.spyOn(messagesService, 'processInboundMessage').mockResolvedValue({} as any);

        await webhooksService.processInboundMessage(payload);

        expect(messagesService.processInboundMessage).toHaveBeenCalledWith({
          event: 'message.text',
          session: 'main-session',
          payload: payload.payload,
        });
      });
    });

    describe('processStatusUpdate', () => {
      it('should process status update successfully', async () => {
        const payload = {
          event: 'message.status',
          session: 'main-session',
          payload: {
            id: 'waha-msg-123',
            status: 'delivered',
            timestamp: 1642248600000,
          },
        };

        const mockMessage = {
          id: 'message-123',
          tenantId: 'tenant-123',
          wahaMessageId: 'waha-msg-123',
          status: 'sent',
        };

        messageRepository.findOne.mockResolvedValue(mockMessage);
        jest.spyOn(messagesService, 'updateMessageStatus').mockResolvedValue();

        await webhooksService.processStatusUpdate(payload);

        expect(messageRepository.findOne).toHaveBeenCalledWith({
          where: { wahaMessageId: 'waha-msg-123' },
        });
        expect(messagesService.updateMessageStatus).toHaveBeenCalledWith('message-123', 'delivered');
      });
    });
  });

  describe('WebhooksController', () => {
    describe('handleWahaWebhook', () => {
      it('should handle WAHA webhook successfully', async () => {
        const payload = {
          event: 'message.text',
          session: 'main-session',
          payload: {
            id: 'waha-msg-123',
            from: '+1234567890',
            to: '+0987654321',
            body: 'Hello, this is a test message',
            timestamp: 1642248600000,
            type: 'text',
          },
        };

        const signature = 'sha256=valid-signature';

        jest.spyOn(webhooksService, 'processWahaWebhook').mockResolvedValue();

        const result = await webhooksController.handleWahaWebhook(payload, signature);

        expect(result.success).toBe(true);
        expect(result.message).toBe('Webhook processed successfully');
      });

      it('should handle webhook processing error gracefully', async () => {
        const payload = {
          event: 'message.text',
          session: 'main-session',
          payload: {
            id: 'waha-msg-123',
            from: '+1234567890',
            to: '+0987654321',
            body: 'Hello, this is a test message',
            timestamp: 1642248600000,
            type: 'text',
          },
        };

        const signature = 'sha256=valid-signature';

        jest.spyOn(webhooksService, 'processWahaWebhook').mockRejectedValue(
          new Error('Processing error'),
        );

        const result = await webhooksController.handleWahaWebhook(payload, signature);

        expect(result.success).toBe(true);
        expect(result.message).toBe('Webhook received but processing failed');
      });
    });

    describe('getHealth', () => {
      it('should return health status', async () => {
        const result = await webhooksController.getHealth();

        expect(result.status).toBe('healthy');
        expect(result.service).toBe('webhooks');
        expect(result.timestamp).toBeDefined();
      });
    });
  });
});
