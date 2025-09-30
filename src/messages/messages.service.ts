import { Injectable, Logger, NotFoundException, BadRequestException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Between, Like, In } from 'typeorm';
import { Message, MessageStatus, MessageDirection } from './entities/message.entity';
import { WahaSession } from '../waha/entities/waha-session.entity';
import { WahaService } from '../waha/waha.service';
import { SecurityAuditService } from '../common/services/security-audit.service';
import {
  SendMessageDto,
  BulkMessageDto,
  MessageFiltersDto,
  MessageStatsDto,
  BulkMessageResponseDto,
  MessageResponseDto,
  WahaInboundPayload,
  DateRangeDto,
} from './dto/message.dto';

@Injectable()
export class MessagesService {
  private readonly logger = new Logger(MessagesService.name);

  constructor(
    @InjectRepository(Message)
    private messageRepository: Repository<Message>,
    @InjectRepository(WahaSession)
    private sessionRepository: Repository<WahaSession>,
    private wahaService: WahaService,
    private securityAuditService: SecurityAuditService,
  ) {}

  // Core messaging methods
  async sendMessage(tenantId: string, sendMessageDto: SendMessageDto): Promise<Message> {
    this.logger.log(`Sending message for tenant ${tenantId} to ${sendMessageDto.to}`);

    // Validate session belongs to tenant
    const session = await this.sessionRepository.findOne({
      where: { id: sendMessageDto.sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found or does not belong to tenant');
    }

    if (session.status !== 'working') {
      throw new BadRequestException('Session is not in working state');
    }

    // Create message record
    const message = this.messageRepository.create({
      tenantId,
      sessionId: sendMessageDto.sessionId,
      direction: MessageDirection.OUTBOUND,
      toMsisdn: sendMessageDto.to,
      fromMsisdn: '', // Will be filled by WAHA
      body: sendMessageDto.body,
      status: MessageStatus.QUEUED,
      metadata: sendMessageDto.metadata || {},
    });

    const savedMessage: Message = await this.messageRepository.save(message);

    try {
      // Send message via WAHA
      const wahaResponse = await this.wahaService.sendMessage(
        sendMessageDto.sessionId,
        tenantId,
        {
          to: sendMessageDto.to,
          text: sendMessageDto.body,
          metadata: sendMessageDto.metadata,
        },
      );

      // Update message with WAHA response
      savedMessage.wahaMessageId = wahaResponse.messageId;
      savedMessage.status = MessageStatus.SENT;
      savedMessage.fromMsisdn = wahaResponse.to; // WAHA provides the from number
      await this.messageRepository.save(savedMessage);

      // Log message sent
      await this.securityAuditService.logSecurityEvent({
        eventType: 'message_sent' as any,
        tenantId,
        resource: 'message',
        action: 'send',
        details: {
          messageId: savedMessage.id,
          recipient: sendMessageDto.to,
          sessionId: sendMessageDto.sessionId,
          messageLength: sendMessageDto.body.length,
        },
        severity: 'low',
      });

      this.logger.log(`Message sent successfully: ${savedMessage.id}`);
      return savedMessage;
    } catch (error) {
      // Update message status to failed
      savedMessage.status = MessageStatus.FAILED;
      await this.messageRepository.save(savedMessage);

      this.logger.error(`Failed to send message ${savedMessage.id}: ${error.message}`);
      throw new BadRequestException(`Failed to send message: ${error.message}`);
    }
  }

  async sendBulkMessages(tenantId: string, bulkDto: BulkMessageDto): Promise<BulkMessageResponseDto> {
    this.logger.log(`Sending bulk messages for tenant ${tenantId} to ${bulkDto.recipients.length} recipients`);

    // Validate session belongs to tenant
    const session = await this.sessionRepository.findOne({
      where: { id: bulkDto.sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found or does not belong to tenant');
    }

    if (session.status !== 'working') {
      throw new BadRequestException('Session is not in working state');
    }

    const bulkMessageId = `bulk-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const batchSize = bulkDto.batchSize || 10;
    const totalBatches = Math.ceil(bulkDto.recipients.length / batchSize);
    const failedRecipients: string[] = [];
    let successCount = 0;

    // Process messages in batches
    for (let i = 0; i < bulkDto.recipients.length; i += batchSize) {
      const batch = bulkDto.recipients.slice(i, i + batchSize);
      
      for (const recipient of batch) {
        try {
          const message = this.messageRepository.create({
            tenantId,
            sessionId: bulkDto.sessionId,
            direction: MessageDirection.OUTBOUND,
            toMsisdn: recipient,
            fromMsisdn: '',
            body: bulkDto.body,
            status: MessageStatus.QUEUED,
            metadata: {
              ...bulkDto.metadata,
              bulkMessageId,
              batchNumber: Math.floor(i / batchSize) + 1,
            },
          });

          await this.messageRepository.save(message);
          successCount++;
        } catch (error) {
          this.logger.error(`Failed to queue message for ${recipient}: ${error.message}`);
          failedRecipients.push(recipient);
        }
      }

      // Add delay between batches to respect rate limits
      if (i + batchSize < bulkDto.recipients.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    // Log bulk message sent
    await this.securityAuditService.logSecurityEvent({
      eventType: 'bulk_message_sent' as any,
      tenantId,
      resource: 'message',
      action: 'send_bulk',
      details: {
        bulkMessageId,
        totalRecipients: bulkDto.recipients.length,
        successCount,
        failureCount: failedRecipients.length,
        sessionId: bulkDto.sessionId,
      },
      severity: 'medium',
    });

    return {
      totalQueued: bulkDto.recipients.length,
      successCount,
      failureCount: failedRecipients.length,
      batchInfo: {
        totalBatches,
        batchSize,
        estimatedProcessingTime: `${totalBatches * 2} minutes`,
      },
      failedRecipients,
      bulkMessageId,
    };
  }

  async getMessages(tenantId: string, filters: MessageFiltersDto): Promise<{
    data: MessageResponseDto[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
      hasNext: boolean;
      hasPrev: boolean;
    };
  }> {
    this.logger.debug(`Getting messages for tenant ${tenantId} with filters`);

    const { page = 1, limit = 20 } = filters;
    const skip = (page - 1) * limit;

    const where: any = { tenantId };

    // Apply filters
    if (filters.sessionId) {
      where.sessionId = filters.sessionId;
    }

    if (filters.direction) {
      where.direction = filters.direction;
    }

    if (filters.status) {
      where.status = filters.status;
    }

    if (filters.fromDate && filters.toDate) {
      where.createdAt = Between(new Date(filters.fromDate), new Date(filters.toDate));
    }

    if (filters.search) {
      where.body = Like(`%${filters.search}%`);
    }

    const [messages, total] = await this.messageRepository.findAndCount({
      where,
      order: { createdAt: 'DESC' },
      skip,
      take: limit,
    });

    const totalPages = Math.ceil(total / limit);

    return {
      data: messages.map(message => this.mapToResponseDto(message)),
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1,
      },
    };
  }

  async getMessageById(messageId: string, tenantId: string): Promise<MessageResponseDto> {
    this.logger.debug(`Getting message ${messageId} for tenant ${tenantId}`);

    const message = await this.messageRepository.findOne({
      where: { id: messageId, tenantId },
    });

    if (!message) {
      throw new NotFoundException('Message not found');
    }

    return this.mapToResponseDto(message);
  }

  async processInboundMessage(payload: WahaInboundPayload): Promise<Message> {
    this.logger.log(`Processing inbound message from WAHA: ${payload.payload.id}`);

    // Find session by external session ID
    const session = await this.sessionRepository.findOne({
      where: { externalSessionId: payload.session },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    // Create inbound message record
    const message = this.messageRepository.create({
      tenantId: session.tenantId,
      sessionId: session.id,
      direction: MessageDirection.INBOUND,
      toMsisdn: payload.payload.to,
      fromMsisdn: payload.payload.from,
      body: payload.payload.body,
      status: MessageStatus.DELIVERED,
      wahaMessageId: payload.payload.id,
      rawPayload: payload,
      metadata: payload.payload.metadata || {},
    });

    const savedMessage: Message = await this.messageRepository.save(message);

    // Log inbound message
    await this.securityAuditService.logSecurityEvent({
      eventType: 'inbound_message_received' as any,
      tenantId: session.tenantId,
      resource: 'message',
      action: 'receive',
      details: {
        messageId: savedMessage.id,
        from: payload.payload.from,
        to: payload.payload.to,
        sessionId: session.id,
        messageLength: payload.payload.body.length,
      },
      severity: 'low',
    });

    this.logger.log(`Inbound message processed: ${savedMessage.id}`);
    return savedMessage;
  }

  async updateMessageStatus(messageId: string, status: MessageStatus): Promise<void> {
    this.logger.debug(`Updating message ${messageId} status to ${status}`);

    const message = await this.messageRepository.findOne({
      where: { id: messageId },
    });

    if (!message) {
      throw new NotFoundException('Message not found');
    }

    message.status = status;
    await this.messageRepository.save(message);

    this.logger.debug(`Message status updated: ${messageId} -> ${status}`);
  }

  async getMessageStats(tenantId: string, dateRange: DateRangeDto): Promise<MessageStatsDto> {
    this.logger.debug(`Getting message stats for tenant ${tenantId}`);

    const fromDate = new Date(dateRange.fromDate);
    const toDate = new Date(dateRange.toDate);

    // Get total messages
    const totalMessages = await this.messageRepository.count({
      where: { tenantId, createdAt: Between(fromDate, toDate) },
    });

    // Get outbound messages
    const outboundMessages = await this.messageRepository.count({
      where: { tenantId, direction: MessageDirection.OUTBOUND, createdAt: Between(fromDate, toDate) },
    });

    // Get inbound messages
    const inboundMessages = await this.messageRepository.count({
      where: { tenantId, direction: MessageDirection.INBOUND, createdAt: Between(fromDate, toDate) },
    });

    // Get messages by status
    const messagesByStatus: Record<MessageStatus, number> = {
      [MessageStatus.QUEUED]: 0,
      [MessageStatus.SENT]: 0,
      [MessageStatus.DELIVERED]: 0,
      [MessageStatus.FAILED]: 0,
    };

    for (const status of Object.values(MessageStatus)) {
      const count = await this.messageRepository.count({
        where: { tenantId, status, createdAt: Between(fromDate, toDate) },
      });
      messagesByStatus[status] = count;
    }

    // Calculate success rate
    const successfulMessages = messagesByStatus[MessageStatus.DELIVERED] + messagesByStatus[MessageStatus.SENT];
    const successRate = totalMessages > 0 ? (successfulMessages / totalMessages) * 100 : 0;

    // Calculate average per day
    const daysDiff = Math.ceil((toDate.getTime() - fromDate.getTime()) / (1000 * 60 * 60 * 24));
    const averagePerDay = daysDiff > 0 ? totalMessages / daysDiff : 0;

    return {
      totalMessages,
      outboundMessages,
      inboundMessages,
      messagesByStatus,
      messagesByDay: [], // This would require more complex querying
      averagePerDay,
      successRate,
      dateRange,
    };
  }

  // Queue management
  async queueMessage(message: Message): Promise<void> {
    this.logger.debug(`Queueing message: ${message.id}`);

    // This would integrate with a queue system like Bull/Redis
    // For now, we'll just update the status
    message.status = MessageStatus.QUEUED;
    await this.messageRepository.save(message);
  }

  async processMessageQueue(): Promise<void> {
    this.logger.log('Processing message queue');

    // This would process queued messages
    // Implementation would depend on the queue system used
  }

  async retryFailedMessage(messageId: string): Promise<void> {
    this.logger.log(`Retrying failed message: ${messageId}`);

    const message = await this.messageRepository.findOne({
      where: { id: messageId },
    });

    if (!message) {
      throw new NotFoundException('Message not found');
    }

    if (message.status !== MessageStatus.FAILED) {
      throw new BadRequestException('Message is not in failed state');
    }

    // Reset status to queued for retry
    message.status = MessageStatus.QUEUED;
    await this.messageRepository.save(message);

    this.logger.log(`Message queued for retry: ${messageId}`);
  }

  // Helper methods
  private mapToResponseDto(message: Message): MessageResponseDto {
    return {
      id: message.id,
      sessionId: message.sessionId,
      direction: message.direction,
      toMsisdn: message.toMsisdn,
      fromMsisdn: message.fromMsisdn,
      body: message.body,
      status: message.status,
      wahaMessageId: message.wahaMessageId,
      priority: message.metadata?.priority,
      metadata: message.metadata,
      createdAt: message.createdAt,
      updatedAt: message.updatedAt,
    };
  }
}
