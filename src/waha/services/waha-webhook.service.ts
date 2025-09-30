import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { WahaSession } from '../entities/waha-session.entity';
import { Message, MessageDirection, MessageStatus } from '../../messages/entities/message.entity';
import { SecurityAuditService } from '../../common/services/security-audit.service';
import { WahaConfigService } from './waha-config.service';

export interface WahaWebhookEvent {
  event: string;
  session: string;
  payload: any;
  timestamp: string;
}

export interface WahaMessageEvent {
  event: 'message';
  session: string;
  payload: {
    id: string;
    from: string;
    to: string;
    body: string;
    timestamp: number;
    type: string;
    metadata?: any;
  };
}

export interface WahaSessionStatusEvent {
  event: 'session.status';
  session: string;
  payload: {
    status: string;
    metadata?: any;
  };
}

@Injectable()
export class WahaWebhookService {
  private readonly logger = new Logger(WahaWebhookService.name);

  constructor(
    @InjectRepository(WahaSession)
    private wahaSessionRepository: Repository<WahaSession>,
    @InjectRepository(Message)
    private messageRepository: Repository<Message>,
    private securityAuditService: SecurityAuditService,
    private wahaConfigService: WahaConfigService,
  ) {}

  async handleWebhookEvent(event: WahaWebhookEvent): Promise<void> {
    this.logger.debug(`Handling WAHA webhook event: ${event.event} for session: ${event.session}`);

    try {
      switch (event.event) {
        case 'message':
          await this.handleMessageEvent(event as WahaMessageEvent);
          break;
        case 'session.status':
          await this.handleSessionStatusEvent(event as WahaSessionStatusEvent);
          break;
        default:
          this.logger.warn(`Unknown webhook event type: ${event.event}`);
      }
    } catch (error) {
      this.logger.error(`Failed to handle webhook event: ${error.message}`, error.stack);
      throw error;
    }
  }

  private async handleMessageEvent(event: WahaMessageEvent): Promise<void> {
    this.logger.log(`Handling message event for session: ${event.session}`);

    // Find the session
    const session = await this.wahaSessionRepository.findOne({
      where: { externalSessionId: event.session },
    });

    if (!session) {
      this.logger.warn(`Session not found for webhook event: ${event.session}`);
      return;
    }

    // Create message record
    const message = this.messageRepository.create({
      tenantId: session.tenantId,
      sessionId: session.id,
      direction: MessageDirection.INBOUND,
      toMsisdn: event.payload.to,
      fromMsisdn: event.payload.from,
      body: event.payload.body,
      status: MessageStatus.DELIVERED,
      wahaMessageId: event.payload.id,
      rawPayload: event.payload,
    });

    await this.messageRepository.save(message);

    // Log message received
    await this.securityAuditService.logSecurityEvent({
      eventType: 'waha_message_received' as any,
      tenantId: session.tenantId,
      resource: 'waha_session',
      action: 'receive_message',
      details: {
        sessionId: session.id,
        messageId: event.payload.id,
        from: event.payload.from,
        to: event.payload.to,
        messageLength: event.payload.body.length,
      },
      severity: 'low',
    });

    this.logger.log(`Message processed successfully: ${event.payload.id}`);
  }

  private async handleSessionStatusEvent(event: WahaSessionStatusEvent): Promise<void> {
    this.logger.log(`Handling session status event for session: ${event.session}`);

    // Find the session
    const session = await this.wahaSessionRepository.findOne({
      where: { externalSessionId: event.session },
    });

    if (!session) {
      this.logger.warn(`Session not found for webhook event: ${event.session}`);
      return;
    }

    // Update session status
    const newStatus = this.mapWahaStatusToEntity(event.payload.status);
    session.status = newStatus;
    session.metadata = {
      ...session.metadata,
      ...event.payload.metadata,
      lastStatusUpdate: new Date(),
    };

    await this.wahaSessionRepository.save(session);

    // Log status change
    await this.securityAuditService.logSecurityEvent({
      eventType: 'waha_session_status_changed' as any,
      tenantId: session.tenantId,
      resource: 'waha_session',
      action: 'status_change',
      details: {
        sessionId: session.id,
        oldStatus: session.status,
        newStatus: newStatus,
        metadata: event.payload.metadata,
      },
      severity: 'medium',
    });

    this.logger.log(`Session status updated: ${event.session} -> ${newStatus}`);
  }

  private mapWahaStatusToEntity(wahaStatus: string): any {
    switch (wahaStatus.toLowerCase()) {
      case 'starting':
        return 'starting';
      case 'scan_qr':
      case 'scanning':
        return 'scan_qr';
      case 'working':
      case 'connected':
        return 'working';
      case 'failed':
      case 'error':
        return 'failed';
      case 'stopped':
      case 'disconnected':
        return 'stopped';
      default:
        return 'failed';
    }
  }

  async validateWebhookSignature(payload: string, signature: string): Promise<boolean> {
    const webhookSecret = this.wahaConfigService.getWebhookConfig().secret;
    
    if (!webhookSecret) {
      this.logger.warn('Webhook secret not configured');
      return false;
    }

    // Implement signature validation logic here
    // This would typically use HMAC-SHA256 or similar
    // For now, we'll just check if the signature is present
    return !!signature;
  }

  async processWebhookBatch(events: WahaWebhookEvent[]): Promise<void> {
    this.logger.log(`Processing webhook batch with ${events.length} events`);

    for (const event of events) {
      try {
        await this.handleWebhookEvent(event);
      } catch (error) {
        this.logger.error(`Failed to process webhook event: ${error.message}`, error.stack);
        // Continue processing other events
      }
    }

    this.logger.log(`Webhook batch processed successfully`);
  }
}
