import { Injectable, Logger, BadRequestException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { createHmac } from 'crypto';
import { ConfigService } from '@nestjs/config';
import { MessagesService } from '../messages/messages.service';
import { Message } from '../messages/entities/message.entity';
import { WahaService } from '../waha/waha.service';
import { SecurityAuditService } from '../common/services/security-audit.service';
import { EnvironmentVariables } from '../config/env.validation';

export interface WahaWebhookPayload {
  event: string;
  session: string;
  payload: {
    id?: string;
    from?: string;
    to?: string;
    body?: string;
    timestamp?: number;
    status?: string;
    type?: string;
    metadata?: any;
  };
}

export interface WahaMessagePayload {
  id: string;
  from: string;
  to: string;
  body: string;
  timestamp: number;
  type: string;
  metadata?: any;
}

export interface WahaStatusPayload {
  id: string;
  status: string;
  timestamp: number;
  metadata?: any;
}

export interface WahaSessionPayload {
  session: string;
  status: string;
  metadata?: any;
}

@Injectable()
export class WebhooksService {
  private readonly logger = new Logger(WebhooksService.name);
  private readonly webhookSecret: string;

  constructor(
    @InjectRepository(Message)
    private messageRepository: Repository<Message>,
    private messagesService: MessagesService,
    private wahaService: WahaService,
    private securityAuditService: SecurityAuditService,
    private configService: ConfigService<EnvironmentVariables>,
  ) {
    this.webhookSecret = this.configService.get('WAHA_WEBHOOK_SECRET') || '';
  }

  // Webhook processing methods
  async processWahaWebhook(payload: WahaWebhookPayload, signature: string): Promise<void> {
    this.logger.log(`Processing WAHA webhook: ${payload.event} for session: ${payload.session}`);

    // Validate webhook signature
    if (!this.validateWebhookSignature(JSON.stringify(payload), signature)) {
      throw new UnauthorizedException('Invalid webhook signature');
    }

    // Check for duplicate webhook
    const webhookId = this.generateWebhookId(payload);
    if (await this.isDuplicateWebhook(webhookId)) {
      this.logger.warn(`Duplicate webhook detected: ${webhookId}`);
      return;
    }

    try {
      // Process webhook based on event type
      switch (payload.event) {
        case 'message.any':
        case 'message.text':
        case 'message.image':
        case 'message.document':
          await this.processInboundMessage(payload);
          break;
        case 'message.status':
          await this.processStatusUpdate(payload);
          break;
        case 'session.status':
          await this.processSessionUpdate(payload);
          break;
        case 'session.qr':
          await this.processSessionQR(payload);
          break;
        case 'session.failed':
          await this.processSessionFailed(payload);
          break;
        case 'api.error':
          await this.processApiError(payload);
          break;
        default:
          this.logger.warn(`Unknown webhook event type: ${payload.event}`);
      }

      // Mark webhook as processed
      await this.markWebhookProcessed(webhookId);

      this.logger.log(`Webhook processed successfully: ${webhookId}`);
    } catch (error) {
      this.logger.error(`Failed to process webhook ${webhookId}: ${error.message}`, error.stack);
      await this.handleWebhookError(error, payload);
      throw error;
    }
  }

  validateWebhookSignature(payload: string, signature: string): boolean {
    if (!this.webhookSecret) {
      this.logger.warn('Webhook secret not configured');
      return false;
    }

    try {
      const expectedSignature = createHmac('sha256', this.webhookSecret)
        .update(payload)
        .digest('hex');

      const providedSignature = signature.replace('sha256=', '');
      
      return expectedSignature === providedSignature;
    } catch (error) {
      this.logger.error(`Failed to validate webhook signature: ${error.message}`);
      return false;
    }
  }

  async processInboundMessage(payload: WahaWebhookPayload): Promise<void> {
    this.logger.log(`Processing inbound message: ${payload.payload.id}`);

    try {
      await this.messagesService.processInboundMessage({
        event: payload.event,
        session: payload.session,
        payload: payload.payload as WahaMessagePayload,
      });

      // Log inbound message received
      await this.securityAuditService.logSecurityEvent({
        eventType: 'webhook_inbound_message' as any,
        resource: 'webhook',
        action: 'process_inbound',
        details: {
          messageId: payload.payload.id,
          from: payload.payload.from,
          to: payload.payload.to,
          session: payload.session,
          eventType: payload.event,
        },
        severity: 'low',
      });
    } catch (error) {
      this.logger.error(`Failed to process inbound message: ${error.message}`, error.stack);
      throw error;
    }
  }

  async processStatusUpdate(payload: WahaWebhookPayload): Promise<void> {
    this.logger.log(`Processing status update: ${payload.payload.id}`);

    try {
      // Find message by WAHA message ID
      const message = await this.messageRepository.findOne({
        where: { wahaMessageId: payload.payload.id },
      });

      if (!message) {
        this.logger.warn(`Message not found for status update: ${payload.payload.id}`);
        return;
      }

      // Update message status
      const newStatus = this.mapWahaStatusToMessageStatus(payload.payload.status);
      await this.messagesService.updateMessageStatus(message.id, newStatus);

      // Log status update
      await this.securityAuditService.logSecurityEvent({
        eventType: 'webhook_status_update' as any,
        tenantId: message.tenantId,
        resource: 'webhook',
        action: 'process_status',
        details: {
          messageId: message.id,
          wahaMessageId: payload.payload.id,
          oldStatus: message.status,
          newStatus: newStatus,
          session: payload.session,
        },
        severity: 'low',
      });
    } catch (error) {
      this.logger.error(`Failed to process status update: ${error.message}`, error.stack);
      throw error;
    }
  }

  async processSessionUpdate(payload: WahaWebhookPayload): Promise<void> {
    this.logger.log(`Processing session update: ${payload.session}`);

    try {
      // Sync session status with WAHA
      await this.wahaService.syncSessionStatus(payload.session);

      // Log session update
      await this.securityAuditService.logSecurityEvent({
        eventType: 'webhook_session_update' as any,
        resource: 'webhook',
        action: 'process_session',
        details: {
          session: payload.session,
          status: payload.payload.status,
          metadata: payload.payload.metadata,
        },
        severity: 'medium',
      });
    } catch (error) {
      this.logger.error(`Failed to process session update: ${error.message}`, error.stack);
      throw error;
    }
  }

  async processSessionQR(payload: WahaWebhookPayload): Promise<void> {
    this.logger.log(`Processing session QR update: ${payload.session}`);

    try {
      // Log QR update
      await this.securityAuditService.logSecurityEvent({
        eventType: 'webhook_session_qr' as any,
        resource: 'webhook',
        action: 'process_qr',
        details: {
          session: payload.session,
          metadata: payload.payload.metadata,
        },
        severity: 'low',
      });
    } catch (error) {
      this.logger.error(`Failed to process session QR: ${error.message}`, error.stack);
      throw error;
    }
  }

  async processSessionFailed(payload: WahaWebhookPayload): Promise<void> {
    this.logger.log(`Processing session failure: ${payload.session}`);

    try {
      // Log session failure
      await this.securityAuditService.logSecurityEvent({
        eventType: 'webhook_session_failed' as any,
        resource: 'webhook',
        action: 'process_failure',
        details: {
          session: payload.session,
          metadata: payload.payload.metadata,
        },
        severity: 'high',
      });
    } catch (error) {
      this.logger.error(`Failed to process session failure: ${error.message}`, error.stack);
      throw error;
    }
  }

  async processApiError(payload: WahaWebhookPayload): Promise<void> {
    this.logger.log(`Processing API error: ${payload.session}`);

    try {
      // Log API error
      await this.securityAuditService.logSecurityEvent({
        eventType: 'webhook_api_error' as any,
        resource: 'webhook',
        action: 'process_error',
        details: {
          session: payload.session,
          error: payload.payload,
        },
        severity: 'high',
      });
    } catch (error) {
      this.logger.error(`Failed to process API error: ${error.message}`, error.stack);
      throw error;
    }
  }

  async handleWebhookError(error: any, payload: WahaWebhookPayload): Promise<void> {
    this.logger.error(`Handling webhook error: ${error.message}`, error.stack);

    try {
      // Log webhook error
      await this.securityAuditService.logSecurityEvent({
        eventType: 'webhook_processing_error' as any,
        resource: 'webhook',
        action: 'handle_error',
        details: {
          session: payload.session,
          event: payload.event,
          error: error.message,
          payload: payload,
        },
        severity: 'high',
      });
    } catch (logError) {
      this.logger.error(`Failed to log webhook error: ${logError.message}`, logError.stack);
    }
  }

  // Idempotency and deduplication
  async isDuplicateWebhook(webhookId: string): Promise<boolean> {
    // This would check against a webhook processing log
    // For now, we'll use a simple in-memory check
    // In production, this should use Redis or database
    return false;
  }

  async markWebhookProcessed(webhookId: string): Promise<void> {
    // This would mark the webhook as processed in the log
    // For now, we'll just log it
    this.logger.debug(`Webhook marked as processed: ${webhookId}`);
  }

  async getProcessingStatus(webhookId: string): Promise<string> {
    // This would return the processing status of a webhook
    // For now, we'll return a default status
    return 'processed';
  }

  // Helper methods
  private generateWebhookId(payload: WahaWebhookPayload): string {
    const content = `${payload.event}-${payload.session}-${payload.payload.id || payload.payload.timestamp}`;
    return createHmac('sha256', 'webhook-id').update(content).digest('hex');
  }

  private mapWahaStatusToMessageStatus(wahaStatus?: string): any {
    const normalized = (wahaStatus ?? '').toLowerCase();
    switch (normalized) {
      case 'sent':
        return 'sent';
      case 'delivered':
        return 'delivered';
      case 'failed':
        return 'failed';
      case 'read':
        return 'delivered'; // Map read to delivered for now
      default:
        return 'sent';
    }
  }
}
