import { Injectable, Logger, NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { WahaSession, WahaSessionStatus, WahaEngine } from './entities/waha-session.entity';
import { WahaClientService } from './services/waha-client.service';
import { SecurityAuditService } from '../common/services/security-audit.service';
import {
  CreateSessionDto,
  SessionResponseDto,
  SendMessageDto,
  MessageResponse,
  WahaHealthResponse,
} from './dto/waha.dto';

@Injectable()
export class WahaService {
  private readonly logger = new Logger(WahaService.name);

  constructor(
    @InjectRepository(WahaSession)
    private wahaSessionRepository: Repository<WahaSession>,
    private wahaClientService: WahaClientService,
    private securityAuditService: SecurityAuditService,
  ) {}

  // Business logic methods
  async createTenantSession(tenantId: string, createDto: CreateSessionDto): Promise<WahaSession> {
    this.logger.log(`Creating WAHA session for tenant ${tenantId}: ${createDto.sessionName}`);

    // Check if session already exists for this tenant
    const existingSession = await this.wahaSessionRepository.findOne({
      where: { tenantId, externalSessionId: createDto.sessionName },
    });

    if (existingSession) {
      throw new ConflictException('Session with this name already exists for the tenant');
    }

    // Create session in WAHA
    const sessionConfig = {
      engine: createDto.engine,
      webhookUrl: createDto.webhookUrl,
      webhookEvents: createDto.webhookEvents,
      config: createDto.config,
    };

    const wahaSessionInfo = await this.wahaClientService.createSession(
      createDto.sessionName,
      sessionConfig,
    );

    // Create session record in database
    const session = this.wahaSessionRepository.create({
      externalSessionId: createDto.sessionName,
      status: WahaSessionStatus.STARTING,
      engine: createDto.engine,
      metadata: wahaSessionInfo.metadata || {},
      tenantId,
    });

    const savedSession = await this.wahaSessionRepository.save(session);

    // Start the session
    try {
      await this.wahaClientService.startSession(createDto.sessionName);
      savedSession.status = WahaSessionStatus.SCAN_QR;
      await this.wahaSessionRepository.save(savedSession);
    } catch (error) {
      this.logger.error(`Failed to start session ${createDto.sessionName}: ${error.message}`);
      // Don't throw error, session is created but not started
    }

    // Log session creation
    await this.securityAuditService.logSecurityEvent({
      eventType: 'waha_session_created' as any,
      tenantId,
      resource: 'waha_session',
      action: 'create',
      details: {
        sessionName: createDto.sessionName,
        engine: createDto.engine,
        message: 'WAHA session created',
      },
      severity: 'medium',
    });

    this.logger.log(`WAHA session created successfully: ${savedSession.id}`);
    return savedSession;
  }

  async getTenantSessions(tenantId: string): Promise<WahaSession[]> {
    this.logger.debug(`Getting WAHA sessions for tenant: ${tenantId}`);

    return this.wahaSessionRepository.find({
      where: { tenantId },
      order: { createdAt: 'DESC' },
    });
  }

  async getSessionDetails(sessionId: string, tenantId: string): Promise<WahaSession> {
    this.logger.debug(`Getting WAHA session details: ${sessionId} for tenant: ${tenantId}`);

    const session = await this.wahaSessionRepository.findOne({
      where: { id: sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    return session;
  }

  async stopTenantSession(sessionId: string, tenantId: string): Promise<void> {
    this.logger.log(`Stopping WAHA session: ${sessionId} for tenant: ${tenantId}`);

    const session = await this.wahaSessionRepository.findOne({
      where: { id: sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    if (session.status === WahaSessionStatus.STOPPED) {
      throw new BadRequestException('Session is already stopped');
    }

    try {
      await this.wahaClientService.stopSession(session.externalSessionId);
      session.status = WahaSessionStatus.STOPPED;
      await this.wahaSessionRepository.save(session);

      // Log session stop
      await this.securityAuditService.logSecurityEvent({
        eventType: 'waha_session_stopped' as any,
        tenantId,
        resource: 'waha_session',
        action: 'stop',
        details: {
          sessionId: session.id,
          sessionName: session.externalSessionId,
          message: 'WAHA session stopped',
        },
        severity: 'medium',
      });

      this.logger.log(`WAHA session stopped successfully: ${sessionId}`);
    } catch (error) {
      this.logger.error(`Failed to stop session ${sessionId}: ${error.message}`);
      throw new BadRequestException(`Failed to stop session: ${error.message}`);
    }
  }

  async deleteTenantSession(sessionId: string, tenantId: string): Promise<void> {
    this.logger.log(`Deleting WAHA session: ${sessionId} for tenant: ${tenantId}`);

    const session = await this.wahaSessionRepository.findOne({
      where: { id: sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    // Stop session first if it's running
    if (session.status !== WahaSessionStatus.STOPPED) {
      try {
        await this.wahaClientService.stopSession(session.externalSessionId);
      } catch (error) {
        this.logger.warn(`Failed to stop session before deletion: ${error.message}`);
      }
    }

    // Delete session from database
    await this.wahaSessionRepository.remove(session);

    // Log session deletion
    await this.securityAuditService.logSecurityEvent({
      eventType: 'waha_session_deleted' as any,
      tenantId,
      resource: 'waha_session',
      action: 'delete',
      details: {
        sessionId: session.id,
        sessionName: session.externalSessionId,
        message: 'WAHA session deleted',
      },
      severity: 'medium',
    });

    this.logger.log(`WAHA session deleted successfully: ${sessionId}`);
  }

  async syncSessionStatus(sessionId: string): Promise<WahaSession> {
    this.logger.debug(`Syncing WAHA session status: ${sessionId}`);

    const session = await this.wahaSessionRepository.findOne({
      where: { id: sessionId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    try {
      const wahaStatus = await this.wahaClientService.getSessionStatus(session.externalSessionId);
      
      // Update session status and metadata
      session.status = this.mapWahaStatusToEntity(wahaStatus.status);
      session.metadata = {
        ...session.metadata,
        ...wahaStatus.metadata,
        lastSync: new Date(),
      };

      const updatedSession = await this.wahaSessionRepository.save(session);
      this.logger.debug(`Session status synced: ${sessionId} -> ${updatedSession.status}`);
      
      return updatedSession;
    } catch (error) {
      this.logger.error(`Failed to sync session status ${sessionId}: ${error.message}`);
      throw new BadRequestException(`Failed to sync session status: ${error.message}`);
    }
  }

  async getSessionQRCode(sessionId: string, tenantId: string): Promise<string> {
    this.logger.debug(`Getting QR code for session: ${sessionId} for tenant: ${tenantId}`);

    const session = await this.wahaSessionRepository.findOne({
      where: { id: sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    if (session.status !== WahaSessionStatus.SCAN_QR) {
      throw new BadRequestException('Session is not in QR scanning state');
    }

    try {
      const qrCode = await this.wahaClientService.getSessionQR(session.externalSessionId);
      return qrCode;
    } catch (error) {
      this.logger.error(`Failed to get QR code for session ${sessionId}: ${error.message}`);
      throw new BadRequestException(`Failed to get QR code: ${error.message}`);
    }
  }

  async sendMessage(sessionId: string, tenantId: string, messageDto: SendMessageDto): Promise<MessageResponse> {
    this.logger.log(`Sending message via session: ${sessionId} for tenant: ${tenantId}`);

    const session = await this.wahaSessionRepository.findOne({
      where: { id: sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    if (session.status !== WahaSessionStatus.WORKING) {
      throw new BadRequestException('Session is not in working state');
    }

    try {
      const messageResponse = await this.wahaClientService.sendTextMessage(
        session.externalSessionId,
        messageDto.to,
        messageDto.text,
      );

      // Log message sent
      await this.securityAuditService.logSecurityEvent({
        eventType: 'waha_message_sent' as any,
        tenantId,
        resource: 'waha_session',
        action: 'send_message',
        details: {
          sessionId: session.id,
          recipient: messageDto.to,
          messageLength: messageDto.text.length,
          messageId: messageResponse.messageId,
        },
        severity: 'low',
      });

      this.logger.log(`Message sent successfully via session: ${sessionId}`);
      return messageResponse;
    } catch (error) {
      this.logger.error(`Failed to send message via session ${sessionId}: ${error.message}`);
      throw new BadRequestException(`Failed to send message: ${error.message}`);
    }
  }

  async getSessionScreen(sessionId: string, tenantId: string): Promise<Buffer> {
    this.logger.debug(`Getting screen for session: ${sessionId} for tenant: ${tenantId}`);

    const session = await this.wahaSessionRepository.findOne({
      where: { id: sessionId, tenantId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    try {
      const screenBuffer = await this.wahaClientService.getSessionScreen(session.externalSessionId);
      return screenBuffer;
    } catch (error) {
      this.logger.error(`Failed to get screen for session ${sessionId}: ${error.message}`);
      throw new BadRequestException(`Failed to get session screen: ${error.message}`);
    }
  }

  async checkHealth(): Promise<WahaHealthResponse> {
    this.logger.debug('Checking WAHA service health');

    try {
      const healthInfo = await this.wahaClientService.getHealthInfo();
      return healthInfo;
    } catch (error) {
      this.logger.error(`WAHA health check failed: ${error.message}`, error.stack);
      throw new BadRequestException(`WAHA service health check failed: ${error.message}`);
    }
  }

  // Helper methods
  private mapWahaStatusToEntity(wahaStatus: string): WahaSessionStatus {
    switch (wahaStatus.toLowerCase()) {
      case 'starting':
        return WahaSessionStatus.STARTING;
      case 'scan_qr':
      case 'scanning':
        return WahaSessionStatus.SCAN_QR;
      case 'working':
      case 'connected':
        return WahaSessionStatus.WORKING;
      case 'failed':
      case 'error':
        return WahaSessionStatus.FAILED;
      case 'stopped':
      case 'disconnected':
        return WahaSessionStatus.STOPPED;
      default:
        return WahaSessionStatus.FAILED;
    }
  }

  async syncAllSessionsStatus(): Promise<void> {
    this.logger.log('Syncing all WAHA sessions status');

    const sessions = await this.wahaSessionRepository.find({
      where: { status: WahaSessionStatus.WORKING },
    });

    for (const session of sessions) {
      try {
        await this.syncSessionStatus(session.id);
      } catch (error) {
        this.logger.error(`Failed to sync session ${session.id}: ${error.message}`);
      }
    }

    this.logger.log(`Synced status for ${sessions.length} sessions`);
  }
}
