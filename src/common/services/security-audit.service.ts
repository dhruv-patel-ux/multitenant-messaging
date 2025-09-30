import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Entity, Column } from 'typeorm';
import { BaseEntity } from '../entities/base.entity';

export enum SecurityEventType {
  CROSS_TENANT_ACCESS_ATTEMPT = 'cross_tenant_access_attempt',
  UNAUTHORIZED_ACCESS_ATTEMPT = 'unauthorized_access_attempt',
  PERMISSION_DENIED = 'permission_denied',
  ROLE_ESCALATION_ATTEMPT = 'role_escalation_attempt',
  TENANT_ISOLATION_VIOLATION = 'tenant_isolation_violation',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
}

export interface SecurityEventData {
  eventType: SecurityEventType;
  userId?: string;
  tenantId?: string;
  resource?: string;
  action?: string;
  ipAddress?: string;
  userAgent?: string;
  details?: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

@Entity('security_events')
export class SecurityEvent extends BaseEntity {
  @Column({ type: 'enum', enum: SecurityEventType })
  eventType: SecurityEventType;

  @Column({ type: 'varchar', length: 255, nullable: true })
  userId?: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  tenantId?: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  resource?: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  action?: string;

  @Column({ type: 'varchar', length: 45, nullable: true })
  ipAddress?: string;

  @Column({ type: 'text', nullable: true })
  userAgent?: string;

  @Column({ type: 'jsonb', nullable: true })
  details?: Record<string, any>;

  @Column({ type: 'enum', enum: ['low', 'medium', 'high', 'critical'] })
  severity: 'low' | 'medium' | 'high' | 'critical';

  @Column({ type: 'boolean', default: false })
  isResolved: boolean;

  @Column({ type: 'text', nullable: true })
  resolution?: string;
}

@Injectable()
export class SecurityAuditService {
  private readonly logger = new Logger('SecurityAudit');

  constructor(
    @InjectRepository(SecurityEvent)
    private securityEventRepository: Repository<SecurityEvent>,
  ) {}

  async logSecurityEvent(eventData: SecurityEventData): Promise<void> {
    try {
      const securityEvent = this.securityEventRepository.create({
        eventType: eventData.eventType,
        userId: eventData.userId,
        tenantId: eventData.tenantId,
        resource: eventData.resource,
        action: eventData.action,
        ipAddress: eventData.ipAddress,
        userAgent: eventData.userAgent,
        details: eventData.details,
        severity: eventData.severity,
      });

      await this.securityEventRepository.save(securityEvent);

      // Log to console for immediate visibility
      this.logger.warn(
        `Security Event: ${eventData.eventType} - ${eventData.severity} severity`,
        {
          userId: eventData.userId,
          tenantId: eventData.tenantId,
          ipAddress: eventData.ipAddress,
          details: eventData.details,
        },
      );

      // For critical events, you might want to send alerts
      if (eventData.severity === 'critical') {
        await this.handleCriticalEvent(eventData);
      }
    } catch (error) {
      this.logger.error('Failed to log security event', error);
    }
  }

  async logCrossTenantAccessAttempt(
    userId: string,
    attemptedTenantId: string,
    actualTenantId: string,
    resource: string,
    ipAddress: string,
    userAgent?: string,
  ): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.CROSS_TENANT_ACCESS_ATTEMPT,
      userId,
      tenantId: actualTenantId,
      resource,
      action: 'cross_tenant_access_attempt',
      ipAddress,
      userAgent,
      details: {
        attemptedTenantId,
        actualTenantId,
        message: 'User attempted to access data from different tenant',
      },
      severity: 'high',
    });
  }

  async logUnauthorizedAccessAttempt(
    userId: string,
    tenantId: string,
    resource: string,
    requiredPermission: string,
    ipAddress: string,
    userAgent?: string,
  ): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
      userId,
      tenantId,
      resource,
      action: 'unauthorized_access_attempt',
      ipAddress,
      userAgent,
      details: {
        requiredPermission,
        message: 'User attempted to access resource without required permission',
      },
      severity: 'medium',
    });
  }

  async logPermissionDenied(
    userId: string,
    tenantId: string,
    resource: string,
    action: string,
    userRole: string,
    requiredRole: string,
    ipAddress: string,
    userAgent?: string,
  ): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.PERMISSION_DENIED,
      userId,
      tenantId,
      resource,
      action,
      ipAddress,
      userAgent,
      details: {
        userRole,
        requiredRole,
        message: 'User role insufficient for requested action',
      },
      severity: 'medium',
    });
  }

  async logRoleEscalationAttempt(
    userId: string,
    tenantId: string,
    currentRole: string,
    attemptedRole: string,
    ipAddress: string,
    userAgent?: string,
  ): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.ROLE_ESCALATION_ATTEMPT,
      userId,
      tenantId,
      action: 'role_escalation_attempt',
      ipAddress,
      userAgent,
      details: {
        currentRole,
        attemptedRole,
        message: 'User attempted to escalate their role',
      },
      severity: 'high',
    });
  }

  async logTenantIsolationViolation(
    userId: string,
    tenantId: string,
    resource: string,
    violationType: string,
    ipAddress: string,
    userAgent?: string,
  ): Promise<void> {
    await this.logSecurityEvent({
      eventType: SecurityEventType.TENANT_ISOLATION_VIOLATION,
      userId,
      tenantId,
      resource,
      action: 'tenant_isolation_violation',
      ipAddress,
      userAgent,
      details: {
        violationType,
        message: 'Tenant isolation boundary was violated',
      },
      severity: 'critical',
    });
  }

  private async handleCriticalEvent(eventData: SecurityEventData): Promise<void> {
    // Implement critical event handling
    // This could include:
    // - Sending alerts to administrators
    // - Blocking user accounts
    // - Notifying security team
    this.logger.error('CRITICAL SECURITY EVENT', eventData);
  }

  async getSecurityEvents(
    tenantId: string,
    limit: number = 100,
    offset: number = 0,
  ): Promise<SecurityEvent[]> {
    return this.securityEventRepository.find({
      where: { tenantId },
      order: { createdAt: 'DESC' },
      take: limit,
      skip: offset,
    });
  }

  async getSecurityEventsBySeverity(
    tenantId: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
  ): Promise<SecurityEvent[]> {
    return this.securityEventRepository.find({
      where: { tenantId, severity },
      order: { createdAt: 'DESC' },
    });
  }
}
