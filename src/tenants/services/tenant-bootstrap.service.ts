import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Tenant, TenantStatus } from '../entities/tenant.entity';
import { User, UserRole } from '../../users/entities/user.entity';
import { SecurityAuditService } from '../../common/services/security-audit.service';
import { AuthService } from '../../auth/auth.service';

export interface TenantBootstrapData {
  name: string;
  adminEmail: string;
  adminPassword: string;
  adminFirstName: string;
  adminLastName: string;
  settings?: Record<string, any>;
}

@Injectable()
export class TenantBootstrapService {
  private readonly logger = new Logger(TenantBootstrapService.name);

  constructor(
    @InjectRepository(Tenant)
    private tenantRepository: Repository<Tenant>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private securityAuditService: SecurityAuditService,
    private authService: AuthService,
  ) {}

  async bootstrapTenant(bootstrapData: TenantBootstrapData): Promise<{
    tenant: Tenant;
    adminUser: User;
  }> {
    this.logger.log(`Bootstrapping new tenant: ${bootstrapData.name}`);

    // Create tenant
    const tenant = this.tenantRepository.create({
      name: bootstrapData.name,
      status: TenantStatus.ACTIVE,
      settings: {
        timezone: 'UTC',
        language: 'en',
        features: ['messaging', 'analytics'],
        ...bootstrapData.settings,
      },
    });

    const savedTenant = await this.tenantRepository.save(tenant);

    // Create admin user
    const adminUser = await this.createTenantAdmin(savedTenant.id, {
      email: bootstrapData.adminEmail,
      password: bootstrapData.adminPassword,
      firstName: bootstrapData.adminFirstName,
      lastName: bootstrapData.adminLastName,
    });

    // Initialize default settings
    await this.initializeDefaultSettings(savedTenant.id);

    // Create audit log entry
    await this.securityAuditService.logSecurityEvent({
      eventType: 'tenant_bootstrapped' as any,
      tenantId: savedTenant.id,
      userId: adminUser.id,
      resource: 'tenant',
      action: 'bootstrap',
      details: {
        tenantName: savedTenant.name,
        adminEmail: bootstrapData.adminEmail,
        message: 'Tenant bootstrapped successfully',
      },
      severity: 'medium',
    });

    this.logger.log(`Tenant bootstrapped successfully: ${savedTenant.id}`);

    return {
      tenant: savedTenant,
      adminUser,
    };
  }

  private async createTenantAdmin(tenantId: string, adminData: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
  }): Promise<User> {
    const hashedPassword = await this.authService.hashPassword(adminData.password);

    const adminUser = this.userRepository.create({
      email: adminData.email,
      passwordHash: hashedPassword,
      role: UserRole.TENANT_ADMIN,
      isActive: true,
      tenantId,
    });

    const savedUser = await this.userRepository.save(adminUser);

    this.logger.log(`Admin user created for tenant ${tenantId}: ${adminData.email}`);

    return savedUser;
  }

  private async initializeDefaultSettings(tenantId: string): Promise<void> {
    // Initialize default tenant settings
    const defaultSettings = {
      messaging: {
        maxSessions: 5,
        maxMessagesPerDay: 1000,
        allowedFileTypes: ['image', 'document', 'audio', 'video'],
        maxFileSize: 10 * 1024 * 1024, // 10MB
      },
      security: {
        passwordPolicy: {
          minLength: 8,
          requireUppercase: true,
          requireLowercase: true,
          requireNumbers: true,
          requireSpecialChars: true,
        },
        sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
        maxLoginAttempts: 5,
        lockoutDuration: 15 * 60 * 1000, // 15 minutes
      },
      notifications: {
        emailNotifications: true,
        webhookNotifications: true,
        notificationChannels: ['email', 'webhook'],
      },
      analytics: {
        retentionDays: 90,
        trackUserActivity: true,
        trackMessageMetrics: true,
      },
    };

    // Update tenant with default settings
    await this.tenantRepository.update(tenantId, {
      settings: defaultSettings as any,
    });

    this.logger.log(`Default settings initialized for tenant: ${tenantId}`);
  }

  async sendWelcomeEmail(tenant: Tenant, adminUser: User): Promise<void> {
    // This would integrate with your email service
    // For now, just log the welcome email details
    this.logger.log(`Welcome email would be sent to: ${adminUser.email}`);
    this.logger.log(`Tenant: ${tenant.name}`);
    this.logger.log(`Login credentials: ${adminUser.email} / [password]`);
  }

  async validateTenantBootstrap(tenantId: string): Promise<boolean> {
    const tenant = await this.tenantRepository.findOne({
      where: { id: tenantId },
    });

    if (!tenant) {
      return false;
    }

    const adminUser = await this.userRepository.findOne({
      where: { tenantId, role: UserRole.TENANT_ADMIN },
    });

    if (!adminUser) {
      return false;
    }

    return tenant.status === TenantStatus.ACTIVE && adminUser.isActive;
  }
}
