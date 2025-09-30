import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from '../../users/entities/user.entity';
import { Tenant, TenantStatus } from '../entities/tenant.entity';
import { SecurityAuditService } from '../../common/services/security-audit.service';
import { AuthService } from '../../auth/auth.service';

export interface PlatformAdminData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

@Injectable()
export class PlatformAdminService {
  private readonly logger = new Logger(PlatformAdminService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Tenant)
    private tenantRepository: Repository<Tenant>,
    private securityAuditService: SecurityAuditService,
    private authService: AuthService,
  ) {}

  async createPlatformAdmin(adminData: PlatformAdminData): Promise<User> {
    this.logger.log(`Creating platform admin: ${adminData.email}`);

    // Check if platform admin already exists
    const existingAdmin = await this.userRepository.findOne({
      where: { email: adminData.email },
    });

    if (existingAdmin) {
      throw new Error('Platform admin already exists');
    }

    // Hash password
    const hashedPassword = await this.authService.hashPassword(adminData.password);

    // Create platform admin user
    const platformTenantId = '00000000-0000-0000-0000-000000000000';
    const platformAdmin = this.userRepository.create({
      email: adminData.email,
      passwordHash: hashedPassword,
      firstName: adminData.firstName,
      lastName: adminData.lastName,
      role: UserRole.TENANT_ADMIN,
      isActive: true,
      tenantId: platformTenantId,
    });

    const savedAdmin: User = await this.userRepository.save(platformAdmin);

    // Log platform admin creation
    await this.securityAuditService.logSecurityEvent({
      eventType: 'platform_admin_created' as any,
      userId: savedAdmin?.id,
      resource: 'platform_admin',
      action: 'create',
      details: {
        email: adminData.email,
        message: 'Platform admin created',
      },
      severity: 'high',
    });

    this.logger.log(`Platform admin created successfully: ${savedAdmin.id}`);

    return savedAdmin;
  }

  async getPlatformStats(): Promise<{
    totalTenants: number;
    activeTenants: number;
    inactiveTenants: number;
    totalUsers: number;
    totalSessions: number;
    totalMessages: number;
  }> {
    const [totalTenants, activeTenants, inactiveTenants] = await Promise.all([
      this.tenantRepository.count(),
      this.tenantRepository.count({ where: { status: TenantStatus.ACTIVE } }),
      this.tenantRepository.count({ where: { status: TenantStatus.INACTIVE } }),
    ]);

    const [totalUsers, totalSessions, totalMessages] = await Promise.all([
      this.userRepository.count(),
      // These would need to be implemented based on your session and message repositories
      // this.sessionRepository.count(),
      // this.messageRepository.count(),
      0, // Placeholder
      0, // Placeholder
    ]);

    return {
      totalTenants,
      activeTenants,
      inactiveTenants,
      totalUsers,
      totalSessions,
      totalMessages,
    };
  }

  async seedPlatformAdmin(): Promise<User | null> {
    const adminData: PlatformAdminData = {
      email: 'admin@platform.com',
      password: 'PlatformAdmin123!',
      firstName: 'Platform',
      lastName: 'Administrator',
    };

    try {
      return await this.createPlatformAdmin(adminData);
    } catch (error) {
      this.logger.warn('Platform admin already exists or creation failed', error.message);
      return null;
    }
  }
}
