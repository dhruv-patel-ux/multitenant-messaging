import { Injectable, NotFoundException, ConflictException, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, FindOptionsWhere, Like, Between } from 'typeorm';
import { Tenant, TenantStatus } from './entities/tenant.entity';
import { User, UserRole } from '../users/entities/user.entity';
import { WahaSession } from '../waha/entities/waha-session.entity';
import { Message } from '../messages/entities/message.entity';
import { SecurityAuditService } from '../common/services/security-audit.service';
import { AuthService } from '../auth/auth.service';
import {
  CreateTenantDto,
  UpdateTenantDto,
  TenantStatsDto,
  TenantResponseDto,
  PaginationDto,
  PaginatedResponse,
  DeactivateTenantDto,
} from './dto/tenant.dto';

@Injectable()
export class TenantsService {
  private readonly logger = new Logger(TenantsService.name);

  constructor(
    @InjectRepository(Tenant)
    private tenantRepository: Repository<Tenant>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(WahaSession)
    private sessionRepository: Repository<WahaSession>,
    @InjectRepository(Message)
    private messageRepository: Repository<Message>,
    private securityAuditService: SecurityAuditService,
    private authService: AuthService,
  ) {}

  // Platform admin methods
  async create(createTenantDto: CreateTenantDto): Promise<TenantResponseDto> {
    this.logger.log(`Creating new tenant: ${createTenantDto.name}`);

    // Check if tenant name already exists
    const existingTenant = await this.tenantRepository.findOne({
      where: { name: createTenantDto.name },
    });

    if (existingTenant) {
      throw new ConflictException('Tenant with this name already exists');
    }

    // Check if admin email already exists
    const existingUser = await this.userRepository.findOne({
      where: { email: createTenantDto.adminEmail },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Create tenant
    const tenant = this.tenantRepository.create({
      name: createTenantDto.name,
      status: TenantStatus.ACTIVE,
      settings: createTenantDto.settings || {},
    });

    const savedTenant = await this.tenantRepository.save(tenant);

    // Create admin user for the tenant
    const adminUser = await this.createTenantAdmin(savedTenant.id, {
      email: createTenantDto.adminEmail,
      password: createTenantDto.adminPassword,
      firstName: createTenantDto.adminFirstName,
      lastName: createTenantDto.adminLastName,
    });

    // Log tenant creation
    await this.securityAuditService.logSecurityEvent({
      eventType: 'tenant_created' as any,
      tenantId: savedTenant.id,
      resource: 'tenant',
      action: 'create',
      details: {
        tenantName: savedTenant.name,
        adminEmail: createTenantDto.adminEmail,
        message: 'New tenant created with admin user',
      },
      severity: 'medium',
    });

    this.logger.log(`Tenant created successfully: ${savedTenant.id}`);

    return this.mapToResponseDto(savedTenant);
  }

  async findAll(pagination: PaginationDto): Promise<PaginatedResponse<TenantResponseDto>> {
    const { page = 1, limit = 10, search, sortBy = 'createdAt', sortOrder = 'DESC' } = pagination;
    const skip = (page - 1) * limit;

    const where: FindOptionsWhere<Tenant> = {};

    if (search) {
      where.name = Like(`%${search}%`);
    }

    const [tenants, total] = await this.tenantRepository.findAndCount({
      where,
      order: { [sortBy]: sortOrder },
      skip,
      take: limit,
    });

    const totalPages = Math.ceil(total / limit);

    return {
      data: tenants.map(tenant => this.mapToResponseDto(tenant)),
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

  async findOne(id: string): Promise<TenantResponseDto> {
    const tenant = await this.tenantRepository.findOne({
      where: { id },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    return this.mapToResponseDto(tenant);
  }

  async update(id: string, updateTenantDto: UpdateTenantDto): Promise<TenantResponseDto> {
    const tenant = await this.tenantRepository.findOne({
      where: { id },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    // Check if name is being changed and if it conflicts
    if (updateTenantDto.name && updateTenantDto.name !== tenant.name) {
      const existingTenant = await this.tenantRepository.findOne({
        where: { name: updateTenantDto.name },
      });

      if (existingTenant) {
        throw new ConflictException('Tenant with this name already exists');
      }
    }

    // Update tenant
    Object.assign(tenant, updateTenantDto);
    const updatedTenant = await this.tenantRepository.save(tenant);

    // Log tenant update
    await this.securityAuditService.logSecurityEvent({
      eventType: 'tenant_updated' as any,
      tenantId: id,
      resource: 'tenant',
      action: 'update',
      details: {
        changes: updateTenantDto,
        message: 'Tenant updated',
      },
      severity: 'medium',
    });

    return this.mapToResponseDto(updatedTenant);
  }

  async deactivate(id: string, deactivateDto: DeactivateTenantDto): Promise<void> {
    const tenant = await this.tenantRepository.findOne({
      where: { id },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    if (tenant.status === TenantStatus.INACTIVE) {
      throw new BadRequestException('Tenant is already inactive');
    }

    // Check if tenant has active users
    const activeUsers = await this.userRepository.count({
      where: { tenantId: id, isActive: true },
    });

    if (activeUsers > 0) {
      throw new BadRequestException('Cannot deactivate tenant with active users');
    }

    // Deactivate tenant
    tenant.status = TenantStatus.INACTIVE;
    await this.tenantRepository.save(tenant);

    // Log tenant deactivation
    await this.securityAuditService.logSecurityEvent({
      eventType: 'tenant_deactivated' as any,
      tenantId: id,
      resource: 'tenant',
      action: 'deactivate',
      details: {
        reason: deactivateDto.reason,
        notes: deactivateDto.notes,
        message: 'Tenant deactivated',
      },
      severity: 'high',
    });

    this.logger.log(`Tenant deactivated: ${id}`);
  }

  // Tenant-specific methods
  async getTenantStats(tenantId: string): Promise<TenantStatsDto> {
    const tenant = await this.tenantRepository.findOne({
      where: { id: tenantId },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    // Get user statistics
    const [totalUsers, activeUsers] = await Promise.all([
      this.userRepository.count({ where: { tenantId } }),
      this.userRepository.count({ where: { tenantId, isActive: true } }),
    ]);

    // Get session statistics
    const [totalSessions, activeSessions] = await Promise.all([
      this.sessionRepository.count({ where: { tenantId } }),
      this.sessionRepository.count({ where: { tenantId, status: 'working' as any } }),
    ]);

    // Get message statistics
    const [totalMessages, messagesLast24h, messagesLast7d, messagesLast30d] = await Promise.all([
      this.messageRepository.count({ where: { tenantId } }),
      this.messageRepository.count({
        where: {
          tenantId,
          createdAt: Between(new Date(Date.now() - 24 * 60 * 60 * 1000), new Date()),
        },
      }),
      this.messageRepository.count({
        where: {
          tenantId,
          createdAt: Between(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), new Date()),
        },
      }),
      this.messageRepository.count({
        where: {
          tenantId,
          createdAt: Between(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), new Date()),
        },
      }),
    ]);

    // Get last activity
    const lastMessage = await this.messageRepository.findOne({
      where: { tenantId },
      order: { createdAt: 'DESC' },
    });

    return {
      totalUsers,
      activeUsers,
      inactiveUsers: totalUsers - activeUsers,
      totalSessions,
      activeSessions,
      totalMessages,
      messagesLast24h,
      messagesLast7d,
      messagesLast30d,
      createdAt: tenant.createdAt,
      lastActivity: lastMessage?.createdAt || tenant.createdAt,
    };
  }

  async getTenantUsers(tenantId: string): Promise<User[]> {
    const tenant = await this.tenantRepository.findOne({
      where: { id: tenantId },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    return this.userRepository.find({
      where: { tenantId },
      order: { createdAt: 'DESC' },
    });
  }

  async getTenantSessions(tenantId: string): Promise<WahaSession[]> {
    const tenant = await this.tenantRepository.findOne({
      where: { id: tenantId },
    });

    if (!tenant) {
      throw new NotFoundException('Tenant not found');
    }

    return this.sessionRepository.find({
      where: { tenantId },
      order: { createdAt: 'DESC' },
    });
  }

  // Helper methods
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

  private mapToResponseDto(tenant: Tenant): TenantResponseDto {
    return {
      id: tenant.id,
      name: tenant.name,
      status: tenant.status,
      settings: tenant.settings || {},
      createdAt: tenant.createdAt,
      updatedAt: tenant.updatedAt,
    };
  }
}
