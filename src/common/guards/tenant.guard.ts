import { Injectable, CanActivate, ExecutionContext, ForbiddenException, BadRequestException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SetMetadata } from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { Tenant, TenantStatus } from '../../tenants/entities/tenant.entity';
import { UserRole } from '../enums/roles.enum';

export const TENANT_KEY = 'tenant';
export const TENANT_PARAM_KEY = 'tenantId';

export const GetTenant = () => SetMetadata(TENANT_KEY, 'tenant');
export const GetUser = () => SetMetadata('user', 'user');

@Injectable()
export class TenantGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private dataSource: DataSource,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const tenantRepository: Repository<Tenant> = this.dataSource.getRepository(Tenant);
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    // Extract tenant ID from JWT payload
    const tenantId = user.tenantId;
    if (!tenantId) {
      throw new ForbiddenException('Tenant context not found in token');
    }

    // Validate tenant exists and is active
    const tenant = await tenantRepository.findOne({
      where: { id: tenantId, status: TenantStatus.ACTIVE },
    });

    if (!tenant) {
      throw new ForbiddenException('Tenant not found or inactive');
    }

    // Check if user belongs to this tenant
    if (user.tenantId !== tenantId) {
      throw new ForbiddenException('User does not belong to the specified tenant');
    }

    // Add tenant context to request
    request.tenant = tenant;
    request.tenantId = tenantId;

    // Check for tenant-specific route parameters
    const params = request.params;
    if (params.tenantId && params.tenantId !== tenantId) {
      throw new ForbiddenException('Access denied: Cross-tenant access not allowed');
    }

    return true;
  }
}

@Injectable()
export class TenantIsolationGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    // Ensure tenant context is present
    if (!user.tenantId) {
      throw new ForbiddenException('Tenant context required');
    }

    // Add tenant context to request for use in services
    request.tenantId = user.tenantId;
    request.tenant = user.tenant;

    return true;
  }
}
