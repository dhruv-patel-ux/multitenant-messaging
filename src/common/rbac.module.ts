import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Tenant } from '../tenants/entities/tenant.entity';
import { SecurityEvent } from './services/security-audit.service';
import { RoleGuard } from './guards/role.guard';
import { TenantGuard, TenantIsolationGuard } from './guards/tenant.guard';
import { TenantIsolationMiddleware } from './middleware/tenant-isolation.middleware';
import { TenantAwareRepositoryFactory } from './services/tenant-aware-repository.service';
import { SecurityAuditService } from './services/security-audit.service';
import { SecurityErrorHandler } from './services/security-error-handler.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Tenant, SecurityEvent]),
  ],
  providers: [
    RoleGuard,
    TenantGuard,
    TenantIsolationGuard,
    TenantIsolationMiddleware,
    TenantAwareRepositoryFactory,
    SecurityAuditService,
    SecurityErrorHandler,
  ],
  exports: [
    RoleGuard,
    TenantGuard,
    TenantIsolationGuard,
    TenantIsolationMiddleware,
    TenantAwareRepositoryFactory,
    SecurityAuditService,
    SecurityErrorHandler,
  ],
})
export class RbacModule {}
