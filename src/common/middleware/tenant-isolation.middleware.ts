import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Tenant, TenantStatus } from '../../tenants/entities/tenant.entity';

export interface TenantRequest extends Request {
  tenantId?: string;
  tenant?: Tenant;
  user?: any;
}

@Injectable()
export class TenantIsolationMiddleware implements NestMiddleware {
  private readonly logger = new Logger('TenantIsolation');

  constructor(
    @InjectRepository(Tenant)
    private tenantRepository: Repository<Tenant>,
  ) {}

  async use(req: TenantRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // Skip tenant isolation for public routes
      if (this.isPublicRoute(req.path)) {
        return next();
      }

      // Extract tenant ID from JWT payload or headers
      const tenantId = this.extractTenantId(req);
      
      if (!tenantId) {
        this.logger.warn(`No tenant ID found in request to ${req.path} from ${req.ip}`);
        return next();
      }

      // Validate tenant exists and is active
      const tenant = await this.tenantRepository.findOne({
        where: { id: tenantId, status: TenantStatus.ACTIVE },
      });

      if (!tenant) {
        this.logger.error(`Invalid or inactive tenant ID: ${tenantId} from ${req.ip}`);
        res.status(403).json({
          success: false,
          message: 'Invalid or inactive tenant',
          error: 'TENANT_INVALID',
        });
        return;
      }

      // Add tenant context to request
      req.tenantId = tenantId;
      req.tenant = tenant;

      // Log tenant access for audit
      this.logger.log(`Tenant access: ${tenantId} to ${req.path} from ${req.ip}`);

      next();
    } catch (error) {
      this.logger.error(`Tenant isolation error: ${error.message}`, error.stack);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: 'TENANT_ISOLATION_ERROR',
      });
    }
  }

  private isPublicRoute(path: string): boolean {
    const publicRoutes = [
      '/health',
      '/auth/login',
      '/auth/refresh',
      '/auth/register',
      '/docs',
      '/api/v1/docs',
    ];

    return publicRoutes.some(route => path.startsWith(route));
  }

  private extractTenantId(req: TenantRequest): string | null {
    // Try to get tenant ID from JWT payload (set by auth guard)
    if (req.user?.tenantId) {
      return req.user.tenantId;
    }

    // Try to get from X-Tenant-ID header
    const tenantHeader = req.headers['x-tenant-id'] as string;
    if (tenantHeader) {
      return tenantHeader;
    }

    // Try to get from route parameters
    const tenantParam = req.params.tenantId;
    if (tenantParam) {
      return tenantParam;
    }

    return null;
  }
}
