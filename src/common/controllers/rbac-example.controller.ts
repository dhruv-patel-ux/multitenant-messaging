import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  UseGuards,
  Request,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/auth.guards';
import { RoleGuard, Roles, RequirePermissions } from '../guards/role.guard';
import { TenantGuard } from '../guards/tenant.guard';
import { CurrentUser, CurrentTenant, TenantId } from '../decorators/authorization.decorators';
import { UserRole, Permission } from '../enums/roles.enum';
import { SecurityErrorHandler, SecurityErrorContext } from '../services/security-error-handler.service';

@ApiTags('RBAC Example')
@Controller('rbac-example')
@UseGuards(JwtAuthGuard, TenantGuard)
export class RbacExampleController {
  constructor(private securityErrorHandler: SecurityErrorHandler) {}

  @Get('admin-only')
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Admin only endpoint' })
  @ApiResponse({ status: 200, description: 'Admin access granted' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  adminOnly(@CurrentUser() user: any, @CurrentTenant() tenant: any) {
    return {
      message: 'Admin access granted',
      user: user.email,
      tenant: tenant.name,
    };
  }

  @Get('manager-or-admin')
  @UseGuards(RoleGuard)
  @Roles(UserRole.MANAGER, UserRole.TENANT_ADMIN)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Manager or admin endpoint' })
  @ApiResponse({ status: 200, description: 'Access granted' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  managerOrAdmin(@CurrentUser() user: any) {
    return {
      message: 'Manager or admin access granted',
      user: user.email,
      role: user.role,
    };
  }

  @Get('permission-based')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_READ, Permission.USERS_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Permission-based endpoint' })
  @ApiResponse({ status: 200, description: 'Access granted' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  permissionBased(@CurrentUser() user: any) {
    return {
      message: 'Permission-based access granted',
      user: user.email,
      permissions: ['messages:read', 'users:read'],
    };
  }

  @Get('tenant-scoped/:resourceId')
  @UseGuards(RoleGuard)
  @Roles(UserRole.AGENT, UserRole.MANAGER, UserRole.TENANT_ADMIN)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Tenant-scoped resource access' })
  @ApiResponse({ status: 200, description: 'Resource accessed' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  tenantScopedResource(
    @Param('resourceId') resourceId: string,
    @CurrentUser() user: any,
    @TenantId() tenantId: string,
  ) {
    // This endpoint automatically enforces tenant isolation
    return {
      message: 'Tenant-scoped resource accessed',
      resourceId,
      tenantId,
      user: user.email,
    };
  }

  @Post('create-resource')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_SEND)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Create resource with permission check' })
  @ApiResponse({ status: 201, description: 'Resource created' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  createResource(
    @Body() createDto: any,
    @CurrentUser() user: any,
    @TenantId() tenantId: string,
  ) {
    return {
      message: 'Resource created successfully',
      data: createDto,
      tenantId,
      createdBy: user.email,
    };
  }

  @Get('audit-logs')
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN, UserRole.AUDITOR)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get audit logs (admin/auditor only)' })
  @ApiResponse({ status: 200, description: 'Audit logs retrieved' })
  @ApiResponse({ status: 403, description: 'Access denied' })
  getAuditLogs(@CurrentUser() user: any, @TenantId() tenantId: string) {
    return {
      message: 'Audit logs retrieved',
      tenantId,
      requestedBy: user.email,
      logs: [], // This would be populated from the audit service
    };
  }

  @Get('cross-tenant-attempt')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Simulate cross-tenant access attempt' })
  @ApiResponse({ status: 403, description: 'Cross-tenant access denied' })
  simulateCrossTenantAttempt(
    @Request() req: any,
    @Param('targetTenantId') targetTenantId: string,
  ) {
    // This would be caught by the tenant guard
    const context: SecurityErrorContext = {
      userId: req.user?.id,
      tenantId: req.user?.tenantId,
      resource: 'cross-tenant-resource',
      action: 'access_attempt',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    };

    throw this.securityErrorHandler.handleCrossTenantAccess(
      context,
      targetTenantId,
    );
  }
}
