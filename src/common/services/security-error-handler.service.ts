import { Injectable, Logger } from '@nestjs/common';
import { HttpException, HttpStatus } from '@nestjs/common';
import { SecurityAuditService } from './security-audit.service';

export enum ErrorType {
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  TENANT_ISOLATION_VIOLATION = 'TENANT_ISOLATION_VIOLATION',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  ROLE_INSUFFICIENT = 'ROLE_INSUFFICIENT',
  CROSS_TENANT_ACCESS = 'CROSS_TENANT_ACCESS',
  RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
}

export interface SecurityErrorContext {
  userId?: string;
  tenantId?: string;
  resource?: string;
  action?: string;
  ipAddress?: string;
  userAgent?: string;
  userRole?: string;
  requiredRole?: string;
  requiredPermission?: string;
}

@Injectable()
export class SecurityErrorHandler {
  private readonly logger = new Logger('SecurityErrorHandler');

  constructor(private securityAuditService: SecurityAuditService) {}

  handleUnauthorized(context: SecurityErrorContext): HttpException {
    this.logger.warn('Unauthorized access attempt', context);
    
    return new HttpException(
      {
        success: false,
        message: 'Authentication required',
        error: ErrorType.UNAUTHORIZED,
        statusCode: HttpStatus.UNAUTHORIZED,
      },
      HttpStatus.UNAUTHORIZED,
    );
  }

  handleForbidden(context: SecurityErrorContext): HttpException {
    this.logger.warn('Forbidden access attempt', context);
    
    return new HttpException(
      {
        success: false,
        message: 'Access denied',
        error: ErrorType.FORBIDDEN,
        statusCode: HttpStatus.FORBIDDEN,
      },
      HttpStatus.FORBIDDEN,
    );
  }

  handlePermissionDenied(context: SecurityErrorContext): HttpException {
    this.logger.warn('Permission denied', context);
    
    // Log security event
    if (context.userId && context.tenantId) {
      this.securityAuditService.logPermissionDenied(
        context.userId,
        context.tenantId,
        context.resource || 'unknown',
        context.action || 'unknown',
        context.userRole || 'unknown',
        context.requiredRole || 'unknown',
        context.ipAddress || 'unknown',
        context.userAgent,
      );
    }

    return new HttpException(
      {
        success: false,
        message: `Insufficient permissions. Required: ${context.requiredPermission || context.requiredRole}`,
        error: ErrorType.PERMISSION_DENIED,
        statusCode: HttpStatus.FORBIDDEN,
      },
      HttpStatus.FORBIDDEN,
    );
  }

  handleTenantIsolationViolation(context: SecurityErrorContext): HttpException {
    this.logger.error('Tenant isolation violation', context);
    
    // Log critical security event
    if (context.userId && context.tenantId) {
      this.securityAuditService.logTenantIsolationViolation(
        context.userId,
        context.tenantId,
        context.resource || 'unknown',
        'cross_tenant_access',
        context.ipAddress || 'unknown',
        context.userAgent,
      );
    }

    return new HttpException(
      {
        success: false,
        message: 'Access denied: Cross-tenant access not allowed',
        error: ErrorType.TENANT_ISOLATION_VIOLATION,
        statusCode: HttpStatus.FORBIDDEN,
      },
      HttpStatus.FORBIDDEN,
    );
  }

  handleCrossTenantAccess(context: SecurityErrorContext, attemptedTenantId: string): HttpException {
    this.logger.error('Cross-tenant access attempt', { ...context, attemptedTenantId });
    
    // Log security event
    if (context.userId && context.tenantId) {
      this.securityAuditService.logCrossTenantAccessAttempt(
        context.userId,
        attemptedTenantId,
        context.tenantId,
        context.resource || 'unknown',
        context.ipAddress || 'unknown',
        context.userAgent,
      );
    }

    return new HttpException(
      {
        success: false,
        message: 'Access denied: Cross-tenant access not allowed',
        error: ErrorType.CROSS_TENANT_ACCESS,
        statusCode: HttpStatus.FORBIDDEN,
      },
      HttpStatus.FORBIDDEN,
    );
  }

  handleRoleInsufficient(context: SecurityErrorContext): HttpException {
    this.logger.warn('Insufficient role', context);
    
    // Log security event
    if (context.userId && context.tenantId) {
      this.securityAuditService.logRoleEscalationAttempt(
        context.userId,
        context.tenantId,
        context.userRole || 'unknown',
        context.requiredRole || 'unknown',
        context.ipAddress || 'unknown',
        context.userAgent,
      );
    }

    return new HttpException(
      {
        success: false,
        message: `Insufficient role. Required: ${context.requiredRole}, Current: ${context.userRole}`,
        error: ErrorType.ROLE_INSUFFICIENT,
        statusCode: HttpStatus.FORBIDDEN,
      },
      HttpStatus.FORBIDDEN,
    );
  }

  handleResourceNotFound(context: SecurityErrorContext): HttpException {
    this.logger.warn('Resource not found', context);
    
    return new HttpException(
      {
        success: false,
        message: 'Resource not found',
        error: ErrorType.RESOURCE_NOT_FOUND,
        statusCode: HttpStatus.NOT_FOUND,
      },
      HttpStatus.NOT_FOUND,
    );
  }

  handleValidationError(context: SecurityErrorContext, details: any): HttpException {
    this.logger.warn('Validation error', { ...context, details });
    
    return new HttpException(
      {
        success: false,
        message: 'Validation failed',
        error: ErrorType.VALIDATION_ERROR,
        statusCode: HttpStatus.BAD_REQUEST,
        details,
      },
      HttpStatus.BAD_REQUEST,
    );
  }
}
