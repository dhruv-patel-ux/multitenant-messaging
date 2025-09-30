import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SetMetadata } from '@nestjs/common';
import { UserRole, Permission, ROLE_PERMISSIONS, HIERARCHICAL_ROLES } from '../enums/roles.enum';

export const ROLES_KEY = 'roles';
export const PERMISSIONS_KEY = 'permissions';

export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
export const RequirePermissions = (...permissions: Permission[]) => 
  SetMetadata(PERMISSIONS_KEY, permissions);

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const requiredPermissions = this.reflector.getAllAndOverride<Permission[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles && !requiredPermissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    const userRole = user.role as UserRole;

    // Check role-based access
    if (requiredRoles && requiredRoles.length > 0) {
      if (!this.hasRequiredRole(userRole, requiredRoles)) {
        throw new ForbiddenException(
          `Access denied. Required roles: ${requiredRoles.join(', ')}. User role: ${userRole}`,
        );
      }
    }

    // Check permission-based access
    if (requiredPermissions && requiredPermissions.length > 0) {
      if (!this.hasRequiredPermissions(userRole, requiredPermissions)) {
        throw new ForbiddenException(
          `Access denied. Required permissions: ${requiredPermissions.join(', ')}. User role: ${userRole}`,
        );
      }
    }

    return true;
  }

  private hasRequiredRole(userRole: UserRole, requiredRoles: UserRole[]): boolean {
    // Check if user has exact role
    if (requiredRoles.includes(userRole)) {
      return true;
    }

    // Check hierarchical permissions
    const userHierarchy = HIERARCHICAL_ROLES[userRole] || [];
    return requiredRoles.some(role => userHierarchy.includes(role));
  }

  private hasRequiredPermissions(userRole: UserRole, requiredPermissions: Permission[]): boolean {
    const userPermissions = ROLE_PERMISSIONS[userRole] || [];
    
    // Check if user has all required permissions
    return requiredPermissions.every(permission => userPermissions.includes(permission));
  }
}
