import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserRole, Permission } from '../enums/roles.enum';

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);

export const CurrentTenant = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.tenant;
  },
);

export const TenantId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.tenantId;
  },
);

export const UserId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user?.id;
  },
);

export const GetUserRole = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user?.role;
  },
);

// Role-based decorators
export const RequireRole = (role: UserRole) => {
  return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
    const originalMethod = descriptor.value;
    descriptor.value = function (...args: any[]) {
      const request = args.find(arg => arg && arg.user);
      if (!request || !request.user) {
        throw new Error('User not authenticated');
      }
      
      if (request.user.role !== role) {
        throw new Error(`Access denied. Required role: ${role}`);
      }
      
      return originalMethod.apply(this, args);
    };
    return descriptor;
  };
};

// Permission-based decorators
export const RequirePermission = (permission: Permission) => {
  return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
    const originalMethod = descriptor.value;
    descriptor.value = function (...args: any[]) {
      const request = args.find(arg => arg && arg.user);
      if (!request || !request.user) {
        throw new Error('User not authenticated');
      }
      
      // This would need to be implemented with the permission checking logic
      // For now, just a placeholder
      return originalMethod.apply(this, args);
    };
    return descriptor;
  };
};
