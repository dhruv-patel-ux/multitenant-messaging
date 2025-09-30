# RBAC & Tenant Isolation Documentation

## Overview

This document describes the Role-Based Access Control (RBAC) system and tenant isolation implementation for the multi-tenant messaging microservice.

## Architecture

### 1. Role Hierarchy

```
TENANT_ADMIN (Highest)
├── Full access to all resources
├── Can manage users and roles
├── Can access all tenant data
└── Can perform system administration

MANAGER
├── Campaign and messaging management
├── User management (read-only)
├── Session management
└── Reports and analytics

AGENT
├── Send and receive messages
├── Access assigned sessions
└── Basic messaging operations

AUDITOR (Lowest)
├── Read-only access to all data
├── Audit logs access
└── Reports and analytics
```

### 2. Permission Matrix

| Permission | TENANT_ADMIN | MANAGER | AGENT | AUDITOR |
|------------|--------------|---------|-------|---------|
| users:create | ✅ | ❌ | ❌ | ❌ |
| users:read | ✅ | ✅ | ❌ | ✅ |
| users:update | ✅ | ❌ | ❌ | ❌ |
| users:delete | ✅ | ❌ | ❌ | ❌ |
| sessions:create | ✅ | ✅ | ❌ | ❌ |
| sessions:read | ✅ | ✅ | ✅ | ✅ |
| sessions:manage | ✅ | ✅ | ❌ | ❌ |
| messages:send | ✅ | ✅ | ✅ | ❌ |
| messages:read | ✅ | ✅ | ✅ | ✅ |
| messages:manage | ✅ | ✅ | ❌ | ❌ |
| reports:read | ✅ | ✅ | ❌ | ✅ |
| analytics:read | ✅ | ✅ | ❌ | ✅ |

## Implementation

### 1. Guards

#### RoleGuard
- **Purpose**: Enforces role-based access control
- **Usage**: `@UseGuards(RoleGuard)`
- **Decorators**: `@Roles()`, `@RequirePermissions()`

#### TenantGuard
- **Purpose**: Validates tenant context and prevents cross-tenant access
- **Usage**: `@UseGuards(TenantGuard)`
- **Features**: Tenant validation, cross-tenant prevention

#### TenantIsolationGuard
- **Purpose**: Ensures all operations are tenant-scoped
- **Usage**: Applied globally via middleware
- **Features**: Automatic tenant filtering

### 2. Decorators

#### Authorization Decorators
```typescript
@CurrentUser()     // Get current user
@CurrentTenant()   // Get current tenant
@TenantId()        // Get tenant ID
@UserId()          // Get user ID
@UserRole()        // Get user role
```

#### Role Decorators
```typescript
@Roles(UserRole.TENANT_ADMIN)                    // Require specific role
@RequirePermissions(Permission.MESSAGES_SEND)   // Require specific permission
```

### 3. Middleware

#### TenantIsolationMiddleware
- **Purpose**: Global tenant isolation enforcement
- **Features**: 
  - Automatic tenant context extraction
  - Cross-tenant access prevention
  - Audit logging for security events

### 4. Services

#### SecurityAuditService
- **Purpose**: Logs security events and violations
- **Features**:
  - Cross-tenant access attempt logging
  - Permission denial tracking
  - Role escalation attempt detection
  - Security event severity classification

#### SecurityErrorHandler
- **Purpose**: Standardized error handling for security violations
- **Features**:
  - Consistent error responses
  - Security event logging
  - Detailed error context

#### TenantAwareRepository
- **Purpose**: Database operations with automatic tenant filtering
- **Features**:
  - Automatic tenant ID injection
  - Query builder with tenant context
  - Cross-tenant data prevention

## Usage Examples

### 1. Basic Role-Based Access

```typescript
@Controller('users')
@UseGuards(JwtAuthGuard, TenantGuard)
export class UsersController {
  @Get()
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN, UserRole.MANAGER)
  async getUsers(@CurrentUser() user: any) {
    // Only admins and managers can access
  }

  @Post()
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN)
  async createUser(@Body() createUserDto: CreateUserDto) {
    // Only admins can create users
  }
}
```

### 2. Permission-Based Access

```typescript
@Controller('messages')
@UseGuards(JwtAuthGuard, TenantGuard)
export class MessagesController {
  @Post()
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_SEND)
  async sendMessage(@Body() messageDto: SendMessageDto) {
    // Requires MESSAGES_SEND permission
  }

  @Get()
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_READ)
  async getMessages(@CurrentUser() user: any) {
    // Requires MESSAGES_READ permission
  }
}
```

### 3. Tenant-Scoped Operations

```typescript
@Controller('sessions')
@UseGuards(JwtAuthGuard, TenantGuard)
export class SessionsController {
  @Get()
  @UseGuards(RoleGuard)
  @Roles(UserRole.AGENT, UserRole.MANAGER, UserRole.TENANT_ADMIN)
  async getSessions(
    @CurrentUser() user: any,
    @TenantId() tenantId: string,
  ) {
    // Automatically filtered by tenant
    // Only returns sessions for the user's tenant
  }
}
```

## Security Features

### 1. Tenant Isolation
- **Data Segregation**: All data is automatically scoped to tenant
- **Cross-Tenant Prevention**: Guards prevent access to other tenants' data
- **Audit Logging**: All cross-tenant attempts are logged

### 2. Role-Based Access
- **Hierarchical Permissions**: Higher roles inherit lower role permissions
- **Permission Granularity**: Fine-grained permission control
- **Dynamic Role Assignment**: Roles can be assigned per user

### 3. Security Monitoring
- **Event Logging**: All security events are logged
- **Violation Detection**: Automatic detection of security violations
- **Audit Trail**: Complete audit trail for compliance

### 4. Error Handling
- **Consistent Responses**: Standardized error responses
- **Security Context**: Detailed error context for debugging
- **Event Correlation**: Security events are correlated with errors

## Error Responses

### 1. Unauthorized (401)
```json
{
  "success": false,
  "message": "Authentication required",
  "error": "UNAUTHORIZED",
  "statusCode": 401
}
```

### 2. Forbidden (403)
```json
{
  "success": false,
  "message": "Access denied",
  "error": "FORBIDDEN",
  "statusCode": 403
}
```

### 3. Permission Denied (403)
```json
{
  "success": false,
  "message": "Insufficient permissions. Required: messages:send",
  "error": "PERMISSION_DENIED",
  "statusCode": 403
}
```

### 4. Tenant Isolation Violation (403)
```json
{
  "success": false,
  "message": "Access denied: Cross-tenant access not allowed",
  "error": "TENANT_ISOLATION_VIOLATION",
  "statusCode": 403
}
```

## Best Practices

### 1. Controller Design
- Always use `@UseGuards(JwtAuthGuard, TenantGuard)` for protected routes
- Use specific role or permission decorators
- Extract user and tenant context using decorators

### 2. Service Implementation
- Use `TenantAwareRepository` for database operations
- Always validate tenant context in service methods
- Log security events for audit purposes

### 3. Error Handling
- Use `SecurityErrorHandler` for consistent error responses
- Log security violations for monitoring
- Provide meaningful error messages

### 4. Testing
- Test role-based access control
- Test tenant isolation boundaries
- Test permission enforcement
- Test security event logging

## Monitoring and Alerting

### 1. Security Events
- **Critical**: Tenant isolation violations, role escalation attempts
- **High**: Cross-tenant access attempts, unauthorized access
- **Medium**: Permission denials, insufficient roles
- **Low**: General security events

### 2. Audit Logs
- All security events are logged with context
- Events include user, tenant, IP, and action details
- Logs are retained for compliance and analysis

### 3. Alerting
- Critical events trigger immediate alerts
- High-severity events are monitored
- Regular security reports are generated

This RBAC system provides enterprise-grade security with comprehensive tenant isolation, role-based access control, and detailed audit logging.
