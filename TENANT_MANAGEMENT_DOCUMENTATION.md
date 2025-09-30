# Tenant Management System Documentation

## Overview

This document describes the comprehensive tenant management system for the multi-tenant messaging microservice, including platform administration, tenant isolation, and business rules.

## Architecture

### 1. System Components

```
Tenant Management System
├── Platform Admin System
│   ├── Platform Admin Service
│   ├── Super Admin Seeder
│   └── Platform Statistics
├── Tenant Management
│   ├── Tenant Service
│   ├── Tenant Controller
│   └── Tenant Bootstrap Service
├── Security & Isolation
│   ├── Tenant Context Validation
│   ├── Cross-Tenant Prevention
│   └── Audit Logging
└── Business Rules
    ├── Tenant Creation
    ├── Tenant Deactivation
    └── Data Retention
```

### 2. Role Hierarchy

```
PLATFORM_ADMIN (Highest)
├── Full access to all tenants
├── Can create, update, deactivate tenants
├── Can view platform-wide statistics
└── Cannot access tenant-specific data directly

TENANT_ADMIN
├── Full access within tenant
├── Can manage tenant users
├── Can view tenant statistics
└── Cannot access other tenants

MANAGER
├── Campaign and messaging management
├── User management (read-only)
└── Session management

AGENT
├── Basic messaging operations
└── Assigned session access

AUDITOR
├── Read-only access to all data
├── Audit logs access
└── Reports and analytics
```

## Implementation

### 1. Platform Admin System

#### Platform Admin Service
- **Purpose**: Manages platform-wide administration
- **Features**:
  - Create platform administrators
  - Platform statistics
  - Super admin seeder
  - Cross-tenant management

#### Platform Admin Endpoints
```typescript
POST /tenants              // Create new tenant
GET /tenants               // List all tenants
GET /tenants/:id           // Get tenant details
PUT /tenants/:id           // Update tenant
PUT /tenants/:id/deactivate // Deactivate tenant
```

### 2. Tenant Management

#### Tenant Service
- **Platform Admin Methods**:
  - `create()` - Create new tenant with admin user
  - `findAll()` - List all tenants with pagination
  - `findOne()` - Get tenant details
  - `update()` - Update tenant information
  - `deactivate()` - Deactivate tenant

- **Tenant-Specific Methods**:
  - `getTenantStats()` - Get tenant statistics
  - `getTenantUsers()` - Get tenant users
  - `getTenantSessions()` - Get tenant WAHA sessions

#### Tenant Controller
- **Platform Admin Routes**: Require platform admin permissions
- **Tenant-Specific Routes**: Require tenant context and appropriate roles
- **Security**: Automatic tenant isolation and role validation

### 3. Tenant Bootstrap Process

#### Bootstrap Service
- **Auto-Creation**: Creates first TENANT_ADMIN user
- **Default Settings**: Initializes tenant configuration
- **Welcome Email**: Sends login credentials
- **Audit Logging**: Records bootstrap process

#### Bootstrap Flow
1. **Tenant Creation**: Create tenant with default settings
2. **Admin User Creation**: Create TENANT_ADMIN user
3. **Settings Initialization**: Set default tenant configuration
4. **Welcome Email**: Send credentials to admin
5. **Audit Logging**: Record bootstrap completion

### 4. Security & Isolation

#### Tenant Context Validation
- **JWT Payload**: Extract tenant ID from token
- **Route Protection**: Ensure tenant context on all operations
- **Cross-Tenant Prevention**: Block access to other tenants' data

#### Security Features
- **Tenant Isolation**: Complete data segregation
- **Role-Based Access**: Hierarchical permission system
- **Audit Logging**: Comprehensive security event tracking
- **Input Validation**: DTO-based request validation

## API Endpoints

### 1. Platform Admin Endpoints

#### Create Tenant
```http
POST /tenants
Content-Type: application/json
Authorization: Bearer <platform_admin_token>

{
  "name": "Acme Corporation",
  "adminEmail": "admin@acme.com",
  "adminPassword": "SecurePassword123!",
  "adminFirstName": "John",
  "adminLastName": "Doe",
  "settings": {
    "timezone": "UTC",
    "language": "en"
  }
}
```

#### List Tenants
```http
GET /tenants?page=1&limit=10&search=acme&sortBy=createdAt&sortOrder=DESC
Authorization: Bearer <platform_admin_token>
```

#### Get Tenant Details
```http
GET /tenants/{tenantId}
Authorization: Bearer <platform_admin_token>
```

#### Update Tenant
```http
PUT /tenants/{tenantId}
Content-Type: application/json
Authorization: Bearer <platform_admin_token>

{
  "name": "Acme Corporation Updated",
  "status": "active",
  "settings": {
    "timezone": "UTC",
    "language": "en",
    "features": ["messaging", "analytics"]
  }
}
```

#### Deactivate Tenant
```http
PUT /tenants/{tenantId}/deactivate
Content-Type: application/json
Authorization: Bearer <platform_admin_token>

{
  "reason": "Tenant requested account closure",
  "notes": "All data will be retained for 30 days"
}
```

### 2. Tenant-Specific Endpoints

#### Get Current Tenant Stats
```http
GET /tenants/current/stats
Authorization: Bearer <tenant_token>
```

#### Get Current Tenant Users
```http
GET /tenants/current/users
Authorization: Bearer <tenant_token>
```

#### Get Current Tenant Sessions
```http
GET /tenants/current/sessions
Authorization: Bearer <tenant_token>
```

#### Get Current Tenant Details
```http
GET /tenants/current
Authorization: Bearer <tenant_token>
```

## DTOs and Responses

### 1. Request DTOs

#### CreateTenantDto
```typescript
{
  name: string;                    // Tenant name (unique)
  adminEmail: string;              // Admin user email
  adminPassword: string;           // Admin user password
  adminFirstName: string;          // Admin first name
  adminLastName: string;           // Admin last name
  settings?: Record<string, any>;  // Initial settings
}
```

#### UpdateTenantDto
```typescript
{
  name?: string;                   // Updated tenant name
  status?: TenantStatus;           // Tenant status
  settings?: Record<string, any>;  // Updated settings
}
```

#### DeactivateTenantDto
```typescript
{
  reason: string;                  // Deactivation reason
  notes?: string;                  // Additional notes
}
```

### 2. Response DTOs

#### TenantResponseDto
```typescript
{
  id: string;                      // Tenant ID
  name: string;                    // Tenant name
  status: TenantStatus;           // Tenant status
  settings: Record<string, any>;   // Tenant settings
  createdAt: Date;                 // Creation date
  updatedAt: Date;                 // Last update date
  stats?: TenantStatsDto;         // Statistics (current tenant only)
}
```

#### TenantStatsDto
```typescript
{
  totalUsers: number;              // Total users
  activeUsers: number;             // Active users
  inactiveUsers: number;           // Inactive users
  totalSessions: number;          // Total sessions
  activeSessions: number;         // Active sessions
  totalMessages: number;          // Total messages
  messagesLast24h: number;         // Messages last 24h
  messagesLast7d: number;          // Messages last 7 days
  messagesLast30d: number;         // Messages last 30 days
  createdAt: Date;                 // Tenant creation date
  lastActivity: Date;              // Last activity date
}
```

## Business Rules

### 1. Tenant Creation
- **Unique Names**: Tenant names must be unique across the platform
- **Admin User**: First user must be TENANT_ADMIN role
- **Default Settings**: Initialize with sensible defaults
- **Audit Logging**: Record all tenant creation events

### 2. Tenant Deactivation
- **Active Users**: Cannot deactivate tenant with active users
- **Data Retention**: Deactivated tenants retain data for 30 days
- **Soft Delete**: Use status field instead of hard deletion
- **Reactivation**: Provide process for tenant reactivation

### 3. Data Isolation
- **Tenant Context**: All operations must include tenant context
- **Cross-Tenant Prevention**: Block access to other tenants' data
- **Query Filtering**: Automatic tenant ID filtering on all queries
- **Audit Logging**: Log all cross-tenant access attempts

### 4. Security Rules
- **Platform Admin**: Special role for platform administration
- **Tenant Admin**: Full access within tenant only
- **Role Hierarchy**: Higher roles inherit lower permissions
- **Permission Granularity**: Fine-grained access control

## Security Features

### 1. Tenant Isolation
- **Data Segregation**: Complete separation of tenant data
- **Context Validation**: Ensure tenant context on all operations
- **Cross-Tenant Prevention**: Automatic blocking of cross-tenant access
- **Query Filtering**: Automatic tenant ID injection

### 2. Role-Based Access Control
- **Platform Admin**: Full platform access
- **Tenant Admin**: Full tenant access
- **Manager**: Campaign and messaging management
- **Agent**: Basic messaging operations
- **Auditor**: Read-only access

### 3. Audit Logging
- **Tenant Operations**: Log all tenant management actions
- **Security Events**: Track security violations
- **Access Attempts**: Monitor cross-tenant access
- **Role Changes**: Audit permission modifications

### 4. Error Handling
- **Consistent Responses**: Standardized error format
- **Security Context**: Detailed error information
- **Event Correlation**: Link errors to security events
- **Audit Trail**: Complete operation history

## Usage Examples

### 1. Platform Admin Operations

#### Create New Tenant
```typescript
const tenant = await tenantsService.create({
  name: 'Acme Corporation',
  adminEmail: 'admin@acme.com',
  adminPassword: 'SecurePassword123!',
  adminFirstName: 'John',
  adminLastName: 'Doe',
  settings: {
    timezone: 'UTC',
    language: 'en',
    features: ['messaging', 'analytics']
  }
});
```

#### List All Tenants
```typescript
const tenants = await tenantsService.findAll({
  page: 1,
  limit: 10,
  search: 'acme',
  sortBy: 'createdAt',
  sortOrder: 'DESC'
});
```

#### Deactivate Tenant
```typescript
await tenantsService.deactivate(tenantId, {
  reason: 'Tenant requested account closure',
  notes: 'All data will be retained for 30 days'
});
```

### 2. Tenant-Specific Operations

#### Get Tenant Statistics
```typescript
const stats = await tenantsService.getTenantStats(tenantId);
// Returns: totalUsers, activeUsers, totalSessions, etc.
```

#### Get Tenant Users
```typescript
const users = await tenantsService.getTenantUsers(tenantId);
// Returns: Array of users for the tenant
```

#### Get Tenant Sessions
```typescript
const sessions = await tenantsService.getTenantSessions(tenantId);
// Returns: Array of WAHA sessions for the tenant
```

## Best Practices

### 1. Controller Design
- Use appropriate guards for each endpoint
- Validate tenant context on all operations
- Provide clear error messages
- Use proper HTTP status codes

### 2. Service Implementation
- Always validate tenant context
- Use tenant-aware repositories
- Log security events
- Handle errors gracefully

### 3. Security Considerations
- Never trust client-provided tenant IDs
- Always validate tenant context from JWT
- Log all security events
- Use parameterized queries

### 4. Performance Optimization
- Use database indexes on tenant_id
- Implement pagination for large datasets
- Cache frequently accessed data
- Monitor query performance

## Monitoring and Alerting

### 1. Security Events
- **Critical**: Cross-tenant access attempts
- **High**: Tenant deactivation, role escalation
- **Medium**: Tenant updates, user management
- **Low**: General tenant operations

### 2. Business Metrics
- **Tenant Growth**: New tenant creation rate
- **User Activity**: Active users per tenant
- **Message Volume**: Messages per tenant
- **Session Usage**: Active sessions per tenant

### 3. Performance Metrics
- **Response Times**: API endpoint performance
- **Database Queries**: Query execution time
- **Memory Usage**: Service memory consumption
- **Error Rates**: Failed request percentage

This tenant management system provides enterprise-grade multi-tenancy with comprehensive security, isolation, and administrative features.
