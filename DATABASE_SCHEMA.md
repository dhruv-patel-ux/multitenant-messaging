# Database Schema Documentation

## Overview

This document describes the complete database schema for the multi-tenant messaging microservice. The schema is designed to support multiple tenants with isolated data, WhatsApp integration via WAHA, and comprehensive message tracking.

## Database Entities

### 1. Base Entity (`BaseEntity`)

All entities extend this base class providing common fields:

```typescript
- id: UUID (Primary Key)
- createdAt: Timestamp
- updatedAt: Timestamp  
- deletedAt: Timestamp (Soft Delete)
```

### 2. Tenant Entity (`tenants`)

**Purpose**: Represents organizations using the messaging service.

**Fields**:
- `id`: UUID (Primary Key)
- `name`: VARCHAR(100) - Unique tenant name
- `status`: ENUM('active', 'inactive') - Tenant status
- `description`: TEXT - Optional description
- `settings`: JSONB - Tenant-specific configuration
- `createdAt`, `updatedAt`, `deletedAt`: Timestamps

**Relationships**:
- One-to-Many with `users`
- One-to-Many with `waha_sessions`
- One-to-Many with `messages`

**Indexes**:
- Unique index on `name`

### 3. User Entity (`users`)

**Purpose**: Represents users within each tenant.

**Fields**:
- `id`: UUID (Primary Key)
- `email`: VARCHAR(255) - User email
- `passwordHash`: VARCHAR(255) - Hashed password
- `firstName`: VARCHAR(50) - User first name
- `lastName`: VARCHAR(50) - User last name
- `role`: ENUM('TENANT_ADMIN', 'MANAGER', 'AGENT', 'AUDITOR') - User role
- `isActive`: BOOLEAN - Account status
- `lastLoginAt`: TIMESTAMP - Last login time
- `preferences`: JSONB - User preferences
- `tenantId`: UUID (Foreign Key to tenants)
- `createdAt`, `updatedAt`, `deletedAt`: Timestamps

**Relationships**:
- Many-to-One with `tenant`

**Indexes**:
- Unique composite index on `email` + `tenantId`
- Index on `tenantId`

### 4. WahaSession Entity (`waha_sessions`)

**Purpose**: Represents WhatsApp sessions managed by WAHA.

**Fields**:
- `id`: UUID (Primary Key)
- `externalSessionId`: VARCHAR(255) - WAHA session identifier
- `status`: ENUM('starting', 'scan_qr', 'working', 'failed', 'stopped') - Session status
- `engine`: ENUM('WEBJS', 'NOWEB') - WAHA engine type
- `metadata`: JSONB - QR code, profile info, etc.
- `config`: JSONB - Session configuration
- `lastActivityAt`: TIMESTAMP - Last activity
- `errorMessage`: TEXT - Error details if failed
- `tenantId`: UUID (Foreign Key to tenants)
- `createdAt`, `updatedAt`, `deletedAt`: Timestamps

**Relationships**:
- Many-to-One with `tenant`
- One-to-Many with `messages`

**Indexes**:
- Unique index on `externalSessionId`
- Index on `tenantId`
- Index on `status`

### 5. Message Entity (`messages`)

**Purpose**: Represents all messages sent/received through the system.

**Fields**:
- `id`: UUID (Primary Key)
- `direction`: ENUM('inbound', 'outbound') - Message direction
- `toMsisdn`: VARCHAR(20) - Recipient phone number
- `fromMsisdn`: VARCHAR(20) - Sender phone number
- `body`: TEXT - Message content
- `status`: ENUM('queued', 'sent', 'delivered', 'failed') - Delivery status
- `wahaMessageId`: VARCHAR(255) - WAHA message identifier
- `rawPayload`: JSONB - Raw WAHA response
- `messageType`: VARCHAR(50) - Message type (text, image, etc.)
- `mediaUrl`: VARCHAR(500) - Media file URL
- `metadata`: JSONB - Additional message data
- `errorMessage`: TEXT - Error details if failed
- `deliveredAt`: TIMESTAMP - Delivery confirmation time
- `tenantId`: UUID (Foreign Key to tenants)
- `sessionId`: UUID (Foreign Key to waha_sessions)
- `createdAt`, `updatedAt`, `deletedAt`: Timestamps

**Relationships**:
- Many-to-One with `tenant`
- Many-to-One with `session`

**Indexes**:
- Index on `tenantId`
- Index on `sessionId`
- Index on `toMsisdn`
- Index on `fromMsisdn`
- Index on `status`
- Index on `createdAt`
- Unique index on `wahaMessageId` (where not null)

## Database Configuration

### Connection Pooling
- **Max Connections**: 20
- **Min Connections**: 5
- **Acquire Timeout**: 30 seconds
- **Idle Timeout**: 30 seconds
- **Connection Timeout**: 2 seconds

### Performance Optimizations
- Comprehensive indexing strategy
- Soft delete support
- JSONB fields for flexible data storage
- Foreign key constraints with CASCADE delete

## Migration Strategy

### Initial Migration (`1700000000000-InitialSchema.ts`)
- Creates all tables with proper constraints
- Establishes foreign key relationships
- Creates performance indexes
- Supports rollback operations

## Data Validation

### Entity Validation
All entities include comprehensive validation using `class-validator`:

- **Required Fields**: Properly marked with `@IsNotEmpty()`
- **String Lengths**: Enforced with `@Length()` decorators
- **Enums**: Validated with `@IsEnum()` decorators
- **Email Format**: Validated with `@IsEmail()` decorators
- **UUID Format**: Validated with `@IsUUID()` decorators

### DTOs Created
- `CreateTenantDto` / `UpdateTenantDto`
- `CreateUserDto` / `UpdateUserDto`
- `CreateWahaSessionDto` / `UpdateWahaSessionDto`
- `CreateMessageDto` / `UpdateMessageDto`

## Security Considerations

### Multi-Tenant Isolation
- All entities include `tenantId` for data isolation
- Foreign key constraints ensure referential integrity
- Soft delete prevents accidental data loss

### Data Protection
- Passwords are hashed (not stored in plain text)
- Sensitive data in JSONB fields can be encrypted
- Audit trail through timestamps

## Scalability Features

### Indexing Strategy
- Composite indexes for common query patterns
- Partial indexes for conditional uniqueness
- Timestamp indexes for time-based queries

### JSONB Usage
- Flexible schema for tenant settings
- Efficient storage and querying of metadata
- Support for complex data structures

## Next Steps

The database schema is complete and ready for:
1. **Authentication System** - User login/logout
2. **Authorization** - Role-based access control
3. **WAHA Integration** - Session management
4. **Message Handling** - Send/receive operations
5. **Webhook Processing** - Real-time updates

This schema provides a solid foundation for a scalable, multi-tenant messaging platform with comprehensive data integrity and performance optimization.
