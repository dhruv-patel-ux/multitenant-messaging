# WAHA Integration Documentation

## Overview

This document describes the comprehensive WAHA (WhatsApp HTTP API) integration system for the multi-tenant messaging microservice, including session management, message handling, and webhook processing.

## Architecture

### 1. System Components

```
WAHA Integration System
├── WAHA Client Service
│   ├── HTTP Client with Retry Logic
│   ├── Connection Pool Management
│   └── Error Handling & Timeout
├── WAHA Service
│   ├── Business Logic Layer
│   ├── Session Management
│   └── Message Processing
├── WAHA Controller
│   ├── REST API Endpoints
│   ├── Authentication & Authorization
│   └── Request/Response Handling
├── Webhook Service
│   ├── Event Processing
│   ├── Signature Validation
│   └── Message Storage
└── Configuration Service
    ├── Environment Variables
    ├── Connection Pool Settings
    └── Webhook Configuration
```

### 2. WAHA Client Service

#### Core API Methods
- **Session Management**:
  - `createSession()` - Create new WAHA session
  - `startSession()` - Start existing session
  - `stopSession()` - Stop running session
  - `getSessionStatus()` - Get session status
  - `listSessions()` - List all sessions

- **Message Operations**:
  - `sendTextMessage()` - Send text message
  - `getSessionQR()` - Get QR code for authentication
  - `getSessionScreen()` - Get session screen

- **Health & Monitoring**:
  - `checkHealth()` - Check WAHA service health
  - `getVersion()` - Get WAHA service version

#### Features
- **HTTP Client**: Axios-based with retry logic
- **Connection Pooling**: Configurable pool settings
- **Timeout Handling**: Configurable request timeouts
- **Error Mapping**: WAHA errors to application errors
- **Retry Logic**: Automatic retry on failures

### 3. WAHA Service

#### Business Logic Methods
- **Tenant Session Management**:
  - `createTenantSession()` - Create session for tenant
  - `getTenantSessions()` - Get all tenant sessions
  - `getSessionDetails()` - Get specific session details
  - `stopTenantSession()` - Stop tenant session
  - `deleteTenantSession()` - Delete tenant session

- **Session Operations**:
  - `syncSessionStatus()` - Sync with WAHA service
  - `getSessionQRCode()` - Get QR code for scanning
  - `sendMessage()` - Send message via session
  - `getSessionScreen()` - Get session screen

- **Health Monitoring**:
  - `checkHealth()` - Check WAHA service health
  - `syncAllSessionsStatus()` - Sync all sessions

#### Features
- **Tenant Isolation**: All operations scoped to tenant
- **Status Synchronization**: Keep local status in sync with WAHA
- **Error Handling**: Comprehensive error handling
- **Audit Logging**: Security event logging
- **Business Rules**: Session state validation

### 4. WAHA Controller

#### API Endpoints
- **Session Management**:
  - `POST /waha/sessions` - Create and start session
  - `GET /waha/sessions` - List tenant sessions
  - `GET /waha/sessions/:id` - Get session details
  - `POST /waha/sessions/:id/stop` - Stop session
  - `DELETE /waha/sessions/:id` - Delete session

- **Session Operations**:
  - `GET /waha/sessions/:id/qr` - Get QR code
  - `POST /waha/sessions/:id/sync` - Sync session status
  - `GET /waha/sessions/:id/screen` - Get session screen

- **Messaging**:
  - `POST /waha/sessions/:id/send` - Send message

- **Health & Monitoring**:
  - `GET /waha/health` - Check WAHA service health

#### Security Features
- **Authentication**: JWT token validation
- **Authorization**: Role-based access control
- **Tenant Isolation**: Automatic tenant context
- **Rate Limiting**: Built-in rate limiting
- **Input Validation**: DTO-based validation

## Implementation

### 1. Configuration

#### Environment Variables
```bash
# WAHA Service Configuration
WAHA_BASE_URL=http://localhost:3000
WAHA_API_KEY=your-api-key
WAHA_TIMEOUT=30000
WAHA_RETRY_ATTEMPTS=3

# Connection Pool Configuration
WAHA_POOL_MAX=20
WAHA_POOL_MIN=5
WAHA_POOL_ACQUIRE_TIMEOUT=30000
WAHA_POOL_IDLE_TIMEOUT=30000

# Webhook Configuration
WAHA_WEBHOOK_SECRET=your-webhook-secret
WAHA_WEBHOOK_TIMEOUT=10000
WAHA_WEBHOOK_RETRY_ATTEMPTS=3
```

#### Configuration Service
- **WahaConfigService**: Centralized configuration management
- **Validation**: Configuration validation on startup
- **Environment**: Environment-specific settings
- **Security**: Secure API key management

### 2. Session Management

#### Session Lifecycle
1. **Creation**: Create session with WAHA service
2. **Starting**: Start session and get QR code
3. **QR Scanning**: User scans QR code with WhatsApp
4. **Working**: Session is active and ready
5. **Stopping**: Stop session gracefully
6. **Deletion**: Remove session permanently

#### Session States
- **STARTING**: Session is being created
- **SCAN_QR**: Waiting for QR code scan
- **WORKING**: Session is active and connected
- **FAILED**: Session failed to start
- **STOPPED**: Session is stopped

#### Session Features
- **Unique Naming**: Session names unique per tenant
- **Status Sync**: Automatic status synchronization
- **QR Caching**: QR code caching and expiration
- **Health Monitoring**: Session health monitoring
- **Recovery**: Automatic recovery after WAHA restart

### 3. Message Handling

#### Message Flow
1. **Send Request**: User sends message via API
2. **Session Validation**: Validate session is working
3. **WAHA API Call**: Send message via WAHA service
4. **Response Handling**: Handle WAHA response
5. **Audit Logging**: Log message sent event

#### Message Types
- **Text Messages**: Plain text messages
- **Media Messages**: Images, documents, audio, video
- **Status Messages**: Message status updates
- **Webhook Events**: Incoming message events

#### Message Features
- **Tenant Isolation**: Messages scoped to tenant
- **Status Tracking**: Message delivery status
- **Error Handling**: Comprehensive error handling
- **Rate Limiting**: WhatsApp rate limiting compliance
- **Audit Trail**: Complete message audit trail

### 4. Webhook Processing

#### Webhook Events
- **Message Events**: Incoming messages
- **Session Status**: Session status changes
- **Connection Events**: Connection state changes
- **Error Events**: Error notifications

#### Webhook Features
- **Signature Validation**: Webhook signature verification
- **Event Processing**: Asynchronous event processing
- **Batch Processing**: Multiple events in single request
- **Error Handling**: Robust error handling
- **Retry Logic**: Automatic retry on failures

## API Endpoints

### 1. Session Management

#### Create Session
```http
POST /waha/sessions
Content-Type: application/json
Authorization: Bearer <jwt_token>

{
  "sessionName": "main-session",
  "engine": "WEBJS",
  "webhookUrl": "https://api.example.com/webhooks/waha",
  "webhookEvents": ["message", "session.status"],
  "config": {
    "proxy": "http://proxy:8080"
  }
}
```

#### List Sessions
```http
GET /waha/sessions
Authorization: Bearer <jwt_token>
```

#### Get Session Details
```http
GET /waha/sessions/{sessionId}
Authorization: Bearer <jwt_token>
```

#### Stop Session
```http
POST /waha/sessions/{sessionId}/stop
Authorization: Bearer <jwt_token>
```

#### Delete Session
```http
DELETE /waha/sessions/{sessionId}
Authorization: Bearer <jwt_token>
```

### 2. Session Operations

#### Get QR Code
```http
GET /waha/sessions/{sessionId}/qr
Authorization: Bearer <jwt_token>
```

#### Sync Session Status
```http
POST /waha/sessions/{sessionId}/sync
Authorization: Bearer <jwt_token>
```

#### Get Session Screen
```http
GET /waha/sessions/{sessionId}/screen
Authorization: Bearer <jwt_token>
```

### 3. Messaging

#### Send Message
```http
POST /waha/sessions/{sessionId}/send
Content-Type: application/json
Authorization: Bearer <jwt_token>

{
  "to": "+1234567890",
  "text": "Hello, this is a test message",
  "metadata": {
    "priority": "high"
  }
}
```

### 4. Health & Monitoring

#### Check WAHA Health
```http
GET /waha/health
Authorization: Bearer <jwt_token>
```

## DTOs and Validation

### 1. Request DTOs

#### CreateSessionDto
```typescript
{
  sessionName: string;           // Session name (unique per tenant)
  engine: WahaEngine;           // WAHA engine type
  webhookUrl?: string;          // Webhook URL
  webhookEvents?: string[];     // Webhook events
  config?: Record<string, any>; // Additional configuration
}
```

#### SendMessageDto
```typescript
{
  to: string;                   // Recipient phone number
  text: string;                 // Message text
  metadata?: Record<string, any>; // Message metadata
}
```

### 2. Response DTOs

#### SessionResponseDto
```typescript
{
  id: string;                   // Session ID
  externalSessionId: string;    // WAHA session ID
  status: WahaSessionStatus;    // Session status
  engine: WahaEngine;           // Session engine
  metadata?: Record<string, any>; // Session metadata
  tenantId: string;             // Tenant ID
  createdAt: Date;              // Creation date
  updatedAt: Date;              // Last update date
}
```

#### MessageResponse
```typescript
{
  messageId: string;            // Message ID from WAHA
  status: string;               // Message status
  to: string;                   // Recipient
  text: string;                 // Message text
  timestamp: Date;              // Message timestamp
}
```

## Security Features

### 1. Authentication & Authorization
- **JWT Authentication**: Token-based authentication
- **Role-Based Access**: Permission-based access control
- **Tenant Isolation**: Automatic tenant context
- **Session Security**: Secure session management

### 2. API Security
- **Rate Limiting**: Built-in rate limiting
- **Input Validation**: DTO-based validation
- **Error Handling**: Secure error responses
- **Audit Logging**: Security event logging

### 3. Webhook Security
- **Signature Validation**: Webhook signature verification
- **Secret Management**: Secure webhook secrets
- **Event Validation**: Webhook event validation
- **Retry Logic**: Secure retry mechanisms

## Error Handling

### 1. Error Types
- **WAHA Service Unavailable**: Service not responding
- **Invalid Session State**: Session not in correct state
- **Network Timeout**: Request timeout
- **Authentication Failure**: Session authentication failed
- **Rate Limiting**: Too many requests

### 2. Error Responses
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Session not found
- **409 Conflict**: Session already exists
- **503 Service Unavailable**: WAHA service unavailable

### 3. Error Handling Features
- **Retry Logic**: Automatic retry on failures
- **Timeout Handling**: Request timeout management
- **Error Mapping**: WAHA errors to application errors
- **Logging**: Comprehensive error logging

## Monitoring and Alerting

### 1. Health Monitoring
- **WAHA Service Health**: Service availability
- **Session Health**: Session status monitoring
- **Connection Pool**: Pool usage monitoring
- **Error Rates**: Error rate tracking

### 2. Performance Metrics
- **Response Times**: API response times
- **Throughput**: Messages per second
- **Session Count**: Active sessions
- **Error Rates**: Failed request percentage

### 3. Business Metrics
- **Message Volume**: Messages sent/received
- **Session Usage**: Session utilization
- **Tenant Activity**: Per-tenant metrics
- **Webhook Events**: Event processing rates

## Best Practices

### 1. Session Management
- Use unique session names per tenant
- Monitor session health regularly
- Implement session recovery logic
- Handle session failures gracefully

### 2. Message Handling
- Validate session state before sending
- Implement rate limiting compliance
- Handle message failures gracefully
- Log all message operations

### 3. Webhook Processing
- Validate webhook signatures
- Process events asynchronously
- Implement retry logic
- Handle batch events efficiently

### 4. Error Handling
- Implement comprehensive error handling
- Use appropriate HTTP status codes
- Provide meaningful error messages
- Log all errors for debugging
- Implement monitoring and alerting

This WAHA integration system provides enterprise-grade WhatsApp messaging capabilities with comprehensive session management, message handling, and webhook processing.
