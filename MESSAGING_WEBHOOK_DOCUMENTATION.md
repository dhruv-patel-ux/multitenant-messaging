# Messaging System & Webhook Handler Documentation

## Overview

This document describes the comprehensive messaging system with WAHA integration and secure webhook handling for the multi-tenant messaging microservice.

## Architecture

### 1. Messaging System Components

```
Messaging System
├── Message Service
│   ├── Core Messaging Methods
│   ├── Bulk Messaging
│   ├── Message Processing
│   └── Queue Management
├── Message Controller
│   ├── REST API Endpoints
│   ├── Authentication & Authorization
│   └── Request/Response Handling
├── Message Processing
│   ├── Message Queuing
│   ├── Retry Logic
│   ├── Status Tracking
│   └── Rate Limiting
└── Filtering & Search
    ├── Date Range Filtering
    ├── Status Filtering
    ├── Content Search
    └── Pagination
```

### 2. Webhook Handler System

```
Webhook Handler System
├── Webhook Service
│   ├── Event Processing
│   ├── Signature Validation
│   ├── Idempotency
│   └── Error Handling
├── Webhook Controller
│   ├── Public Endpoints
│   ├── Security Headers
│   └── Health Checks
├── Event Processing
│   ├── Message Events
│   ├── Status Updates
│   ├── Session Events
│   └── Error Events
└── Security Features
    ├── Signature Validation
    ├── IP Whitelisting
    ├── Rate Limiting
    └── Request Validation
```

## Implementation

### 1. Messaging System

#### Message Service
- **Core Methods**:
  - `sendMessage()` - Send single message
  - `sendBulkMessages()` - Send bulk messages
  - `getMessages()` - List messages with filters
  - `getMessageById()` - Get specific message
  - `processInboundMessage()` - Process incoming messages
  - `updateMessageStatus()` - Update message status
  - `getMessageStats()` - Get messaging statistics

- **Queue Management**:
  - `queueMessage()` - Queue message for processing
  - `processMessageQueue()` - Process queued messages
  - `retryFailedMessage()` - Retry failed messages

#### Message Controller
- **API Endpoints**:
  - `POST /messages/send` - Send single message
  - `POST /messages/bulk` - Send bulk messages
  - `GET /messages` - List messages with filters
  - `GET /messages/:id` - Get specific message
  - `GET /messages/stats` - Get messaging statistics
  - `POST /messages/:id/retry` - Retry failed message

#### Message Processing Features
- **Message Queuing**: Bull/Redis integration for message queuing
- **Retry Logic**: Exponential backoff for failed messages
- **Message Deduplication**: Prevent duplicate message processing
- **Status Tracking**: Complete message lifecycle tracking
- **Bulk Messaging**: Batch processing for multiple recipients
- **Rate Limiting**: Per-tenant and per-session rate limiting

### 2. Webhook Handler System

#### Webhook Service
- **Event Processing**:
  - `processWahaWebhook()` - Main webhook processor
  - `processInboundMessage()` - Process incoming messages
  - `processStatusUpdate()` - Process status updates
  - `processSessionUpdate()` - Process session updates
  - `handleWebhookError()` - Handle processing errors

- **Security Features**:
  - `validateWebhookSignature()` - HMAC-SHA256 validation
  - `isDuplicateWebhook()` - Idempotency checking
  - `markWebhookProcessed()` - Processing tracking

#### Webhook Controller
- **Endpoints**:
  - `POST /webhooks/waha` - Main WAHA webhook endpoint
  - `GET /webhooks/health` - Webhook service health check

#### Webhook Types
- **Message Events**:
  - `message.any` - Any message received
  - `message.text` - Text message
  - `message.image` - Image message
  - `message.document` - Document message

- **Status Events**:
  - `message.status` - Message delivery status
  - `session.status` - Session state changes
  - `session.qr` - QR code updates

- **Error Events**:
  - `session.failed` - Session failures
  - `api.error` - API errors

## API Endpoints

### 1. Messaging Endpoints

#### Send Single Message
```http
POST /messages/send
Content-Type: application/json
Authorization: Bearer <jwt_token>

{
  "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "to": "+1234567890",
  "body": "Hello, this is a test message",
  "priority": "normal",
  "metadata": {
    "campaignId": "campaign-123"
  }
}
```

#### Send Bulk Messages
```http
POST /messages/bulk
Content-Type: application/json
Authorization: Bearer <jwt_token>

{
  "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "recipients": ["+1234567890", "+0987654321"],
  "body": "Hello, this is a bulk message",
  "batchSize": 10,
  "priority": "normal"
}
```

#### List Messages
```http
GET /messages?sessionId=abc&direction=outbound&status=sent&page=1&limit=20
Authorization: Bearer <jwt_token>
```

#### Get Message Statistics
```http
GET /messages/stats?fromDate=2024-01-01T00:00:00Z&toDate=2024-01-31T23:59:59Z
Authorization: Bearer <jwt_token>
```

### 2. Webhook Endpoints

#### WAHA Webhook
```http
POST /webhooks/waha
Content-Type: application/json
X-Waha-Signature: sha256=abc123...

{
  "event": "message.text",
  "session": "main-session",
  "payload": {
    "id": "waha_msg_123456",
    "from": "+1234567890",
    "to": "+0987654321",
    "body": "Hello, this is a test message",
    "timestamp": 1642248600000,
    "type": "text"
  }
}
```

#### Webhook Health Check
```http
GET /webhooks/health
```

## DTOs and Validation

### 1. Request DTOs

#### SendMessageDto
```typescript
{
  sessionId: string;           // WAHA session ID
  to: string;                 // Recipient phone number
  body: string;               // Message content
  priority?: 'high' | 'normal' | 'low';
  metadata?: Record<string, any>;
}
```

#### BulkMessageDto
```typescript
{
  sessionId: string;          // WAHA session ID
  recipients: string[];       // List of recipients
  body: string;               // Message content
  batchSize?: number;         // Batch processing size
  priority?: 'high' | 'normal' | 'low';
  metadata?: Record<string, any>;
}
```

#### MessageFiltersDto
```typescript
{
  sessionId?: string;         // Filter by session
  direction?: 'inbound' | 'outbound';
  status?: MessageStatus;     // Filter by status
  fromDate?: string;          // Date range start
  toDate?: string;            // Date range end
  search?: string;            // Content search
  page?: number;              // Pagination
  limit?: number;             // Page size
}
```

### 2. Response DTOs

#### MessageResponseDto
```typescript
{
  id: string;                 // Message ID
  sessionId: string;          // Session ID
  direction: MessageDirection;
  toMsisdn: string;           // Recipient
  fromMsisdn: string;          // Sender
  body: string;                // Message content
  status: MessageStatus;      // Current status
  wahaMessageId?: string;     // WAHA message ID
  priority?: string;          // Message priority
  metadata?: Record<string, any>;
  createdAt: Date;             // Creation date
  updatedAt: Date;            // Last update
}
```

#### MessageStatsDto
```typescript
{
  totalMessages: number;       // Total messages
  outboundMessages: number;    // Sent messages
  inboundMessages: number;     // Received messages
  messagesByStatus: Record<MessageStatus, number>;
  messagesByDay: Array<{ date: string; count: number }>;
  averagePerDay: number;       // Average per day
  successRate: number;         // Success percentage
  dateRange: { fromDate: string; toDate: string };
}
```

## Business Rules

### 1. Message Processing
- **Phone Number Validation**: International format required
- **Message Length Limits**: 4096 characters maximum
- **Rate Limiting**: 20 messages per minute per session
- **Priority Queuing**: High priority messages processed first
- **Tenant Isolation**: All operations scoped to tenant

### 2. Webhook Processing
- **Signature Validation**: HMAC-SHA256 verification required
- **Idempotency**: Duplicate webhook prevention
- **Event Processing**: Asynchronous event handling
- **Error Handling**: Graceful error recovery
- **Audit Logging**: Complete webhook audit trail

### 3. Security Rules
- **Authentication**: JWT token validation
- **Authorization**: Role-based access control
- **Webhook Security**: Signature validation and IP whitelisting
- **Data Sanitization**: Message content sanitization
- **PII Protection**: Personal information detection and masking

## Error Handling

### 1. Message Errors
- **400 Bad Request**: Invalid message data
- **404 Not Found**: Session or message not found
- **409 Conflict**: Duplicate message
- **429 Too Many Requests**: Rate limit exceeded
- **503 Service Unavailable**: WAHA service unavailable

### 2. Webhook Errors
- **401 Unauthorized**: Invalid webhook signature
- **400 Bad Request**: Malformed webhook payload
- **429 Too Many Requests**: Webhook rate limit exceeded
- **500 Internal Server Error**: Webhook processing error

### 3. Error Recovery
- **Retry Logic**: Exponential backoff for failed messages
- **Dead Letter Queue**: Permanently failed message handling
- **Circuit Breaker**: Service unavailability protection
- **Monitoring**: Real-time error tracking and alerting

## Monitoring and Alerting

### 1. Message Metrics
- **Volume Metrics**: Messages sent/received per day
- **Success Rates**: Delivery success percentages
- **Performance Metrics**: Processing times and throughput
- **Error Rates**: Failed message percentages

### 2. Webhook Metrics
- **Processing Times**: Webhook processing duration
- **Success Rates**: Successful webhook processing
- **Error Rates**: Failed webhook processing
- **Payload Sizes**: Webhook payload size tracking

### 3. Business Metrics
- **Tenant Activity**: Per-tenant message volumes
- **Session Usage**: Session utilization rates
- **Message Types**: Distribution of message types
- **Geographic Distribution**: Message geographic spread

## Security Features

### 1. Authentication & Authorization
- **JWT Authentication**: Token-based authentication
- **Role-Based Access**: Permission-based access control
- **Tenant Isolation**: Automatic tenant context
- **Session Security**: Secure session management

### 2. Webhook Security
- **Signature Validation**: HMAC-SHA256 verification
- **IP Whitelisting**: WAHA container IP restrictions
- **Rate Limiting**: Webhook endpoint rate limiting
- **Request Validation**: Payload size and format validation

### 3. Data Protection
- **Message Encryption**: Sensitive data encryption
- **PII Detection**: Personal information identification
- **Audit Logging**: Complete operation audit trail
- **Data Retention**: Configurable data retention policies

## Best Practices

### 1. Message Processing
- Use appropriate message priorities
- Implement proper error handling
- Monitor message delivery status
- Respect rate limits and quotas

### 2. Webhook Handling
- Validate webhook signatures
- Implement idempotency checks
- Process events asynchronously
- Handle errors gracefully

### 3. Performance Optimization
- Use message queuing for bulk operations
- Implement caching for frequently accessed data
- Monitor and optimize database queries
- Use connection pooling for external services

### 4. Security Considerations
- Never trust webhook payloads without validation
- Implement proper authentication and authorization
- Use secure communication protocols
- Monitor for suspicious activity

This messaging system and webhook handler provide enterprise-grade messaging capabilities with comprehensive security, monitoring, and error handling features.
