# Multi-Tenant Messaging API - Messaging & Webhook Systems

## Overview

This document provides comprehensive information about the messaging system and webhook handler implementation for the multi-tenant messaging microservice.

## Table of Contents

1. [Messaging System](#messaging-system)
2. [Webhook Handler System](#webhook-handler-system)
3. [API Endpoints](#api-endpoints)
4. [Security Features](#security-features)
5. [Business Rules](#business-rules)
6. [Error Handling](#error-handling)
7. [Monitoring & Alerting](#monitoring--alerting)
8. [Testing](#testing)
9. [Deployment](#deployment)

## Messaging System

### Core Components

#### 1. Message Service (`MessagesService`)
- **Single Message Sending**: Send individual messages via WAHA sessions
- **Bulk Message Processing**: Send multiple messages to multiple recipients
- **Message Retrieval**: Get messages with advanced filtering and pagination
- **Status Management**: Track and update message delivery status
- **Statistics**: Generate comprehensive messaging analytics

#### 2. Message Controller (`MessagesController`)
- **REST API Endpoints**: Complete CRUD operations for messages
- **Authentication**: JWT-based authentication with role-based access
- **Authorization**: Role-based permissions for different operations
- **Validation**: Comprehensive input validation and sanitization

#### 3. Message Processing Features
- **Message Queuing**: Asynchronous message processing with Bull/Redis
- **Retry Logic**: Exponential backoff for failed messages
- **Deduplication**: Prevent duplicate message processing
- **Status Tracking**: Complete message lifecycle management
- **Rate Limiting**: Per-tenant and per-session rate limiting

### Key Features

#### Message Types
- **Text Messages**: Standard text content
- **Media Messages**: Images, documents, and other media
- **Bulk Messages**: Batch processing for multiple recipients
- **Priority Messages**: High-priority message queuing

#### Message Status Lifecycle
```
QUEUED → SENT → DELIVERED
   ↓       ↓
FAILED ← RETRY
```

#### Filtering & Search
- **Date Range**: Filter messages by creation date
- **Status Filtering**: Filter by message status
- **Direction Filtering**: Inbound vs outbound messages
- **Content Search**: Search message content and phone numbers
- **Session Filtering**: Filter by WAHA session

## Webhook Handler System

### Core Components

#### 1. Webhook Service (`WebhooksService`)
- **Event Processing**: Handle various WAHA webhook events
- **Signature Validation**: HMAC-SHA256 signature verification
- **Idempotency**: Prevent duplicate webhook processing
- **Error Handling**: Graceful error recovery and logging

#### 2. Webhook Controller (`WebhooksController`)
- **Public Endpoints**: WAHA webhook endpoint (no authentication required)
- **Health Checks**: Service health monitoring
- **Security Headers**: Proper security header handling

#### 3. Event Processing
- **Message Events**: Process incoming messages and status updates
- **Session Events**: Handle session state changes
- **Error Events**: Process API errors and session failures

### Webhook Event Types

#### Message Events
- `message.any` - Any message received
- `message.text` - Text message
- `message.image` - Image message
- `message.document` - Document message

#### Status Events
- `message.status` - Message delivery status
- `session.status` - Session state changes
- `session.qr` - QR code updates

#### Error Events
- `session.failed` - Session failures
- `api.error` - API errors

## API Endpoints

### Messaging Endpoints

#### Send Single Message
```http
POST /messages/send
Authorization: Bearer <jwt_token>
Content-Type: application/json

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
Authorization: Bearer <jwt_token>
Content-Type: application/json

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

### Webhook Endpoints

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

## Security Features

### Authentication & Authorization
- **JWT Authentication**: Token-based authentication for all endpoints
- **Role-Based Access**: Permission-based access control
- **Tenant Isolation**: Automatic tenant context enforcement
- **Session Security**: Secure session management

### Webhook Security
- **Signature Validation**: HMAC-SHA256 verification for all webhooks
- **IP Whitelisting**: Restrict webhook access to WAHA container IPs
- **Rate Limiting**: Prevent webhook endpoint abuse
- **Request Validation**: Validate webhook payload size and format

### Data Protection
- **Message Encryption**: Encrypt sensitive message content
- **PII Detection**: Identify and protect personal information
- **Audit Logging**: Complete operation audit trail
- **Data Retention**: Configurable data retention policies

## Business Rules

### Message Processing
- **Phone Number Validation**: International format required (+country code)
- **Message Length Limits**: 4096 characters maximum per message
- **Rate Limiting**: 20 messages per minute per session
- **Priority Queuing**: High-priority messages processed first
- **Tenant Isolation**: All operations scoped to tenant context

### Webhook Processing
- **Signature Validation**: All webhooks must have valid signatures
- **Idempotency**: Duplicate webhook prevention
- **Event Processing**: Asynchronous event handling
- **Error Handling**: Graceful error recovery
- **Audit Logging**: Complete webhook audit trail

### Security Rules
- **Authentication**: All endpoints require valid JWT tokens
- **Authorization**: Role-based permissions enforced
- **Webhook Security**: Signature validation and IP restrictions
- **Data Sanitization**: Message content sanitization
- **PII Protection**: Personal information detection and masking

## Error Handling

### Message Errors
- **400 Bad Request**: Invalid message data or session not in working state
- **404 Not Found**: Session or message not found
- **409 Conflict**: Duplicate message or session conflict
- **429 Too Many Requests**: Rate limit exceeded
- **503 Service Unavailable**: WAHA service unavailable

### Webhook Errors
- **401 Unauthorized**: Invalid webhook signature
- **400 Bad Request**: Malformed webhook payload
- **429 Too Many Requests**: Webhook rate limit exceeded
- **500 Internal Server Error**: Webhook processing error

### Error Recovery
- **Retry Logic**: Exponential backoff for failed messages
- **Dead Letter Queue**: Permanently failed message handling
- **Circuit Breaker**: Service unavailability protection
- **Monitoring**: Real-time error tracking and alerting

## Monitoring & Alerting

### Message Metrics
- **Volume Metrics**: Messages sent/received per day
- **Success Rates**: Delivery success percentages
- **Performance Metrics**: Processing times and throughput
- **Error Rates**: Failed message percentages

### Webhook Metrics
- **Processing Times**: Webhook processing duration
- **Success Rates**: Successful webhook processing
- **Error Rates**: Failed webhook processing
- **Payload Sizes**: Webhook payload size tracking

### Business Metrics
- **Tenant Activity**: Per-tenant message volumes
- **Session Usage**: Session utilization rates
- **Message Types**: Distribution of message types
- **Geographic Distribution**: Message geographic spread

## Testing

### Unit Tests
- **Service Tests**: Test all service methods
- **Controller Tests**: Test API endpoints
- **Webhook Tests**: Test webhook processing
- **Error Handling**: Test error scenarios

### Integration Tests
- **End-to-End**: Complete message flow testing
- **Webhook Integration**: Test webhook event processing
- **Database Integration**: Test database operations
- **External Service Integration**: Test WAHA integration

### Test Coverage
- **Code Coverage**: Minimum 80% coverage
- **Branch Coverage**: Test all code paths
- **Error Scenarios**: Test all error conditions
- **Edge Cases**: Test boundary conditions

## Deployment

### Environment Variables
```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=password
DB_DATABASE=messaging_api

# JWT
JWT_SECRET=your-jwt-secret
JWT_EXPIRES_IN=24h
JWT_REFRESH_SECRET=your-refresh-secret
JWT_REFRESH_EXPIRES_IN=7d

# WAHA
WAHA_BASE_URL=http://localhost:3000
WAHA_API_KEY=your-waha-api-key
WAHA_WEBHOOK_SECRET=your-webhook-secret

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# Webhook
WEBHOOK_SECRET=your-webhook-secret
```

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "run", "start:prod"]
```

### Health Checks
- **Application Health**: `/health` endpoint
- **Database Health**: Database connection checks
- **WAHA Health**: WAHA service connectivity
- **Redis Health**: Redis connection checks

### Monitoring Setup
- **Application Metrics**: Prometheus metrics
- **Log Aggregation**: ELK stack or similar
- **Alerting**: PagerDuty or similar
- **Dashboard**: Grafana dashboards

## Best Practices

### Message Processing
1. **Use Appropriate Priorities**: Set message priorities based on urgency
2. **Implement Proper Error Handling**: Handle all error scenarios gracefully
3. **Monitor Message Delivery**: Track message delivery status
4. **Respect Rate Limits**: Implement proper rate limiting

### Webhook Handling
1. **Validate Signatures**: Always validate webhook signatures
2. **Implement Idempotency**: Prevent duplicate webhook processing
3. **Process Asynchronously**: Use queues for webhook processing
4. **Handle Errors Gracefully**: Implement proper error recovery

### Performance Optimization
1. **Use Message Queuing**: Implement proper queuing for bulk operations
2. **Implement Caching**: Cache frequently accessed data
3. **Monitor Database Queries**: Optimize database operations
4. **Use Connection Pooling**: Implement proper connection pooling

### Security Considerations
1. **Never Trust Webhook Payloads**: Always validate webhook data
2. **Implement Proper Authentication**: Use strong authentication mechanisms
3. **Use Secure Communication**: Implement HTTPS and secure protocols
4. **Monitor for Suspicious Activity**: Implement security monitoring

## Troubleshooting

### Common Issues

#### Message Sending Failures
- **Session Not Working**: Ensure WAHA session is in working state
- **Rate Limiting**: Check if rate limits are exceeded
- **Invalid Phone Numbers**: Validate phone number format
- **WAHA Service Unavailable**: Check WAHA service connectivity

#### Webhook Processing Issues
- **Invalid Signatures**: Verify webhook secret configuration
- **Duplicate Processing**: Check idempotency implementation
- **Processing Errors**: Review error logs and handling
- **Database Issues**: Check database connectivity and queries

#### Performance Issues
- **Slow Message Processing**: Check queue processing and database performance
- **High Memory Usage**: Monitor memory usage and optimize queries
- **Database Locks**: Check for database locking issues
- **External Service Timeouts**: Monitor WAHA service response times

### Debugging Steps

1. **Check Logs**: Review application and error logs
2. **Verify Configuration**: Ensure all environment variables are set
3. **Test Connectivity**: Verify database and external service connectivity
4. **Monitor Metrics**: Check application and system metrics
5. **Review Code**: Review code for potential issues

### Support

For technical support and questions:
- **Documentation**: Refer to this documentation
- **Logs**: Check application logs for error details
- **Monitoring**: Use monitoring tools to identify issues
- **Community**: Check community forums and resources

This comprehensive messaging system and webhook handler provide enterprise-grade messaging capabilities with robust security, monitoring, and error handling features.
