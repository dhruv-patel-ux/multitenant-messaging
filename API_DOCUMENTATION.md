# Multi-Tenant Messaging API Documentation

## Overview

The Multi-Tenant Messaging API is a comprehensive messaging microservice built with NestJS that provides WhatsApp messaging capabilities through WAHA (WhatsApp HTTP API) integration. This API supports multi-tenant architecture with role-based access control, real-time messaging, and secure webhook handling.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
4. [Rate Limiting](#rate-limiting)
5. [Error Handling](#error-handling)
6. [Webhooks](#webhooks)
7. [Examples](#examples)
8. [SDKs and Tools](#sdks-and-tools)

## Getting Started

### Base URL

- **Development**: `http://localhost:3000`
- **Staging**: `https://staging-api.messaging-api.com`
- **Production**: `https://api.messaging-api.com`

### API Version

Current API version: `v1`

All endpoints are prefixed with `/api/v1/`

### Content Type

All requests must include the `Content-Type: application/json` header.

## Authentication

The API uses JWT (JSON Web Token) authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

### Authentication Flow

1. **Login** - Get access and refresh tokens
2. **Use Access Token** - Include in Authorization header
3. **Refresh Token** - Get new access token when expired
4. **Logout** - Invalidate tokens

### Example Authentication

```bash
# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@company.com",
    "password": "SecurePass123!"
  }'

# Response
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600,
    "user": {
      "id": "user-123",
      "email": "admin@company.com",
      "role": "TENANT_ADMIN",
      "tenantId": "tenant-123"
    }
  }
}
```

## API Endpoints

### Authentication Endpoints

#### POST /auth/login
Login with email and password.

**Request Body:**
```json
{
  "email": "admin@company.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "jwt-token",
    "refreshToken": "refresh-token",
    "expiresIn": 3600,
    "user": {
      "id": "user-123",
      "email": "admin@company.com",
      "role": "TENANT_ADMIN",
      "tenantId": "tenant-123"
    }
  }
}
```

#### POST /auth/refresh
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refreshToken": "your-refresh-token"
}
```

#### GET /auth/profile
Get current user profile.

**Headers:**
```
Authorization: Bearer <jwt-token>
```

#### POST /auth/logout
Logout and invalidate tokens.

**Headers:**
```
Authorization: Bearer <jwt-token>
```

### Message Endpoints

#### POST /messages/send
Send a single message via WAHA session.

**Headers:**
```
Authorization: Bearer <jwt-token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "to": "+1234567890",
  "body": "Hello from the messaging API!",
  "priority": "normal",
  "metadata": {
    "campaignId": "campaign-123",
    "tags": ["marketing"]
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "msg-123456",
    "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "direction": "outbound",
    "toMsisdn": "+1234567890",
    "fromMsisdn": "+0987654321",
    "body": "Hello from the messaging API!",
    "status": "sent",
    "wahaMessageId": "waha_msg_123456",
    "priority": "normal",
    "metadata": {
      "campaignId": "campaign-123",
      "tags": ["marketing"]
    },
    "createdAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:30:00Z"
  }
}
```

#### POST /messages/bulk
Send multiple messages to multiple recipients.

**Request Body:**
```json
{
  "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "recipients": ["+1234567890", "+0987654321", "+1122334455"],
  "body": "Bulk notification message",
  "batchSize": 10,
  "priority": "normal",
  "metadata": {
    "campaignId": "bulk-001",
    "tags": ["notification"]
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "totalQueued": 100,
    "successCount": 95,
    "failureCount": 5,
    "batchInfo": {
      "totalBatches": 10,
      "batchSize": 10,
      "estimatedProcessingTime": "5 minutes"
    },
    "failedRecipients": ["+invalid1", "+invalid2"],
    "bulkMessageId": "bulk-msg-123456"
  }
}
```

#### GET /messages
List messages with filtering and pagination.

**Query Parameters:**
- `sessionId` (optional): Filter by session ID
- `direction` (optional): Filter by direction (inbound/outbound)
- `status` (optional): Filter by status (queued/sent/delivered/failed)
- `fromDate` (optional): Filter from date (ISO string)
- `toDate` (optional): Filter to date (ISO string)
- `search` (optional): Search in content and phone numbers
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 20, max: 100)

**Example:**
```
GET /messages?direction=outbound&status=sent&page=1&limit=20
```

**Response:**
```json
{
  "success": true,
  "data": {
    "data": [
      {
        "id": "msg-123456",
        "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "direction": "outbound",
        "toMsisdn": "+1234567890",
        "fromMsisdn": "+0987654321",
        "body": "Hello from the messaging API!",
        "status": "sent",
        "wahaMessageId": "waha_msg_123456",
        "priority": "normal",
        "metadata": {
          "campaignId": "campaign-123"
        },
        "createdAt": "2024-01-15T10:30:00Z",
        "updatedAt": "2024-01-15T10:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 100,
      "totalPages": 5,
      "hasNext": true,
      "hasPrev": false
    }
  }
}
```

#### GET /messages/:id
Get specific message by ID.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "msg-123456",
    "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "direction": "outbound",
    "toMsisdn": "+1234567890",
    "fromMsisdn": "+0987654321",
    "body": "Hello from the messaging API!",
    "status": "sent",
    "wahaMessageId": "waha_msg_123456",
    "priority": "normal",
    "metadata": {
      "campaignId": "campaign-123"
    },
    "createdAt": "2024-01-15T10:30:00Z",
    "updatedAt": "2024-01-15T10:30:00Z"
  }
}
```

#### GET /messages/stats
Get messaging statistics for a date range.

**Query Parameters:**
- `fromDate` (required): Start date (ISO string)
- `toDate` (required): End date (ISO string)

**Example:**
```
GET /messages/stats?fromDate=2024-01-01T00:00:00Z&toDate=2024-01-31T23:59:59Z
```

**Response:**
```json
{
  "success": true,
  "data": {
    "totalMessages": 1250,
    "outboundMessages": 1000,
    "inboundMessages": 250,
    "messagesByStatus": {
      "queued": 50,
      "sent": 900,
      "delivered": 800,
      "failed": 100
    },
    "messagesByDay": [
      {
        "date": "2024-01-01",
        "count": 100
      },
      {
        "date": "2024-01-02",
        "count": 150
      }
    ],
    "averagePerDay": 40.3,
    "successRate": 88.5,
    "dateRange": {
      "fromDate": "2024-01-01T00:00:00Z",
      "toDate": "2024-01-31T23:59:59Z"
    }
  }
}
```

#### POST /messages/:id/retry
Retry a failed message.

**Response:**
```json
{
  "success": true,
  "message": "Message queued for retry"
}
```

### WAHA Session Endpoints

#### POST /waha/sessions
Create a new WAHA session.

**Request Body:**
```json
{
  "name": "main-session",
  "engine": "WEBJS",
  "config": {
    "timeout": 30000
  }
}
```

#### GET /waha/sessions
List all WAHA sessions for the tenant.

#### GET /waha/sessions/:id
Get specific session details.

#### GET /waha/sessions/:id/qr
Get QR code for session authentication.

#### POST /waha/sessions/:id/stop
Stop a WAHA session.

#### DELETE /waha/sessions/:id
Delete a WAHA session.

### Webhook Endpoints

#### POST /webhooks/waha
Main webhook endpoint for WAHA events.

**Headers:**
```
Content-Type: application/json
X-Waha-Signature: sha256=signature
```

**Request Body:**
```json
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

#### GET /webhooks/health
Webhook service health check.

### Health Endpoints

#### GET /health
Application health check.

**Response:**
```json
{
  "success": true,
  "data": "Application is healthy!"
}
```

## Rate Limiting

The API implements rate limiting to ensure fair usage:

### Rate Limits

- **Login attempts**: 5 attempts per 15 minutes per IP
- **Message sending**: 20 messages per minute per session
- **API requests**: 100 requests per minute per user
- **Bulk messages**: 1000 messages per hour per tenant

### Rate Limit Headers

When rate limits are exceeded, the API returns:

```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1642248600
Retry-After: 60
```

### Rate Limit Response

```json
{
  "success": false,
  "statusCode": 429,
  "message": "Too many requests. Please try again later.",
  "error": "Too Many Requests",
  "retryAfter": 60,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Error Handling

### Standard Error Response

```json
{
  "success": false,
  "statusCode": 400,
  "message": "Validation failed",
  "error": "Bad Request",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/v1/messages/send"
}
```

### HTTP Status Codes

- **200 OK**: Request successful
- **201 Created**: Resource created successfully
- **400 Bad Request**: Invalid request data
- **401 Unauthorized**: Invalid or expired token
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

### Validation Errors

```json
{
  "success": false,
  "statusCode": 400,
  "message": [
    "email must be a valid email address",
    "password must be at least 8 characters"
  ],
  "error": "Bad Request",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Webhooks

### Webhook Events

The API supports the following webhook events:

- `message.any` - Any message received
- `message.text` - Text message
- `message.image` - Image message
- `message.document` - Document message
- `message.status` - Message delivery status
- `session.status` - Session state changes
- `session.qr` - QR code updates
- `session.failed` - Session failures
- `api.error` - API errors

### Webhook Security

All webhooks are cryptographically signed using HMAC-SHA256. Verify the signature:

```javascript
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return expectedSignature === signature.replace('sha256=', '');
}
```

### Webhook Response

```json
{
  "success": true,
  "message": "Webhook processed successfully"
}
```

## Examples

### Complete Message Flow

1. **Login**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@company.com", "password": "SecurePass123!"}'
```

2. **Create WAHA Session**
```bash
curl -X POST http://localhost:3000/waha/sessions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "main-session", "engine": "WEBJS"}'
```

3. **Send Message**
```bash
curl -X POST http://localhost:3000/messages/send \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "session-id",
    "to": "+1234567890",
    "body": "Hello from the API!"
  }'
```

4. **Check Message Status**
```bash
curl -X GET http://localhost:3000/messages \
  -H "Authorization: Bearer <token>"
```

### Bulk Messaging Example

```bash
curl -X POST http://localhost:3000/messages/bulk \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "session-id",
    "recipients": ["+1234567890", "+0987654321"],
    "body": "Bulk notification",
    "batchSize": 10
  }'
```

### Webhook Example

```bash
curl -X POST http://localhost:3000/webhooks/waha \
  -H "Content-Type: application/json" \
  -H "X-Waha-Signature: sha256=signature" \
  -d '{
    "event": "message.text",
    "session": "main-session",
    "payload": {
      "id": "msg-123",
      "from": "+1234567890",
      "to": "+0987654321",
      "body": "Hello!",
      "timestamp": 1642248600000
    }
  }'
```

## SDKs and Tools

### Postman Collection

Import the provided Postman collection for easy API testing:

1. Download `Multi-Tenant-Messaging-API.postman_collection.json`
2. Import into Postman
3. Set up environment variables
4. Start testing!

### Environment Variables

Create a Postman environment with these variables:

- `base_url`: API base URL
- `jwt_token`: JWT access token
- `refresh_token`: JWT refresh token
- `tenant_id`: Tenant ID
- `session_id`: WAHA session ID

### cURL Examples

All endpoints can be tested with cURL. See the examples section above.

### JavaScript SDK

```javascript
class MessagingAPI {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async sendMessage(sessionId, to, body) {
    const response = await fetch(`${this.baseUrl}/messages/send`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ sessionId, to, body })
    });
    return response.json();
  }
}
```

## Support

For technical support and questions:

- **Documentation**: Refer to this comprehensive API documentation
- **Health Check**: Use the `/health` endpoint to verify service status
- **Logs**: Check application logs for detailed error information
- **Community**: Join our developer community for support

## Changelog

### Version 1.0.0
- Initial release
- Multi-tenant messaging support
- WAHA integration
- Webhook handling
- Comprehensive API documentation
