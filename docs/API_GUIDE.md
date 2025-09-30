# API Usage Guide

This guide provides detailed examples and best practices for using the Multi-Tenant Messaging API.

## Table of Contents

1. [Authentication](#authentication)
2. [User Management](#user-management)
3. [WAHA Sessions](#waha-sessions)
4. [Messaging](#messaging)
5. [Webhooks](#webhooks)
6. [Error Handling](#error-handling)
7. [Rate Limiting](#rate-limiting)
8. [Best Practices](#best-practices)

## Authentication

### Login Flow

```bash
# 1. Login to get tokens
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

### Token Refresh

```bash
# 2. Refresh access token when expired
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token"
  }'
```

### Using Tokens

```bash
# 3. Include token in all authenticated requests
curl -X GET http://localhost:3000/users \
  -H "Authorization: Bearer your-access-token"
```

## User Management

### Creating Users

```bash
# Create a new user (TENANT_ADMIN only)
curl -X POST http://localhost:3000/users \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "agent@company.com",
    "password": "SecurePass123!",
    "role": "AGENT"
  }'
```

### Listing Users

```bash
# Get all users in tenant
curl -X GET http://localhost:3000/users \
  -H "Authorization: Bearer your-access-token"

# With pagination
curl -X GET "http://localhost:3000/users?page=1&limit=10" \
  -H "Authorization: Bearer your-access-token"
```

### Updating Users

```bash
# Update user role
curl -X PUT http://localhost:3000/users/user-id \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "MANAGER"
  }'
```

## WAHA Sessions

### Creating Sessions

```bash
# Create a new WAHA session
curl -X POST http://localhost:3000/waha/sessions \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "main-session",
    "engine": "WEBJS",
    "config": {
      "timeout": 30000,
      "webhook": {
        "url": "https://your-domain.com/webhooks/waha",
        "events": ["message", "session.status"]
      }
    }
  }'
```

### Getting QR Code

```bash
# Get QR code for WhatsApp authentication
curl -X GET http://localhost:3000/waha/sessions/session-id/qr \
  -H "Authorization: Bearer your-access-token"
```

### Session Management

```bash
# List all sessions
curl -X GET http://localhost:3000/waha/sessions \
  -H "Authorization: Bearer your-access-token"

# Stop session
curl -X POST http://localhost:3000/waha/sessions/session-id/stop \
  -H "Authorization: Bearer your-access-token"

# Delete session
curl -X DELETE http://localhost:3000/waha/sessions/session-id \
  -H "Authorization: Bearer your-access-token"
```

## Messaging

### Sending Single Messages

```bash
# Send a text message
curl -X POST http://localhost:3000/messages/send \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "session-id",
    "to": "+1234567890",
    "body": "Hello from the API!",
    "priority": "normal",
    "metadata": {
      "campaignId": "campaign-123",
      "tags": ["marketing"]
    }
  }'
```

### Bulk Messaging

```bash
# Send bulk messages
curl -X POST http://localhost:3000/messages/bulk \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "session-id",
    "recipients": ["+1234567890", "+0987654321", "+1122334455"],
    "body": "Bulk notification message",
    "batchSize": 10,
    "priority": "normal",
    "metadata": {
      "campaignId": "bulk-001,
      "tags": ["notification"]
    }
  }'
```

### Message Filtering

```bash
# Get messages with filters
curl -X GET "http://localhost:3000/messages?direction=outbound&status=sent&page=1&limit=20" \
  -H "Authorization: Bearer your-access-token"

# Search messages
curl -X GET "http://localhost:3000/messages?search=hello&fromDate=2024-01-01T00:00:00Z&toDate=2024-01-31T23:59:59Z" \
  -H "Authorization: Bearer your-access-token"
```

### Message Statistics

```bash
# Get messaging statistics
curl -X GET "http://localhost:3000/messages/stats?fromDate=2024-01-01T00:00:00Z&toDate=2024-01-31T23:59:59Z" \
  -H "Authorization: Bearer your-access-token"
```

### Retrying Failed Messages

```bash
# Retry a failed message
curl -X POST http://localhost:3000/messages/message-id/retry \
  -H "Authorization: Bearer your-access-token"
```

## Webhooks

### Setting Up Webhooks

1. **Configure WAHA session with webhook URL**:
```json
{
  "name": "webhook-session",
  "engine": "WEBJS",
  "config": {
    "webhook": {
      "url": "https://your-domain.com/webhooks/waha",
      "events": ["message.any", "message.text", "message.status", "session.status"]
    }
  }
}
```

2. **Handle incoming webhooks**:
```bash
# Your webhook endpoint will receive POST requests
curl -X POST https://your-domain.com/webhooks/waha \
  -H "Content-Type: application/json" \
  -H "X-Waha-Signature: sha256=signature" \
  -d '{
    "event": "message.text",
    "session": "webhook-session",
    "payload": {
      "id": "waha-msg-123",
      "from": "+1234567890",
      "to": "+0987654321",
      "body": "Hello from WhatsApp!",
      "timestamp": 1642248600000,
      "type": "text"
    }
  }'
```

### Webhook Security

```javascript
// Verify webhook signature
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return expectedSignature === signature.replace('sha256=', '');
}
```

## Error Handling

### Common Error Responses

```json
// Validation Error
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

// Authentication Error
{
  "success": false,
  "statusCode": 401,
  "message": "Unauthorized",
  "error": "Unauthorized",
  "timestamp": "2024-01-15T10:30:00Z"
}

// Rate Limit Error
{
  "success": false,
  "statusCode": 429,
  "message": "Too many requests. Please try again later.",
  "error": "Too Many Requests",
  "retryAfter": 60,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Handling Best Practices

```javascript
// Example error handling in JavaScript
async function sendMessage(messageData) {
  try {
    const response = await fetch('/messages/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(messageData)
    });

    if (!response.ok) {
      const error = await response.json();
      
      if (response.status === 429) {
        // Handle rate limiting
        const retryAfter = error.retryAfter || 60;
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        return sendMessage(messageData); // Retry
      }
      
      throw new Error(error.message);
    }

    return await response.json();
  } catch (error) {
    console.error('Message sending failed:', error.message);
    throw error;
  }
}
```

## Rate Limiting

### Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| Login | 5 attempts | 15 minutes |
| Messages | 20 messages | 1 minute |
| API Requests | 100 requests | 1 minute |
| Bulk Messages | 1000 messages | 1 hour |

### Handling Rate Limits

```javascript
// Check rate limit headers
const response = await fetch('/messages/send', options);

if (response.status === 429) {
  const retryAfter = response.headers.get('Retry-After');
  const rateLimitRemaining = response.headers.get('X-RateLimit-Remaining');
  
  console.log(`Rate limited. Retry after ${retryAfter} seconds`);
  console.log(`Requests remaining: ${rateLimitRemaining}`);
}
```

## Best Practices

### 1. Authentication

```javascript
// Store tokens securely
const tokenStorage = {
  setTokens: (accessToken, refreshToken) => {
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
  },
  
  getAccessToken: () => localStorage.getItem('accessToken'),
  getRefreshToken: () => localStorage.getItem('refreshToken'),
  
  clearTokens: () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  }
};

// Auto-refresh tokens
async function makeAuthenticatedRequest(url, options = {}) {
  let token = tokenStorage.getAccessToken();
  
  let response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`
    }
  });
  
  // If token expired, refresh and retry
  if (response.status === 401) {
    const refreshToken = tokenStorage.getRefreshToken();
    const refreshResponse = await fetch('/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    
    if (refreshResponse.ok) {
      const { accessToken, refreshToken: newRefreshToken } = await refreshResponse.json();
      tokenStorage.setTokens(accessToken, newRefreshToken);
      
      // Retry original request
      response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${accessToken}`
        }
      });
    }
  }
  
  return response;
}
```

### 2. Message Handling

```javascript
// Queue messages for better performance
class MessageQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
  }
  
  async add(message) {
    this.queue.push(message);
    if (!this.processing) {
      this.process();
    }
  }
  
  async process() {
    this.processing = true;
    
    while (this.queue.length > 0) {
      const message = this.queue.shift();
      try {
        await this.sendMessage(message);
      } catch (error) {
        console.error('Failed to send message:', error);
        // Implement retry logic
      }
    }
    
    this.processing = false;
  }
  
  async sendMessage(message) {
    return makeAuthenticatedRequest('/messages/send', {
      method: 'POST',
      body: JSON.stringify(message)
    });
  }
}
```

### 3. Error Recovery

```javascript
// Implement exponential backoff for retries
async function retryWithBackoff(fn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      
      const delay = Math.pow(2, i) * 1000; // Exponential backoff
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}
```

### 4. Webhook Processing

```javascript
// Process webhooks idempotently
const processedWebhooks = new Set();

async function processWebhook(webhookData) {
  const webhookId = webhookData.payload.id;
  
  // Check if already processed
  if (processedWebhooks.has(webhookId)) {
    return { success: true, message: 'Webhook already processed' };
  }
  
  try {
    // Process webhook
    await processInboundMessage(webhookData);
    
    // Mark as processed
    processedWebhooks.add(webhookId);
    
    return { success: true, message: 'Webhook processed successfully' };
  } catch (error) {
    console.error('Webhook processing failed:', error);
    throw error;
  }
}
```

### 5. Monitoring and Logging

```javascript
// Add request logging
function logRequest(req, res, next) {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
  });
  
  next();
}

// Monitor message delivery
async function monitorMessageDelivery(messageId) {
  const maxAttempts = 10;
  let attempts = 0;
  
  while (attempts < maxAttempts) {
    const message = await getMessage(messageId);
    
    if (message.status === 'delivered') {
      console.log('Message delivered successfully');
      return;
    }
    
    if (message.status === 'failed') {
      console.log('Message delivery failed');
      return;
    }
    
    await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
    attempts++;
  }
  
  console.log('Message delivery monitoring timeout');
}
```

This guide provides comprehensive examples for using the Multi-Tenant Messaging API effectively. For more detailed information, refer to the Swagger documentation at `/api/docs`.
