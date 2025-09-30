import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { INestApplication } from '@nestjs/common';
import { Environment } from './env.validation';

export interface SwaggerConfig {
  title: string;
  description: string;
  version: string;
  contact: {
    name: string;
    email: string;
    url: string;
  };
  license: {
    name: string;
    url: string;
  };
  servers: Array<{
    url: string;
    description: string;
  }>;
}

export const createSwaggerConfig = (environment: Environment): SwaggerConfig => {
  const baseConfig = {
    title: 'Multi-Tenant Messaging API',
    description: `
# Multi-Tenant Messaging API

A comprehensive messaging microservice built with NestJS that provides WhatsApp messaging capabilities through WAHA (WhatsApp HTTP API) integration.

## Features

- **Multi-Tenant Architecture**: Complete tenant isolation with role-based access control
- **WhatsApp Integration**: Full WAHA integration for WhatsApp messaging
- **Message Management**: Send single and bulk messages with advanced filtering
- **Webhook Handling**: Secure webhook processing for real-time message updates
- **Authentication**: JWT-based authentication with refresh token support
- **Rate Limiting**: Built-in rate limiting and quota management
- **Audit Logging**: Comprehensive security audit trails
- **Health Monitoring**: Health checks and service monitoring

## Authentication

This API uses JWT (JSON Web Token) authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Rate Limiting

The API implements rate limiting to ensure fair usage:
- **Login attempts**: 5 attempts per 15 minutes per IP
- **Message sending**: 20 messages per minute per session
- **API requests**: 100 requests per minute per user

## Multi-Tenancy

All operations are automatically scoped to the authenticated user's tenant. Users can only access data within their tenant context.

## Webhooks

The API provides webhook endpoints for real-time event processing:
- **WAHA Webhooks**: Receive WhatsApp message events
- **Signature Validation**: All webhooks are cryptographically signed
- **Idempotency**: Duplicate webhook prevention

## Support

For technical support and questions:
- **Documentation**: Refer to the comprehensive API documentation
- **Health Check**: Use the \`/health\` endpoint to verify service status
- **Logs**: Check application logs for detailed error information
    `,
    version: '1.0.0',
    contact: {
      name: 'API Support Team',
      email: 'support@messaging-api.com',
      url: 'https://messaging-api.com/support',
    },
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
  };

  const servers = [
    {
      url: 'http://localhost:3000',
      description: 'Development Server',
    },
  ];

  if (environment === Environment.Production) {
    servers.push(
      {
        url: 'https://api.messaging-api.com',
        description: 'Production Server',
      },
      {
        url: 'https://staging-api.messaging-api.com',
        description: 'Staging Server',
      },
    );
  } else if (environment === Environment.Test) {
    servers.push({
      url: 'http://localhost:3001',
      description: 'Test Server',
    });
  }

  return {
    ...baseConfig,
    servers,
  };
};

export const setupSwagger = (app: INestApplication, environment: Environment): void => {
  const config = createSwaggerConfig(environment);
  
  const builder = new DocumentBuilder()
    .setTitle(config.title)
    .setDescription(config.description)
    .setVersion(config.version)
    .setContact(config.contact.name, config.contact.url, config.contact.email)
    .setLicense(config.license.name, config.license.url)
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'JWT',
        description: 'Enter JWT token',
        in: 'header',
      },
      'JWT-auth',
    )
    .addTag('Authentication', 'User authentication and authorization endpoints')
    .addTag('Users', 'User management and profile operations')
    .addTag('Tenants', 'Tenant management and configuration')
    .addTag('WAHA', 'WAHA session management and WhatsApp integration')
    .addTag('Messages', 'Message sending, receiving, and management')
    .addTag('Webhooks', 'Webhook handling for real-time events')
    .addTag('Health', 'Health check and monitoring endpoints');

  config.servers.forEach(server => {
    builder.addServer(server.url, server.description);
  });

  const swaggerConfig = builder.build();

  // Servers are already added before build

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  
  // Add custom schemas and examples
  document.components = {
    ...document.components,
    schemas: {
      ...document.components?.schemas,
      ErrorResponse: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: false,
            description: 'Indicates if the request was successful',
          },
          statusCode: {
            type: 'number',
            example: 400,
            description: 'HTTP status code',
          },
          message: {
            type: 'string',
            example: 'Validation failed',
            description: 'Error message',
          },
          error: {
            type: 'string',
            example: 'Bad Request',
            description: 'Error type',
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            example: '2024-01-15T10:30:00Z',
            description: 'Timestamp of the error',
          },
          path: {
            type: 'string',
            example: '/api/v1/messages/send',
            description: 'Request path',
          },
        },
        required: ['success', 'statusCode', 'message', 'timestamp'],
      },
      ValidationError: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: false,
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
          message: {
            type: 'array',
            items: {
              type: 'string',
            },
            example: ['email must be a valid email address', 'password must be at least 8 characters'],
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            example: '2024-01-15T10:30:00Z',
          },
        },
      },
      RateLimitError: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: false,
          },
          statusCode: {
            type: 'number',
            example: 429,
          },
          message: {
            type: 'string',
            example: 'Too many requests. Please try again later.',
          },
          error: {
            type: 'string',
            example: 'Too Many Requests',
          },
          retryAfter: {
            type: 'number',
            example: 60,
            description: 'Seconds to wait before retrying',
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            example: '2024-01-15T10:30:00Z',
          },
        },
      },
    },
  };

  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      docExpansion: 'none',
      filter: true,
      showRequestHeaders: true,
      showCommonExtensions: true,
      tryItOutEnabled: true,
      requestInterceptor: (req) => {
        // Add common headers for testing
        req.headers['Content-Type'] = 'application/json';
        return req;
      },
    },
    customSiteTitle: 'Multi-Tenant Messaging API Documentation',
    customfavIcon: '/favicon.ico',
    customCss: `
      .swagger-ui .topbar { display: none; }
      .swagger-ui .info { margin: 20px 0; }
      .swagger-ui .info .title { color: #3b82f6; }
      .swagger-ui .scheme-container { background: #f8fafc; padding: 10px; border-radius: 4px; }
    `,
  });
};

export const createSwaggerDocument = (app: INestApplication, environment: Environment) => {
  const cfg = createSwaggerConfig(environment);
  const builder = new DocumentBuilder()
    .setTitle(cfg.title)
    .setDescription(cfg.description)
    .setVersion(cfg.version)
    .setContact(cfg.contact.name, cfg.contact.url, cfg.contact.email)
    .setLicense(cfg.license.name, cfg.license.url)
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', name: 'JWT', description: 'Enter JWT token', in: 'header' },
      'JWT-auth',
    )
    .addTag('Authentication', 'User authentication and authorization endpoints')
    .addTag('Users', 'User management and profile operations')
    .addTag('Tenants', 'Tenant management and configuration')
    .addTag('WAHA', 'WAHA session management and WhatsApp integration')
    .addTag('Messages', 'Message sending, receiving, and management')
    .addTag('Webhooks', 'Webhook handling for real-time events')
    .addTag('Health', 'Health check and monitoring endpoints');

  cfg.servers.forEach(server => builder.addServer(server.url, server.description));

  const built = builder.build();
  return SwaggerModule.createDocument(app, built);
};
