import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  UseGuards,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse, 
  ApiBearerAuth, 
  ApiParam, 
  ApiQuery,
  ApiBody,
  ApiExtraModels,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/auth.guards';
import { RoleGuard, RequirePermissions } from '../common/guards/role.guard';
import { TenantGuard } from '../common/guards/tenant.guard';
import { CurrentUser, TenantId } from '../common/decorators/authorization.decorators';
import { Permission } from '../common/enums/roles.enum';
import { MessagesService } from './messages.service';
import {
  SendMessageDto,
  BulkMessageDto,
  MessageFiltersDto,
  MessageStatsDto,
  BulkMessageResponseDto,
  MessageResponseDto,
  DateRangeDto,
} from './dto/message.dto';
import { 
  ErrorResponseDto, 
  ValidationErrorDto, 
  RateLimitErrorDto,
  PaginatedResponseDto,
} from '../common/dto/api.dto';

@ApiTags('Messages')
@Controller('messages')
@UseGuards(JwtAuthGuard, TenantGuard)
export class MessagesController {
  constructor(private readonly messagesService: MessagesService) {}

  @Post('send')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_SEND)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Send single message',
    description: `
Sends a single message via WAHA session to a recipient phone number.

**Features:**
- Real-time message delivery through WhatsApp
- Message priority queuing (high, normal, low)
- Custom metadata support
- Automatic tenant isolation
- Rate limiting protection

**Requirements:**
- Valid WAHA session in 'working' state
- Valid phone number in international format (+country code)
- MESSAGES_SEND permission

**Rate Limits:**
- 20 messages per minute per session
- 100 messages per hour per tenant

**Example Request:**
\`\`\`json
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
\`\`\`
    `,
  })
  @ApiBody({
    type: SendMessageDto,
    description: 'Message details including recipient, content, and metadata',
    examples: {
      basic: {
        summary: 'Basic message',
        description: 'Send a simple text message',
        value: {
          sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
          to: '+1234567890',
          body: 'Hello from the messaging API!',
          priority: 'normal',
        },
      },
      priority: {
        summary: 'High priority message',
        description: 'Send a high priority message with metadata',
        value: {
          sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
          to: '+1234567890',
          body: 'Urgent: System maintenance scheduled',
          priority: 'high',
          metadata: {
            campaignId: 'urgent-001',
            tags: ['urgent', 'maintenance'],
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Message sent successfully',
    type: MessageResponseDto,
    example: {
      id: 'msg-123456',
      sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
      direction: 'outbound',
      toMsisdn: '+1234567890',
      fromMsisdn: '+0987654321',
      body: 'Hello from the messaging API!',
      status: 'sent',
      wahaMessageId: 'waha_msg_123456',
      priority: 'normal',
      metadata: {
        campaignId: 'campaign-123',
        tags: ['marketing'],
      },
      createdAt: '2024-01-15T10:30:00Z',
      updatedAt: '2024-01-15T10:30:00Z',
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid request data or session not in working state',
    type: ErrorResponseDto,
    example: {
      success: false,
      statusCode: 400,
      message: 'Session is not in working state',
      error: 'Bad Request',
      timestamp: '2024-01-15T10:30:00Z',
      path: '/api/v1/messages/send',
    },
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found or does not belong to tenant',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Rate limit exceeded',
    type: RateLimitErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired JWT token',
    type: ErrorResponseDto,
  })
  async sendMessage(
    @Body() sendMessageDto: SendMessageDto,
    @TenantId() tenantId: string,
    @CurrentUser() user: any,
  ): Promise<MessageResponseDto> {
    const message = await this.messagesService.sendMessage(tenantId, sendMessageDto);
    
    return {
      id: message.id,
      sessionId: message.sessionId,
      direction: message.direction,
      toMsisdn: message.toMsisdn,
      fromMsisdn: message.fromMsisdn,
      body: message.body,
      status: message.status,
      wahaMessageId: message.wahaMessageId,
      priority: message.metadata?.priority,
      metadata: message.metadata,
      createdAt: message.createdAt,
      updatedAt: message.updatedAt,
    };
  }

  @Post('bulk')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_SEND)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Send bulk messages',
    description: `
Sends multiple messages to multiple recipients in batches.

**Features:**
- Batch processing for efficient delivery
- Configurable batch size (1-50 messages per batch)
- Priority queuing for urgent messages
- Automatic rate limiting compliance
- Progress tracking and error reporting

**Requirements:**
- Valid WAHA session in 'working' state
- Valid phone numbers in international format
- MESSAGES_SEND permission

**Rate Limits:**
- 20 messages per minute per session
- 100 messages per hour per tenant
- Batch processing respects rate limits

**Example Request:**
\`\`\`json
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
\`\`\`
    `,
  })
  @ApiBody({
    type: BulkMessageDto,
    description: 'Bulk message details including recipients, content, and batch configuration',
    examples: {
      small: {
        summary: 'Small bulk message',
        description: 'Send to a small group of recipients',
        value: {
          sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
          recipients: ['+1234567890', '+0987654321'],
          body: 'Welcome to our service!',
          batchSize: 5,
          priority: 'normal',
        },
      },
      large: {
        summary: 'Large bulk message',
        description: 'Send to many recipients with custom batch size',
        value: {
          sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
          recipients: ['+1234567890', '+0987654321', '+1122334455', '+5566778899'],
          body: 'Important system update notification',
          batchSize: 20,
          priority: 'high',
          metadata: {
            campaignId: 'system-update-001',
            tags: ['system', 'update'],
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Bulk messages queued successfully',
    type: BulkMessageResponseDto,
    example: {
      totalQueued: 100,
      successCount: 95,
      failureCount: 5,
      batchInfo: {
        totalBatches: 10,
        batchSize: 10,
        estimatedProcessingTime: '5 minutes',
      },
      failedRecipients: ['+invalid1', '+invalid2'],
      bulkMessageId: 'bulk-msg-123456',
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid request data or session not in working state',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found or does not belong to tenant',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Rate limit exceeded',
    type: RateLimitErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired JWT token',
    type: ErrorResponseDto,
  })
  async sendBulkMessages(
    @Body() bulkMessageDto: BulkMessageDto,
    @TenantId() tenantId: string,
    @CurrentUser() user: any,
  ): Promise<BulkMessageResponseDto> {
    return this.messagesService.sendBulkMessages(tenantId, bulkMessageDto);
  }

  @Get()
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'List messages with filters',
    description: `
Retrieves messages with advanced filtering, searching, and pagination capabilities.

**Features:**
- Advanced filtering by session, direction, status, and date range
- Full-text search in message content and phone numbers
- Pagination with configurable page size
- Automatic tenant isolation
- Sorting by creation date (newest first)

**Filter Options:**
- **sessionId**: Filter by specific WAHA session
- **direction**: Filter by message direction (inbound/outbound)
- **status**: Filter by message status (queued/sent/delivered/failed)
- **fromDate/toDate**: Filter by date range (ISO format)
- **search**: Search in message content and phone numbers
- **page/limit**: Pagination controls

**Example Queries:**
- Get all outbound messages: \`?direction=outbound\`
- Get messages from last week: \`?fromDate=2024-01-08T00:00:00Z&toDate=2024-01-15T23:59:59Z\`
- Search for specific content: \`?search=hello\`
- Get failed messages: \`?status=failed\`
- Get messages from specific session: \`?sessionId=abc-123\`

**Rate Limits:**
- 100 requests per minute per user
- 1000 requests per hour per tenant
    `,
  })
  @ApiQuery({
    name: 'sessionId',
    required: false,
    description: 'Filter by session ID',
    example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
  })
  @ApiQuery({
    name: 'direction',
    required: false,
    description: 'Filter by message direction',
    enum: ['inbound', 'outbound'],
    example: 'outbound',
  })
  @ApiQuery({
    name: 'status',
    required: false,
    description: 'Filter by message status',
    enum: ['queued', 'sent', 'delivered', 'failed'],
    example: 'sent',
  })
  @ApiQuery({
    name: 'fromDate',
    required: false,
    description: 'Filter from date (ISO string)',
    example: '2024-01-01T00:00:00Z',
  })
  @ApiQuery({
    name: 'toDate',
    required: false,
    description: 'Filter to date (ISO string)',
    example: '2024-01-31T23:59:59Z',
  })
  @ApiQuery({
    name: 'search',
    required: false,
    description: 'Search in message content and phone numbers',
    example: 'hello',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    description: 'Page number (1-based)',
    example: 1,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    description: 'Number of items per page (1-100)',
    example: 20,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Messages retrieved successfully',
    type: PaginatedResponseDto<MessageResponseDto>,
    example: {
      data: [
        {
          id: 'msg-123456',
          sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
          direction: 'outbound',
          toMsisdn: '+1234567890',
          fromMsisdn: '+0987654321',
          body: 'Hello from the messaging API!',
          status: 'sent',
          wahaMessageId: 'waha_msg_123456',
          priority: 'normal',
          metadata: {
            campaignId: 'campaign-123',
          },
          createdAt: '2024-01-15T10:30:00Z',
          updatedAt: '2024-01-15T10:30:00Z',
        },
      ],
      pagination: {
        page: 1,
        limit: 20,
        total: 100,
        totalPages: 5,
        hasNext: true,
        hasPrev: false,
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid filter parameters',
    type: ValidationErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
    type: ErrorResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired JWT token',
    type: ErrorResponseDto,
  })
  async getMessages(
    @Query() filters: MessageFiltersDto,
    @TenantId() tenantId: string,
  ): Promise<{
    data: MessageResponseDto[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
      hasNext: boolean;
      hasPrev: boolean;
    };
  }> {
    return this.messagesService.getMessages(tenantId, filters);
  }

  @Get(':id')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Message ID', type: 'string' })
  @ApiOperation({
    summary: 'Get specific message',
    description: 'Retrieves detailed information about a specific message. Requires MESSAGES_READ permission.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Message details retrieved successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Message not found',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async getMessage(
    @Param('id') messageId: string,
    @TenantId() tenantId: string,
  ): Promise<MessageResponseDto> {
    return this.messagesService.getMessageById(messageId, tenantId);
  }

  @Get('stats')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.ANALYTICS_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Get messaging statistics',
    description: 'Retrieves comprehensive messaging statistics for the tenant. Requires ANALYTICS_READ permission.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Statistics retrieved successfully',
    type: MessageStatsDto,
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async getMessageStats(
    @Query() dateRange: DateRangeDto,
    @TenantId() tenantId: string,
  ): Promise<MessageStatsDto> {
    return this.messagesService.getMessageStats(tenantId, dateRange);
  }

  @Post(':id/retry')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_SEND)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Message ID', type: 'string' })
  @ApiOperation({
    summary: 'Retry failed message',
    description: 'Retries a failed message. Requires MESSAGES_SEND permission.',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'Message queued for retry',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Message not found',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Message is not in failed state',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async retryMessage(
    @Param('id') messageId: string,
    @TenantId() tenantId: string,
  ): Promise<void> {
    await this.messagesService.retryFailedMessage(messageId);
  }
}
