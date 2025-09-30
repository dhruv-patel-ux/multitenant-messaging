import {
  Controller,
  Post,
  Get,
  Body,
  Headers,
  UseGuards,
  HttpStatus,
  HttpCode,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiHeader } from '@nestjs/swagger';
import { Public } from '../common/decorators/public.decorator';
import { WebhooksService } from './webhooks.service';
import type { WahaWebhookPayload } from './webhooks.service';

@ApiTags('Webhooks')
@Controller('webhooks')
export class WebhooksController {
  private readonly logger = new Logger(WebhooksController.name);

  constructor(private readonly webhooksService: WebhooksService) {}

  @Post('waha')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'WAHA webhook endpoint',
    description: 'Main webhook endpoint for receiving WAHA events. This is a public endpoint that WAHA calls.',
  })
  @ApiHeader({
    name: 'X-Waha-Signature',
    description: 'Webhook signature for verification',
    required: true,
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Webhook processed successfully',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid webhook signature',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid webhook payload',
  })
  async handleWahaWebhook(
    @Body() payload: WahaWebhookPayload,
    @Headers('x-waha-signature') signature: string,
  ): Promise<{ success: boolean; message: string }> {
    this.logger.log(`Received WAHA webhook: ${payload.event} for session: ${payload.session}`);

    try {
      await this.webhooksService.processWahaWebhook(payload, signature);

      return {
        success: true,
        message: 'Webhook processed successfully',
      };
    } catch (error) {
      this.logger.error(`Failed to process WAHA webhook: ${error.message}`, error.stack);

      if (error instanceof UnauthorizedException) {
        throw error;
      }

      // Return success to WAHA to prevent retries for processing errors
      return {
        success: true,
        message: 'Webhook received but processing failed',
      };
    }
  }

  @Get('health')
  @Public()
  @ApiOperation({
    summary: 'Webhook service health check',
    description: 'Checks the health status of the webhook service.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Webhook service is healthy',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', example: 'healthy' },
        timestamp: { type: 'string', example: '2024-01-15T10:30:00Z' },
        service: { type: 'string', example: 'webhooks' },
      },
    },
  })
  async getHealth(): Promise<{
    status: string;
    timestamp: string;
    service: string;
  }> {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'webhooks',
    };
  }
}
