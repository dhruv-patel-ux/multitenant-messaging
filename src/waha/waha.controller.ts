import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpStatus,
  HttpCode,
  Res,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam } from '@nestjs/swagger';
import type { Response } from 'express';
import { JwtAuthGuard } from '../auth/guards/auth.guards';
import { RoleGuard, RequirePermissions } from '../common/guards/role.guard';
import { TenantGuard } from '../common/guards/tenant.guard';
import { CurrentUser, TenantId } from '../common/decorators/authorization.decorators';
import { Permission } from '../common/enums/roles.enum';
import { WahaService } from './waha.service';
import {
  CreateSessionDto,
  SessionResponseDto,
  SendMessageDto,
  MessageResponse,
  WahaHealthResponse,
} from './dto/waha.dto';

@ApiTags('WAHA Sessions')
@Controller('waha')
@UseGuards(JwtAuthGuard, TenantGuard)
export class WahaController {
  constructor(private readonly wahaService: WahaService) {}

  @Post('sessions')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_CREATE)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Create and start WAHA session',
    description: 'Creates a new WAHA session for the current tenant and starts it. Requires SESSIONS_CREATE permission.',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Session created and started successfully',
    type: SessionResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Session with this name already exists',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async createSession(
    @Body() createSessionDto: CreateSessionDto,
    @TenantId() tenantId: string,
    @CurrentUser() user: any,
  ): Promise<SessionResponseDto> {
    const session = await this.wahaService.createTenantSession(tenantId, createSessionDto);
    
    return {
      id: session.id,
      externalSessionId: session.externalSessionId,
      status: session.status,
      engine: session.engine,
      metadata: session.metadata,
      tenantId: session.tenantId,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
    };
  }

  @Get('sessions')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'List tenant WAHA sessions',
    description: 'Retrieves all WAHA sessions for the current tenant. Requires SESSIONS_READ permission.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Sessions retrieved successfully',
    type: [SessionResponseDto],
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async getSessions(@TenantId() tenantId: string): Promise<SessionResponseDto[]> {
    const sessions = await this.wahaService.getTenantSessions(tenantId);
    
    return sessions.map(session => ({
      id: session.id,
      externalSessionId: session.externalSessionId,
      status: session.status,
      engine: session.engine,
      metadata: session.metadata,
      tenantId: session.tenantId,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
    }));
  }

  @Get('sessions/:id')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Session ID', type: 'string' })
  @ApiOperation({
    summary: 'Get WAHA session details',
    description: 'Retrieves detailed information about a specific WAHA session. Requires SESSIONS_READ permission.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Session details retrieved successfully',
    type: SessionResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async getSession(
    @Param('id') sessionId: string,
    @TenantId() tenantId: string,
  ): Promise<SessionResponseDto> {
    const session = await this.wahaService.getSessionDetails(sessionId, tenantId);
    
    return {
      id: session.id,
      externalSessionId: session.externalSessionId,
      status: session.status,
      engine: session.engine,
      metadata: session.metadata,
      tenantId: session.tenantId,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
    };
  }

  @Get('sessions/:id/qr')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Session ID', type: 'string' })
  @ApiOperation({
    summary: 'Get QR code for session',
    description: 'Retrieves the QR code for WhatsApp authentication. Requires SESSIONS_READ permission.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'QR code retrieved successfully',
    schema: {
      type: 'string',
      format: 'base64',
      example: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
    },
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Session is not in QR scanning state',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async getSessionQR(
    @Param('id') sessionId: string,
    @TenantId() tenantId: string,
  ): Promise<{ qrCode: string }> {
    const qrCode = await this.wahaService.getSessionQRCode(sessionId, tenantId);
    return { qrCode };
  }

  @Post('sessions/:id/stop')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_MANAGE)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Session ID', type: 'string' })
  @ApiOperation({
    summary: 'Stop WAHA session',
    description: 'Stops a running WAHA session. Requires SESSIONS_MANAGE permission.',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'Session stopped successfully',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Session is already stopped',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async stopSession(
    @Param('id') sessionId: string,
    @TenantId() tenantId: string,
  ): Promise<void> {
    await this.wahaService.stopTenantSession(sessionId, tenantId);
  }

  @Delete('sessions/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_DELETE)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Session ID', type: 'string' })
  @ApiOperation({
    summary: 'Delete WAHA session',
    description: 'Deletes a WAHA session permanently. Requires SESSIONS_DELETE permission.',
  })
  @ApiResponse({
    status: HttpStatus.NO_CONTENT,
    description: 'Session deleted successfully',
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async deleteSession(
    @Param('id') sessionId: string,
    @TenantId() tenantId: string,
  ): Promise<void> {
    await this.wahaService.deleteTenantSession(sessionId, tenantId);
  }

  @Post('sessions/:id/sync')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Session ID', type: 'string' })
  @ApiOperation({
    summary: 'Sync session status',
    description: 'Synchronizes the session status with WAHA service. Requires SESSIONS_READ permission.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Session status synced successfully',
    type: SessionResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async syncSession(
    @Param('id') sessionId: string,
    @TenantId() tenantId: string,
  ): Promise<SessionResponseDto> {
    const session = await this.wahaService.syncSessionStatus(sessionId);
    
    return {
      id: session.id,
      externalSessionId: session.externalSessionId,
      status: session.status,
      engine: session.engine,
      metadata: session.metadata,
      tenantId: session.tenantId,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
    };
  }

  @Post('sessions/:id/send')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.MESSAGES_SEND)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Session ID', type: 'string' })
  @ApiOperation({
    summary: 'Send message via session',
    description: 'Sends a text message via the specified WAHA session. Requires MESSAGES_SEND permission.',
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Message sent successfully',
    type: MessageResponse,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Session is not in working state',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async sendMessage(
    @Param('id') sessionId: string,
    @Body() sendMessageDto: SendMessageDto,
    @TenantId() tenantId: string,
  ): Promise<MessageResponse> {
    return this.wahaService.sendMessage(sessionId, tenantId, sendMessageDto);
  }

  @Get('sessions/:id/screen')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.SESSIONS_READ)
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Session ID', type: 'string' })
  @ApiOperation({
    summary: 'Get session screen',
    description: 'Retrieves the current screen of the WAHA session. Requires SESSIONS_READ permission.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Screen retrieved successfully',
    content: {
      'image/png': {
        schema: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: 'Session not found',
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Insufficient permissions',
  })
  async getSessionScreen(
    @Param('id') sessionId: string,
    @TenantId() tenantId: string,
    @Res() res: Response,
  ): Promise<void> {
    const screenBuffer = await this.wahaService.getSessionScreen(sessionId, tenantId);
    
    res.set({
      'Content-Type': 'image/png',
      'Content-Length': screenBuffer.length.toString(),
    });
    
    res.send(screenBuffer);
  }

  @Get('health')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({
    summary: 'Check WAHA service health',
    description: 'Checks the health status of the WAHA service.',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'WAHA service health information',
    type: WahaHealthResponse,
  })
  @ApiResponse({
    status: HttpStatus.SERVICE_UNAVAILABLE,
    description: 'WAHA service is unavailable',
  })
  async checkHealth(): Promise<WahaHealthResponse> {
    return this.wahaService.checkHealth();
  }
}
