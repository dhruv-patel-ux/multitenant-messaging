import {
  Controller,
  Get,
  Post,
  Put,
  Body,
  Param,
  Query,
  UseGuards,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/auth.guards';
import { RoleGuard, Roles, RequirePermissions } from '../common/guards/role.guard';
import { TenantGuard } from '../common/guards/tenant.guard';
import { CurrentUser, CurrentTenant, TenantId } from '../common/decorators/authorization.decorators';
import { UserRole, Permission } from '../common/enums/roles.enum';
import { TenantsService } from './tenants.service';
import {
  CreateTenantDto,
  UpdateTenantDto,
  TenantResponseDto,
  TenantStatsDto,
  PaginationDto,
  PaginatedResponse,
  DeactivateTenantDto,
} from './dto/tenant.dto';
import { User } from '../users/entities/user.entity';
import { WahaSession } from '../waha/entities/waha-session.entity';

@ApiTags('Tenants')
@Controller('tenants')
@UseGuards(JwtAuthGuard)
export class TenantsController {
  constructor(private readonly tenantsService: TenantsService) {}

  // Platform admin endpoints
  @Post()
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.TENANT_READ) // Platform admin permission
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Create new tenant (Platform Admin only)',
    description: 'Creates a new tenant with an admin user. Only platform administrators can perform this action.',
  })
  @ApiResponse({ 
    status: HttpStatus.CREATED, 
    description: 'Tenant created successfully',
    type: TenantResponseDto,
  })
  @ApiResponse({ 
    status: HttpStatus.CONFLICT, 
    description: 'Tenant name or admin email already exists',
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async create(@Body() createTenantDto: CreateTenantDto): Promise<TenantResponseDto> {
    return this.tenantsService.create(createTenantDto);
  }

  @Get()
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.TENANT_READ) // Platform admin permission
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'List all tenants (Platform Admin only)',
    description: 'Retrieves a paginated list of all tenants. Only platform administrators can perform this action.',
  })
  @ApiResponse({ 
    status: HttpStatus.OK, 
    description: 'Tenants retrieved successfully',
    type: [TenantResponseDto],
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async findAll(@Query() pagination: PaginationDto): Promise<PaginatedResponse<TenantResponseDto>> {
    return this.tenantsService.findAll(pagination);
  }

  @Get(':id')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.TENANT_READ) // Platform admin permission
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Tenant ID', type: 'string' })
  @ApiOperation({ 
    summary: 'Get tenant details (Platform Admin only)',
    description: 'Retrieves detailed information about a specific tenant. Only platform administrators can perform this action.',
  })
  @ApiResponse({ 
    status: HttpStatus.OK, 
    description: 'Tenant details retrieved successfully',
    type: TenantResponseDto,
  })
  @ApiResponse({ 
    status: HttpStatus.NOT_FOUND, 
    description: 'Tenant not found',
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async findOne(@Param('id') id: string): Promise<TenantResponseDto> {
    return this.tenantsService.findOne(id);
  }

  @Put(':id')
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.TENANT_UPDATE) // Platform admin permission
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Tenant ID', type: 'string' })
  @ApiOperation({ 
    summary: 'Update tenant (Platform Admin only)',
    description: 'Updates tenant information. Only platform administrators can perform this action.',
  })
  @ApiResponse({ 
    status: HttpStatus.OK, 
    description: 'Tenant updated successfully',
    type: TenantResponseDto,
  })
  @ApiResponse({ 
    status: HttpStatus.NOT_FOUND, 
    description: 'Tenant not found',
  })
  @ApiResponse({ 
    status: HttpStatus.CONFLICT, 
    description: 'Tenant name already exists',
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async update(
    @Param('id') id: string,
    @Body() updateTenantDto: UpdateTenantDto,
  ): Promise<TenantResponseDto> {
    return this.tenantsService.update(id, updateTenantDto);
  }

  @Put(':id/deactivate')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(RoleGuard)
  @RequirePermissions(Permission.TENANT_DELETE) // Platform admin permission
  @ApiBearerAuth('JWT-auth')
  @ApiParam({ name: 'id', description: 'Tenant ID', type: 'string' })
  @ApiOperation({ 
    summary: 'Deactivate tenant (Platform Admin only)',
    description: 'Deactivates a tenant. Only platform administrators can perform this action.',
  })
  @ApiResponse({ 
    status: HttpStatus.NO_CONTENT, 
    description: 'Tenant deactivated successfully',
  })
  @ApiResponse({ 
    status: HttpStatus.NOT_FOUND, 
    description: 'Tenant not found',
  })
  @ApiResponse({ 
    status: HttpStatus.BAD_REQUEST, 
    description: 'Cannot deactivate tenant with active users',
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async deactivate(
    @Param('id') id: string,
    @Body() deactivateDto: DeactivateTenantDto,
  ): Promise<void> {
    return this.tenantsService.deactivate(id, deactivateDto);
  }

  // Tenant-specific endpoints
  @Get('current/stats')
  @UseGuards(TenantGuard)
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN, UserRole.MANAGER, UserRole.AUDITOR)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get current tenant statistics',
    description: 'Retrieves statistics for the current tenant. Available to tenant admins, managers, and auditors.',
  })
  @ApiResponse({ 
    status: HttpStatus.OK, 
    description: 'Tenant statistics retrieved successfully',
    type: TenantStatsDto,
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async getCurrentTenantStats(@TenantId() tenantId: string): Promise<TenantStatsDto> {
    return this.tenantsService.getTenantStats(tenantId);
  }

  @Get('current/users')
  @UseGuards(TenantGuard)
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN, UserRole.MANAGER, UserRole.AUDITOR)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get current tenant users',
    description: 'Retrieves all users for the current tenant. Available to tenant admins, managers, and auditors.',
  })
  @ApiResponse({ 
    status: HttpStatus.OK, 
    description: 'Tenant users retrieved successfully',
    type: [User],
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async getCurrentTenantUsers(@TenantId() tenantId: string): Promise<User[]> {
    return this.tenantsService.getTenantUsers(tenantId);
  }

  @Get('current/sessions')
  @UseGuards(TenantGuard)
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN, UserRole.MANAGER, UserRole.AGENT, UserRole.AUDITOR)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get current tenant WAHA sessions',
    description: 'Retrieves all WAHA sessions for the current tenant. Available to all tenant roles.',
  })
  @ApiResponse({ 
    status: HttpStatus.OK, 
    description: 'Tenant sessions retrieved successfully',
    type: [WahaSession],
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async getCurrentTenantSessions(@TenantId() tenantId: string): Promise<WahaSession[]> {
    return this.tenantsService.getTenantSessions(tenantId);
  }

  @Get('current')
  @UseGuards(TenantGuard)
  @UseGuards(RoleGuard)
  @Roles(UserRole.TENANT_ADMIN, UserRole.MANAGER, UserRole.AUDITOR)
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ 
    summary: 'Get current tenant details',
    description: 'Retrieves detailed information about the current tenant. Available to tenant admins, managers, and auditors.',
  })
  @ApiResponse({ 
    status: HttpStatus.OK, 
    description: 'Current tenant details retrieved successfully',
    type: TenantResponseDto,
  })
  @ApiResponse({ 
    status: HttpStatus.FORBIDDEN, 
    description: 'Insufficient permissions',
  })
  async getCurrentTenant(@TenantId() tenantId: string): Promise<TenantResponseDto> {
    const tenant = await this.tenantsService.findOne(tenantId);
    const stats = await this.tenantsService.getTenantStats(tenantId);
    
    return {
      ...tenant,
      stats,
    };
  }
}
