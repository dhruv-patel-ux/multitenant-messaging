import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Tenant } from './entities/tenant.entity';
import { User } from '../users/entities/user.entity';
import { WahaSession } from '../waha/entities/waha-session.entity';
import { Message } from '../messages/entities/message.entity';
import { TenantsService } from './tenants.service';
import { TenantsController } from './tenants.controller';
import { PlatformAdminService } from './services/platform-admin.service';
import { TenantBootstrapService } from './services/tenant-bootstrap.service';
import { RbacModule } from '../common/rbac.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Tenant, User, WahaSession, Message]),
    RbacModule,
    AuthModule,
  ],
  controllers: [TenantsController],
  providers: [
    TenantsService,
    PlatformAdminService,
    TenantBootstrapService,
  ],
  exports: [
    TenantsService,
    PlatformAdminService,
    TenantBootstrapService,
  ],
})
export class TenantsModule {}
