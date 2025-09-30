import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HttpModule } from '@nestjs/axios';
import { WahaSession } from './entities/waha-session.entity';
import { Tenant } from '../tenants/entities/tenant.entity';
import { WahaService } from './waha.service';
import { WahaController } from './waha.controller';
import { WahaClientService } from './services/waha-client.service';
import { RbacModule } from '../common/rbac.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([WahaSession, Tenant]),
    HttpModule.register({
      timeout: 30000,
      maxRedirects: 5,
    }),
    RbacModule,
    AuthModule,
  ],
  controllers: [WahaController],
  providers: [
    WahaService,
    WahaClientService,
  ],
  exports: [
    WahaService,
    WahaClientService,
  ],
})
export class WahaModule {}
