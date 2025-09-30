import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Message } from './entities/message.entity';
import { WahaSession } from '../waha/entities/waha-session.entity';
import { Tenant } from '../tenants/entities/tenant.entity';
import { MessagesService } from './messages.service';
import { MessagesController } from './messages.controller';
import { RbacModule } from '../common/rbac.module';
import { WahaModule } from '../waha/waha.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Message, WahaSession, Tenant]),
    RbacModule,
    WahaModule,
  ],
  controllers: [MessagesController],
  providers: [MessagesService],
  exports: [MessagesService],
})
export class MessagesModule {}
