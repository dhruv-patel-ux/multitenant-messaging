import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Message } from '../messages/entities/message.entity';
import { Tenant } from '../tenants/entities/tenant.entity';
import { WebhooksService } from './webhooks.service';
import { WebhooksController } from './webhooks.controller';
import { MessagesModule } from '../messages/messages.module';
import { WahaModule } from '../waha/waha.module';
import { RbacModule } from '../common/rbac.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Message, Tenant]),
    MessagesModule,
    WahaModule,
    RbacModule,
  ],
  controllers: [WebhooksController],
  providers: [WebhooksService],
  exports: [WebhooksService],
})
export class WebhooksModule {}
