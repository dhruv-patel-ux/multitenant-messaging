import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class InitialSchema1700000000000 implements MigrationInterface {
  name = 'InitialSchema1700000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create tenants table
    await queryRunner.createTable(
      new Table({
        name: 'tenants',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'name',
            type: 'varchar',
            length: '100',
            isNullable: false,
          },
          {
            name: 'status',
            type: 'enum',
            enum: ['active', 'inactive'],
            default: "'active'",
          },
          {
            name: 'description',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'settings',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
            onUpdate: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'deletedAt',
            type: 'timestamp',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    // Create users table
    await queryRunner.createTable(
      new Table({
        name: 'users',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'email',
            type: 'varchar',
            length: '255',
            isNullable: false,
          },
          {
            name: 'passwordHash',
            type: 'varchar',
            length: '255',
            isNullable: false,
          },
          {
            name: 'firstName',
            type: 'varchar',
            length: '50',
            isNullable: false,
          },
          {
            name: 'lastName',
            type: 'varchar',
            length: '50',
            isNullable: false,
          },
          {
            name: 'role',
            type: 'enum',
            enum: ['TENANT_ADMIN', 'MANAGER', 'AGENT', 'AUDITOR'],
            default: "'AGENT'",
          },
          {
            name: 'isActive',
            type: 'boolean',
            default: true,
          },
          {
            name: 'lastLoginAt',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'preferences',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'tenantId',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
            onUpdate: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'deletedAt',
            type: 'timestamp',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    // Create waha_sessions table
    await queryRunner.createTable(
      new Table({
        name: 'waha_sessions',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'externalSessionId',
            type: 'varchar',
            length: '255',
            isNullable: false,
          },
          {
            name: 'status',
            type: 'enum',
            enum: ['starting', 'scan_qr', 'working', 'failed', 'stopped'],
            default: "'starting'",
          },
          {
            name: 'engine',
            type: 'enum',
            enum: ['WEBJS', 'NOWEB'],
            default: "'WEBJS'",
          },
          {
            name: 'metadata',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'config',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'lastActivityAt',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'errorMessage',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'tenantId',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
            onUpdate: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'deletedAt',
            type: 'timestamp',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    // Create refresh_tokens table
    await queryRunner.createTable(
      new Table({
        name: 'refresh_tokens',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'token',
            type: 'text',
            isNullable: false,
          },
          {
            name: 'expiresAt',
            type: 'timestamp',
            isNullable: false,
          },
          {
            name: 'userAgent',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'ipAddress',
            type: 'varchar',
            length: '45',
            isNullable: true,
          },
          {
            name: 'isRevoked',
            type: 'boolean',
            default: false,
          },
          {
            name: 'revokedAt',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'userId',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
            onUpdate: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'deletedAt',
            type: 'timestamp',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    // Create login_attempts table
    await queryRunner.createTable(
      new Table({
        name: 'login_attempts',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'email',
            type: 'varchar',
            length: '255',
            isNullable: false,
          },
          {
            name: 'ipAddress',
            type: 'varchar',
            length: '45',
            isNullable: false,
          },
          {
            name: 'isSuccessful',
            type: 'boolean',
            default: false,
          },
          {
            name: 'userAgent',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'failureReason',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
            onUpdate: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'deletedAt',
            type: 'timestamp',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    // Create messages table
    await queryRunner.createTable(
      new Table({
        name: 'messages',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'direction',
            type: 'enum',
            enum: ['inbound', 'outbound'],
            isNullable: false,
          },
          {
            name: 'toMsisdn',
            type: 'varchar',
            length: '20',
            isNullable: false,
          },
          {
            name: 'fromMsisdn',
            type: 'varchar',
            length: '20',
            isNullable: false,
          },
          {
            name: 'body',
            type: 'text',
            isNullable: false,
          },
          {
            name: 'status',
            type: 'enum',
            enum: ['queued', 'sent', 'delivered', 'failed'],
            default: "'queued'",
          },
          {
            name: 'wahaMessageId',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'rawPayload',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'messageType',
            type: 'varchar',
            length: '50',
            isNullable: true,
          },
          {
            name: 'mediaUrl',
            type: 'varchar',
            length: '500',
            isNullable: true,
          },
          {
            name: 'metadata',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'errorMessage',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'deliveredAt',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'tenantId',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'sessionId',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP(6)',
            onUpdate: 'CURRENT_TIMESTAMP(6)',
          },
          {
            name: 'deletedAt',
            type: 'timestamp',
            isNullable: true,
          },
        ],
      }),
      true,
    );

    // Create foreign key constraints
    await queryRunner.query(
      `ALTER TABLE "users" ADD CONSTRAINT "FK_users_tenantId" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );

    await queryRunner.query(
      `ALTER TABLE "waha_sessions" ADD CONSTRAINT "FK_waha_sessions_tenantId" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );

    await queryRunner.query(
      `ALTER TABLE "messages" ADD CONSTRAINT "FK_messages_tenantId" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );

    await queryRunner.query(
      `ALTER TABLE "messages" ADD CONSTRAINT "FK_messages_sessionId" FOREIGN KEY ("sessionId") REFERENCES "waha_sessions"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );

    await queryRunner.query(
      `ALTER TABLE "refresh_tokens" ADD CONSTRAINT "FK_refresh_tokens_userId" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`,
    );

    // Create indexes for performance
    await queryRunner.query(`CREATE UNIQUE INDEX "IDX_tenants_name" ON "tenants" ("name")`);
    
    await queryRunner.query(`CREATE UNIQUE INDEX "IDX_users_email_tenantId" ON "users" ("email", "tenantId")`);
    await queryRunner.query(`CREATE INDEX "IDX_users_tenantId" ON "users" ("tenantId")`);
    
    await queryRunner.query(`CREATE UNIQUE INDEX "IDX_waha_sessions_externalSessionId" ON "waha_sessions" ("externalSessionId")`);
    await queryRunner.query(`CREATE INDEX "IDX_waha_sessions_tenantId" ON "waha_sessions" ("tenantId")`);
    await queryRunner.query(`CREATE INDEX "IDX_waha_sessions_status" ON "waha_sessions" ("status")`);
    
    await queryRunner.query(`CREATE INDEX "IDX_messages_tenantId" ON "messages" ("tenantId")`);
    await queryRunner.query(`CREATE INDEX "IDX_messages_sessionId" ON "messages" ("sessionId")`);
    await queryRunner.query(`CREATE INDEX "IDX_messages_toMsisdn" ON "messages" ("toMsisdn")`);
    await queryRunner.query(`CREATE INDEX "IDX_messages_fromMsisdn" ON "messages" ("fromMsisdn")`);
    await queryRunner.query(`CREATE INDEX "IDX_messages_status" ON "messages" ("status")`);
    await queryRunner.query(`CREATE INDEX "IDX_messages_createdAt" ON "messages" ("createdAt")`);
    await queryRunner.query(`CREATE UNIQUE INDEX "IDX_messages_wahaMessageId" ON "messages" ("wahaMessageId") WHERE "wahaMessageId" IS NOT NULL`);
    
    await queryRunner.query(`CREATE UNIQUE INDEX "IDX_refresh_tokens_token" ON "refresh_tokens" ("token")`);
    await queryRunner.query(`CREATE INDEX "IDX_refresh_tokens_userId" ON "refresh_tokens" ("userId")`);
    await queryRunner.query(`CREATE INDEX "IDX_refresh_tokens_expiresAt" ON "refresh_tokens" ("expiresAt")`);
    
    await queryRunner.query(`CREATE INDEX "IDX_login_attempts_email_ipAddress" ON "login_attempts" ("email", "ipAddress")`);
    await queryRunner.query(`CREATE INDEX "IDX_login_attempts_email" ON "login_attempts" ("email")`);
    await queryRunner.query(`CREATE INDEX "IDX_login_attempts_ipAddress" ON "login_attempts" ("ipAddress")`);
    await queryRunner.query(`CREATE INDEX "IDX_login_attempts_createdAt" ON "login_attempts" ("createdAt")`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop foreign key constraints
    await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP CONSTRAINT "FK_refresh_tokens_userId"`);
    await queryRunner.query(`ALTER TABLE "messages" DROP CONSTRAINT "FK_messages_sessionId"`);
    await queryRunner.query(`ALTER TABLE "messages" DROP CONSTRAINT "FK_messages_tenantId"`);
    await queryRunner.query(`ALTER TABLE "waha_sessions" DROP CONSTRAINT "FK_waha_sessions_tenantId"`);
    await queryRunner.query(`ALTER TABLE "users" DROP CONSTRAINT "FK_users_tenantId"`);

    // Drop tables
    await queryRunner.dropTable('login_attempts');
    await queryRunner.dropTable('refresh_tokens');
    await queryRunner.dropTable('messages');
    await queryRunner.dropTable('waha_sessions');
    await queryRunner.dropTable('users');
    await queryRunner.dropTable('tenants');
  }
}
