import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialSchema1700000000000 implements MigrationInterface {
  name = 'InitialSchema1700000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create tenants table
    await queryRunner.query(`
      CREATE TABLE "tenants" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "name" character varying(100) NOT NULL,
        "status" character varying NOT NULL DEFAULT 'active',
        "description" text,
        "settings" jsonb,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt" TIMESTAMP NOT NULL DEFAULT now(),
        "deletedAt" TIMESTAMP,
        CONSTRAINT "PK_tenants_id" PRIMARY KEY ("id")
      )
    `);

    // Create unique index on tenant name
    await queryRunner.query(`
      CREATE UNIQUE INDEX "IDX_tenants_name" ON "tenants" ("name")
    `);

    // Create users table
    await queryRunner.query(`
      CREATE TABLE "users" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "tenantId" uuid NOT NULL,
        "email" character varying(255) NOT NULL,
        "passwordHash" character varying(255) NOT NULL,
        "firstName" character varying(100) NOT NULL,
        "lastName" character varying(100) NOT NULL,
        "role" character varying NOT NULL DEFAULT 'AGENT',
        "isActive" boolean NOT NULL DEFAULT true,
        "lastLoginAt" TIMESTAMP,
        "preferences" jsonb,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt" TIMESTAMP NOT NULL DEFAULT now(),
        "deletedAt" TIMESTAMP,
        CONSTRAINT "PK_users_id" PRIMARY KEY ("id")
      )
    `);

    // Create unique index on email + tenantId
    await queryRunner.query(`
      CREATE UNIQUE INDEX "IDX_users_email_tenant" ON "users" ("email", "tenantId")
    `);

    // Create index on tenantId
    await queryRunner.query(`
      CREATE INDEX "IDX_users_tenantId" ON "users" ("tenantId")
    `);

    // Create waha_sessions table
    await queryRunner.query(`
      CREATE TABLE "waha_sessions" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "tenantId" uuid NOT NULL,
        "externalSessionId" character varying(255) NOT NULL,
        "status" character varying NOT NULL DEFAULT 'starting',
        "engine" character varying NOT NULL DEFAULT 'WEBJS',
        "metadata" jsonb,
        "lastActivityAt" TIMESTAMP,
        "errorMessage" text,
        "config" jsonb,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt" TIMESTAMP NOT NULL DEFAULT now(),
        "deletedAt" TIMESTAMP,
        CONSTRAINT "PK_waha_sessions_id" PRIMARY KEY ("id")
      )
    `);

    // Create unique index on externalSessionId
    await queryRunner.query(`
      CREATE UNIQUE INDEX "IDX_waha_sessions_externalSessionId" ON "waha_sessions" ("externalSessionId")
    `);

    // Create indexes on waha_sessions
    await queryRunner.query(`
      CREATE INDEX "IDX_waha_sessions_tenantId" ON "waha_sessions" ("tenantId")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_waha_sessions_status" ON "waha_sessions" ("status")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_waha_sessions_engine" ON "waha_sessions" ("engine")
    `);

    // Create messages table
    await queryRunner.query(`
      CREATE TABLE "messages" (
        "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
        "tenantId" uuid NOT NULL,
        "sessionId" uuid NOT NULL,
        "direction" character varying NOT NULL,
        "toMsisdn" character varying(20) NOT NULL,
        "fromMsisdn" character varying(20) NOT NULL,
        "body" text NOT NULL,
        "type" character varying NOT NULL DEFAULT 'text',
        "status" character varying NOT NULL DEFAULT 'queued',
        "wahaMessageId" character varying(255),
        "rawPayload" jsonb,
        "metadata" jsonb,
        "errorMessage" text,
        "sentAt" TIMESTAMP,
        "deliveredAt" TIMESTAMP,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt" TIMESTAMP NOT NULL DEFAULT now(),
        "deletedAt" TIMESTAMP,
        CONSTRAINT "PK_messages_id" PRIMARY KEY ("id")
      )
    `);

    // Create indexes on messages table
    await queryRunner.query(`
      CREATE INDEX "IDX_messages_tenantId" ON "messages" ("tenantId")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_messages_sessionId" ON "messages" ("sessionId")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_messages_direction" ON "messages" ("direction")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_messages_status" ON "messages" ("status")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_messages_toMsisdn" ON "messages" ("toMsisdn")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_messages_fromMsisdn" ON "messages" ("fromMsisdn")
    `);
    await queryRunner.query(`
      CREATE INDEX "IDX_messages_createdAt" ON "messages" ("createdAt")
    `);

    // Add foreign key constraints
    await queryRunner.query(`
      ALTER TABLE "users" 
      ADD CONSTRAINT "FK_users_tenantId" 
      FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE
    `);

    await queryRunner.query(`
      ALTER TABLE "waha_sessions" 
      ADD CONSTRAINT "FK_waha_sessions_tenantId" 
      FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE
    `);

    await queryRunner.query(`
      ALTER TABLE "messages" 
      ADD CONSTRAINT "FK_messages_tenantId" 
      FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE
    `);

    await queryRunner.query(`
      ALTER TABLE "messages" 
      ADD CONSTRAINT "FK_messages_sessionId" 
      FOREIGN KEY ("sessionId") REFERENCES "waha_sessions"("id") ON DELETE CASCADE
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop foreign key constraints
    await queryRunner.query(`ALTER TABLE "messages" DROP CONSTRAINT "FK_messages_sessionId"`);
    await queryRunner.query(`ALTER TABLE "messages" DROP CONSTRAINT "FK_messages_tenantId"`);
    await queryRunner.query(`ALTER TABLE "waha_sessions" DROP CONSTRAINT "FK_waha_sessions_tenantId"`);
    await queryRunner.query(`ALTER TABLE "users" DROP CONSTRAINT "FK_users_tenantId"`);

    // Drop tables
    await queryRunner.query(`DROP TABLE "messages"`);
    await queryRunner.query(`DROP TABLE "waha_sessions"`);
    await queryRunner.query(`DROP TABLE "users"`);
    await queryRunner.query(`DROP TABLE "tenants"`);
  }
}
