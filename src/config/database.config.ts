import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { EnvironmentVariables } from './env.validation';

export const getDatabaseConfig = (
  configService: ConfigService<EnvironmentVariables>,
): TypeOrmModuleOptions => ({
  type: 'postgres',
  host: configService.get('DB_HOST'),
  port: configService.get('DB_PORT'),
  username: configService.get('DB_USERNAME'),
  password: configService.get('DB_PASSWORD'),
  database: configService.get('DB_DATABASE'),
  entities: [__dirname + '/../**/*.entity{.ts,.js}'],
  migrations: [__dirname + '/../migrations/*{.ts,.js}'],
  synchronize: configService.get('NODE_ENV') === 'development',
  logging: configService.get('NODE_ENV') === 'development',
  ssl: configService.get('NODE_ENV') === 'production' ? { rejectUnauthorized: false } : false,
  // Connection pooling configuration
  extra: {
    max: 20, // Maximum number of connections in the pool
    min: 5,  // Minimum number of connections in the pool
    acquireTimeoutMillis: 30000, // Maximum time to wait for a connection
    idleTimeoutMillis: 30000,    // Maximum time a connection can be idle
    connectionTimeoutMillis: 2000, // Maximum time to establish a connection
  },
});
