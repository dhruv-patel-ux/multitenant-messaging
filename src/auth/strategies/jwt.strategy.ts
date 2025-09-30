import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { Tenant, TenantStatus } from '../../tenants/entities/tenant.entity';
import { EnvironmentVariables } from '../../config/env.validation';

export interface JwtPayload {
  sub: string; // user id
  email: string;
  tenantId: string;
  role: string;
  iat: number;
  exp: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService<EnvironmentVariables>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Tenant)
    private tenantRepository: Repository<Tenant>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET') || 'default-secret',
    });
  }

  async validate(payload: JwtPayload): Promise<any> {
    const { sub: userId, tenantId } = payload;

    // Validate user exists and is active
    const user = await this.userRepository.findOne({
      where: { id: userId, isActive: true },
      relations: ['tenant'],
    });

    if (!user) {
      throw new UnauthorizedException('User not found or inactive');
    }

    // Validate tenant exists and is active
    const tenant = await this.tenantRepository.findOne({
      where: { id: tenantId, status: TenantStatus.ACTIVE },
    });

    if (!tenant) {
      throw new UnauthorizedException('Tenant not found or inactive');
    }

    // Add tenant context to the request
    return {
      ...user,
      tenant,
    };
  }
}
