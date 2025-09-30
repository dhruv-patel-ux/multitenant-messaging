import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, SelectQueryBuilder, FindOptionsWhere, DeepPartial } from 'typeorm';
import { BaseEntity } from '../entities/base.entity';

export interface TenantContext {
  tenantId: string;
  userId?: string;
  userRole?: string;
}

@Injectable()
export class TenantAwareRepository<T extends BaseEntity> {
  constructor(
    private repository: Repository<T>,
    private tenantContext: TenantContext,
  ) {}

  // Create a tenant-aware query builder
  createQueryBuilder(alias?: string): SelectQueryBuilder<T> {
    const qb = this.repository.createQueryBuilder(alias);
    return qb.andWhere(`${alias || 'entity'}.tenantId = :tenantId`, {
      tenantId: this.tenantContext.tenantId,
    });
  }

  // Find with tenant isolation
  async find(options?: FindOptionsWhere<T>): Promise<T[]> {
    const tenantOptions = {
      ...options,
      tenantId: this.tenantContext.tenantId,
    } as any;
    return this.repository.find({ where: tenantOptions });
  }

  // Find one with tenant isolation
  async findOne(options: FindOptionsWhere<T>): Promise<T | null> {
    const tenantOptions = {
      ...options,
      tenantId: this.tenantContext.tenantId,
    } as any;
    return this.repository.findOne({ where: tenantOptions });
  }

  // Save with tenant context
  async save(entity: DeepPartial<T>): Promise<T> {
    const entityWithTenant: DeepPartial<T> = {
      ...entity,
      tenantId: this.tenantContext.tenantId,
    } as DeepPartial<T>;
    return this.repository.save(entityWithTenant);
  }

  // Update with tenant isolation
  async update(criteria: FindOptionsWhere<T>, partialEntity: Partial<T>): Promise<void> {
    const tenantCriteria = {
      ...criteria,
      tenantId: this.tenantContext.tenantId,
    } as any;
    await this.repository.update(tenantCriteria, partialEntity as any);
  }

  // Delete with tenant isolation
  async delete(criteria: FindOptionsWhere<T>): Promise<void> {
    const tenantCriteria = {
      ...criteria,
      tenantId: this.tenantContext.tenantId,
    } as any;
    await this.repository.delete(tenantCriteria);
  }

  // Count with tenant isolation
  async count(options?: FindOptionsWhere<T>): Promise<number> {
    const tenantOptions = {
      ...options,
      tenantId: this.tenantContext.tenantId,
    } as any;
    return this.repository.count({ where: tenantOptions });
  }

  // Check if entity exists with tenant isolation
  async exists(options: FindOptionsWhere<T>): Promise<boolean> {
    const tenantOptions = {
      ...options,
      tenantId: this.tenantContext.tenantId,
    } as any;
    const count = await this.repository.count({ where: tenantOptions });
    return count > 0;
  }
}

// Factory for creating tenant-aware repositories
@Injectable()
export class TenantAwareRepositoryFactory {
  create<T extends BaseEntity>(
    repository: Repository<T>,
    tenantContext: TenantContext,
  ): TenantAwareRepository<T> {
    return new TenantAwareRepository(repository, tenantContext);
  }
}
