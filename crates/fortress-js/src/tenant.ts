/**
 * Tenant management functionality for Fortress JavaScript/TypeScript SDK
 */

import { FortressConfig } from './config';
import { FortressError } from './error';
import { TenantConfig, TenantStats, ResourceLimits } from './types';

/**
 * Tenant manager class
 */
export class TenantManager {
  private config: FortressConfig;
  private tenants: Map<string, TenantConfig>;
  private stats: Map<string, TenantStats>;

  constructor(config: FortressConfig) {
    this.config = config;
    this.tenants = new Map();
    this.stats = new Map();
    
    // Initialize with default tenant
    this.tenants.set('default', config.tenantConfig);
    this.stats.set('default', this.createDefaultStats('default'));
  }

  /**
   * Create a new tenant
   */
  async createTenant(config: Omit<TenantConfig, 'id'>): Promise<string> {
    try {
      const tenantId = this.generateId();
      const tenantConfig: TenantConfig = {
        id: tenantId,
        ...config,
      };

      this.tenants.set(tenantId, tenantConfig);
      this.stats.set(tenantId, this.createDefaultStats(tenantId));

      return tenantId;
    } catch (error) {
      throw FortressError.tenant('Failed to create tenant', error as Error);
    }
  }

  /**
   * Get tenant configuration
   */
  getTenant(tenantId: string): TenantConfig | null {
    return this.tenants.get(tenantId) || null;
  }

  /**
   * Update tenant configuration
   */
  async updateTenant(tenantId: string, updates: Partial<TenantConfig>): Promise<boolean> {
    try {
      const tenant = this.tenants.get(tenantId);
      if (!tenant) {
        return false;
      }

      const updatedTenant = { ...tenant, ...updates };
      this.tenants.set(tenantId, updatedTenant);

      return true;
    } catch (error) {
      throw FortressError.tenant('Failed to update tenant', error as Error);
    }
  }

  /**
   * Delete a tenant
   */
  async deleteTenant(tenantId: string): Promise<boolean> {
    try {
      const deleted = this.tenants.delete(tenantId);
      if (deleted) {
        this.stats.delete(tenantId);
      }
      return deleted;
    } catch (error) {
      throw FortressError.tenant('Failed to delete tenant', error as Error);
    }
  }

  /**
   * List all tenants
   */
  listTenants(): string[] {
    return Array.from(this.tenants.keys());
  }

  /**
   * Get tenant statistics
   */
  getTenantStats(tenantId: string): TenantStats | null {
    return this.stats.get(tenantId) || null;
  }

  /**
   * Update tenant statistics
   */
  async updateStats(tenantId: string, operation: 'encrypt' | 'decrypt'): Promise<void> {
    try {
      const stats = this.stats.get(tenantId);
      if (!stats) {
        return;
      }

      if (operation === 'encrypt') {
        stats.total_encryptions++;
      } else {
        stats.total_decryptions++;
      }

      stats.last_activity = new Date();
    } catch (error) {
      throw FortressError.tenant('Failed to update stats', error as Error);
    }
  }

  /**
   * Check resource limits
   */
  async checkResourceLimits(tenantId: string, resource: string, amount: number = 1): Promise<boolean> {
    try {
      const tenant = this.tenants.get(tenantId);
      const stats = this.stats.get(tenantId);
      
      if (!tenant || !stats) {
        return false;
      }

      const limits = tenant.resource_limits;

      switch (resource) {
        case 'keys':
          return stats.total_keys + amount <= limits.max_keys;
        case 'storage':
          return stats.storage_usage_bytes + amount <= limits.max_storage_bytes;
        case 'encryptions':
          return stats.total_encryptions + amount <= limits.max_encryptions_per_hour;
        case 'decryptions':
          return stats.total_decryptions + amount <= limits.max_decryptions_per_hour;
        case 'concurrent_operations':
          return amount <= limits.max_concurrent_operations;
        default:
          return true;
      }
    } catch (error) {
      throw FortressError.tenant('Failed to check resource limits', error as Error);
    }
  }

  /**
   * Get all tenant statistics
   */
  getAllStats(): Map<string, TenantStats> {
    return new Map(this.stats);
  }

  /**
   * Reset tenant statistics
   */
  async resetStats(tenantId: string): Promise<boolean> {
    try {
      const tenant = this.tenants.get(tenantId);
      if (!tenant) {
        return false;
      }

      this.stats.set(tenantId, this.createDefaultStats(tenantId));
      return true;
    } catch (error) {
      throw FortressError.tenant('Failed to reset stats', error as Error);
    }
  }

  /**
   * Validate tenant configuration
   */
  validateTenantConfig(config: TenantConfig): boolean {
    try {
      // Check required fields
      if (!config.id || !config.name || !config.isolation_level) {
        return false;
      }

      // Check resource limits
      const limits = config.resource_limits;
      if (limits.max_keys <= 0 || 
          limits.max_storage_bytes <= 0 ||
          limits.max_encryptions_per_hour <= 0 ||
          limits.max_decryptions_per_hour <= 0 ||
          limits.max_concurrent_operations <= 0) {
        return false;
      }

      // Check isolation level
      const validIsolationLevels = ['strict', 'shared', 'partial'];
      if (!validIsolationLevels.includes(config.isolation_level)) {
        return false;
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Create default statistics for a tenant
   */
  private createDefaultStats(tenantId: string): TenantStats {
    return {
      tenant_id: tenantId,
      total_keys: 0,
      active_keys: 0,
      total_encryptions: 0,
      total_decryptions: 0,
      storage_usage_bytes: 0,
      audit_entries: 0,
      last_activity: new Date(),
    };
  }

  /**
   * Generate unique ID for tenants
   */
  private generateId(): string {
    return 'tenant_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  }

  /**
   * Get tenant by isolation level
   */
  getTenantsByIsolationLevel(level: 'strict' | 'shared' | 'partial'): string[] {
    return Array.from(this.tenants.values())
      .filter(tenant => tenant.isolation_level === level)
      .map(tenant => tenant.id);
  }

  /**
   * Get tenants approaching resource limits
   */
  getTenantsNearLimits(threshold: number = 0.8): Array<{ tenantId: string; resource: string; usage: number; limit: number }> {
    const results: Array<{ tenantId: string; resource: string; usage: number; limit: number }> = [];

    for (const [tenantId, tenant] of this.tenants) {
      const stats = this.stats.get(tenantId);
      if (!stats) continue;

      const limits = tenant.resource_limits;

      // Check each resource
      const checks = [
        { resource: 'keys', usage: stats.total_keys, limit: limits.max_keys },
        { resource: 'storage', usage: stats.storage_usage_bytes, limit: limits.max_storage_bytes },
        { resource: 'encryptions', usage: stats.total_encryptions, limit: limits.max_encryptions_per_hour },
        { resource: 'decryptions', usage: stats.total_decryptions, limit: limits.max_decryptions_per_hour },
      ];

      for (const check of checks) {
        if (check.limit > 0 && (check.usage / check.limit) >= threshold) {
          results.push({
            tenantId,
            ...check,
          });
        }
      }
    }

    return results;
  }
}
