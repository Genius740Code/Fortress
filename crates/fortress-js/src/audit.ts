/**
 * Audit logging functionality for Fortress JavaScript/TypeScript SDK
 */

import { FortressConfig } from './config';
import { FortressError } from './error';
import { AuditEntry, Resource } from './types';

/**
 * Audit logger class
 */
export class AuditLogger {
  private config: FortressConfig;
  private entries: AuditEntry[];

  constructor(config: FortressConfig) {
    this.config = config;
    this.entries = [];
  }

  /**
   * Log an audit entry
   */
  async log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<void> {
    try {
      if (!this.config.auditConfig.enabled) {
        return;
      }

      const auditEntry: AuditEntry = {
        id: this.generateId(),
        timestamp: new Date(),
        ...entry,
      };

      this.entries.push(auditEntry);

      // Batch flush if needed
      if (this.entries.length >= this.config.auditConfig.batch_size!) {
        await this.flush();
      }
    } catch (error) {
      throw FortressError.audit('Failed to log audit entry', error as Error);
    }
  }

  /**
   * Log successful operation
   */
  async logSuccess(
    tenantId: string,
    userId: string,
    action: string,
    resource: Resource,
    metadata?: any
  ): Promise<void> {
    await this.log({
      tenant_id: tenantId,
      user_id: userId,
      action,
      resource,
      result: 'success',
      metadata,
    });
  }

  /**
   * Log failed operation
   */
  async logFailure(
    tenantId: string,
    userId: string,
    action: string,
    resource: Resource,
    error: string,
    metadata?: any
  ): Promise<void> {
    await this.log({
      tenant_id: tenantId,
      user_id: userId,
      action,
      resource,
      result: 'failure',
      error,
      metadata,
    });
  }

  /**
   * Query audit entries
   */
  async query(options: AuditQueryOptions = {}): Promise<AuditEntry[]> {
    try {
      let entries = [...this.entries];

      // Filter by tenant
      if (options.tenantId) {
        entries = entries.filter(entry => entry.tenant_id === options.tenantId);
      }

      // Filter by user
      if (options.userId) {
        entries = entries.filter(entry => entry.user_id === options.userId);
      }

      // Filter by action
      if (options.action) {
        entries = entries.filter(entry => entry.action === options.action);
      }

      // Filter by resource type
      if (options.resourceType) {
        entries = entries.filter(entry => entry.resource.type === options.resourceType);
      }

      // Filter by result
      if (options.result) {
        entries = entries.filter(entry => entry.result === options.result);
      }

      // Filter by date range
      if (options.startDate) {
        entries = entries.filter(entry => entry.timestamp >= options.startDate!);
      }

      if (options.endDate) {
        entries = entries.filter(entry => entry.timestamp <= options.endDate!);
      }

      // Sort by timestamp (newest first)
      entries.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

      // Apply pagination
      if (options.offset) {
        entries = entries.slice(options.offset);
      }

      if (options.limit) {
        entries = entries.slice(0, options.limit);
      }

      return entries;
    } catch (error) {
      throw FortressError.audit('Failed to query audit entries', error as Error);
    }
  }

  /**
   * Get audit statistics
   */
  async getStats(options?: AuditStatsOptions): Promise<AuditStats> {
    try {
      const entries = await this.query(options);
      
      const stats: AuditStats = {
        totalEntries: entries.length,
        successfulOperations: entries.filter(e => e.result === 'success').length,
        failedOperations: entries.filter(e => e.result === 'failure').length,
        uniqueUsers: new Set(entries.map(e => e.user_id).filter(Boolean)).size,
        uniqueActions: new Set(entries.map(e => e.action)).size,
        timeRange: {
          start: entries.length > 0 ? entries[entries.length - 1].timestamp : new Date(),
          end: entries.length > 0 ? entries[0].timestamp : new Date(),
        },
      };

      return stats;
    } catch (error) {
      throw FortressError.audit('Failed to get audit statistics', error as Error);
    }
  }

  /**
   * Flush audit entries to storage
   */
  async flush(): Promise<void> {
    try {
      if (this.entries.length === 0) {
        return;
      }

      // Create a snapshot of entries to flush
      const entriesToFlush = [...this.entries];
      
      // Store audit entries in batches to avoid memory issues
      const batchSize = 100;
      for (let i = 0; i < entriesToFlush.length; i += batchSize) {
        const batch = entriesToFlush.slice(i, i + batchSize);
        const batchKey = `audit_batch_${Date.now()}_${i}`;
        
        // Serialize the batch
        const serializedBatch = JSON.stringify(batch);
        const data = new TextEncoder().encode(serializedBatch);
        
        // Store using the configured storage backend
        // Note: In a real implementation, this would use the Fortress storage backend
        // For now, we'll store in localStorage if available, otherwise memory
        if (typeof localStorage !== 'undefined') {
          try {
            localStorage.setItem(batchKey, serializedBatch);
          } catch (error) {
            console.warn('Failed to store audit batch in localStorage:', error);
            // Fallback to memory storage
            this.storeInMemory(batchKey, data);
          }
        } else {
          // Node.js or environment without localStorage
          this.storeInMemory(batchKey, data);
        }
      }
      
      // Clear flushed entries from memory
      this.entries = this.entries.slice(entriesToFlush.length);
      
    } catch (error) {
      throw FortressError.audit('Failed to flush audit entries', error as Error);
    }
  }

  /**
   * Store data in memory as fallback
   */
  private storeInMemory(key: string, data: Uint8Array): void {
    // Simple in-memory storage fallback
    // In a real implementation, this would use the Fortress storage backend
    if (!(globalThis as any)._fortressAuditStorage) {
      (globalThis as any)._fortressAuditStorage = new Map();
    }
    (globalThis as any)._fortressAuditStorage.set(key, data);
  }

  /**
   * Clear old audit entries based on retention policy
   */
  async cleanup(): Promise<void> {
    try {
      const retentionDays = this.config.auditConfig.retention_days || 30;
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      this.entries = this.entries.filter(entry => entry.timestamp >= cutoffDate);
    } catch (error) {
      throw FortressError.audit('Failed to cleanup audit entries', error as Error);
    }
  }

  /**
   * Generate unique ID for audit entries
   */
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  }
}

export interface AuditQueryOptions {
  tenantId?: string;
  userId?: string;
  action?: string;
  resourceType?: string;
  result?: 'success' | 'failure';
  startDate?: Date;
  endDate?: Date;
  offset?: number;
  limit?: number;
}

export interface AuditStatsOptions extends AuditQueryOptions {}

export interface AuditStats {
  totalEntries: number;
  successfulOperations: number;
  failedOperations: number;
  uniqueUsers: number;
  uniqueActions: number;
  timeRange: {
    start: Date;
    end: Date;
  };
}
