/**
 * Configuration management for Fortress JavaScript/TypeScript SDK
 */

import { EncryptionProfile, StorageConfig, AuditConfig, PolicyConfig, TenantConfig } from './types';

/**
 * Fortress configuration class
 */
export class FortressConfig {
  private _encryptionProfile: EncryptionProfile;
  private _storageConfig: StorageConfig;
  private _auditConfig: AuditConfig;
  private _policyConfig: PolicyConfig;
  private _tenantConfig: TenantConfig;
  private _debug: boolean;
  private _logLevel: 'debug' | 'info' | 'warn' | 'error';

  constructor(options?: Partial<FortressConfigOptions>) {
    const defaults: FortressConfigOptions = {
      encryptionProfile: {
        name: 'default',
        algorithm: 'aegis256',
        key_size: 32,
        nonce_size: 12,
        tag_size: 16,
      },
      storageConfig: {
        backend: 'memory',
        max_connections: 10,
        timeout_ms: 5000,
        retry_attempts: 3,
        cache_size: 1000,
      },
      auditConfig: {
        enabled: true,
        log_level: 'info',
        storage_backend: {
          backend: 'memory',
        },
        retention_days: 30,
        batch_size: 100,
        flush_interval_ms: 1000,
      },
      policyConfig: {
        name: 'default',
        version: '1.0.0',
        rules: [],
        default_action: 'deny',
        evaluation_mode: 'all',
      },
      tenantConfig: {
        id: 'default',
        name: 'Default Tenant',
        isolation_level: 'strict',
        resource_limits: {
          max_keys: 1000,
          max_storage_bytes: 1024 * 1024 * 1024, // 1GB
          max_encryptions_per_hour: 10000,
          max_decryptions_per_hour: 10000,
          max_concurrent_operations: 100,
        },
        encryption_profile: 'default',
        audit_config: {
          enabled: true,
          log_level: 'info',
          storage_backend: {
            backend: 'memory',
          },
        },
        policy_config: {
          name: 'default',
          version: '1.0.0',
          rules: [],
          default_action: 'deny',
          evaluation_mode: 'all',
        },
      },
      debug: false,
      logLevel: 'info',
    };

    const config = { ...defaults, ...options };
    
    this._encryptionProfile = config.encryptionProfile!;
    this._storageConfig = config.storageConfig!;
    this._auditConfig = config.auditConfig!;
    this._policyConfig = config.policyConfig!;
    this._tenantConfig = config.tenantConfig!;
    this._debug = config.debug!;
    this._logLevel = config.logLevel!;
  }

  // Getters
  get encryptionProfile(): EncryptionProfile {
    return this._encryptionProfile;
  }

  get storageConfig(): StorageConfig {
    return this._storageConfig;
  }

  get auditConfig(): AuditConfig {
    return this._auditConfig;
  }

  get policyConfig(): PolicyConfig {
    return this._policyConfig;
  }

  get tenantConfig(): TenantConfig {
    return this._tenantConfig;
  }

  get debug(): boolean {
    return this._debug;
  }

  get logLevel(): string {
    return this._logLevel;
  }

  // Setters
  setEncryptionProfile(profile: EncryptionProfile): void {
    this._encryptionProfile = profile;
  }

  setStorageConfig(config: StorageConfig): void {
    this._storageConfig = config;
  }

  setAuditConfig(config: AuditConfig): void {
    this._auditConfig = config;
  }

  setPolicyConfig(config: PolicyConfig): void {
    this._policyConfig = config;
  }

  setTenantConfig(config: TenantConfig): void {
    this._tenantConfig = config;
  }

  setDebug(debug: boolean): void {
    this._debug = debug;
  }

  setLogLevel(level: 'debug' | 'info' | 'warn' | 'error'): void {
    this._logLevel = level;
  }

  // Utility methods
  clone(): FortressConfig {
    return new FortressConfig({
      encryptionProfile: { ...this._encryptionProfile },
      storageConfig: { ...this._storageConfig },
      auditConfig: { ...this._auditConfig },
      policyConfig: { ...this._policyConfig },
      tenantConfig: { ...this._tenantConfig },
      debug: this._debug,
      logLevel: this._logLevel,
    });
  }

  toJSON(): object {
    return {
      encryptionProfile: this._encryptionProfile,
      storageConfig: this._storageConfig,
      auditConfig: this._auditConfig,
      policyConfig: this._policyConfig,
      tenantConfig: this._tenantConfig,
      debug: this._debug,
      logLevel: this._logLevel,
    };
  }

  static fromJSON(json: string): FortressConfig {
    const config = JSON.parse(json);
    return new FortressConfig(config);
  }

  // Predefined configurations
  static lightning(): FortressConfig {
    return new FortressConfig({
      encryptionProfile: {
        name: 'lightning',
        algorithm: 'chacha20poly1305',
        key_size: 32,
        nonce_size: 12,
        tag_size: 16,
      },
      storageConfig: {
        backend: 'memory',
        max_connections: 50,
        timeout_ms: 1000,
        retry_attempts: 1,
        cache_size: 10000,
      },
      auditConfig: {
        enabled: false,
        log_level: 'error',
        storage_backend: {
          backend: 'memory',
        },
      },
      debug: false,
      logLevel: 'error',
    });
  }

  static balanced(): FortressConfig {
    return new FortressConfig({
      encryptionProfile: {
        name: 'balanced',
        algorithm: 'aegis256',
        key_size: 32,
        nonce_size: 12,
        tag_size: 16,
      },
      storageConfig: {
        backend: 'memory',
        max_connections: 20,
        timeout_ms: 3000,
        retry_attempts: 2,
        cache_size: 5000,
      },
      auditConfig: {
        enabled: true,
        log_level: 'info',
        storage_backend: {
          backend: 'memory',
        },
        retention_days: 7,
      },
      debug: false,
      logLevel: 'info',
    });
  }

  static fortress(): FortressConfig {
    return new FortressConfig({
      encryptionProfile: {
        name: 'fortress',
        algorithm: 'aegis256',
        key_size: 32,
        nonce_size: 12,
        tag_size: 16,
        iterations: 3,
      },
      storageConfig: {
        backend: 'file',
        max_connections: 10,
        timeout_ms: 5000,
        retry_attempts: 3,
        cache_size: 1000,
      },
      auditConfig: {
        enabled: true,
        log_level: 'info',
        storage_backend: {
          backend: 'file',
        },
        retention_days: 30,
        batch_size: 100,
        flush_interval_ms: 1000,
      },
      debug: false,
      logLevel: 'info',
    });
  }

  static enterprise(): FortressConfig {
    return new FortressConfig({
      encryptionProfile: {
        name: 'enterprise',
        algorithm: 'composite_encrypt',
        key_size: 64,
        nonce_size: 16,
        tag_size: 32,
        iterations: 5,
        memory_limit: 1024 * 1024 * 64, // 64MB
      },
      storageConfig: {
        backend: 'postgres',
        max_connections: 100,
        timeout_ms: 10000,
        retry_attempts: 5,
        cache_size: 50000,
      },
      auditConfig: {
        enabled: true,
        log_level: 'debug',
        storage_backend: {
          backend: 'postgres',
        },
        retention_days: 365,
        batch_size: 1000,
        flush_interval_ms: 500,
      },
      debug: true,
      logLevel: 'debug',
    });
  }
}

export interface FortressConfigOptions {
  encryptionProfile?: EncryptionProfile;
  storageConfig?: StorageConfig;
  auditConfig?: AuditConfig;
  policyConfig?: PolicyConfig;
  tenantConfig?: TenantConfig;
  debug?: boolean;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}
