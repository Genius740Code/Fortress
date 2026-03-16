/**
 * Main Fortress class for JavaScript/TypeScript SDK
 */

import { FortressConfig } from './config';
import { EncryptionAlgorithm } from './encryption';
import { KeyManager } from './key-management';
import { StorageBackend } from './storage';
import { PolicyEngine } from './policy';
import { AuditLogger } from './audit';
import { TenantManager } from './tenant';
import { FortressError } from './error';
import { Utils } from './utils';
import { BuildInfo, CompatibilityInfo, EncryptionOptions, KeyGenerationOptions } from './types';
import { FortressConfigOptions } from './config';

// Import WASM module
interface FortressWasm {
  getVersion(): string;
  getBuildInfo(): any;
  listAlgorithms(): string[];
  checkWasmSupport(): boolean;
  getSupportedFeatures(): string[];
  createConfig(profile?: string): any;
}

let wasmModule: FortressWasm | null = null;

/**
 * Dynamically import the WASM module
 */
async function loadWasmModule(): Promise<FortressWasm> {
  if (wasmModule) {
    return wasmModule;
  }

  try {
    // Try to import the WASM module from the expected location
    // This will work when the package is properly built with wasm-pack
    // @ts-ignore - WASM module may not exist during development
    const module = await import('../pkg/fortress_js');
    wasmModule = module;
    return module;
  } catch (error) {
    // Fallback for development/testing when WASM isn't built yet
    console.warn('WASM module not available, using fallback implementation:', error);
    
    // Provide a fallback implementation that mimics the WASM interface
    const fallback: FortressWasm = {
      getVersion: () => '0.1.0-dev',
      getBuildInfo: () => ({
        timestamp: new Date().toISOString(),
        git_sha: 'development',
        rust_version: 'unknown',
        target: 'unknown',
      }),
      listAlgorithms: () => [
        'aegis256',
        'chacha20poly1305',
        'aes256gcm',
        'xchacha20poly1305',
        'blake3_encrypt',
        'hmacsha512_encrypt',
        'aes256ctr',
        'argon2id_encrypt',
        'composite_encrypt',
      ],
      checkWasmSupport: () => typeof WebAssembly !== 'undefined',
      getSupportedFeatures: () => [
        'encryption',
        'key_management',
        'storage',
        'configuration',
        'audit_logging',
        'policy_engine',
        'multi_tenant',
        'error_handling',
        'webassembly',
      ],
      createConfig: (profile?: string) => ({
        profile: profile || 'default',
        encryption: { algorithm: 'aegis256' },
        storage: { backend: 'memory' },
      }),
    };
    
    wasmModule = fallback;
    return fallback;
  }
}

/**
 * Main Fortress class providing access to all Fortress functionality
 */
export class Fortress {
  private config: FortressConfig;
  private keyManager!: KeyManager;
  private storage!: StorageBackend;
  private policyEngine!: PolicyEngine;
  private auditLogger!: AuditLogger;
  private tenantManager!: TenantManager;
  private utils: Utils;
  private initialized: boolean = false;

  constructor(config?: FortressConfig) {
    this.config = config || new FortressConfig();
    this.utils = new Utils();
  }

  /**
   * Initialize Fortress with the given configuration
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      // Initialize WASM module
      await loadWasmModule();

      // Initialize components
      this.keyManager = new KeyManager(this.config.encryptionProfile);
      this.storage = new StorageBackend(this.config.storageConfig);
      this.policyEngine = new PolicyEngine(this.config.policyConfig);
      this.auditLogger = new AuditLogger(this.config);
      this.tenantManager = new TenantManager(this.config);

      this.initialized = true;
    } catch (error) {
      throw new FortressError('Failed to initialize Fortress', 'INITIALIZATION_ERROR', error);
    }
  }

  /**
   * Get Fortress version information
   */
  async getVersion(): Promise<string> {
    const wasm = await loadWasmModule();
    return wasm.getVersion();
  }

  /**
   * Get Fortress build information
   */
  async getBuildInfo(): Promise<BuildInfo> {
    const wasm = await loadWasmModule();
    const wasmBuildInfo = wasm.getBuildInfo();
    
    return {
      timestamp: wasmBuildInfo.timestamp || new Date().toISOString(),
      git_sha: wasmBuildInfo.git_sha || 'unknown',
      rust_version: wasmBuildInfo.rust_version || 'unknown',
      target: wasmBuildInfo.target || 'unknown',
    };
  }

  /**
   * Get compatibility information
   */
  getCompatibilityInfo(): CompatibilityInfo {
    return {
      version: '0.1.0', // Fallback version for compatibility info
      api_version: '1.0.0',
      features: [
        'encryption',
        'key_management',
        'storage',
        'configuration',
        'audit_logging',
        'policy_engine',
        'multi_tenant',
        'error_handling',
        'webassembly',
      ],
      platform: typeof window !== 'undefined' ? 'browser' : 'node',
      arch: 'unknown', // Could be detected if needed
    };
  }

  /**
   * Check if WebAssembly is supported
   */
  async checkWasmSupport(): Promise<boolean> {
    try {
      const wasm = await loadWasmModule();
      return wasm.checkWasmSupport();
    } catch (error) {
      return false;
    }
  }

  /**
   * List available encryption algorithms
   */
  async listAlgorithms(): Promise<string[]> {
    const wasm = await loadWasmModule();
    return wasm.listAlgorithms();
  }

  /**
   * Create an encryption algorithm instance
   */
  createAlgorithm(algorithmName: string): EncryptionAlgorithm {
    this.ensureInitialized();
    return new EncryptionAlgorithm(algorithmName, this.config);
  }

  /**
   * Generate a new encryption key
   */
  async generateKey(options?: KeyGenerationOptions): Promise<Uint8Array> {
    this.ensureInitialized();
    return await this.keyManager.generateKey(options);
  }

  /**
   * Import an existing key
   */
  async importKey(keyData: Uint8Array, algorithm: string): Promise<string> {
    this.ensureInitialized();
    return await this.keyManager.importKey(keyData, algorithm);
  }

  /**
   * Export a key
   */
  async exportKey(keyId: string): Promise<Uint8Array> {
    this.ensureInitialized();
    return await this.keyManager.exportKey(keyId);
  }

  /**
   * Delete a key
   */
  async deleteKey(keyId: string): Promise<void> {
    this.ensureInitialized();
    return await this.keyManager.deleteKey(keyId);
  }

  /**
   * List all keys
   */
  async listKeys(): Promise<string[]> {
    this.ensureInitialized();
    return await this.keyManager.listKeys();
  }

  /**
   * Encrypt data
   */
  async encrypt(
    plaintext: Uint8Array,
    options?: EncryptionOptions
  ): Promise<Uint8Array> {
    this.ensureInitialized();
    
    const algorithm = this.createAlgorithm(options?.algorithm || 'aegis256');
    const key = options?.key_id 
      ? await this.keyManager.getKey(options.key_id)
      : await this.generateKey({ algorithm: options?.algorithm || 'aegis256' });
    
    return await algorithm.encrypt(plaintext, key, options);
  }

  /**
   * Decrypt data
   */
  async decrypt(
    ciphertext: Uint8Array,
    keyId: string,
    algorithm?: string
  ): Promise<Uint8Array> {
    this.ensureInitialized();
    
    const alg = this.createAlgorithm(algorithm || 'aegis256');
    const key = await this.keyManager.getKey(keyId);
    
    return await alg.decrypt(ciphertext, key);
  }

  /**
   * Get the key manager instance
   */
  getKeyManager(): KeyManager {
    this.ensureInitialized();
    return this.keyManager;
  }

  /**
   * Get the storage backend instance
   */
  getStorage(): StorageBackend {
    this.ensureInitialized();
    return this.storage;
  }

  /**
   * Get the policy engine instance
   */
  getPolicyEngine(): PolicyEngine {
    this.ensureInitialized();
    return this.policyEngine;
  }

  /**
   * Get the audit logger instance
   */
  getAuditLogger(): AuditLogger {
    this.ensureInitialized();
    return this.auditLogger;
  }

  /**
   * Get the tenant manager instance
   */
  getTenantManager(): TenantManager {
    this.ensureInitialized();
    return this.tenantManager;
  }

  /**
   * Get the utilities instance
   */
  getUtils(): Utils {
    return this.utils;
  }

  /**
   * Get the current configuration
   */
  getConfig(): FortressConfig {
    return this.config;
  }

  /**
   * Update the configuration
   */
  updateConfig(config: Partial<FortressConfigOptions>): void {
    // Create new config with merged properties
    const currentConfig = this.config.toJSON();
    const newConfig = { ...currentConfig, ...config };
    this.config = FortressConfig.fromJSON(JSON.stringify(newConfig));
  }

  /**
   * Perform a health check
   */
  async healthCheck(): Promise<{ status: 'healthy' | 'unhealthy'; details: Record<string, any> }> {
    try {
      this.ensureInitialized();
      
      const details = {
        wasm_support: await this.checkWasmSupport(),
        version: await this.getVersion(),
        algorithms: await this.listAlgorithms(),
        storage_healthy: await this.storage.healthCheck(),
        key_manager_healthy: await this.keyManager.healthCheck(),
      };

      const status = Object.values(details).every(v => 
        typeof v === 'boolean' ? v : true
      ) ? 'healthy' : 'unhealthy';

      return { status, details };
    } catch (error) {
      return {
        status: 'unhealthy',
        details: { error: (error as Error).message }
      };
    }
  }

  /**
   * Shutdown Fortress and clean up resources
   */
  async shutdown(): Promise<void> {
    if (!this.initialized) {
      return;
    }

    try {
      await this.storage.close();
      await this.auditLogger.flush();
      
      this.initialized = false;
    } catch (error) {
      throw new FortressError('Failed to shutdown Fortress', 'SHUTDOWN_ERROR', error);
    }
  }

  /**
   * Ensure Fortress is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new FortressError('Fortress is not initialized. Call initialize() first.', 'NOT_INITIALIZED');
    }
  }
}
