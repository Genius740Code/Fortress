/**
 * Fortress JavaScript/TypeScript SDK
 * 
 * A comprehensive JavaScript/TypeScript interface to the Fortress secure database system,
 * providing enterprise-grade encryption, key management, and multi-tenant isolation.
 * 
 * @example
 * ```typescript
 * import { Fortress, EncryptionAlgorithm } from 'fortress';
 * 
 * // Initialize Fortress
 * const fortress = new Fortress();
 * 
 * // Create encryption algorithm
 * const algorithm = fortress.createAlgorithm('aegis256');
 * 
 * // Generate key
 * const key = fortress.generateKey('aegis256');
 * 
 * // Encrypt data
 * const plaintext = new TextEncoder().encode('Hello, Fortress!');
 * const ciphertext = await algorithm.encrypt(plaintext, key);
 * 
 * // Decrypt data
 * const decrypted = await algorithm.decrypt(ciphertext, key);
 * console.log(new TextDecoder().decode(decrypted));
 * ```
 */

export { Fortress } from './fortress';
export { EncryptionAlgorithm } from './encryption';
export { KeyManager } from './key-management';
export { StorageBackend } from './storage';
export { FortressConfig } from './config';
export { PolicyEngine } from './policy';
export { AuditLogger } from './audit';
export { TenantManager } from './tenant';
export { FortressError } from './error';
export { Utils } from './utils';

// Re-export types
export type {
  BuildInfo,
  CompatibilityInfo,
  BenchmarkResult,
  KeyMetadata,
  EncryptionProfile,
  StorageConfig,
  AuditConfig,
  PolicyConfig,
  TenantConfig,
  Role,
  Permission,
  Resource,
  AuditEntry,
  TenantStats,
  ResourceLimits
} from './types';

// Version information
export const VERSION = '0.1.0';

// Utility functions
export * from './utils';
