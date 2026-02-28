/**
 * Type definitions for Fortress JavaScript/TypeScript SDK
 */

export interface BuildInfo {
  timestamp: string;
  git_sha: string;
  rust_version: string;
  target: string;
}

export interface CompatibilityInfo {
  version: string;
  api_version: string;
  features: string[];
  platform: string;
  arch: string;
}

export interface BenchmarkResult {
  algorithm: string;
  operation: 'encrypt' | 'decrypt' | 'keygen';
  data_size: number;
  duration_ms: number;
  throughput_mbps: number;
  memory_usage_bytes: number;
}

export interface KeyMetadata {
  id: string;
  algorithm: string;
  created_at: Date;
  last_used?: Date;
  usage_count: number;
  version: number;
  status: 'active' | 'deprecated' | 'revoked';
}

export interface EncryptionProfile {
  name: string;
  algorithm: string;
  key_size: number;
  nonce_size: number;
  tag_size: number;
  iterations?: number;
  memory_limit?: number;
}

export interface AlgorithmMetadata {
  name: string;
  key_size: number;
  nonce_size: number;
  tag_size: number;
  supports_associated_data: boolean;
}

export interface StorageConfig {
  backend: 'memory' | 'file' | 'redis' | 'postgres' | 'mysql';
  connection_string?: string;
  max_connections?: number;
  timeout_ms?: number;
  retry_attempts?: number;
  cache_size?: number;
}

export interface AuditConfig {
  enabled: boolean;
  log_level: 'debug' | 'info' | 'warn' | 'error';
  storage_backend: StorageConfig;
  retention_days?: number;
  batch_size?: number;
  flush_interval_ms?: number;
}

export interface PolicyConfig {
  name: string;
  version: string;
  rules: PolicyRule[];
  default_action: 'allow' | 'deny';
  evaluation_mode: 'all' | 'any';
}

export interface PolicyRule {
  id: string;
  name: string;
  conditions: Condition[];
  action: 'allow' | 'deny';
  priority: number;
  enabled: boolean;
}

export interface Condition {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'contains';
  value: any;
}

export interface TenantConfig {
  id: string;
  name: string;
  description?: string;
  isolation_level: 'strict' | 'shared' | 'partial';
  resource_limits: ResourceLimits;
  encryption_profile: string;
  audit_config: AuditConfig;
  policy_config: PolicyConfig;
}

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: Permission[];
  is_system: boolean;
  created_at: Date;
  updated_at?: Date;
}

export interface Permission {
  id: string;
  resource: Resource;
  actions: string[];
  conditions?: Condition[];
  effect?: 'allow' | 'deny';
}

export interface Resource {
  type: string;
  id?: string;
  attributes?: Record<string, any>;
}

export interface AuditEntry {
  id: string;
  tenant_id: string;
  user_id?: string;
  action: string;
  resource: Resource;
  result: 'success' | 'failure';
  error?: string;
  metadata?: Record<string, any>;
  timestamp: Date;
  ip_address?: string;
  user_agent?: string;
}

export interface TenantStats {
  tenant_id: string;
  total_keys: number;
  active_keys: number;
  total_encryptions: number;
  total_decryptions: number;
  storage_usage_bytes: number;
  audit_entries: number;
  last_activity: Date;
}

export interface ResourceLimits {
  max_keys: number;
  max_storage_bytes: number;
  max_encryptions_per_hour: number;
  max_decryptions_per_hour: number;
  max_concurrent_operations: number;
}

export interface EncryptionOptions {
  algorithm?: string;
  associated_data?: Uint8Array;
  compression?: boolean;
  key_id?: string;
}

export interface KeyGenerationOptions {
  algorithm?: string;
  key_size?: number;
  exportable?: boolean;
  metadata?: Record<string, any>;
}

export interface StorageOptions {
  consistency_level?: 'eventual' | 'strong';
  ttl_seconds?: number;
  compression?: boolean;
  encryption?: boolean;
}

export interface QueryOptions {
  limit?: number;
  offset?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  filter?: Record<string, any>;
}
