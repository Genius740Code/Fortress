/**
 * Key management implementation for Fortress JavaScript/TypeScript SDK
 */

import { KeyMetadata, KeyGenerationOptions } from './types';

export class KeyManager {
  private keys: Map<string, { data: Uint8Array; metadata: KeyMetadata }>;

  constructor(config?: any) {
    this.keys = new Map();
  }

  async generateKey(options?: KeyGenerationOptions): Promise<Uint8Array> {
    const algorithm = options?.algorithm || 'aegis256';
    const keySize = options?.key_size || this.getKeySize(algorithm);
    
    // Generate random key
    const key = new Uint8Array(keySize);
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(key);
    } else {
      // Node.js fallback
      for (let i = 0; i < keySize; i++) {
        key[i] = Math.floor(Math.random() * 256);
      }
    }

    // Store key if metadata provided
    if (options?.metadata) {
      const keyId = this.generateKeyId();
      const metadata: KeyMetadata = {
        id: keyId,
        algorithm,
        created_at: new Date(),
        usage_count: 0,
        version: 1,
        status: 'active',
        ...options.metadata
      };
      
      this.keys.set(keyId, { data: key, metadata });
    }

    return key;
  }

  async importKey(keyData: Uint8Array, algorithm: string): Promise<string> {
    const keyId = this.generateKeyId();
    const metadata: KeyMetadata = {
      id: keyId,
      algorithm,
      created_at: new Date(),
      usage_count: 0,
      version: 1,
      status: 'active'
    };

    this.keys.set(keyId, { data: keyData, metadata });
    return keyId;
  }

  async exportKey(keyId: string): Promise<Uint8Array> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key not found: ${keyId}`);
    }
    return keyEntry.data;
  }

  async deleteKey(keyId: string): Promise<void> {
    if (!this.keys.has(keyId)) {
      throw new Error(`Key not found: ${keyId}`);
    }
    this.keys.delete(keyId);
  }

  async getKey(keyId: string): Promise<Uint8Array> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key not found: ${keyId}`);
    }
    
    // Update usage count
    keyEntry.metadata.usage_count++;
    keyEntry.metadata.last_used = new Date();
    
    return keyEntry.data;
  }

  async listKeys(): Promise<string[]> {
    return Array.from(this.keys.keys());
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key not found: ${keyId}`);
    }
    return keyEntry.metadata;
  }

  async rotateKey(keyId: string): Promise<string> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key not found: ${keyId}`);
    }

    // Generate new key with same algorithm
    const newKeyId = this.generateKeyId();
    const newKey = new Uint8Array(keyEntry.data.length);
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(newKey);
    } else {
      for (let i = 0; i < newKey.length; i++) {
        newKey[i] = Math.floor(Math.random() * 256);
      }
    }

    const newMetadata: KeyMetadata = {
      ...keyEntry.metadata,
      id: newKeyId,
      created_at: new Date(),
      usage_count: 0,
      version: keyEntry.metadata.version + 1
    };

    this.keys.set(newKeyId, { data: newKey, metadata: newMetadata });
    
    // Mark old key as deprecated
    keyEntry.metadata.status = 'deprecated';

    return newKeyId;
  }

  async healthCheck(): Promise<boolean> {
    try {
      // Basic health check - try to generate a test key
      const testKey = await this.generateKey({ algorithm: 'aegis256' });
      return testKey.length > 0;
    } catch {
      return false;
    }
  }

  private generateKeyId(): string {
    return `key_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private getKeySize(algorithm: string): number {
    switch (algorithm) {
      case 'aegis256':
      case 'chacha20poly1305':
      case 'aes256gcm':
        return 32;
      case 'xchacha20poly1305':
        return 32;
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }
}
