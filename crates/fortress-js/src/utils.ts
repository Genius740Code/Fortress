/**
 * Utility functions for Fortress JavaScript/TypeScript SDK
 */

import { FortressError } from './error';

// Type declarations for Node.js globals
declare const require: any;
declare const Buffer: any;
declare const globalThis: any;

/**
 * Utility class for common operations
 */
export class Utils {
  /**
   * Convert Uint8Array to hex string
   */
  static bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Convert hex string to Uint8Array
   */
  static hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
      throw FortressError.validation('Hex string must have even length');
    }
    
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  /**
   * Convert Uint8Array to base64 string
   */
  static bytesToBase64(bytes: Uint8Array): string {
    if (typeof btoa !== 'undefined') {
      // Browser
      return btoa(String.fromCharCode.apply(null, Array.from(bytes)));
    } else {
      // Node.js
      if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64');
      } else {
        // Fallback for environments without Buffer
        const binary = Array.from(bytes).map(b => String.fromCharCode(b)).join('');
        return btoa(binary);
      }
    }
  }

  /**
   * Convert base64 string to Uint8Array
   */
  static base64ToBytes(base64: string): Uint8Array {
    if (typeof atob !== 'undefined') {
      // Browser
      const binaryString = atob(base64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes;
    } else {
      // Node.js
      if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
      } else {
        // Fallback for environments without Buffer
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
      }
    }
  }

  /**
   * Convert string to Uint8Array
   */
  static stringToBytes(str: string, encoding: 'utf8' | 'ascii' | 'utf16le' = 'utf8'): Uint8Array {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(str);
    } else {
      // Node.js fallback
      if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(str, encoding));
      } else {
        // Manual UTF-8 encoding fallback
        const bytes: number[] = [];
        for (let i = 0; i < str.length; i++) {
          const code = str.charCodeAt(i);
          if (code < 0x80) {
            bytes.push(code);
          } else if (code < 0x800) {
            bytes.push(0xc0 | (code >> 6));
            bytes.push(0x80 | (code & 0x3f));
          } else {
            bytes.push(0xe0 | (code >> 12));
            bytes.push(0x80 | ((code >> 6) & 0x3f));
            bytes.push(0x80 | (code & 0x3f));
          }
        }
        return new Uint8Array(bytes);
      }
    }
  }

  /**
   * Convert Uint8Array to string
   */
  static bytesToString(bytes: Uint8Array, encoding: 'utf8' | 'ascii' | 'utf16le' = 'utf8'): string {
    if (typeof TextDecoder !== 'undefined') {
      return new TextDecoder(encoding).decode(bytes);
    } else {
      // Node.js fallback
      if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString(encoding);
      } else {
        // Manual UTF-8 decoding fallback
        let str = '';
        for (let i = 0; i < bytes.length; i++) {
          str += String.fromCharCode(bytes[i]);
        }
        return str;
      }
    }
  }

  /**
   * Generate random bytes
   */
  static randomBytes(length: number): Uint8Array {
    if (typeof crypto !== 'undefined' && (crypto as any).getRandomValues) {
      // Browser or modern Node.js
      const bytes = new Uint8Array(length);
      (crypto as any).getRandomValues(bytes);
      return bytes;
    } else if (typeof require !== 'undefined') {
      // Node.js fallback
      try {
        const crypto = require('crypto');
        return new Uint8Array(crypto.randomBytes(length));
      } catch {
        throw new FortressError('No secure random number generator available', 'NO_RANDOM_GENERATOR');
      }
    } else {
      throw new FortressError('No secure random number generator available', 'NO_RANDOM_GENERATOR');
    }
  }

  /**
   * Generate random hex string
   */
  static randomHex(length: number): string {
    return this.bytesToHex(this.randomBytes(length));
  }

  /**
   * Generate random base64 string
   */
  static randomBase64(length: number): string {
    return this.bytesToBase64(this.randomBytes(length));
  }

  /**
   * Compare two Uint8Arrays in constant time
   */
  static constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  /**
   * Zero out a Uint8Array (secure memory clearing)
   */
  static zeroize(bytes: Uint8Array): void {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }

  /**
   * Create a copy of Uint8Array
   */
  static cloneBytes(bytes: Uint8Array): Uint8Array {
    return new Uint8Array(bytes);
  }

  /**
   * Concatenate multiple Uint8Arrays
   */
  static concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    
    return result;
  }

  /**
   * Split Uint8Array into chunks
   */
  static chunkBytes(bytes: Uint8Array, chunkSize: number): Uint8Array[] {
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < bytes.length; i += chunkSize) {
      chunks.push(bytes.slice(i, i + chunkSize));
    }
    return chunks;
  }

  /**
   * Get current timestamp in milliseconds
   */
  static now(): number {
    return Date.now();
  }

  /**
   * Get current timestamp in seconds
   */
  static nowSeconds(): number {
    return Math.floor(Date.now() / 1000);
  }

  /**
   * Sleep for specified milliseconds
   */
  static sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Retry a function with exponential backoff
   */
  static async retry<T>(
    fn: () => Promise<T>,
    maxAttempts: number = 3,
    baseDelay: number = 1000,
    maxDelay: number = 30000
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error instanceof Error ? error : new FortressError(String(error));
        
        if (attempt === maxAttempts) {
          break;
        }
        
        const delay = Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);
        await this.sleep(delay);
      }
    }
    
    throw lastError!;
  }

  /**
   * Validate input parameters
   */
  static validateInput(value: any, name: string, options: ValidationOptions = {}): void {
    const { 
      required = true, 
      type, 
      minLength, 
      maxLength, 
      pattern, 
      allowedValues 
    } = options;

    if (value === null || value === undefined) {
      if (required) {
        throw FortressError.validation(`${name} is required`);
      }
      return;
    }

    if (type && typeof value !== type) {
      throw FortressError.validation(`${name} must be of type ${type}`);
    }

    if (typeof value === 'string') {
      if (minLength !== undefined && value.length < minLength) {
        throw FortressError.validation(`${name} must be at least ${minLength} characters long`);
      }
      
      if (maxLength !== undefined && value.length > maxLength) {
        throw FortressError.validation(`${name} must be at most ${maxLength} characters long`);
      }
      
      if (pattern && !pattern.test(value)) {
        throw FortressError.validation(`${name} does not match required pattern`);
      }
    }

    if (allowedValues && !allowedValues.includes(value)) {
      throw FortressError.validation(`${name} must be one of: ${allowedValues.join(', ')}`);
    }
  }

  /**
   * Deep clone an object
   */
  static deepClone<T>(obj: T): T {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (obj instanceof Date) {
      return new Date(obj.getTime()) as unknown as T;
    }

    if (obj instanceof Uint8Array) {
      return this.cloneBytes(obj) as unknown as T;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.deepClone(item)) as unknown as T;
    }

    const cloned: any = {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        cloned[key] = this.deepClone((obj as any)[key]);
      }
    }
    return cloned;
  }

  /**
   * Check if running in Node.js
   */
  static isNode(): boolean {
    return typeof (globalThis as any).process !== 'undefined' && 
           (globalThis as any).process.versions && 
           (globalThis as any).process.versions.node;
  }

  /**
   * Check if running in browser
   */
  static isBrowser(): boolean {
    return typeof window !== 'undefined' && typeof document !== 'undefined';
  }

  /**
   * Get platform information
   */
  static getPlatform(): PlatformInfo {
    return {
      isNode: this.isNode(),
      isBrowser: this.isBrowser(),
      userAgent: this.isBrowser() ? (typeof navigator !== 'undefined' ? navigator.userAgent : undefined) : undefined,
      nodeVersion: this.isNode() ? (globalThis as any).process?.version : undefined,
      platform: this.isNode() ? (globalThis as any).process?.platform : undefined,
    };
  }
}

export interface ValidationOptions {
  required?: boolean;
  type?: 'string' | 'number' | 'boolean' | 'object' | 'function';
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  allowedValues?: any[];
}

export interface PlatformInfo {
  isNode: boolean;
  isBrowser: boolean;
  userAgent?: string;
  nodeVersion?: string;
  platform?: string;
}
