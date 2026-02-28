/**
 * Error handling for Fortress JavaScript/TypeScript SDK
 */

/**
 * Fortress error class
 */
export class FortressError extends Error {
  public readonly code: string;
  public readonly kind: string;
  public readonly source?: Error;
  public readonly isRetryable: boolean;
  public readonly isTemporary: boolean;

  constructor(
    message: string,
    code: string = 'UNKNOWN_ERROR',
    source?: Error | unknown,
    isRetryable: boolean = false,
    isTemporary: boolean = false
  ) {
    super(message);
    this.name = 'FortressError';
    this.code = code;
    this.kind = this.determineKind(code);
    this.source = source instanceof Error ? source : undefined;
    this.isRetryable = isRetryable;
    this.isTemporary = isTemporary;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if ((Error as any).captureStackTrace) {
      (Error as any).captureStackTrace(this, FortressError);
    }
  }

  private determineKind(code: string): string {
    if (code.startsWith('ENCRYPTION_')) return 'Encryption';
    if (code.startsWith('KEY_')) return 'KeyManagement';
    if (code.startsWith('STORAGE_')) return 'Storage';
    if (code.startsWith('POLICY_')) return 'Policy';
    if (code.startsWith('AUDIT_')) return 'Audit';
    if (code.startsWith('TENANT_')) return 'Tenant';
    if (code.startsWith('CONFIG_')) return 'Configuration';
    if (code.startsWith('NETWORK_')) return 'Network';
    if (code.startsWith('VALIDATION_')) return 'Validation';
    if (code.startsWith('PERMISSION_')) return 'Permission';
    if (code.startsWith('RATE_LIMIT_')) return 'RateLimit';
    if (code.startsWith('TIMEOUT_')) return 'Timeout';
    return 'Unknown';
  }

  /**
   * Get error details as an object
   */
  getDetails(): ErrorDetails {
    return {
      message: this.message,
      name: this.name,
      code: this.code,
      kind: this.kind,
      source: this.source?.message,
      stack: this.stack,
      isRetryable: this.isRetryable,
      isTemporary: this.isTemporary,
    };
  }

  /**
   * Convert to JSON string
   */
  toJSON(): string {
    return JSON.stringify(this.getDetails());
  }

  /**
   * Create error from WASM error
   */
  static fromWasmError(wasmError: any): FortressError {
    if (wasmError && typeof wasmError === 'object') {
      return new FortressError(
        wasmError.message || 'Unknown WASM error',
        wasmError.code || 'WASM_ERROR',
        wasmError.source,
        wasmError.isRetryable || false,
        wasmError.isTemporary || false
      );
    }
    return new FortressError(String(wasmError), 'WASM_ERROR');
  }

  /**
   * Create encryption error
   */
  static encryption(message: string, source?: Error): FortressError {
    return new FortressError(message, 'ENCRYPTION_ERROR', source, false, false);
  }

  /**
   * Create key management error
   */
  static keyManagement(message: string, source?: Error): FortressError {
    return new FortressError(message, 'KEY_MANAGEMENT_ERROR', source, false, false);
  }

  /**
   * Create storage error
   */
  static storage(message: string, source?: Error, isRetryable: boolean = true): FortressError {
    return new FortressError(message, 'STORAGE_ERROR', source, isRetryable, false);
  }

  /**
   * Create policy error
   */
  static policy(message: string, source?: Error): FortressError {
    return new FortressError(message, 'POLICY_ERROR', source, false, false);
  }

  /**
   * Create audit error
   */
  static audit(message: string, source?: Error): FortressError {
    return new FortressError(message, 'AUDIT_ERROR', source, true, false);
  }

  /**
   * Create tenant error
   */
  static tenant(message: string, source?: Error): FortressError {
    return new FortressError(message, 'TENANT_ERROR', source, false, false);
  }

  /**
   * Create configuration error
   */
  static configuration(message: string, source?: Error): FortressError {
    return new FortressError(message, 'CONFIG_ERROR', source, false, false);
  }

  /**
   * Create network error
   */
  static network(message: string, source?: Error): FortressError {
    return new FortressError(message, 'NETWORK_ERROR', source, true, true);
  }

  /**
   * Create validation error
   */
  static validation(message: string, source?: Error): FortressError {
    return new FortressError(message, 'VALIDATION_ERROR', source, false, false);
  }

  /**
   * Create permission error
   */
  static permission(message: string, source?: Error): FortressError {
    return new FortressError(message, 'PERMISSION_ERROR', source, false, false);
  }

  /**
   * Create rate limit error
   */
  static rateLimit(message: string, source?: Error): FortressError {
    return new FortressError(message, 'RATE_LIMIT_ERROR', source, true, true);
  }

  /**
   * Create timeout error
   */
  static timeout(message: string, source?: Error): FortressError {
    return new FortressError(message, 'TIMEOUT_ERROR', source, true, true);
  }

  /**
   * Create initialization error
   */
  static initialization(message: string, source?: Error): FortressError {
    return new FortressError(message, 'INITIALIZATION_ERROR', source, false, false);
  }

  /**
   * Create shutdown error
   */
  static shutdown(message: string, source?: Error): FortressError {
    return new FortressError(message, 'SHUTDOWN_ERROR', source, false, false);
  }
}

export interface ErrorDetails {
  message: string;
  name: string;
  code: string;
  kind: string;
  source?: string;
  stack?: string;
  isRetryable: boolean;
  isTemporary: boolean;
}

/**
 * Error handler utility class
 */
export class ErrorHandler {
  /**
   * Handle and convert unknown errors to FortressError
   */
  static handle(error: unknown, defaultMessage: string = 'Unknown error occurred'): FortressError {
    if (error instanceof FortressError) {
      return error;
    }

    if (error instanceof Error) {
      return new FortressError(error.message, 'UNKNOWN_ERROR', error);
    }

    if (typeof error === 'string') {
      return new FortressError(error, 'UNKNOWN_ERROR');
    }

    return new FortressError(defaultMessage, 'UNKNOWN_ERROR', error as Error);
  }

  /**
   * Wrap async function with error handling
   */
  static async wrapAsync<T>(
    fn: () => Promise<T>,
    errorMessage: string = 'Operation failed'
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      throw ErrorHandler.handle(error, errorMessage);
    }
  }

  /**
   * Wrap sync function with error handling
   */
  static wrap<T>(
    fn: () => T,
    errorMessage: string = 'Operation failed'
  ): T {
    try {
      return fn();
    } catch (error) {
      throw ErrorHandler.handle(error, errorMessage);
    }
  }

  /**
   * Check if error is retryable
   */
  static isRetryable(error: unknown): boolean {
    const fortressError = ErrorHandler.handle(error);
    return fortressError.isRetryable;
  }

  /**
   * Check if error is temporary
   */
  static isTemporary(error: unknown): boolean {
    const fortressError = ErrorHandler.handle(error);
    return fortressError.isTemporary;
  }

  /**
   * Get error code
   */
  static getErrorCode(error: unknown): string {
    const fortressError = ErrorHandler.handle(error);
    return fortressError.code;
  }

  /**
   * Get error kind
   */
  static getErrorKind(error: unknown): string {
    const fortressError = ErrorHandler.handle(error);
    return fortressError.kind;
  }
}
