# Fortress Codebase Formatting Standards

## Overview
This guide defines consistent formatting standards for the entire Fortress codebase to ensure clean, professional, and maintainable code across all modules.

## Core Principles

### 1. Minimal Emoji Usage
- Use emojis sparingly and only for critical status indicators
- Prefer clean text formatting over emoji decoration
- Limit to 1-2 emojis per output/interaction maximum
- Never use emojis in production error messages or logs

### 2. Clean Headers and Sections
- Use simple, clear headers without excessive decoration
- Prefer bold text over emoji for emphasis
- Keep headers concise and professional
- Use consistent header formatting across all modules

### 3. Consistent Status Indicators
- Use standard symbols: ✓ for success, ✗ for error, ⚠ for warning
- Avoid decorative emojis that don't add meaning
- Maintain consistency across all code modules
- Use appropriate colors for different status types

### 4. Professional Code Presentation
- Use clean formatting for all output and logging
- Align columns properly in tables/lists
- Use consistent spacing and indentation
- Avoid unnecessary visual clutter

## Formatting Standards by Module Type

### CLI Commands
- Clean headers with underlines
- Standard success/error/warning indicators
- Professional table formatting
- Minimal emoji usage

### Server/GraphQL Modules
- Clean log messages without emojis
- Professional error responses
- Consistent status reporting
- Clean API documentation

### Core Library Modules
- Professional debug logging
- Clean error messages
- Consistent status reporting
- Minimal decorative elements

### Test Modules
- Clean test output formatting
- Professional assertion messages
- Consistent test reporting
- Minimal emoji usage (acceptable in test descriptions)

## Output Format Standards

### Success Messages
```
✓ Operation completed successfully
✓ Configuration updated successfully
✓ Database initialized successfully
```

### Error Messages
```
✗ Operation failed: Invalid configuration
✗ Connection timeout exceeded
✗ Validation error: Missing required field
```

### Warning Messages
```
⚠ Deprecated configuration detected
⚠ Using default values
⚠ Performance impact detected
```

### Progress Indicators
```
Processing... [████████████████████] 100%
Complete: 1500 records processed in 2.3s
Initializing components...
```

### Section Headers
```
Database Operations
==================

Security Configuration
--------------------

API Endpoints
=============
```

### Table Formatting
```
ID       NAME        STATUS    CREATED
----     ----        ------    -------
001      user1       Active    2024-01-01
002      user2       Pending   2024-01-02
```

## Logging Standards

### Info Logs
```
INFO: Server started on port 8080
INFO: Database connection established
INFO: Request processed successfully
```

### Error Logs
```
ERROR: Failed to connect to database
ERROR: Invalid API key provided
ERROR: Configuration file not found
```

### Warning Logs
```
WARN: Deprecated API endpoint used
WARN: High memory usage detected
WARN: Connection pool exhausted
```

## Code Comment Standards

### Function Documentation
```rust
/// Initialize the Fortress database with the given configuration.
/// 
/// # Arguments
/// * `config` - Database configuration settings
/// 
/// # Returns
/// * `Result<()>` - Success or error status
/// 
/// # Examples
/// ```
/// let result = init_database(config)?;
/// ```
```

### Inline Comments
```rust
// Validate input parameters
if config.host.is_empty() {
    return Err(FortressError::validation("Host cannot be empty"));
}

// Initialize connection pool
let pool = create_connection_pool(&config).await?;
```

## Error Message Standards

### User-Facing Errors
```
✗ Database connection failed: Invalid credentials
✗ Configuration error: Missing required field 'host'
✗ Permission denied: Insufficient privileges for operation
```

### Internal Errors
```
ERROR: Internal server error: Database timeout
ERROR: System error: Resource exhausted
ERROR: Security error: Invalid token signature
```

## API Response Standards

### Success Responses
```json
{
  "status": "success",
  "message": "Operation completed successfully",
  "data": { ... }
}
```

### Error Responses
```json
{
  "status": "error", 
  "message": "Validation failed",
  "errors": [
    "Field 'name' is required",
    "Invalid email format"
  ]
}
```

## Test Output Standards

### Test Success
```
✓ Database initialization test passed
✓ API endpoint test completed successfully
✓ Security validation test passed
```

### Test Failure
```
✗ Connection timeout test failed
✗ Authentication test failed: Invalid credentials
✗ Performance test failed: Response time exceeded threshold
```

## Color Usage Guidelines

### When to Use Colors
- Success messages: Green
- Error messages: Red  
- Warning messages: Yellow
- Headers: Blue or Cyan
- Key data: White (default)

### When to Avoid Colors
- In log files (redirected output)
- When terminal doesn't support colors
- For accessibility compliance
- In automated test output

## Implementation Rules

### 1. Replace Excessive Emojis
- Remove decorative emojis from all output
- Keep only functional status indicators (✓, ✗, ⚠)
- Use text instead of emojis for section headers
- Clean up log messages and error reporting

### 2. Standardize Headers
- Use consistent header formatting across all modules
- Add proper spacing around headers
- Use underlines for main headers
- Use dashes for sub-headers

### 3. Clean Up Output
- Remove unnecessary visual clutter
- Align table columns properly
- Use consistent spacing and indentation
- Ensure professional appearance

### 4. Consistent Error Handling
- Use standard error message format
- Provide clear, actionable error information
- Include context for debugging
- Use appropriate error levels

## Module-Specific Guidelines

### CLI Modules
- Clean command output formatting
- Professional help messages
- Consistent status indicators
- Minimal emoji usage

### Server Modules  
- Clean log messages
- Professional API responses
- Consistent error reporting
- Clean status endpoints

### Core Library Modules
- Professional debug output
- Clean error messages
- Consistent logging levels
- Minimal decorative elements

### GraphQL Modules
- Clean error responses
- Professional query results
- Consistent status reporting
- Clean documentation

### Test Modules
- Clean test output
- Professional assertion messages
- Consistent test reporting
- Minimal emoji usage acceptable

## Migration Checklist

### Phase 1: CLI Commands
- [ ] Update all CLI command output
- [ ] Standardize success/error messages
- [ ] Clean up help text
- [ ] Remove excessive emojis

### Phase 2: Server Modules
- [ ] Update log messages
- [ ] Clean API responses
- [ ] Standardize error reporting
- [ ] Remove decorative elements

### Phase 3: Core Library
- [ ] Update debug output
- [ ] Clean error messages
- [ ] Standardize logging
- [ ] Remove unnecessary decorations

### Phase 4: GraphQL Modules
- [ ] Update error responses
- [ ] Clean query output
- [ ] Standardize documentation
- [ ] Remove visual clutter

### Phase 5: Test Modules
- [ ] Update test output
- [ ] Clean assertion messages
- [ ] Standardize test reporting
- [ ] Remove excessive emojis

This guide ensures the entire Fortress codebase provides a clean, professional, and consistent experience across all modules and interfaces.
