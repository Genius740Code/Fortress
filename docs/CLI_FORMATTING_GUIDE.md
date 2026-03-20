# Fortress CLI Formatting Guide

## Overview
This guide defines the formatting standards for Fortress CLI output to ensure clean, professional, and consistent user experience.

## Core Principles

### 1. Minimal Emoji Usage
- Use emojis sparingly and only for critical status indicators
- Prefer clean text formatting over emoji decoration
- Limit to 1-2 emojis per command output maximum

### 2. Clean Section Headers
- Use simple, clear headers without excessive decoration
- Prefer bold text over emoji for emphasis
- Keep headers concise and professional

### 3. Consistent Status Indicators
- Use standard symbols: ✓ for success, ✗ for error, ⚠ for warning
- Avoid decorative emojis that don't add meaning
- Maintain consistency across all commands

### 4. Professional Data Presentation
- Use clean table formatting for structured data
- Align columns properly
- Use consistent spacing and indentation
- Avoid unnecessary visual clutter

## Output Format Standards

### Success Messages
```
✓ Key generated successfully
Key ID: fc35f980-6020-4834-b906-ab046e2eae0c
Algorithm: Aegis256
Created: 2026-03-20 19:24:00 UTC
```

### Error Messages
```
✗ Key generation failed: Invalid configuration
Error: Configuration file not found at /path/to/config.toml
```

### Warning Messages
```
⚠ Configuration file uses deprecated settings
Consider updating to the latest format
```

### Progress Indicators
```
Processing... [████████████████████] 100%
Complete: 1500 records processed in 2.3s
```

### Table Formatting
```
KEY ID                              VERSION  CREATED              STATUS
--------------------------------- -------- -------------------- ------
fc35f980-6020-4834-b906-ab04...   v1.0    2026-03-20 19:24:00  Active
a1b2c3d4-e5f6-7890-abcd-ef12...   v1.1    2026-03-19 15:30:00  Active
```

### Section Headers
```
Key Management
==============

Database Operations
==================
```

## Command-Specific Guidelines

### Key Commands
- `key generate`: Simple success message with key details
- `key list`: Clean table format, minimal decoration
- `key show`: Structured key information display

### Configuration Commands
- `config show`: Hierarchical configuration display
- `config set`: Simple confirmation message
- `config validate`: Clear validation results

### Database Commands
- `create`: Progress indication during creation
- `status`: Clean status summary
- `start/stop`: Simple confirmation messages

### Cluster Commands
- `cluster status`: Node list with health indicators
- `cluster health`: Summary metrics table
- `cluster init/join`: Progress tracking

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

## Examples

### Good Example
```
✓ Key generated successfully
Key ID: fc35f980-6020-4834-b906-ab046e2eae0c
Algorithm: Aegis256
Created: 2026-03-20 19:24:00 UTC
```

### Bad Example (Current)
```
🔑 Generating new encryption key
✅ Key generated successfully!
📋 Key ID: fc35f980-6020-4834-b906-ab046e2eae0c
🔐 Algorithm: Aegis256
📅 Created: 2026-03-20 19:24:00 UTC
```

## Implementation Notes

### Console Styling
- Use `console::style()` for text styling
- Apply colors and formatting consistently
- Test output in different terminal environments

### Progress Bars
- Use `indicatif` for progress indication
- Show meaningful progress information
- Include completion statistics

### Error Handling
- Provide clear error context
- Include actionable suggestions
- Maintain professional tone

This guide ensures Fortress CLI provides a clean, professional, and consistent user experience across all commands.
