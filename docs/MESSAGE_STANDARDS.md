# Fortress Message Standards Guide

This document establishes consistent messaging standards across all Fortress codebase files to ensure clear, professional user experience.

## Core Principles

### 1. Clarity Over Decoration
- Use plain text instead of emojis for professional appearance
- Focus on clear, descriptive messages
- Avoid visual noise that can distract from important information

### 2. Consistent Success/Failure Indicators
- **Success**: Use `✓` (checkmark) for success states
- **Failure**: Use `✗` (X mark) for failure states
- **Warning**: Use `Warning:` prefix for non-critical issues

### 3. Action-Oriented Language
- Start messages with verbs: "Testing...", "Building...", "Creating..."
- Use present tense for ongoing actions
- Use past tense for completed actions

### 4. Contextual Information
- Provide context for what's happening
- Explain why something matters
- Include relevant details (version, component, etc.)

## File-Type Specific Standards

### Rust Files (.rs)
```rust
// Progress messages
println!("Testing {}...", feature_name);
println!("Building {} for {}", component, target);

// Success messages  
println!("✓ {} completed successfully", operation);
println!("✓ {} test passed", test_name);

// Error messages
println!("✗ {} failed: {}", operation, error);
println!("Warning: {} - {}", issue, suggestion);
```

### JavaScript/TypeScript Files (.js, .ts)
```javascript
// Progress messages
console.log(`Testing ${feature}...`);
console.log(`Building ${component} for ${target}`);

// Success messages
console.log(`✓ ${operation} completed successfully`);
console.log(`✓ ${testName} test passed`);

// Error messages  
console.log(`✗ ${operation} failed: ${error}`);
console.log(`Warning: ${issue} - ${suggestion}`);
```

### Shell Scripts (.sh)
```bash
# Progress messages
echo "Testing $feature..."
echo "Building $component for $target"

# Success messages
echo "✓ $operation completed successfully"
echo "✓ $test_name test passed"

# Error messages
echo "✗ $operation failed: $error"
echo "Warning: $issue - $suggestion"
```

### Documentation Files (.md)
```markdown
## Section Headers (no emojis)
### Installation
### Configuration
### Usage

# Status indicators
- ✓ Implemented
- ✗ Failed  
- Warning: Issue exists

# Code examples
```rust
println!("✓ Operation completed");
```

## Message Categories

### Testing Messages
- **Start**: "Testing [feature]..."
- **Success**: "✓ [test] passed"
- **Failure**: "✗ [test] failed: [reason]"
- **Summary**: "All [category] tests passed successfully"

### Build Messages  
- **Start**: "Building [component] for [target]..."
- **Success**: "✓ [component] build successful"
- **Failure**: "✗ [component] build failed: [error]"
- **Publish**: "✓ Published to [platform]"

### Runtime Messages
- **Initialization**: "Starting [service]..."
- **Ready**: "✓ [service] ready on [port]"
- **Operation**: "✓ [operation] completed"
- **Error**: "✗ [operation] failed: [details]"

### Configuration Messages
- **Loading**: "Loading configuration from [file]..."
- **Validation**: "✓ Configuration valid"
- **Error**: "✗ Configuration error: [issue]"

## Prohibited Patterns

### Emojis to Avoid
🎉 ✅ ❌ ⚠️ 🔐 📁 👥 ⏰ 💾 🔍 🎭 🏗️ 🔑 🚀 💡 📊 🔧 🛠️ ✨ 🎯 🔨 📦 🧪 🧹 🛡️ ⚡ 🏷️ 📝 🎲 🔓 ⏱️ 📈 📚 🌐 🔄 🎊 🎈 🎁 🎂 🍰 🎪 🎨 🎬 🎮 🎯 🎲 🎸 🎺 🎻 🎼 🎵 🎶 🎤 🎧 🎙️ 📻 📱 📲 📞 📟 📠 📡 📺 📻 📷 📸 📹 📼 💿 📀 💾 💻 🖥️ ⌨️ 🖱️ 🖨️ 🖱️ 🖲️ 🕹️ 🗜️ 🔧 🔨 ⚒️ 🛠️ ⛏️ 🔩 ⚙️ 🧱 ⛓️ 🧲 🔫 💣 🔪 🗡️ ⚔️ 🛡️ 🚬 ⚰️ ⚱️ 🏺 🔮 📿 💎 💍 🌟 ⭐ ✨ 💫 ☄️ ☀️ 🌝 🌛 🌜 🌚 🌕 🌖 🌗 🌘 🌑 🌒 🌓 🌔 🌙 🌎 🌍 🌏 🪐 💫 ☄️ 🌠 🌌 🌉 🌃 🌄 🌅 🌆 🌇 🌈 🌉 🌊 🌋 🌌 🌠 🏔️ ⛰️ 🌋 🗻 🏕️ 🏖️ 🏜️ 🏝️ 🏟️ 🏛️ 🏗️ 🧱 🏘️ 🏚️ 🏭️ 🏢 🏬 🏣 🏤 🏥 🏦 🏨 🏪 🏫 🏩 💒 🏛️ ⛪ 🕌 🕍 🛕 🕋 ⛩️ 🛤️ 🛣️ 🗾 🎑 🏞️ 🌅 🌄 🌠 🎇 🎆 🎆 🌇 🌆 🏙️ 🌃 🌌 🌉 🌁 🌃 🏞️

### Inconsistent Patterns
- Mixed success indicators (✅ vs ✓)
- Unclear error messages
- Missing context for operations
- Inconsistent capitalization

## Implementation Guidelines

### 1. Search and Replace
- Search for prohibited emojis in all files
- Replace with standard text equivalents
- Ensure consistency across file types

### 2. Review Changes
- Test messages display correctly
- Verify no formatting issues
- Check for missed emojis

### 3. Maintain Standards
- Apply standards to new files
- Review contributions for compliance
- Update this document as needed

## Benefits

### Professional Appearance
- Clean, readable output
- Better accessibility
- Terminal compatibility
- Reduced visual clutter

### Improved User Experience
- Clear progress indication
- Consistent success/failure feedback
- Better error understanding
- Professional documentation

### Maintenance Benefits
- Easier to update messages
- Consistent across codebase
- Simplified localization
- Better debugging experience

## Verification Checklist

- [ ] No emojis in Rust source files
- [ ] No emojis in JavaScript/TypeScript files  
- [ ] No emojis in shell scripts
- [ ] No emojis in documentation files
- [ ] Consistent success indicators (✓)
- [ ] Consistent failure indicators (✗)
- [ ] Action-oriented message structure
- [ ] Contextual information provided

## Files Updated

This standards guide should be applied to all new message additions and existing message updates across the Fortress codebase.
