# Contributing to Fortress

Thank you for your interest in contributing to Fortress! This document provides guidelines and information for contributors.

## 🚀 Quick Start for Contributors

### Prerequisites

- Rust 1.70 or higher
- Git
- Basic knowledge of Rust and cryptography concepts

### Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/Fortress.git
   cd Fortress
   ```

2. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/Genius740Code/Fortress.git
   ```

3. **Install development dependencies**
   ```bash
   cargo install cargo-watch cargo-flamegraph
   ```

4. **Build the project**
   ```bash
   # Build with core features (recommended for development)
   cargo build --workspace --features core
   
   # Or build all features (may take longer)
   cargo build --workspace --all-features
   ```

5. **Run tests**
   ```bash
   # Run basic tests
   cargo test --workspace --features core
   
   # Run all tests (including integration)
   cargo test --workspace --all-features
   ```

## 📋 Development Workflow

### 1. Create a Branch

```bash
# Sync with upstream
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Test Your Changes

```bash
# Run tests
cargo test --workspace --features core

# Run with auto-reload during development
cargo watch -x "test --workspace --features core"

# Run benchmarks
cargo bench

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy --workspace --features core -- -D warnings
```

### 4. Submit Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

## 🏗️ Project Structure

```
Fortress/
├── crates/                    # Workspace crates
│   ├── fortress-core/         # Core library
│   ├── fortress-cli/          # Command-line interface
│   └── fortress-server/       # REST API server
├── docs/                      # Documentation
├── examples/                  # Usage examples
├── tests/                     # Integration tests
└── docker/                    # Docker configurations
```

### Core Components

- **fortress-core**: Core encryption, storage, and security features
- **fortress-cli**: Command-line tool for database management
- **fortress-server**: HTTP/REST API server

## 📝 Code Style Guidelines

### Rust Style

- Use `rustfmt` for formatting
- Use `clippy` for linting
- Follow Rust naming conventions
- Add comprehensive documentation

### Documentation

- Document all public APIs
- Include examples in documentation
- Update README.md for user-facing changes
- Add inline comments for complex logic

### Testing

- Write unit tests for all public functions
- Add integration tests for major features
- Include edge cases and error conditions
- Use `#[cfg(test)]` for test-only code

## 🧪 Testing Guidelines

### Running Tests

```bash
# Unit tests
cargo test --workspace --features core

# Integration tests
cargo test --test integration --workspace --features core

# Benchmarks
cargo bench

# Specific test
cargo test test_name --workspace --features core
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encryption_roundtrip() {
        // Arrange
        let algorithm = Aegis256::new();
        let key_manager = KeyManager::new();
        let key = key_manager.generate_key(&algorithm).unwrap();
        let plaintext = b"test data";

        // Act
        let ciphertext = algorithm.encrypt(plaintext, &key).unwrap();
        let decrypted = algorithm.decrypt(&ciphertext, &key).unwrap();

        // Assert
        assert_eq!(plaintext, decrypted);
    }
}
```

## 🔧 Development Tools

### Useful Commands

```bash
# Auto-reload during development
cargo watch -x run

# Generate flamegraph
cargo flamegraph --bin fortress-server

# Check for unused dependencies
cargo machete

# Update dependencies
cargo update

# Check for security vulnerabilities
cargo audit
```

### IDE Configuration

#### VS Code

Install these extensions:
- rust-analyzer
- CodeLLDB (for debugging)
- TOML

#### Configuration

```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.cargo.features": "core",
    "rust-analyzer.cargo.loadOutDirsFromCheck": true
}
```

## 🐛 Bug Reports

### Reporting Bugs

1. Check existing issues first
2. Use the bug report template
3. Include:
   - Fortress version
   - Rust version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Backtrace if available

### Bug Report Template

```markdown
## Bug Description
Brief description of the bug

## Environment
- Fortress version: 
- Rust version:
- OS:
- Architecture:

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen

## Actual Behavior
What actually happened

## Additional Context
Any other relevant information
```

## 💡 Feature Requests

### Proposing Features

1. Check existing issues and discussions
2. Use the feature request template
3. Include:
   - Problem description
   - Proposed solution
   - Use cases
   - Implementation ideas (optional)

### Feature Request Template

```markdown
## Feature Description
Clear description of the feature

## Problem Statement
What problem does this solve?

## Proposed Solution
How should it work?

## Use Cases
Who would use this and why?

## Implementation Ideas
Technical considerations (optional)
```

## 🔐 Security Contributions

### Security Issues

**Do NOT report security issues in public issues!**

For security vulnerabilities, email: security@fortress-db.com

### Security Guidelines

- Follow secure coding practices
- Use constant-time operations for crypto
- Validate all inputs
- Use proper error handling
- No panic in production code

## 📚 Documentation Contributions

### Improving Documentation

- Fix typos and grammar
- Improve clarity and examples
- Add missing documentation
- Translate to other languages

### Documentation Types

- API documentation (doc comments)
- User guides (docs/)
- Examples (examples/)
- README files

## 🚀 Release Process

### Version Bump

1. Update version numbers in Cargo.toml files
2. Update CHANGELOG.md
3. Create release tag
4. Publish to crates.io

### Changelog Format

```markdown
## [0.2.0] - 2026-01-15

### Added
- New feature 1
- New feature 2

### Changed
- Breaking change 1
- Improvement 2

### Fixed
- Bug fix 1
- Bug fix 2

### Security
- Security fix 1
```

## 🏷️ Labeling Issues

### Common Labels

- `bug`: Bug reports
- `enhancement`: Feature requests
- `documentation`: Documentation issues
- `good first issue`: Good for newcomers
- `help wanted`: Needs community help
- `security`: Security issues
- `performance`: Performance issues

### Priority Labels

- `critical`: Must fix immediately
- `high`: Important to fix
- `medium`: Normal priority
- `low`: Nice to have

## 🤝 Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- No harassment or discrimination
- Follow Rust's Code of Conduct

### Communication

- Use GitHub issues for bug reports and features
- Use discussions for questions and ideas
- Be patient with responses
- Help others when you can

## 🎯 Getting Help

### Resources

- [Documentation](https://docs.fortress-db.com)
- [API Reference](docs/API_DOCUMENTATION.md)
- [Examples](examples/)
- [Discord Community](https://discord.gg/fortress)

### Asking Questions

1. Check documentation first
2. Search existing issues
3. Create discussion for questions
4. Provide context and details

## 🏆 Recognition

### Contributors

- All contributors are recognized in README.md
- Top contributors get special recognition
- Contributors can join core team

### Recognition Types

- Code contributions
- Documentation improvements
- Bug reports
- Community support
- Security research

## 📊 Contribution Metrics

### What Counts as Contributions

- Code (pull requests)
- Documentation (improvements)
- Bug reports (issues)
- Feature requests (discussions)
- Community support (helping others)
- Security research (responsible disclosure)

### Tracking Contributions

- GitHub automatically tracks commits and PRs
- Manual recognition for other contributions
- Quarterly contributor highlights

## 🔧 Development Environment

### Recommended Tools

- **Editor**: VS Code with rust-analyzer
- **Debugger**: CodeLLDB or gdb
- **Profiler**: cargo-flamegraph
- **Testing**: cargo test
- **Linting**: clippy

### Environment Setup

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install tools
cargo install cargo-watch cargo-flamegraph cargo-audit

# Set up git hooks (optional)
cp scripts/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

## 📋 Review Process

### Pull Request Review

1. Automated checks (CI/CD)
2. Code review by maintainers
3. Documentation review
4. Security review (if needed)
5. Approval and merge

### Review Criteria

- Code quality and style
- Test coverage
- Documentation
- Performance impact
- Security implications
- Breaking changes

## 🚨 Common Issues

### Build Failures

- Check Rust version
- Clear cargo cache: `cargo clean`
- Update dependencies: `cargo update`
- Check feature flags

### Test Failures

- Run tests individually
- Check test environment
- Update test data
- Check for race conditions

### Documentation Build

- Install required tools
- Check doc comments
- Validate examples
- Fix broken links

## 🎉 Celebrating Contributions

### Contributor Spotlight

- Monthly contributor highlights
- Annual contributor awards
- Special recognition for security researchers
- Community appreciation posts

### Milestone Recognition

- 100th PR celebration
- 1.0 release contributors
- Security hall of fame
- Documentation champions

---

Thank you for contributing to Fortress! Every contribution helps make Fortress better for everyone. 🛡️✨
