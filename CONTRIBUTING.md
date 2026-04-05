# Contributing to Fortress

Thank you for your interest in contributing to Fortress! This guide will help you get started with development, testing, and submitting contributions.

## 🚀 Quick Start

### Prerequisites

Before you begin, ensure you have the following installed:

- **Rust**: Latest stable version (1.70+)
- **Git**: For version control
- **OpenSSL**: For cryptographic operations

#### System Dependencies

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev
```

**macOS**:
```bash
brew install openssl pkg-config
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
```

**Windows**:
```bash
# Using vcpkg
vcpkg install openssl:x64-windows
vcpkg integrate install

# Or using Chocolatey
choco install openssl
```

### Development Setup

1. **Fork and Clone**:
```bash
git clone https://github.com/your-username/fortress.git
cd fortress
```

2. **Install Development Tools**:
```bash
# Install CLI tool locally
cargo install --path crates/fortress-cli

# Install development dependencies
cargo install cargo-watch cargo-tarpaulin cargo-audit
```

3. **Build the Project**:
```bash
# Build all crates
cargo build --all

# Build with release optimizations
cargo build --release --all
```

4. **Run Tests**:
```bash
# Run all tests
cargo test --all

# Run with coverage
cargo tarpaulin --out Html

# Run integration tests
cargo test --test '*integration*'
```

## 🧪 Testing

### Test Categories

**Unit Tests**:
```bash
# Run unit tests for a specific crate
cargo test -p fortress-core

# Run with specific features
cargo test --features "aws,azure"
```

**Integration Tests**:
```bash
# Run all integration tests
cargo test --test '*integration*'

# Run specific integration test
cargo test --test api_integration
```

**Benchmarks**:
```bash
# Run encryption benchmarks
cargo bench --bench encryption

# Run all benchmarks
cargo bench
```

### Test Coverage

We aim for high test coverage:
- **Unit Tests**: 90%+ coverage
- **Integration Tests**: Critical paths covered
- **Security Tests**: All security features tested

```bash
# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage/

# View coverage in browser
open coverage/tarpaulin-report.html
```

## 🐛 Bug Reports

### Reporting Bugs

1. **Search Existing Issues**: Check if the bug has already been reported
2. **Use Bug Report Template**: Use the provided template
3. **Provide Reproduction Steps**: Include clear steps to reproduce
4. **Include Environment Details**: OS, Rust version, Fortress version

### Bug Report Template

```markdown
## Bug Description
Clear and concise description of the bug

## Reproduction Steps
1. Step one
2. Step two
3. Step three

## Expected Behavior
What you expected to happen

## Actual Behavior
What actually happened

## Environment
- OS: [e.g., Ubuntu 20.04]
- Rust version: [e.g., 1.70.0]
- Fortress version: [e.g., 1.0.0]

## Additional Context
Any other relevant information
```

## ✨ Feature Requests

### Proposing Features

1. **Check Roadmap**: Ensure the feature aligns with project goals
2. **Open Issue**: Discuss the feature before implementing
3. **Design Document**: For large features, create a design doc
4. **Implementation**: Follow the coding standards

### Feature Request Template

```markdown
## Feature Description
Clear description of the proposed feature

## Problem Statement
What problem does this feature solve?

## Proposed Solution
How do you envision this feature working?

## Alternatives Considered
What other approaches did you consider?

## Additional Context
Any other relevant information
```

## 💻 Development Guidelines

### Code Style

We use the following tools to maintain code quality:

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy -- -D warnings

# Security audit
cargo audit
```

### Code Standards

1. **Follow Rust Conventions**: Use `rustfmt` for formatting
2. **Documentation**: Document all public APIs
3. **Error Handling**: Use proper `Result` types
4. **Testing**: Write tests for new functionality
5. **Security**: Follow security best practices

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style
- `refactor`: Refactoring
- `test`: Tests
- `chore`: Maintenance

**Examples**:
```
feat(crypto): add AEGIS-256 encryption support

fix(auth): resolve JWT token validation issue

docs(api): update authentication documentation
```

## 🔐 Security Considerations

### Security Review Process

1. **Self-Review**: Review your own code for security issues
2. **Peer Review**: Security-focused code review
3. **Automated Scanning**: `cargo audit` for dependency vulnerabilities
4. **Manual Review**: Core team security review

### Security Guidelines

1. **No Unsafe Code**: Avoid `unsafe` blocks unless absolutely necessary
2. **Input Validation**: Validate all external inputs
3. **Error Handling**: Don't leak sensitive information in errors
4. **Cryptography**: Use well-vetted cryptographic libraries
5. **Secrets**: Never commit secrets or credentials

## 📝 Documentation

### Documentation Types

1. **API Documentation**: Doc comments for all public APIs
2. **User Documentation**: Guides and tutorials in `docs/`
3. **Developer Documentation**: Architecture and design docs
4. **Examples**: Working code examples

### Writing Documentation

1. **Clear and Concise**: Use simple, clear language
2. **Examples**: Include code examples
3. **Cross-References**: Link to related documentation
4. **Up-to-Date**: Keep documentation current with code

## 🚀 Pull Request Process

### Before Submitting

1. **Test Your Changes**: Ensure all tests pass
2. **Update Documentation**: Update relevant documentation
3. **Check Style**: Run `cargo fmt` and `cargo clippy`
4. **Security Review**: Consider security implications

### Submitting PRs

1. **Create Branch**: `git checkout -b feature/amazing-feature`
2. **Make Changes**: Implement your feature/fix
3. **Commit Changes**: Use conventional commit format
4. **Push Branch**: `git push origin feature/amazing-feature`
5. **Open PR**: Fill out the PR template

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Security considerations addressed
```

## 🤝 Code Review

### Review Process

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Peer Review**: At least one maintainer review required
3. **Security Review**: For security-related changes
4. **Approval**: Maintainer approval required to merge

### Review Guidelines

1. **Be Constructive**: Provide helpful, specific feedback
2. **Focus on Code**: Review the code, not the person
3. **Explain Reasoning**: Explain why changes are needed
4. **Be Timely**: Respond to reviews promptly

## 🏗️ Project Structure

### Directory Layout

```
fortress/
├── crates/                 # Rust crates
│   ├── fortress-core/     # Core library
│   ├── fortress-cli/      # Command-line interface
│   └── fortress-server/   # Server implementation
├── docs/                  # Documentation
├── examples/              # Example code
├── tests/                 # Integration tests
├── benches/               # Performance benchmarks
└── scripts/               # Build and utility scripts
```

### Architecture

Fortress follows a modular architecture:
- **Core**: Cryptographic operations and data structures
- **CLI**: Command-line interface for management
- **Server**: HTTP/gRPC server implementation
- **Plugins**: Extensible plugin system

## 🌟 Community

### Getting Help

1. **GitHub Discussions**: For questions and discussions
2. **GitHub Issues**: For bug reports and feature requests
3. **Documentation**: Check existing documentation first

### Communication Channels

1. **Issues**: For bug reports and feature requests
2. **Discussions**: For general questions and ideas
3. **PR Reviews**: For code-specific discussions

## 📋 Release Process

### Version Bumping

We follow semantic versioning:
- **Major**: Breaking changes
- **Minor**: New features (backward compatible)
- **Patch**: Bug fixes (backward compatible)

### Release Checklist

1. **Update Version**: Bump version in Cargo.toml files
2. **Update Changelog**: Add release notes
3. **Tag Release**: Create git tag
4. **Publish**: Publish to crates.io
5. **Documentation**: Update documentation

## 🏅 Recognition

### Contributors

All contributors are recognized in:
- **README.md**: Contributor list
- **Release Notes**: Contributors to each release
- **Git History**: Commit authorship

### Types of Contributions

We value all types of contributions:
- **Code**: Bug fixes, features, improvements
- **Documentation**: Guides, API docs, examples
- **Testing**: Test cases, bug reports
- **Community**: Support, discussions, reviews

## 📞 Getting Help

### Resources

1. **Documentation**: [docs/](docs/) directory
2. **API Reference**: Rust doc comments
3. **Examples**: [examples/](examples/) directory
4. **Issues**: GitHub issues for known problems

### Contact

1. **Maintainers**: Tag maintainainers in issues/PRs
2. **Security**: security@fortress-db.com for security issues
3. **General**: GitHub discussions for general questions

---

Thank you for contributing to Fortress! Your contributions help make Fortress better for everyone.

## 📜 Code of Conduct

Please be respectful and inclusive in all interactions. We're committed to providing a welcoming environment for everyone.

### Our Pledge

- **Be Respectful**: Treat others with respect and professionalism
- **Be Inclusive**: Welcome contributors from all backgrounds
- **Be Constructive**: Provide helpful, constructive feedback
- **Be Patient**: Remember that everyone was a beginner once

### Reporting Issues

If you experience or witness inappropriate behavior, please contact the maintainers privately.
