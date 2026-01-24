# Contributing to Fortress

Thank you for your interest in contributing to Fortress! This document provides guidelines and information for contributors.

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please read and follow it in all your interactions with the project.

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Git
- A passion for secure and performant database systems!

### Development Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/your-username/fortress.git
   cd fortress
   ```

2. **Add upstream remote**
   ```bash
   git remote add upstream https://github.com/Genius740Code/Fortress.git
   ```

3. **Install dependencies**
   ```bash
   cargo fetch
   ```

4. **Run tests**
   ```bash
   cargo test --all-features
   ```

5. **Check formatting**
   ```bash
   cargo fmt --all -- --check
   ```

6. **Run clippy**
   ```bash
   cargo clippy --all-features -- -D warnings
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-fix-name
```

### 2. Make Changes

- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Commit Changes

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
feat: add AEGIS-256 encryption support
fix: resolve key rotation memory leak
docs: update API documentation
test: add integration tests for storage backends
refactor: simplify encryption trait hierarchy
```

### 4. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:
- Clear title and description
- Reference any relevant issues
- Include testing instructions
- Add any necessary reviewers

## Code Style

### Rust Guidelines

- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Prefer `Result<T>` over panics for error handling
- Use `#[derive(Debug)]` for public types
- Document all public APIs with `///` doc comments
- Use `#[warn(missing_docs)]` internally

### Documentation

- Public APIs must have documentation
- Include examples in doc comments
- Update `README.md` for user-facing changes
- Update relevant documentation in `docs/`

### Testing

- Unit tests for all public functions
- Integration tests for major workflows
- Property tests for cryptographic operations
- Benchmarks for performance-critical code
- Security tests for encryption operations

## Project Structure

```
fortress/
├── src/                    # Main library source
├── crates/                 # Workspace crates
│   ├── fortress-core/      # Core library
│   ├── fortress-cli/       # Command-line interface
│   ├── fortress-server/    # Server application
│   ├── fortress-wasm/      # WebAssembly bindings
│   └── fortress-proto/     # Protocol definitions
├── docs/                   # Documentation
├── tests/                  # Integration tests
├── benches/                # Performance benchmarks
└── examples/               # Example usage
```

## Contributing Areas

### Core Cryptography

- New encryption algorithms
- Key management improvements
- Performance optimizations
- Security audits and fixes

### Storage Backends

- New storage implementations
- Performance improvements
- Cloud provider integrations
- Caching strategies

### Query Engine

- SQL parser improvements
- Query optimization
- Index implementations
- Transaction support

### APIs and Interfaces

- REST API enhancements
- gRPC protocol improvements
- CLI features
- WebAssembly optimizations

### Documentation and Tooling

- Documentation improvements
- Example applications
- Developer tools
- Benchmarking tools

## Security Considerations

### When Working with Cryptography

- Never implement your own cryptography
- Use well-vetted libraries and algorithms
- Follow constant-time practices
- Zero out sensitive memory
- Review cryptographic implementations carefully

### Security Reviews

- All security-related changes require review
- Consider threat modeling for new features
- Include security tests for encryption operations
- Document security assumptions and guarantees

## Performance Guidelines

### Benchmarking

- Add benchmarks for performance-critical code
- Use `criterion` for micro-benchmarks
- Profile with tools like `perf` or `flamegraph`
- Consider hardware acceleration opportunities

### Memory Management

- Minimize allocations in hot paths
- Use memory pools for frequent allocations
- Zero out sensitive memory promptly
- Consider cache-friendly data structures

## Release Process

### Version Management

- Follow semantic versioning (SemVer)
- Update `CHANGELOG.md` for all releases
- Tag releases with version numbers
- Update documentation for breaking changes

### Testing Before Release

- Full test suite must pass
- Security audit for cryptographic changes
- Performance regression testing
- Documentation review

## Getting Help

### Communication Channels

- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: General questions and ideas
- Discord: Real-time discussion (link in README)

### Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust Crypto Book](https://github.com/RustCrypto/crypto-book)
- [Fortress Documentation](https://docs.fortress-db.com)

## Recognition

Contributors are recognized in:
- `AUTHORS.md` file
- Release notes
- Project README
- Annual contributor highlights

## License

By contributing to Fortress, you agree that your contributions will be licensed under the Apache License 2.0, the same license as the project.

Thank you for contributing to Fortress! 🎉
