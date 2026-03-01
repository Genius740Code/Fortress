# Fortress Testing Guide

This document provides comprehensive testing procedures for the Fortress codebase, including feature testing, error detection, and logic validation.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Core Library Testing](#core-library-testing)
- [Plugin System Testing](#plugin-system-testing)
- [API Testing](#api-testing)
- [Security Testing](#security-testing)
- [Performance Testing](#performance-testing)
- [Integration Testing](#integration-testing)
- [Error Detection and Logic Validation](#error-detection-and-logic-validation)
- [Continuous Testing](#continuous-testing)

## Prerequisites

Ensure you have the following installed:
- Rust (latest stable)
- Python 3.8+
- Node.js (for JavaScript bindings)
- Go (for Go bindings)
- Docker (for integration tests)

## Environment Setup

### 1. Install Dependencies

```bash
# Install Rust dependencies
cargo build --all

# Install Python dependencies
cd crates/fortress-python
pip install -r requirements.txt
cd ../..

# Install Node.js dependencies
cd crates/fortress-js
npm install
cd ../..

# Install Go dependencies
cd crates/fortress-go
go mod download
cd ../..
```

### 2. Set Up Test Environment

```bash
# Create test directories
mkdir -p test_data/encryption
mkdir -p test_data/storage
mkdir -p test_data/plugins

# Set environment variables
export FORTRESS_TEST_MODE=1
export FORTRESS_LOG_LEVEL=debug
export RUST_LOG=debug
```

## Core Library Testing

### 1. Run All Unit Tests

```bash
# Run all tests with detailed output
cargo test --all --verbose

# Run tests with coverage
cargo tarpaulin --out Html --output-dir test_coverage

# Run specific module tests
cargo test -p fortress-core --lib
cargo test -p fortress-cli
```

### 2. Encryption Module Testing

```bash
# Test encryption functionality
cargo test -p fortress-core encryption

# Test specific encryption algorithms
cargo test -p fortress-core test_argon2id_encrypt
cargo test -p fortress-core test_scrypt_encrypt

# Test error handling in encryption
cargo test -p fortress-core test_invalid_key_length
cargo test -p fortress-core test_encryption_error_handling
```

### 3. Storage Module Testing

```bash
# Test storage backends
cargo test -p fortress-core storage

# Test file storage
cargo test -p fortress-core test_file_storage

# Test memory storage
cargo test -p fortress-core test_memory_storage

# Test storage error handling
cargo test -p fortress-core test_storage_serialization_errors
```

### 4. Key Management Testing

```bash
# Test key generation and management
cargo test -p fortress-core key

# Test key derivation
cargo test -p fortress-core test_key_derivation

# Test key rotation
cargo test -p fortress-core test_key_rotation
```

## Plugin System Testing

### 1. Plugin Compilation Testing

```bash
# Test plugin compilation
cargo test -p fortress-core plugin

# Test plugin loading
cargo test -p fortress-core test_plugin_loading

# Test plugin validation
cargo test -p fortress-core test_plugin_validation
```

### 2. Plugin Integration Testing

```bash
# Build test plugins
cd testplugin
cargo build --release
cd ..

# Test plugin execution
cargo test test_plugin_execution

# Test plugin error handling
cargo test test_plugin_error_handling
```

### 3. Plugin Security Testing

```bash
# Test plugin sandboxing
cargo test test_plugin_sandboxing

# Test plugin resource limits
cargo test test_plugin_resource_limits

# Test plugin permission system
cargo test test_plugin_permissions
```

## API Testing

### 1. REST API Testing

```bash
# Start the API server
cargo run -p fortress-server --bin fortress-server &

# Wait for server to start
sleep 5

# Test API endpoints
curl -X GET http://localhost:8080/health
curl -X POST http://localhost:8080/api/v1/encrypt -H "Content-Type: application/json" -d '{"data": "test"}'
curl -X POST http://localhost:8080/api/v1/decrypt -H "Content-Type: application/json" -d '{"encrypted_data": "..."}'

# Stop the server
pkill fortress-server
```

### 2. Python API Testing

```bash
cd crates/fortress-python

# Run Python tests
python -m pytest tests/ -v

# Test specific functionality
python -m pytest tests/test_encryption.py -v
python -m pytest tests/test_storage.py -v

# Test error handling
python -m pytest tests/test_errors.py -v
```

### 3. JavaScript API Testing

```bash
cd crates/fortress-js

# Run JavaScript tests
npm test

# Run TypeScript compilation check
npm run build

# Test specific modules
npm test -- --grep "encryption"
npm test -- --grep "storage"
```

### 4. Go API Testing

```bash
cd crates/fortress-go

# Run Go tests
go test ./...

# Test with race detection
go test -race ./...

# Test specific packages
go test ./encryption
go test ./storage
```

## Security Testing

### 1. Cryptographic Security Testing

```bash
# Test cryptographic implementations
cargo test -p fortress-core test_crypto_security

# Test side-channel resistance
cargo test -p fortress-core test_side_channel_resistance

# Test key strength validation
cargo test -p fortress-core test_key_strength_validation
```

### 2. Input Validation Testing

```bash
# Test input sanitization
cargo test -p fortress-core test_input_validation

# Test boundary conditions
cargo test -p fortress-core test_boundary_conditions

# Test malformed input handling
cargo test -p fortress-core test_malformed_input
```

### 3. Memory Safety Testing

```bash
# Run with memory sanitizer (Linux)
RUSTFLAGS="-Z sanitizer=memory" cargo test -Z build-std --target x86_64-unknown-linux-gnu

# Run with address sanitizer
RUSTFLAGS="-Z sanitizer=address" cargo test -Z build-std --target x86_64-unknown-linux-gnu

# Run with thread sanitizer
RUSTFLAGS="-Z sanitizer=thread" cargo test -Z build-std --target x86_64-unknown-linux-gnu
```

## Performance Testing

### 1. Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmarks
cargo bench -p fortress-core encryption
cargo bench -p fortress-core storage

# Run with profiling
cargo bench --features profiling
```

### 2. Load Testing

```bash
# Test encryption performance
cargo run --example benchmark_encryption

# Test storage performance
cargo run --example benchmark_storage

# Test concurrent operations
cargo run --example benchmark_concurrent
```

### 3. Memory Profiling

```bash
# Profile memory usage
cargo run --example memory_profiling

# Test memory leaks
valgrind --leak-check=full cargo run --example memory_leak_test
```

## Integration Testing

### 1. End-to-End Testing

```bash
# Run integration tests
cargo test --test '*integration*'

# Test full workflow
cargo test --test test_full_workflow

# Test cross-language integration
cargo test --test test_cross_language_integration
```

### 2. Docker Integration Testing

```bash
# Build Docker image
docker build -t fortress-test .

# Run containerized tests
docker run --rm fortress-test cargo test --all

# Test multi-container scenarios
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### 3. Database Integration Testing

```bash
# Test with different storage backends
cargo test test_postgresql_integration
cargo test test_mysql_integration
cargo test test_redis_integration
```

## Error Detection and Logic Validation

### 1. Static Analysis

```bash
# Run Clippy for linting
cargo clippy --all -- -D warnings

# Check for unused dependencies
cargo machete

# Run security audit
cargo audit

# Check code formatting
cargo fmt --all -- --check
```

### 2. Dynamic Analysis

```bash
# Run tests with detailed logging
RUST_LOG=debug cargo test --all --nocapture

# Run tests with backtrace on panic
RUST_BACKTRACE=1 cargo test --all

# Run tests with error tracing
RUST_LOG=error cargo test --all
```

### 3. Logic Validation Commands

```bash
# Test error propagation
cargo test test_error_propagation

# Test error recovery
cargo test test_error_recovery

# Test edge cases
cargo test test_edge_cases

# Test race conditions
cargo test test_race_conditions -- --ignored

# Test deadlock scenarios
cargo test test_deadlock_scenarios -- --ignored
```

### 4. Code Coverage Analysis

```bash
# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage_report

# Check specific modules coverage
cargo tarpaulin -p fortress-core --out Html

# Generate XML coverage for CI
cargo tarpaulin --out Xml
```

### 5. Fuzz Testing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Initialize fuzz targets
cargo fuzz init

# Run fuzz testing
cargo fuzz run encryption_fuzz
cargo fuzz run storage_fuzz
cargo fuzz run api_fuzz
```

## Continuous Testing

### 1. Pre-commit Testing

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run pre-commit checks
pre-commit run --all-files
```

### 2. CI/CD Pipeline Testing

```bash
# Simulate CI pipeline
./scripts/ci-test.sh

# Test all target platforms
cargo test --target x86_64-pc-windows-gnu
cargo test --target x86_64-apple-darwin
cargo test --target x86_64-unknown-linux-gnu
```

### 3. Regression Testing

```bash
# Run regression test suite
cargo test --test regression_tests

# Compare with baseline performance
cargo bench --baseline main

# Validate API compatibility
./scripts/validate_api_compatibility.sh
```

## Test Data Management

### 1. Generate Test Data

```bash
# Generate encryption test vectors
cargo run --example generate_test_vectors

# Generate performance test data
cargo run --example generate_performance_data

# Generate stress test data
cargo run --example generate_stress_data
```

### 2. Clean Test Environment

```bash
# Clean test artifacts
cargo clean

# Remove test data
rm -rf test_data/

# Reset test environment
./scripts/reset_test_env.sh
```

## Troubleshooting

### Common Issues and Solutions

1. **Test Failures Due to Missing Dependencies**
   ```bash
   cargo clean && cargo build --all
   ```

2. **Permission Errors in Tests**
   ```bash
   chmod +x scripts/*.sh
   ```

3. **Memory Issues in Large Tests**
   ```bash
   export CARGO_TARGET_DIR=/tmp/fortress_build
   ```

4. **Network Issues in Integration Tests**
   ```bash
   export FORTRESS_TEST_TIMEOUT=30
   ```

## Reporting Test Results

### 1. Generate Test Report

```bash
# Generate comprehensive test report
cargo test --all --format json | python scripts/generate_test_report.py
```

### 2. Coverage Report

```bash
# Open coverage report in browser
open coverage_report/tarpaulin-report.html
```

### 3. Performance Report

```bash
# Generate performance benchmark report
cargo bench -- --output-format json > benchmark_results.json
python scripts/generate_performance_report.py benchmark_results.json
```

## Best Practices

1. **Always run tests before committing**
2. **Use descriptive test names**
3. **Test both success and failure paths**
4. **Include edge cases and boundary conditions**
5. **Maintain high code coverage (>90%)**
6. **Regularly update test data**
7. **Use property-based testing for complex logic**
8. **Document test scenarios and expected outcomes**

## Automation Scripts

### Quick Test Script

Create `scripts/quick_test.sh`:
```bash
#!/bin/bash
echo "Running quick test suite..."
cargo test --lib
cargo clippy -- -D warnings
cargo fmt -- --check
echo "Quick tests completed!"
```

### Full Test Script

Create `scripts/full_test.sh`:
```bash
#!/bin/bash
echo "Running full test suite..."
cargo test --all --verbose
cargo bench
cargo tarpaulin --out Html
cargo audit
echo "Full tests completed! Check coverage_report/tarpaulin-report.html"
```

This comprehensive testing guide ensures thorough validation of the Fortress codebase across all modules, languages, and deployment scenarios.
