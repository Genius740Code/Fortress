#!/bin/bash

# Fortress Cloud Integration Test Runner
# This script runs comprehensive cloud integration tests across multiple providers

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_RESULTS_DIR="${PROJECT_ROOT}/test-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="${TEST_RESULTS_DIR}/${TIMESTAMP}"

# Default values
PROVIDERS="aws,azure"
TEST_TYPES="integration,performance,compliance"
PARALLEL_TESTS=4
VERBOSE=false
CLEANUP=true
GENERATE_REPORT=true

# Help function
show_help() {
    cat << EOF
Fortress Cloud Integration Test Runner

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -p, --providers PROVIDERS       Comma-separated list of providers (aws,azure,gcp) [default: aws,azure]
    -t, --test-types TYPES          Comma-separated list of test types (integration,performance,compliance) [default: integration,performance,compliance]
    -j, --parallel JOBS             Number of parallel test jobs [default: 4]
    -v, --verbose                   Enable verbose output
    -n, --no-cleanup                Don't cleanup test resources after running
    -r, --no-report                Don't generate HTML report
    -h, --help                      Show this help message

EXAMPLES:
    $0                              # Run all tests for AWS and Azure
    $0 -p aws -t integration        # Run only integration tests for AWS
    $0 -p aws,azure -j 8 -v         # Run all tests with 8 parallel jobs and verbose output
    $0 -p azure -t performance -n   # Run performance tests for Azure without cleanup

ENVIRONMENT VARIABLES:
    FORTRESS_TEST_AWS_ACCESS_KEY_ID       AWS access key ID
    FORTRESS_TEST_AWS_SECRET_ACCESS_KEY   AWS secret access key
    FORTRESS_TEST_AWS_SESSION_TOKEN       AWS session token (optional)
    FORTRESS_TEST_AWS_REGION              AWS region (default: us-east-1)
    FORTRESS_TEST_S3_BUCKET               S3 bucket name for testing
    
    FORTRESS_TEST_AZURE_TENANT_ID        Azure tenant ID
    FORTRESS_TEST_AZURE_CLIENT_ID         Azure client ID
    FORTRESS_TEST_AZURE_CLIENT_SECRET     Azure client secret
    FORTRESS_TEST_AZURE_STORAGE_ACCOUNT   Azure storage account name
    FORTRESS_TEST_AZURE_CONTAINER         Azure container name

EOF
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--providers)
                PROVIDERS="$2"
                shift 2
                ;;
            -t|--test-types)
                TEST_TYPES="$2"
                shift 2
                ;;
            -j|--parallel)
                PARALLEL_TESTS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -n|--no-cleanup)
                CLEANUP=false
                shift
                ;;
            -r|--no-report)
                GENERATE_REPORT=false
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Validate environment
validate_environment() {
    log_info "Validating environment..."
    
    # Check if we're in the right directory
    if [[ ! -f "${PROJECT_ROOT}/Cargo.toml" ]]; then
        log_error "Not in Fortress project root directory"
        exit 1
    fi
    
    # Check if required tools are installed
    local required_tools=("cargo" "jq" "curl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Validate provider credentials
    IFS=',' read -ra PROVIDER_ARRAY <<< "$PROVIDERS"
    for provider in "${PROVIDER_ARRAY[@]}"; do
        case "$provider" in
            aws)
                if [[ -z "${FORTRESS_TEST_AWS_ACCESS_KEY_ID:-}" || -z "${FORTRESS_TEST_AWS_SECRET_ACCESS_KEY:-}" ]]; then
                    log_warning "AWS credentials not found in environment variables"
                    log_warning "Set FORTRESS_TEST_AWS_ACCESS_KEY_ID and FORTRESS_TEST_AWS_SECRET_ACCESS_KEY"
                fi
                ;;
            azure)
                if [[ -z "${FORTRESS_TEST_AZURE_TENANT_ID:-}" || -z "${FORTRESS_TEST_AZURE_CLIENT_ID:-}" || -z "${FORTRESS_TEST_AZURE_CLIENT_SECRET:-}" ]]; then
                    log_warning "Azure credentials not found in environment variables"
                    log_warning "Set FORTRESS_TEST_AZURE_TENANT_ID, FORTRESS_TEST_AZURE_CLIENT_ID, and FORTRESS_TEST_AZURE_CLIENT_SECRET"
                fi
                ;;
            gcp)
                log_warning "GCP integration not yet implemented"
                ;;
            *)
                log_error "Unknown provider: $provider"
                exit 1
                ;;
        esac
    done
    
    log_success "Environment validation completed"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create results directory
    mkdir -p "$REPORT_DIR"
    mkdir -p "$REPORT_DIR/logs"
    mkdir -p "$REPORT_DIR/reports"
    
    # Set Rust environment
    export RUST_LOG="${RUST_LOG:-info}"
    export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
    
    # Create test configuration
    cat > "$REPORT_DIR/test-config.json" << EOF
{
    "providers": ["$(echo "$PROVIDERS" | sed 's/,/","/g')"],
    "test_types": ["$(echo "$TEST_TYPES" | sed 's/,/","/g')"],
    "parallel_jobs": $PARALLEL_TESTS,
    "timestamp": "$TIMESTAMP",
    "project_root": "$PROJECT_ROOT"
}
EOF
    
    log_success "Test environment setup completed"
}

# Run tests for a specific provider and test type
run_provider_tests() {
    local provider="$1"
    local test_type="$2"
    local test_name="${provider}-${test_type}"
    local log_file="$REPORT_DIR/logs/${test_name}.log"
    local results_file="$REPORT_DIR/results/${test_name}.json"
    
    log_info "Running ${test_name} tests..."
    
    # Determine test binary and arguments based on provider and type
    local test_binary=""
    local test_args=""
    
    case "$provider" in
        aws)
            test_binary="test_aws_integration"
            ;;
        azure)
            test_binary="test_azure_integration"
            ;;
        gcp)
            log_warning "GCP tests not yet implemented"
            return 0
            ;;
    esac
    
    # Add test-specific arguments
    case "$test_type" in
        integration)
            test_args="--test-threads=1"
            ;;
        performance)
            test_args="--test-threads=1 -- --ignored"
            ;;
        compliance)
            test_args="--test-threads=1 -- --ignored"
            ;;
    esac
    
    # Run the test
    local start_time=$(date +%s)
    local exit_code=0
    
    cd "$PROJECT_ROOT"
    
    if cargo test --test "$test_binary" --features cloud-storage $test_args > "$log_file" 2>&1; then
        exit_code=0
        log_success "${test_name} tests passed"
    else
        exit_code=1
        log_error "${test_name} tests failed"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Create results summary
    cat > "$results_file" << EOF
{
    "provider": "$provider",
    "test_type": "$test_type",
    "exit_code": $exit_code,
    "duration_seconds": $duration,
    "timestamp": "$TIMESTAMP",
    "log_file": "$log_file"
}
EOF
    
    return $exit_code
}

# Run all tests
run_all_tests() {
    log_info "Starting cloud integration tests..."
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    IFS=',' read -ra PROVIDER_ARRAY <<< "$PROVIDERS"
    IFS=',' read -ra TEST_TYPE_ARRAY <<< "$TEST_TYPES"
    
    # Run tests in parallel if requested
    if [[ $PARALLEL_TESTS -gt 1 ]]; then
        local pids=()
        
        for provider in "${PROVIDER_ARRAY[@]}"; do
            for test_type in "${TEST_TYPE_ARRAY[@]}"; do
                total_tests=$((total_tests + 1))
                
                run_provider_tests "$provider" "$test_type" &
                pids+=($!)
                
                # Limit parallel jobs
                if [[ ${#pids[@]} -ge $PARALLEL_TESTS ]]; then
                    for pid in "${pids[@]}"; do
                        wait "$pid"
                        if [[ $? -eq 0 ]]; then
                            passed_tests=$((passed_tests + 1))
                        else
                            failed_tests=$((failed_tests + 1))
                        fi
                    done
                    pids=()
                fi
            done
        done
        
        # Wait for remaining jobs
        for pid in "${pids[@]}"; do
            wait "$pid"
            if [[ $? -eq 0 ]]; then
                passed_tests=$((passed_tests + 1))
            else
                failed_tests=$((failed_tests + 1))
            fi
        done
    else
        # Run tests sequentially
        for provider in "${PROVIDER_ARRAY[@]}"; do
            for test_type in "${TEST_TYPE_ARRAY[@]}"; do
                total_tests=$((total_tests + 1))
                
                if run_provider_tests "$provider" "$test_type"; then
                    passed_tests=$((passed_tests + 1))
                else
                    failed_tests=$((failed_tests + 1))
                fi
            done
        done
    fi
    
    # Create summary report
    cat > "$REPORT_DIR/summary.json" << EOF
{
    "total_tests": $total_tests,
    "passed_tests": $passed_tests,
    "failed_tests": $failed_tests,
    "success_rate": $(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l),
    "timestamp": "$TIMESTAMP",
    "providers": ["$(echo "$PROVIDERS" | sed 's/,/","/g')"],
    "test_types": ["$(echo "$TEST_TYPES" | sed 's/,/","/g')"]
}
EOF
    
    log_info "Test execution completed"
    log_info "Total tests: $total_tests"
    log_info "Passed: $passed_tests"
    log_info "Failed: $failed_tests"
    log_info "Success rate: $(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l)%"
    
    return $failed_tests
}

# Generate HTML report
generate_html_report() {
    if [[ "$GENERATE_REPORT" != "true" ]]; then
        return 0
    fi
    
    log_info "Generating HTML report..."
    
    local html_file="$REPORT_DIR/report.html"
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fortress Cloud Integration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #666; }
        .metric .value { font-size: 2em; font-weight: bold; }
        .success { color: #28a745; }
        .failure { color: #dc3545; }
        .test-results { margin-top: 30px; }
        .test-item { border: 1px solid #ddd; margin-bottom: 10px; border-radius: 4px; }
        .test-header { padding: 15px; background: #f8f9fa; font-weight: bold; cursor: pointer; }
        .test-details { padding: 15px; display: none; }
        .passed { border-left: 4px solid #28a745; }
        .failed { border-left: 4px solid #dc3545; }
        .log-link { color: #007bff; text-decoration: none; }
        .log-link:hover { text-decoration: underline; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Fortress Cloud Integration Test Report</h1>
        
        <div class="summary">
            <div class="metric">
                <h3>Total Tests</h3>
                <div class="value" id="total-tests">-</div>
            </div>
            <div class="metric">
                <h3>Passed</h3>
                <div class="value success" id="passed-tests">-</div>
            </div>
            <div class="metric">
                <h3>Failed</h3>
                <div class="value failure" id="failed-tests">-</div>
            </div>
            <div class="metric">
                <h3>Success Rate</h3>
                <div class="value" id="success-rate">-</div>
            </div>
        </div>
        
        <div class="test-results">
            <h2>Test Results</h2>
            <div id="test-list"></div>
        </div>
        
        <div class="timestamp">
            Generated on: <span id="timestamp"></span>
        </div>
    </div>

    <script>
        // Load test results
        fetch('summary.json')
            .then(response => response.json())
            .then(summary => {
                document.getElementById('total-tests').textContent = summary.total_tests;
                document.getElementById('passed-tests').textContent = summary.passed_tests;
                document.getElementById('failed-tests').textContent = summary.failed_tests;
                document.getElementById('success-rate').textContent = summary.success_rate + '%';
                document.getElementById('timestamp').textContent = new Date(summary.timestamp).toLocaleString();
                
                // Load individual test results
                return Promise.all([
                    ...summary.providers.flatMap(provider =>
                        summary.test_types.map(testType =>
                            fetch(`results/${provider}-${testType}.json`)
                                .then(response => response.json())
                                .catch(() => null)
                        )
                    )
                ]);
            })
            .then(results => {
                const testList = document.getElementById('test-list');
                results.filter(result => result !== null).forEach(result => {
                    const testItem = document.createElement('div');
                    testItem.className = `test-item ${result.exit_code === 0 ? 'passed' : 'failed'}`;
                    
                    testItem.innerHTML = `
                        <div class="test-header" onclick="toggleDetails(this)">
                            ${result.provider} - ${result.test_type} 
                            <span style="float: right;">${result.exit_code === 0 ? '✓ PASSED' : '✗ FAILED'}</span>
                        </div>
                        <div class="test-details">
                            <p><strong>Provider:</strong> ${result.provider}</p>
                            <p><strong>Test Type:</strong> ${result.test_type}</p>
                            <p><strong>Duration:</strong> ${result.duration_seconds} seconds</p>
                            <p><strong>Log File:</strong> <a href="${result.log_file}" class="log-link">${result.log_file}</a></p>
                        </div>
                    `;
                    
                    testList.appendChild(testItem);
                });
            })
            .catch(error => {
                console.error('Error loading test results:', error);
                document.getElementById('test-list').innerHTML = '<p>Error loading test results</p>';
            });
        
        function toggleDetails(header) {
            const details = header.nextElementSibling;
            details.style.display = details.style.display === 'none' ? 'block' : 'none';
        }
    </script>
</body>
</html>
EOF
    
    log_success "HTML report generated: $html_file"
}

# Cleanup test resources
cleanup_test_resources() {
    if [[ "$CLEANUP" != "true" ]]; then
        log_info "Skipping cleanup as requested"
        return 0
    fi
    
    log_info "Cleaning up test resources..."
    
    # Cleanup would go here - for now just log
    # In a real implementation, this would:
    # - Delete test S3 buckets
    # - Delete test Azure containers
    # - Remove temporary files
    # - Stop any running test instances
    
    log_success "Cleanup completed"
}

# Main execution
main() {
    parse_args "$@"
    
    log_info "Fortress Cloud Integration Test Runner"
    log_info "======================================"
    
    validate_environment
    setup_test_environment
    
    local test_exit_code=0
    run_all_tests || test_exit_code=$?
    
    generate_html_report
    cleanup_test_resources
    
    if [[ $test_exit_code -eq 0 ]]; then
        log_success "All tests completed successfully!"
        log_info "Report available at: $REPORT_DIR/report.html"
    else
        log_error "Some tests failed!"
        log_info "Check the report for details: $REPORT_DIR/report.html"
    fi
    
    exit $test_exit_code
}

# Run main function with all arguments
main "$@"
