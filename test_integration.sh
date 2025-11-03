#!/bin/bash

# Integration Test Runner for IPv6 MTU Discovery Tool
# This script runs integration tests with proper setup and error handling

set -e

echo "=== IPv6 MTU Discovery Integration Tests ==="
echo

# Check if running as root (required for raw sockets)
if [[ $EUID -ne 0 ]]; then
    echo "Warning: Integration tests may require root privileges for raw socket operations"
    echo "Some tests may be skipped or fail without proper privileges"
    echo
fi

# Check IPv6 support
if ! ip -6 addr show lo | grep -q "::1"; then
    echo "Warning: IPv6 loopback not available, some tests may fail"
    echo
fi

# Set test timeout
export TEST_TIMEOUT=${TEST_TIMEOUT:-30s}

# Function to run tests with proper error handling
run_test_package() {
    local package=$1
    local description=$2
    
    echo "--- Running $description ---"
    
    if go test -timeout $TEST_TIMEOUT -v "./$package" -run "Integration"; then
        echo "✅ $description: PASSED"
    else
        echo "❌ $description: FAILED"
        return 1
    fi
    echo
}

# Function to run tests in short mode (unit tests only)
run_short_tests() {
    echo "--- Running Unit Tests (Short Mode) ---"
    
    if go test -short -timeout $TEST_TIMEOUT -v ./...; then
        echo "✅ Unit Tests: PASSED"
    else
        echo "❌ Unit Tests: FAILED"
        return 1
    fi
    echo
}

# Main test execution
main() {
    local failed=0
    
    echo "Go version: $(go version)"
    echo "Test timeout: $TEST_TIMEOUT"
    echo
    
    # Run unit tests first
    if ! run_short_tests; then
        failed=1
    fi
    
    # Run integration tests
    echo "=== Integration Tests ==="
    echo
    
    if ! run_test_package "internal/app" "Application Integration Tests"; then
        failed=1
    fi
    
    if ! run_test_package "internal/probe" "Probe Integration Tests"; then
        failed=1
    fi
    
    if ! run_test_package "internal/network" "Network Integration Tests"; then
        failed=1
    fi
    
    # Summary
    echo "=== Test Summary ==="
    if [[ $failed -eq 0 ]]; then
        echo "🎉 All tests passed!"
        exit 0
    else
        echo "💥 Some tests failed!"
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    "unit")
        echo "Running unit tests only..."
        run_short_tests
        ;;
    "integration")
        echo "Running integration tests only..."
        run_test_package "internal/app" "Application Integration Tests"
        run_test_package "internal/probe" "Probe Integration Tests" 
        run_test_package "internal/network" "Network Integration Tests"
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [unit|integration|help]"
        echo
        echo "Options:"
        echo "  unit         Run unit tests only (short mode)"
        echo "  integration  Run integration tests only"
        echo "  help         Show this help message"
        echo
        echo "Environment variables:"
        echo "  TEST_TIMEOUT  Test timeout duration (default: 30s)"
        echo
        echo "Examples:"
        echo "  $0                    # Run all tests"
        echo "  $0 unit              # Run unit tests only"
        echo "  $0 integration       # Run integration tests only"
        echo "  TEST_TIMEOUT=60s $0  # Run with 60 second timeout"
        ;;
    *)
        main
        ;;
esac